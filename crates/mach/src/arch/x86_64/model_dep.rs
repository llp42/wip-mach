// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The machine-dependent boot and halt path: the idle and relax instructions,
//! the `/dev/time` mmap hook, the wall clock, the bootstrap allocator and the
//! boot entry points.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::VM_MIN_KERNEL_ADDRESS;
use crate::arch::vm_param::{PAGE_MASK, PAGE_SHIFT};
use crate::arch::x86_64::clock_platform;
use crate::arch::x86_64::multiboot::{
    MultibootLoaderFlags, MultibootModule, MultibootRawInfo,
    MultibootRawMmapEntry, MultibootRawModule, load_modules,
};
use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::spl;
use crate::arch::x86_64::{
    apic, cpuboot, fpu, gdt, idt, int_init, ioapic, irq, ktss, ldt, mbinfo,
    mp_desc, per_cpu, pit, rtc,
};
use crate::config::KERNEL_VERSION;
use crate::kern::console::{Console, kprint};
use crate::kern::debug::kpanic;
use crate::kern::kheap::Kalloc;
use crate::mig;
use crate::mig::time_value::TimeValue64;
use core::ffi::{CStr, c_char, c_int};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use kmem::{AllocError, KVec};
use mach_device::io_req::DevT;
use mach_host::time as host_time;
use mach_page::memmap::{self, MapEntry};
use mach_pmap::bootstrap;
use mach_pmap::pmap::{kernel_pmap_ptr, pmap_extract};
use mach_pmap::types::Bootstrap;
use mach_thread::smp::CpuId;
use mach_vm::types::VmProt;
use raw_cpuid::FeatureInfo;
use volatile::VolatilePtr;
use x86_64::instructions::interrupts;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

/// The ELF section type of a symbol table.
const ELF_SHT_SYMTAB: u32 = 2;
/// The ELF section type of a string table.
const ELF_SHT_STRTAB: u32 = 3;

/// The CPU type of x86-64.
const CPU_TYPE_X86_64: c_int = 21;
/// The CPU subtype of an AT-compatible PC.
const CPU_SUBTYPE_AT386: c_int = 1;

/// The multiboot information block the boot loader left, which
/// [`c_boot_entry`] copies out of low memory.
// SAFETY: `MultibootRawInfo` is all integers, for which zero is a valid bit
// pattern.
pub(crate) static mut BOOT_INFO: MultibootRawInfo =
    unsafe { core::mem::zeroed() };

/// The boot command line, `""` until [`i386at_init`] can copy the loader's
/// line to safe memory.
static KERNEL_CMDLINE: AtomicPtr<c_char> =
    AtomicPtr::new(c"".as_ptr().cast_mut());

/// The boot loader's information block, frozen by the boot sequence.
#[must_use]
pub(crate) fn boot_info() -> MultibootRawInfo {
    // SAFETY: `c_boot_entry` and `i386at_init` are the block's only
    // writers, and both ran before the bootstrap.
    unsafe { *ptr::addr_of!(BOOT_INFO) }
}

/// Copies the loader's module records, images and command lines, empty
/// when the loader left none.
///
/// # Errors
///
/// [`AllocError`] when the heap cannot hold the list or a command line.
pub(crate) fn boot_modules()
-> Result<KVec<MultibootModule, Kalloc>, AllocError> {
    let info = boot_info();
    let flags = MultibootLoaderFlags::from_bits_retain(info.flags);
    if !flags.contains(MultibootLoaderFlags::MODULES) || info.mods_count == 0 {
        return Ok(KVec::new(Kalloc));
    }
    // SAFETY: the loader left `mods_count` records at `mods_addr`, and
    // `i386at_init` copied every record, image and command line into
    // kernel memory before the bootstrap.
    unsafe { load_modules(info.mods_addr, info.mods_count) }
}

/// The boot command line, frozen by the boot sequence.
#[must_use]
pub(crate) fn kernel_cmdline() -> &'static CStr {
    // SAFETY: `i386at_init` is the line's only writer, its string is
    // NUL-terminated, and it lives as long as the kernel.
    unsafe { CStr::from_ptr(KERNEL_CMDLINE.load(Ordering::Relaxed)) }
}

/// Set when ctrl-alt-del should reboot the machine.
pub static REBOOTFLAG: AtomicBool = AtomicBool::new(false);

/// An ELF section header, which [`register_boot_data`] walks.
#[repr(C)]
#[allow(missing_docs)]
struct ElfShdr {
    name: u32,
    type_: u32,
    flags: u32,
    addr: VmOffset,
    offset: VmOffset,
    size: u32,
    link: u32,
    info: u32,
    addralign: u32,
    entsize: u32,
}

const _: () = {
    assert!(size_of::<ElfShdr>() == 56);
    assert!(align_of::<ElfShdr>() == align_of::<u64>());
    assert!(offset_of!(ElfShdr, addr) == 16);
    assert!(offset_of!(ElfShdr, size) == 32);
};

/// The six bytes the AP boot code reserves for `gdt_descr_tmp`: the
/// pseudo-descriptor up to its padding, which the realmode GDT pointer
/// occupies.
#[repr(C, packed)]
#[allow(missing_docs)]
pub struct GdtDescrTmp {
    pub limit: u16,
    pub linear_base: u32,
}

const _: () = {
    assert!(size_of::<GdtDescrTmp>() == 6);
    assert!(align_of::<GdtDescrTmp>() == 1);
    assert!(offset_of!(GdtDescrTmp, linear_base) == 2);
};

/// The kernel virtual address of the physical address `pa`.
const fn phystokv(pa: VmOffset) -> VmOffset {
    pa.wrapping_add(VM_MIN_KERNEL_ADDRESS)
}

/// The pointer-width address a 32-bit multiboot field holds; the widening to
/// `usize` is lossless.
const fn address(value: u32) -> VmOffset {
    value as VmOffset
}

/// The kernel pointer a direct-map address denotes.
const fn kv_ptr<T>(value: VmOffset) -> *const T {
    ptr::with_exposed_provenance(value)
}

/// The writable kernel pointer a direct-map address denotes.
const fn kv_ptr_mut<T>(value: VmOffset) -> *mut T {
    ptr::with_exposed_provenance_mut(value)
}

/// Idles the CPU until the next interrupt.
pub(crate) fn machine_idle(_cpu: c_int) {
    x86_64::instructions::hlt();
}

/// The page frame holding the kernel's mapped time value, or `None` when the
/// request asks for write access.
pub(crate) fn mapped_time_page(prot: VmProt) -> Option<VmOffset> {
    if prot.contains(VmProt::WRITE) {
        return None;
    }

    // `mapable_time_init()` wired the page at boot, before `/dev/time` can be
    // opened.
    let address = clock_platform::mapped_time_page() as VmOffset;
    // SAFETY: `kernel_pmap_ptr()` is the kernel's own pmap, so it maps
    // `address`.
    let phys =
        unsafe { pmap_extract::<MachPlatform>(kernel_pmap_ptr(), address) };
    Some(phys >> PAGE_SHIFT)
}

/// The mmap hook of the `/dev/time` device: the page frame of the mapped time
/// page, or `VmOffset::MAX` for a writable mapping.
pub(crate) fn timemmap(_dev: DevT, _off: VmOffset, prot: c_int) -> VmOffset {
    mapped_time_page(VmProt::from_bits_retain(prot)).unwrap_or(VmOffset::MAX)
}

/// Set the kernel's wall clock.
fn set_wallclock(seconds: i64) {
    host_time::set_wallclock::<MachPlatform>(TimeValue64 {
        seconds,
        nanoseconds: 0,
    });
}

/// Sets the wall clock from the CMOS clock.
pub(crate) fn inittodr() {
    // The C left the seconds at zero when the clock had no valid time.
    let seconds = rtc::read_todc().unwrap_or(0);
    // The C converted the `uint64_t` seconds to the record's `int64_t` field;
    // the cast reinterprets the bits as that conversion does.
    set_wallclock(seconds as i64);
}

/// Writes the wall clock back to the CMOS clock.
pub(crate) fn resettodr() {
    // The C ignored a clock that cannot keep the time.
    let _ = rtc::write_todc(host_time::wallclock::<MachPlatform>().seconds);
}

/// Allocate `size` bytes of physical memory during bootstrap, page-rounded, or
/// `None` when the bootstrap allocator is out of pages.
pub(crate) fn alloc_aligned(size: VmSize) -> Option<VmOffset> {
    let rounded = size.wrapping_add(PAGE_MASK) & !PAGE_MASK;
    // The page count, kept to the allocator's 32 bits.
    let pages = (rounded >> PAGE_SHIFT) as u32;
    let address = memmap::bootalloc(pages);
    if address == 0 { None } else { Some(address) }
}

/// Finishes the machine setup: frees the boot memory, then sets up the FPU,
/// the APICs, the console, the buses and the clocks.
pub(crate) fn machine_init() {
    // SAFETY: `machine_init` runs once, from `setup_main`, after the memory
    // map's setup.
    unsafe { memmap::free_usable() };
    // SAFETY: the FPU init runs once, on the boot CPU.
    unsafe { fpu::init_fpu() };

    if let Err(error) = crate::arch::x86_64::acpi::init() {
        kprint!("acpi_apic_init failed with {:?}\n", error);
        loop {
            core::hint::spin_loop();
        }
    }

    crate::arch::x86_64::smp::init();
    irq::init_irqs();
    ioapic::ioapic_configure();
    pit::clkstart();

    // SAFETY: `cninit` and `probeio` are the console and AT-bus boot steps,
    // both Rust now.
    unsafe {
        crate::device::cons::init();
        crate::arch::x86_64::autoconf::probeio();
    }

    inittodr();

    // SAFETY: the BIOS data word at 0x472 lives in the direct map, and the C
    // wrote the same value there.
    unsafe {
        VolatilePtr::new(NonNull::new_unchecked(phystokv(0x472) as *mut u16))
    }
    .write(0x1234);

    if VM_MIN_KERNEL_ADDRESS == 0 {
        // SAFETY: page 0 is mapped in this configuration, and the C unmapped
        // it here.
        unsafe { bootstrap::pmap_unmap_page_zero::<MachPlatform>() };
    }

    patch_realmode_gdt();

    apic::hpet_init();
}

/// Patch the realmode GDT and the far jump after it with the address the AP
/// boot code was copied to.
fn patch_realmode_gdt() {
    // The AP boot page sits below 4 GiB, so the C's narrowing to the realmode
    // `u32` fields loses nothing.
    let apboot = mp_desc::APBOOT_ADDR.load(Ordering::Relaxed) as u32;
    // SAFETY: `gdt_descr_tmp` and `apboot_jmp_offset` are the AP boot page's
    // objects, and `machine_init` is their only writer.
    unsafe {
        let base = phystokv(
            ptr::addr_of_mut!(cpuboot::gdt_descr_tmp.linear_base).addr(),
        ) as *mut u32;
        *base = (*base).wrapping_add(apboot);
        let jmp =
            phystokv(ptr::addr_of_mut!(cpuboot::apboot_jmp_offset).addr())
                as *mut u32;
        *jmp = (*jmp).wrapping_add(apboot);
    }
}

/// Halts this CPU for good.
pub(crate) fn halt_cpu() -> ! {
    interrupts::disable();
    loop {
        x86_64::instructions::hlt();
    }
}

/// Halts the machine, rebooting it when `reboot` is set.
pub(crate) fn halt_all_cpus(reboot: c_int) -> ! {
    // Persist the ticking wall clock before this CPU stops advancing it.
    resettodr();
    if reboot != 0 {
        // SAFETY: `kdreboot` is the keyboard controller's reset path, and the
        // C took it under the same flag.
        unsafe { crate::arch::x86_64::kd::kdreboot() };
    } else {
        REBOOTFLAG.store(true, Ordering::Relaxed);
        kprint!("Shutdown completed successfully, now in tight loop.\n");
        kprint!(
            "You can safely power off the system or hit ctl-alt-del to reboot\n"
        );
        // SAFETY: lowering to `spl0` here has no lock to hold back.
        unsafe { spl::spl0() };
    }
    loop {
        x86_64::instructions::hlt();
    }
}

/// Register the boot loader's data with the memory map and `mbinfo`.
fn register_boot_data(mbi: &MultibootRawInfo) {
    let flags = MultibootLoaderFlags::from_bits_retain(mbi.flags);
    let begin = ptr::addr_of!(mig::_start).addr();
    let end = ptr::addr_of!(mig::_end).addr();
    // SAFETY: the image bounds are the linker's, and this is the bootstrap
    // phase the call requires.
    unsafe {
        memmap::register_boot_data(
            begin.wrapping_sub(VM_MIN_KERNEL_ADDRESS),
            end.wrapping_sub(VM_MIN_KERNEL_ADDRESS),
            false,
        );
    };

    if flags.contains(MultibootLoaderFlags::CMDLINE) && mbi.cmdline != 0 {
        let start = address(mbi.cmdline);
        // SAFETY: the loader stored a NUL-terminated line at `start`, which
        // is in the direct map.
        let length = unsafe {
            CStr::from_ptr(kv_ptr::<c_char>(phystokv(start))).count_bytes()
        } + 1;
        // SAFETY: the range is the line the loader stored.
        unsafe {
            memmap::register_boot_data(
                start,
                start.wrapping_add(length),
                true,
            );
        };
    }

    if flags.contains(MultibootLoaderFlags::MODULES) && mbi.mods_count != 0 {
        register_boot_modules(mbi);
    }

    if flags.contains(MultibootLoaderFlags::SHDR) {
        register_boot_section_headers(mbi);
    }

    // SAFETY: this is the bootstrap phase the call requires.
    unsafe {
        mbinfo::mbinfo_register_boot_data(
            ptr::from_ref::<MultibootRawInfo>(mbi).cast(),
        );
    };
}

/// Register the boot loader's module records and images, the module half of
/// `register_boot_data()`.
fn register_boot_modules(mbi: &MultibootRawInfo) {
    let bytes = mbi
        .mods_count
        .wrapping_mul(size_of::<MultibootRawModule>() as u32);
    // SAFETY: the loader stored `mods_count` module records at
    // `mods_addr`.
    unsafe {
        memmap::register_boot_data(
            address(mbi.mods_addr),
            address(mbi.mods_addr.wrapping_add(bytes)),
            true,
        );
    };

    let modules =
        kv_ptr_mut::<MultibootRawModule>(phystokv(address(mbi.mods_addr)));
    for i in 0..mbi.mods_count {
        // SAFETY: `i` is below `mods_count`, and the records are live.
        let module = unsafe { modules.add(i as usize) };
        // SAFETY: `i` is below `mods_count`, and the records are live.
        let (start, end, string) = unsafe {
            ((*module).mod_start, (*module).mod_end, (*module).string)
        };
        if end != start {
            // SAFETY: the loader's two bounds bracket a module image.
            unsafe {
                memmap::register_boot_data(address(start), address(end), true);
            };
        }

        if string != 0 {
            let string_start = address(string);
            // SAFETY: the loader stored a NUL-terminated name there.
            let length = unsafe {
                CStr::from_ptr(kv_ptr::<c_char>(phystokv(string_start)))
                    .count_bytes()
            } + 1;
            // SAFETY: the range is the name's.
            unsafe {
                memmap::register_boot_data(
                    string_start,
                    string_start.wrapping_add(length),
                    true,
                );
            };
        }
    }
}

/// Register the boot loader's ELF section headers, the header half of
/// `register_boot_data()`.
fn register_boot_section_headers(mbi: &MultibootRawInfo) {
    let bytes = mbi.shdr_num.wrapping_mul(mbi.shdr_size);
    if bytes != 0 {
        // SAFETY: the loader stored `shdr_num` headers at `shdr_addr`.
        unsafe {
            memmap::register_boot_data(
                address(mbi.shdr_addr),
                address(mbi.shdr_addr.wrapping_add(bytes)),
                false,
            );
        };
    }

    let table = phystokv(address(mbi.shdr_addr));
    for i in 0..mbi.shdr_num {
        let offset = i.wrapping_mul(mbi.shdr_size);
        // `i` is below `shdr_num`, and each record is `shdr_size` bytes
        // of the loader's table.
        let shdr = ptr::with_exposed_provenance::<ElfShdr>(
            table.wrapping_add(address(offset)),
        );
        // SAFETY: the loader stored `shdr_num` headers at `shdr_addr`; the
        // loader's table is only 4-byte aligned, so the record is read
        // unaligned.
        let shdr = unsafe { ptr::read_unaligned(shdr) };
        let (type_, size, addr) = (shdr.type_, shdr.size, shdr.addr);
        if type_ != ELF_SHT_SYMTAB && type_ != ELF_SHT_STRTAB {
            continue;
        }

        if size != 0 {
            // SAFETY: the header names `size` bytes of the section at
            // `addr`.
            unsafe {
                memmap::register_boot_data(
                    addr,
                    addr.wrapping_add(address(size)),
                    false,
                );
            };
        }
    }
}

/// Copy the boot loader's module records and images out of the low pages
/// before the memory map's setup can hand them to the VM system, the module half
/// of `i386at_init()`.
fn copy_boot_modules(mods_count: u32, mods_addr: u32) {
    let bytes =
        mods_count.wrapping_mul(size_of::<MultibootRawModule>() as u32);
    let Some(mem) = alloc_aligned(address(bytes)) else {
        kpanic!(
            "i386at_init",
            "could not allocate memory for multiboot modules"
        )
    };
    let modules = kv_ptr_mut::<MultibootRawModule>(phystokv(mem));
    // SAFETY: the loader stored `mods_count` records at `mods_addr`, the
    // boot allocator returned `bytes` for the copy, and the two do not
    // overlap.
    unsafe {
        ptr::copy_nonoverlapping(
            kv_ptr::<u8>(phystokv(address(mods_addr))),
            modules.cast::<u8>(),
            address(bytes),
        );
    };
    // SAFETY: `BOOT_INFO` is written only on this boot path, on one CPU.
    unsafe { BOOT_INFO.mods_addr = mem as u32 };

    for i in 0..mods_count {
        // SAFETY: `i` is below `mods_count`, and the records were just
        // copied into `modules`.
        let module = unsafe { modules.add(i as usize) };
        // SAFETY: `i` is below `mods_count`, and the records were just copied
        // into `modules`.
        let (start, end, string) = unsafe {
            ((*module).mod_start, (*module).mod_end, (*module).string)
        };
        let size = end.wrapping_sub(start);
        let Some(image) = alloc_aligned(address(size)) else {
            kpanic!(
                "i386at_init",
                "could not allocate memory for multiboot module {}",
                i
            )
        };
        // SAFETY: `start` names `size` readable bytes and the boot
        // allocator returned `size` writable ones.
        unsafe {
            ptr::copy_nonoverlapping(
                kv_ptr::<u8>(phystokv(address(start))),
                kv_ptr_mut::<u8>(phystokv(image)),
                address(size),
            );
        };
        // SAFETY: the record was copied into `modules`, and this CPU is
        // its only writer.
        unsafe {
            (*module).mod_start = image as u32;
            (*module).mod_end = image.wrapping_add(address(size)) as u32;
        }

        let string_start = address(string);
        // SAFETY: the loader stored a NUL-terminated name at `string`.
        let length = unsafe {
            CStr::from_ptr(kv_ptr::<c_char>(phystokv(string_start)))
                .count_bytes()
        } + 1;
        let Some(name) = alloc_aligned(length) else {
            kpanic!(
                "i386at_init",
                "could not allocate memory for multiboot module command line {}",
                i
            )
        };
        // SAFETY: `string_start` names `length` readable bytes and the
        // boot allocator returned `length` writable ones.
        unsafe {
            ptr::copy_nonoverlapping(
                kv_ptr::<u8>(phystokv(string_start)),
                kv_ptr_mut::<u8>(phystokv(name)),
                length,
            );
        };
        // SAFETY: the record was copied into `modules`, and this CPU is
        // its only writer.
        unsafe { (*module).string = name as u32 };
    }
}

/// Prepares the boot CPU: masks the 8259, builds the memory map, saves the
/// command line and modules, turns paging on with the kernel's page tables,
/// loads the descriptor tables, and allocates the interrupt stacks.
#[expect(
    clippy::too_many_lines,
    reason = "the boot CPU's preparation is one ordered sequence, each step \
              used once"
)]
fn i386at_init() {
    ioapic::picdisable();

    // SAFETY: `BOOT_INFO` is the loader's block, copied to safe memory by
    // `c_boot_entry`, which is the only writer.
    register_boot_data(unsafe { &*ptr::addr_of!(BOOT_INFO) });
    // SAFETY: `BOOT_INFO` is the loader's block, copied to safe memory by
    // `c_boot_entry`, which is the only writer.
    let mbi = unsafe { &*ptr::addr_of!(BOOT_INFO) };
    let apboot = if MultibootLoaderFlags::from_bits_retain(mbi.flags)
        .contains(MultibootLoaderFlags::MMAP)
    {
        let mut entry = phystokv(mbi.mmap_addr as VmOffset);
        let end = entry.wrapping_add(mbi.mmap_length as VmOffset);
        let entries = core::iter::from_fn(|| {
            if entry >= end {
                return None;
            }
            // SAFETY: the loader left one packed entry at this address, and
            // `packed` keeps the reference valid at any alignment.
            let raw = unsafe {
                &*ptr::with_exposed_provenance::<MultibootRawMmapEntry>(entry)
            };
            entry = entry
                .wrapping_add(size_of::<u32>())
                .wrapping_add(raw.size as VmOffset);
            Some(MapEntry {
                base_addr: raw.base_addr,
                length: raw.length,
                type_: raw.type_,
            })
        });
        // SAFETY: this is the boot phase, on the boot CPU alone.
        unsafe { memmap::bootstrap(entries, mbi.mem_upper) }
    } else {
        // Without a map, the lower and upper memory sizes stand for the
        // available memory below and above 1 MiB.
        let entries = [
            MapEntry {
                base_addr: 0,
                length: u64::from(mbi.mem_lower.wrapping_shl(PAGE_SHIFT)),
                type_: 1,
            },
            MapEntry {
                base_addr: 0x0010_0000,
                length: u64::from(mbi.mem_upper.wrapping_shl(PAGE_SHIFT)),
                type_: 1,
            },
        ];
        // SAFETY: this is the boot phase, on the boot CPU alone.
        unsafe { memmap::bootstrap(entries, mbi.mem_upper) }
    };
    mp_desc::APBOOT_ADDR.store(apboot, Ordering::Relaxed);

    // The copy below overwrites `BOOT_INFO`'s own fields, so the loader's
    // values are read first.
    // SAFETY: `BOOT_INFO` is the loader's block, copied to safe memory by
    // `c_boot_entry`, which is the only writer; no other CPU is running
    // yet.
    let (flags, cmdline, mods_count, mods_addr) = unsafe {
        (
            BOOT_INFO.flags,
            BOOT_INFO.cmdline,
            BOOT_INFO.mods_count,
            BOOT_INFO.mods_addr,
        )
    };
    let flags = MultibootLoaderFlags::from_bits_retain(flags);

    // The loader's command line and modules are copied out of low memory
    // before the memory map's setup can hand those pages to the VM system.
    if flags.contains(MultibootLoaderFlags::CMDLINE) {
        let source = address(cmdline);
        // SAFETY: the loader stored a NUL-terminated line at `source`.
        let length = unsafe {
            CStr::from_ptr(kv_ptr::<c_char>(phystokv(source))).count_bytes()
        } + 1;
        let Some(mem) = alloc_aligned(length) else {
            kpanic!(
                "i386at_init",
                "could not allocate memory for multiboot command line"
            )
        };
        // SAFETY: `source` names `length` readable bytes and the boot
        // allocator returned `length` writable ones.
        unsafe {
            ptr::copy_nonoverlapping(
                kv_ptr::<u8>(phystokv(source)),
                kv_ptr_mut::<u8>(phystokv(mem)),
                length,
            );
        };
        KERNEL_CMDLINE
            .store(kv_ptr_mut::<c_char>(phystokv(mem)), Ordering::Relaxed);
        // SAFETY: `BOOT_INFO` is written only here and only on the boot CPU.
        unsafe { BOOT_INFO.cmdline = mem as u32 };
    }

    if flags.contains(MultibootLoaderFlags::MODULES) && mods_count != 0 {
        copy_boot_modules(mods_count, mods_addr);
    }

    let features = raw_cpuid::CpuId::new().get_feature_info();
    let global_pages = features.as_ref().is_some_and(FeatureInfo::has_pge);

    bootstrap::pmap_bootstrap::<MachPlatform>(&Bootstrap {
        text_start: ptr::addr_of!(mig::_start).addr(),
        text_end: ptr::addr_of!(mig::etext).addr(),
        directmap_end: memmap::directmap_end(),
        global_pages,
        pae: features.as_ref().is_some_and(FeatureInfo::has_pae),
    });
    // SAFETY: the memory map's setup runs once, after its bootstrap, on the
    // same CPU.
    unsafe { memmap::setup(&mut Console) };

    bootstrap::pmap_make_temporary_mapping();
    bootstrap::pmap_set_page_dir();

    // SAFETY: CR3 holds the kernel's tables, which map the running code, so
    // paging stays on; write protection and the caches change no mapping.
    unsafe {
        Cr0::update(|flags| {
            flags.insert(Cr0Flags::PAGING | Cr0Flags::WRITE_PROTECT);
            flags
                .remove(Cr0Flags::CACHE_DISABLE | Cr0Flags::NOT_WRITE_THROUGH);
        });
    }
    if global_pages {
        // SAFETY: the CPU reports global pages, which the kernel's tables
        // mark only for the kernel's own mappings.
        unsafe { Cr4::update(|flags| flags.insert(Cr4Flags::PAGE_GLOBAL)) };
    }

    // The descriptor tables are built on the boot CPU before any other one
    // starts.
    gdt::gdt_init();
    idt::idt_init();
    int_init::int_init();
    ldt::ldt_init();
    ktss::ktss_init();
    // SAFETY: this runs on the boot CPU's boot path, before anything
    // reads that block.
    unsafe { per_cpu::init(CpuId::BOOT) };
    mp_desc::mp_desc_init(0);

    bootstrap::pmap_remove_temporary_mapping();

    mp_desc::interrupt_stack_alloc();
    ioapic::SPL_INIT.store(true, Ordering::Relaxed);
}

/// `c_boot_entry()`: the entry the boot header calls, with the physical
/// address of the loader's Multiboot information in `bi`.
pub(crate) extern "C" fn c_boot_entry(bi: VmOffset) {
    // SAFETY: `bi` is the physical address the boot header passes, and the
    // loader's block there is readable.
    unsafe { BOOT_INFO = *kv_ptr::<MultibootRawInfo>(phystokv(bi)) };

    kprint!("{}\n", KERNEL_VERSION);

    i386at_init();

    let slot = mach_host::machine::slot(CpuId::BOOT);
    slot.is_cpu.store(1, Ordering::Relaxed);
    slot.cpu_subtype.store(CPU_SUBTYPE_AT386, Ordering::Relaxed);
    slot.cpu_type.store(CPU_TYPE_X86_64, Ordering::Relaxed);

    // SAFETY: the boot CPU calls `setup_main` once.
    unsafe { crate::kern::startup::setup_main() };
}

/// Starts the clock interrupt on this CPU.
pub(crate) fn startrtclock() {
    // The clock is the I/O APIC timer pin plus each CPU's local APIC timer.
    let pin = ioapic::TIMER_PIN.load(Ordering::Relaxed);
    ioapic::unmask(pin);
    ioapic::calibrate_lapic_timer();
    if per_cpu::cpu_id() != CpuId::BOOT {
        ioapic::lapic_enable_timer();
    }
}
