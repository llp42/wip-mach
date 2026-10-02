// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from i386/i386at/model_dep.c:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University.
//   Copyright (c) 1986 Avadis Tevanian, Jr., Michael Wayne Young.
// Derived from i386/i386at/model_dep.h:
//   Copyright (c) 2013 Free Software Foundation.
// Derived from i386/i386/model_dep.h:
//   Copyright (C) 2008 Free Software Foundation, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The machine-dependent boot and halt path of `i386/i386at/model_dep.c`:
//! the idle and relax instructions, the `/dev/time` mmap hook, the wall
//! clock, the bootstrap allocator and the boot entry points.
//!
//! The `extern "C"` edge is in [`model_dep_ffi`].

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::{PAGE_MASK, PAGE_SHIFT, PAGE_SIZE};
use crate::arch::x86_64::clock_platform;
use crate::arch::x86_64::io_req::DevT;
use crate::arch::x86_64::multiboot::{
    MultibootLoaderFlags, MultibootModule, MultibootRawInfo,
    MultibootRawModule, load_modules,
};
use crate::arch::x86_64::pmap::KERNEL_PMAP;
use crate::arch::x86_64::pmap::pmap_extract;
use crate::arch::x86_64::spl;
use crate::arch::x86_64::{
    apic, biosmem, cpuboot, fpu, gdt, idt, int_init, ioapic, irq, ktss, ldt,
    locore, mbinfo, mp_desc, per_cpu, pit, pmap, rtc,
};
use crate::glue;
use crate::glue::time_value::TimeValue64;
use crate::kern::console::{CStrArg, kprint};
use crate::kern::debug::kpanic;
use crate::kern::host_time;
use crate::kern::smp::CpuId;
use crate::vm::types::VmProt;
use crate::vm::vm_kern::VM_MIN_KERNEL_ADDRESS;
use alloc::vec::Vec;
use core::arch::asm;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr;

/// `ELF_SHT_SYMTAB` of i386/i386at/elf.h.
const ELF_SHT_SYMTAB: u32 = 2;
/// `ELF_SHT_STRTAB` of i386/i386at/elf.h.
const ELF_SHT_STRTAB: u32 = 3;

/// `CPU_TYPE_X86_64` of <mach/machine.h>.
const CPU_TYPE_X86_64: c_int = 21;
/// `CPU_SUBTYPE_AT386` of <mach/machine.h>.
const CPU_SUBTYPE_AT386: c_int = 1;

/// `boot_info` of `i386/i386at/model_dep.c`: the multiboot information block
/// the boot loader left, which `c_boot_entry` copies out of low memory.
// SAFETY: `MultibootRawInfo` is all integers, for which zero is a valid bit
// pattern.
pub(crate) static mut BOOT_INFO: MultibootRawInfo =
    unsafe { core::mem::zeroed() };

/// `kernel_cmdline` of `i386/i386at/model_dep.c`: the boot command line, `""`
/// until `i386at_init` can copy the loader's line to safe memory.
pub static mut KERNEL_CMDLINE: *mut c_char = c"".as_ptr().cast_mut();

/// The boot loader's information block, frozen by the boot sequence.
#[must_use]
pub(crate) fn boot_info() -> MultibootRawInfo {
    // SAFETY: `c_boot_entry` and `i386at_init` are the block's only
    // writers, and both ran before the bootstrap.
    unsafe { *ptr::addr_of!(BOOT_INFO) }
}

/// Copies the loader's module records, images and command lines, empty
/// when the loader left none.
#[must_use]
pub(crate) fn boot_modules() -> Vec<MultibootModule> {
    let info = boot_info();
    let flags = MultibootLoaderFlags::from_raw(info.flags);
    if !flags.contains(MultibootLoaderFlags::MODULES) || info.mods_count == 0 {
        return Vec::new();
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
    unsafe { CStr::from_ptr(KERNEL_CMDLINE) }
}

/// `rebootflag` of `i386/i386at/model_dep.c`: set when ctrl-alt-del should
/// reboot the machine.
pub static mut REBOOTFLAG: c_int = 0;

/// `struct elf_shdr` of `i386/i386at/elf.h`, the section header
/// `register_boot_data` walks; `addr` and `offset` are the C's
/// `unsigned long`.
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

/// The six bytes `cpuboot.S` reserves for `gdt_descr_tmp`: `struct
/// pseudo_descriptor` up to the padding its C type adds, which the realmode
/// GDT pointer actually occupies.
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

/// `phystokv()` of <`i386/vm_param.h`>.
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

/// Halt the calling CPU until the next interrupt.
fn idle() {
    // SAFETY: `hlt` stops the CPU until an interrupt is delivered.
    unsafe { asm!("hlt", options(nostack, preserves_flags)) };
}

/// `machine_idle()` of <`i386/i386/model_dep.h`>.
pub(crate) fn machine_idle(_cpu: c_int) {
    idle();
}

/// The page frame holding the kernel's mapped time value, or `None` when the
/// request asks for write access.
pub(crate) fn mapped_time_page(prot: VmProt) -> Option<VmOffset> {
    if prot.contains(VmProt::WRITE) {
        return None;
    }

    // SAFETY: `mapable_time_init()` wired the page at boot, before `/dev/time`
    // can be opened.
    let address = unsafe { clock_platform::mapped_time_page() } as VmOffset;
    // SAFETY: `kernel_pmap` is the kernel's own pmap, so it maps `address`;
    // the C called `pmap_extract` with the same two values.
    let phys = unsafe { pmap_extract(KERNEL_PMAP, address) };
    Some(phys >> PAGE_SHIFT)
}

/// `timemmap()` of <`i386at/model_dep.h`>, the `d_mmap` hook of the `/dev/time`
/// device in `i386/i386at/conf.c`.
pub(crate) fn timemmap(_dev: DevT, _off: VmOffset, prot: c_int) -> VmOffset {
    mapped_time_page(VmProt::from_bits(prot)).unwrap_or(VmOffset::MAX)
}

/// Set the kernel's wall clock.
fn set_wallclock(seconds: i64) {
    host_time::set_wallclock(TimeValue64 {
        seconds,
        nanoseconds: 0,
    });
}

/// `inittodr()` of <`i386/i386at/model_dep.h`>.
pub(crate) fn inittodr() {
    let mut seconds: u64 = 0;
    // SAFETY: `seconds` is a local valid for a write, and `readtodc` leaves it
    // alone when it fails.
    unsafe { rtc::readtodc(&raw mut seconds) };
    // The C converted the `uint64_t` seconds to the record's `int64_t` field;
    // the cast reinterprets the bits as that conversion does.
    set_wallclock(seconds as i64);
}

/// `resettodr()` of <`i386/i386/model_dep.h`>.
pub(crate) fn resettodr() {
    // SAFETY: `writetodc` takes no argument, and the C passed none.
    unsafe { rtc::writetodc() };
}

/// Allocate `size` bytes of physical memory during bootstrap, page-rounded, or
/// `None` when the bootstrap allocator is out of pages.
pub(crate) fn alloc_aligned(size: VmSize) -> Option<VmOffset> {
    let rounded = size.wrapping_add(PAGE_MASK) & !PAGE_MASK;
    // vm_page_atop(): the page count, whose C parameter is an `unsigned int`,
    // so only the low 32 bits reach the allocator.
    let pages = (rounded >> PAGE_SHIFT) as u32;
    let address = biosmem::bootalloc(pages);
    if address == 0 { None } else { Some(address) }
}

/// `init_alloc_aligned()` of <`i386at/model_dep.h`>.
///
/// # Safety
///
/// `addrp` must be valid for a write; the C wrote the allocated address
/// through it.
pub(crate) unsafe fn init_alloc_aligned(
    size: VmSize,
    addrp: *mut VmOffset,
) -> c_int {
    let address = alloc_aligned(size).unwrap_or(0);
    unsafe { *addrp = address };
    c_int::from(address != 0)
}

/// `pmap_grab_page()` of <vm/pmap.h>.
///
/// # Panics
///
/// Halts the kernel when no page is left, as the C `panic()` did.
pub(crate) fn pmap_grab_page() -> VmOffset {
    alloc_aligned(PAGE_SIZE).unwrap_or_else(|| {
        kpanic!("pmap_grab_page", "Not enough memory to initialize Mach")
    })
}

/// `machine_init()` of <`i386/i386/model_dep.h`>.
pub(crate) fn machine_init() {
    // SAFETY: `machine_init` runs once, from `setup_main`, before any other
    // `biosmem` entry point is used again.
    unsafe { biosmem::biosmem_free_usable() };
    // SAFETY: `init_fpu` is the real C routine of `i386/i386/fpu.c`, and the
    // boot CPU is the caller's.
    unsafe { fpu::init_fpu() };

    let err = crate::arch::x86_64::acpi_parse_apic::acpi_apic_init();
    if err != 0 {
        kprint!("acpi_apic_init failed with {}\n", err);
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
    unsafe { ptr::write_volatile(phystokv(0x472) as *mut u16, 0x1234) };

    if VM_MIN_KERNEL_ADDRESS == 0 {
        // SAFETY: page 0 is mapped in this configuration, and the C unmapped
        // it here.
        unsafe { pmap::pmap_unmap_page_zero() };
    }

    patch_realmode_gdt();

    apic::hpet_init();
}

/// Patch the realmode GDT and the far jump after it with the address the AP
/// boot code was copied to.
fn patch_realmode_gdt() {
    // SAFETY: `gdt_descr_tmp` and `apboot_jmp_offset` are `cpuboot.S`'s
    // objects, and `machine_init` is their only writer.
    unsafe {
        // The AP boot page sits below 4 GiB, so the C's narrowing to the
        // realmode `u32` fields loses nothing.
        let base = phystokv(
            ptr::addr_of_mut!(cpuboot::gdt_descr_tmp.linear_base).addr(),
        ) as *mut u32;
        *base = (*base).wrapping_add(mp_desc::APBOOT_ADDR as u32);
        let jmp =
            phystokv(ptr::addr_of_mut!(cpuboot::apboot_jmp_offset).addr())
                as *mut u32;
        *jmp = (*jmp).wrapping_add(mp_desc::APBOOT_ADDR as u32);
    }
}

/// `halt_cpu()` of <`i386/i386/model_dep.h`>.
pub(crate) fn halt_cpu() -> ! {
    // SAFETY: `cli` is legal at CPL 0, and this CPU never returns to the
    // interrupted code.
    unsafe { asm!("cli", options(nostack, preserves_flags)) };
    loop {
        idle();
    }
}

/// `halt_all_cpus()` of <`i386/i386/model_dep.h`>.
pub(crate) fn halt_all_cpus(reboot: c_int) -> ! {
    // Persist the ticking wall clock before this CPU stops advancing it.
    resettodr();
    if reboot != 0 {
        // SAFETY: `kdreboot` is the keyboard controller's reset path, and the
        // C took it under the same flag.
        unsafe { crate::arch::x86_64::kd::kdreboot() };
    } else {
        // SAFETY: `rebootflag` has no other writer, and this CPU stops here.
        unsafe { REBOOTFLAG = 1 };
        kprint!("Shutdown completed successfully, now in tight loop.\n");
        kprint!(
            "You can safely power off the system or hit ctl-alt-del to reboot\n"
        );
        // SAFETY: `spl0()` is the real asm function <i386/spl.h> declares.
        unsafe { spl::spl0() };
    }
    loop {
        idle();
    }
}

/// Register the boot loader's data with `biosmem` and `mbinfo`.
fn register_boot_data(mbi: &MultibootRawInfo) {
    let flags = MultibootLoaderFlags::from_raw(mbi.flags);
    let begin = ptr::addr_of!(glue::_start).addr();
    let end = ptr::addr_of!(glue::_end).addr();
    // SAFETY: the image bounds are the linker's, and this is the bootstrap
    // phase the call requires.
    unsafe {
        biosmem::biosmem_register_boot_data(
            begin.wrapping_sub(VM_MIN_KERNEL_ADDRESS),
            end.wrapping_sub(VM_MIN_KERNEL_ADDRESS),
            0,
        );
    };

    if flags.contains(MultibootLoaderFlags::CMDLINE) && mbi.cmdline != 0 {
        let start = address(mbi.cmdline);
        // SAFETY: the loader stored a NUL-terminated line at `start`, which
        // is in the direct map.
        let length = unsafe {
            crate::utils::string::strlen(kv_ptr::<c_char>(phystokv(start)))
        } + 1;
        // SAFETY: the range is the line the loader stored.
        unsafe {
            biosmem::biosmem_register_boot_data(
                start,
                start.wrapping_add(length),
                1,
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
        biosmem::biosmem_register_boot_data(
            address(mbi.mods_addr),
            address(mbi.mods_addr.wrapping_add(bytes)),
            1,
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
                biosmem::biosmem_register_boot_data(
                    address(start),
                    address(end),
                    1,
                );
            };
        }

        if string != 0 {
            let string_start = address(string);
            // SAFETY: the loader stored a NUL-terminated name there.
            let length = unsafe {
                crate::utils::string::strlen(kv_ptr::<c_char>(phystokv(
                    string_start,
                )))
            } + 1;
            // SAFETY: the range is the name's.
            unsafe {
                biosmem::biosmem_register_boot_data(
                    string_start,
                    string_start.wrapping_add(length),
                    1,
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
            biosmem::biosmem_register_boot_data(
                address(mbi.shdr_addr),
                address(mbi.shdr_addr.wrapping_add(bytes)),
                0,
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
                biosmem::biosmem_register_boot_data(
                    addr,
                    addr.wrapping_add(address(size)),
                    0,
                );
            };
        }
    }
}

/// Copy the boot loader's module records and images out of the low pages
/// before `biosmem_setup()` can hand them to the VM system, the module half
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
        crate::utils::string::memcpy(
            modules.cast(),
            kv_ptr::<c_void>(phystokv(address(mods_addr))),
            address(bytes),
        )
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
            crate::utils::string::memcpy(
                kv_ptr_mut::<c_void>(phystokv(image)),
                kv_ptr::<c_void>(phystokv(address(start))),
                address(size),
            )
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
            crate::utils::string::strlen(kv_ptr::<c_char>(phystokv(
                string_start,
            )))
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
            crate::utils::string::memcpy(
                kv_ptr_mut::<c_void>(phystokv(name)),
                kv_ptr::<c_void>(phystokv(string_start)),
                length,
            )
        };
        // SAFETY: the record was copied into `modules`, and this CPU is
        // its only writer.
        unsafe { (*module).string = name as u32 };
    }
}

/// `i386at_init()` in `i386/i386at/model_dep.c`.
fn i386at_init() {
    ioapic::picdisable();

    // SAFETY: `BOOT_INFO` is the loader's block, copied to safe memory by
    // `c_boot_entry`, which is the only writer.
    register_boot_data(unsafe { &*ptr::addr_of!(BOOT_INFO) });
    // SAFETY: `BOOT_INFO` is the loader's block, copied to safe memory by
    // `c_boot_entry`, which is the only writer; this is the boot phase
    // `biosmem_bootstrap` requires.
    unsafe { biosmem::biosmem_bootstrap(ptr::addr_of!(BOOT_INFO).cast()) };

    // The copy below overwrites `BOOT_INFO`'s own fields, so the loader's
    // values are read first.
    // SAFETY: `BOOT_INFO` is the loader's block, copied to safe memory by
    // `c_boot_entry`, which is the only writer; this is the boot phase
    // `biosmem_bootstrap` requires; no other CPU is running yet.
    let (flags, cmdline, mods_count, mods_addr) = unsafe {
        (
            BOOT_INFO.flags,
            BOOT_INFO.cmdline,
            BOOT_INFO.mods_count,
            BOOT_INFO.mods_addr,
        )
    };
    let flags = MultibootLoaderFlags::from_raw(flags);

    // The loader's command line and modules are copied out of low memory
    // before `biosmem_setup` can hand those pages to the VM system.
    if flags.contains(MultibootLoaderFlags::CMDLINE) {
        let source = address(cmdline);
        // SAFETY: the loader stored a NUL-terminated line at `source`.
        let length = unsafe {
            crate::utils::string::strlen(kv_ptr::<c_char>(phystokv(source)))
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
            crate::utils::string::memcpy(
                kv_ptr_mut::<c_void>(phystokv(mem)),
                kv_ptr::<c_void>(phystokv(source)),
                length,
            )
        };
        // SAFETY: `KERNEL_CMDLINE` and `BOOT_INFO` are written only here and
        // only on the boot CPU.
        unsafe {
            KERNEL_CMDLINE = kv_ptr_mut::<c_char>(phystokv(mem));
            BOOT_INFO.cmdline = mem as u32;
        }
    }

    if flags.contains(MultibootLoaderFlags::MODULES) && mods_count != 0 {
        copy_boot_modules(mods_count, mods_addr);
    }

    pmap::pmap_bootstrap();
    // SAFETY: `biosmem_setup` runs once, after `biosmem_bootstrap`, on the
    // same CPU.
    unsafe { biosmem::biosmem_setup() };

    pmap::pmap_make_temporary_mapping();
    pmap::pmap_set_page_dir();

    let cr0 = fpu::read_cr0();
    fpu::write_cr0(cr0 | fpu::CR0_PG | fpu::CR0_WP);
    let cr0 = fpu::read_cr0();
    fpu::write_cr0(cr0 & !(fpu::CR0_CD | fpu::CR0_NW));
    if pmap::cpu_has_feature(pmap::CPU_FEATURE_PGE) {
        let cr4 = fpu::read_cr4();
        fpu::write_cr4(cr4 | fpu::CR4_PGE);
    }
    mp_desc::flush_instr_queue();

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

    pmap::pmap_remove_temporary_mapping();

    mp_desc::interrupt_stack_alloc();
    // SAFETY: `spl_init` is `ioapic.rs`'s global, and this is its only writer
    // once the real IOAPIC is up.
    unsafe { ioapic::SPL_INIT = 1 };
}

/// `c_boot_entry()` of <`i386/i386/model_dep.h`>, the C entry `boothdr.S` calls.
pub(crate) fn c_boot_entry(bi: VmOffset) {
    // SAFETY: `bi` is the physical address `boothdr.S` passes, and the
    // loader's block there is readable.
    unsafe { BOOT_INFO = *kv_ptr::<MultibootRawInfo>(phystokv(bi)) };

    // SAFETY: `glue::version` is the NUL-terminated version string.
    kprint!("{}", unsafe {
        CStrArg::from_ptr(ptr::addr_of!(glue::version))
    });
    kprint!("\n");

    // The call also fills `cpu_features`; its return value is unused.
    #[expect(unused_variables)]
    let cpu_type = locore::discover_x86_cpu_type();

    i386at_init();

    // SAFETY: the boot CPU's slot is this CPU's to fill, and the C filled the
    // same fields.
    unsafe {
        let slot = crate::kern::machine::slot(CpuId::BOOT);
        (*slot).is_cpu = 1;
        (*slot).cpu_subtype = CPU_SUBTYPE_AT386;
    }

    // SAFETY: the boot CPU's slot is this CPU's to fill, and the C filled the
    // same fields.
    unsafe {
        let slot = crate::kern::machine::slot(CpuId::BOOT);
        (*slot).cpu_type = CPU_TYPE_X86_64;
    }

    // SAFETY: `setup_main` is the real C routine of `kern/startup.c`.
    unsafe { crate::kern::startup::setup_main() };
}

/// `startrtclock()` of <`i386/i386/model_dep.h`>.
pub(crate) fn startrtclock() {
    // The C's non-APIC branch (`clkstart()` plus `unmask_irq(0)`) went with
    // the 8259 driver; APIC support is unconditional now.
    // SAFETY: `timer_pin` is read after `ioapic_configure` picked it, and the
    // boot path is single-threaded.
    let pin = unsafe { ioapic::TIMER_PIN };
    ioapic::unmask(pin);
    ioapic::calibrate_lapic_timer();
    if per_cpu::cpu_id() != CpuId::BOOT {
        ioapic::lapic_enable_timer();
    }
}
