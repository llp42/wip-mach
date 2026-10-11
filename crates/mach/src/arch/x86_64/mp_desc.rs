// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The interrupt stacks and the per-processor descriptor tables.

use crate::arch::types::{AtomicVmOffset, VmOffset};
use crate::arch::x86_64::apic;
use crate::arch::x86_64::error::Error;
use crate::arch::x86_64::fpu;
use crate::arch::x86_64::model_dep;
use crate::arch::x86_64::pcb::{RealDescriptor, TaskTss};
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::spl;
use crate::arch::x86_64::{cpuboot, gdt, idt, int_init, ktss, ldt, smp};
use crate::config::MAX_NCPUS;
use crate::kern::console::{CStrArg, kprint};
use crate::kern::debug::kpanic;
use core::ffi::{CStr, c_int, c_uint, c_ulong};
use core::mem::{align_of, offset_of, size_of};
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};
use mach_pmap::bootstrap;
use mach_thread::smp as kern_smp;
use mach_thread::smp::CpuId;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

/// The number of iterations [`simple_lock_pause`] spins.
const PAUSE_LOOP: u32 = 100;

/// The count [`simple_lock_pause`] adds one to per call.
static PAUSE_COUNT: AtomicU32 = AtomicU32::new(0);

/// The counter the pause loop increments, which the C kept in a function-local
/// `static volatile int`.
static PAUSE_DUMMY: AtomicU32 = AtomicU32::new(0);

/// The size of one interrupt stack: one page.
pub(crate) const INTSTACK_SIZE: usize = 4096;

const _: () = assert!(INTSTACK_SIZE == 4096);

/// The number of IDT gates.
pub(crate) const IDTSZ: usize = 0x100;

/// The number of GDT descriptors: the eight-byte descriptors up to the per-CPU
/// segment.
pub(crate) const GDTSZ: usize = 14;

/// The number of LDT descriptors.
const LDTSZ: usize = 4;

/// An IDT gate: the two words followed by the offset extension and its
/// reserved word.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct RealGate {
    /// The 16-bit offset low half followed by the 16-bit selector.
    pub offset_low_selector: u32,
    /// The 8-bit word count, the 8-bit access byte and the 16-bit offset high
    /// half.
    pub word_count_access_offset_high: u32,
    pub offset_ext: u32,
    pub reserved: u32,
}

const _: () = {
    assert!(size_of::<RealGate>() == 16);
    assert!(align_of::<RealGate>() == align_of::<u32>());
    assert!(offset_of!(RealGate, offset_low_selector) == 0);
    assert!(offset_of!(RealGate, word_count_access_offset_high) == 4);
    assert!(offset_of!(RealGate, offset_ext) == 8);
    assert!(offset_of!(RealGate, reserved) == 12);
};

impl RealGate {
    /// An all-zero gate, the image a C `static` began with.
    pub(crate) const ZERO: Self = Self {
        offset_low_selector: 0,
        word_count_access_offset_high: 0,
        offset_ext: 0,
        reserved: 0,
    };
}

/// One CPU's descriptor tables, which the `gdt`, `idt`, `ktss` and `ldt`
/// modules fill.
///
/// The sizes, offsets and alignment below were read from the built kernel's
/// debug information.
#[repr(C)]
#[allow(missing_docs)]
pub struct MpDescTable {
    pub idt: [RealGate; IDTSZ],
    pub gdt: [RealDescriptor; GDTSZ],
    pub ldt: [RealDescriptor; LDTSZ],
    pub ktss: TaskTss,
}

const _: () = {
    assert!(size_of::<MpDescTable>() == 12540);
    assert!(align_of::<MpDescTable>() == align_of::<u32>());
    assert!(offset_of!(MpDescTable, idt) == 0);
    assert!(offset_of!(MpDescTable, gdt) == 4096);
    assert!(offset_of!(MpDescTable, ldt) == 4208);
    assert!(offset_of!(MpDescTable, ktss) == 4240);
};

/// The interrupt stacks, which the boot CPU starts on and the interrupt entry
/// points switch to.
#[repr(C, align(4096))]
#[allow(missing_docs)]
pub(crate) struct IntStacks(pub(crate) [u8; MAX_NCPUS * INTSTACK_SIZE]);

/// The interrupt stacks of every CPU.
#[unsafe(export_name = "solid_intstack")]
pub(crate) static mut SOLID_INTSTACK: IntStacks =
    IntStacks([0; MAX_NCPUS * INTSTACK_SIZE]);

/// One stack bottom per CPU, carved from [`SOLID_INTSTACK`]. The interrupt
/// entries index it by CPU number; [`interrupt_stack_alloc`] fills it before
/// any CPU runs one.
#[unsafe(export_name = "int_stack_base")]
pub static INT_STACK_BASE: [AtomicVmOffset; MAX_NCPUS] =
    [const { AtomicVmOffset::new(0) }; MAX_NCPUS];

/// One stack top per CPU, the word below the next stack's bottom.
#[unsafe(export_name = "int_stack_top")]
pub static INT_STACK_TOP: [AtomicVmOffset; MAX_NCPUS] =
    [const { AtomicVmOffset::new(0) }; MAX_NCPUS];

/// Assigns each CPU its interrupt stack.
pub(crate) fn interrupt_stack_alloc() {
    // SAFETY: this runs before any other CPU, and it is the first reader or
    // writer of the stacks.
    let stacks = unsafe { ptr::addr_of_mut!(SOLID_INTSTACK.0) }.cast::<u8>();
    for i in 0..MAX_NCPUS {
        let base = stacks.wrapping_add(i * INTSTACK_SIZE);
        let top = stacks.wrapping_add((i + 1) * INTSTACK_SIZE).wrapping_sub(4);
        // Relaxed: the write happens once at boot, before any CPU reads the
        // table, and the boot order is what publishes it.
        INT_STACK_BASE[i].store(base.addr(), Ordering::Relaxed);
        INT_STACK_TOP[i].store(top.addr(), Ordering::Relaxed);
    }
}

/// The physical page the AP boot code was copied to.
pub static APBOOT_ADDR: AtomicVmOffset = AtomicVmOffset::new(0);

/// One allocated table set per CPU other than the boot CPU, which uses the
/// [`gdt`] and [`ktss`]
/// tables.
pub static mut MP_DESC_TABLE: [*mut MpDescTable; MAX_NCPUS] =
    [ptr::null_mut(); MAX_NCPUS];

/// The TSS of each CPU.
pub static mut MP_KTSS: [*mut TaskTss; MAX_NCPUS] =
    [ptr::null_mut(); MAX_NCPUS];

/// The GDT of each CPU.
pub static mut MP_GDT: [*mut RealDescriptor; MAX_NCPUS] =
    [ptr::null_mut(); MAX_NCPUS];

/// The kernel virtual address of the physical address `pa`.
const fn phystokv(pa: VmOffset) -> VmOffset {
    pa.wrapping_add(crate::arch::vm_param::VM_MIN_KERNEL_ADDRESS)
}

/// Waits a bit for a lock another CPU holds in the opposite order.
pub(crate) fn simple_lock_pause() {
    PAUSE_COUNT.fetch_add(1, Ordering::Relaxed);
    for _ in 0..PAUSE_LOOP {
        // Nothing is published and no one reads `PAUSE_DUMMY`, so the ordering
        // is `Relaxed`; the increment itself is the delay, and a relaxed
        // atomic keeps the spin from being optimized away.
        PAUSE_DUMMY.fetch_add(1, Ordering::Relaxed);
    }
}

/// The machine-dependent processor control hook.
///
/// # Errors
///
/// Always returns [`Error::NotSupported`]: this machine has no processor
/// control.
///
/// # Safety
///
/// `info` must be valid for `count` reads.
pub(crate) unsafe fn cpu_control(
    cpu: CpuId,
    info: *const c_int,
    count: c_uint,
) -> Result<(), Error> {
    kprint!(
        "cpu_control({}, {:x}, {}) not implemented\n",
        cpu,
        info.expose_provenance(),
        count,
    );
    Err(Error::NotSupported)
}

/// Interrupts processor `cpu` to make it flush its pmap.
pub(crate) fn interrupt_processor(cpu: CpuId) {
    smp::pmap_update(cpu);
}

/// Points CPU `mycpu` at its descriptor tables: the static ones for the boot
/// CPU, a fresh zeroed set for the others.  Returns `mycpu`.
pub(crate) fn mp_desc_init(mycpu: c_int) -> c_int {
    if mycpu == 0 {
        // SAFETY: the boot CPU uses the tables `gdt.rs` and `ktss.rs` built,
        // and `mp_desc_init` runs on each CPU only once.
        unsafe {
            MP_KTSS[0] = ptr::addr_of_mut!(ktss::KTSS);
            MP_GDT[0] = ptr::addr_of_mut!(gdt::GDT).cast::<RealDescriptor>();
        }
        return 0;
    }

    let Some(mem) = model_dep::alloc_aligned(size_of::<MpDescTable>()) else {
        kpanic!("mp_desc_init", "not enough memory for descriptor tables")
    };
    let mpt = ptr::with_exposed_provenance_mut::<MpDescTable>(phystokv(mem));

    // SAFETY: `mpt` is the table set `alloc_aligned` just took from the
    // boot allocator, and `mycpu` is the CPU this call initializes.
    unsafe {
        MP_DESC_TABLE[mycpu as usize] = mpt;
        MP_KTSS[mycpu as usize] = ptr::addr_of_mut!((*mpt).ktss);
        MP_GDT[mycpu as usize] = (*mpt).gdt.as_mut_ptr();

        ptr::write_bytes(
            ptr::addr_of_mut!((*mpt).idt).cast::<u8>(),
            0,
            size_of::<[RealGate; IDTSZ]>(),
        );
        ptr::write_bytes(
            (*mpt).gdt.as_mut_ptr().cast::<u8>(),
            0,
            size_of::<[RealDescriptor; GDTSZ]>(),
        );
        ptr::write_bytes(
            (*mpt).ldt.as_mut_ptr().cast::<u8>(),
            0,
            size_of::<[RealDescriptor; LDTSZ]>(),
        );
        ptr::write_bytes(
            ptr::addr_of_mut!((*mpt).ktss).cast::<u8>(),
            0,
            size_of::<TaskTss>(),
        );
    }

    mycpu
}

/// Turns paging on for an AP, with PAE and, when the CPU has it, PGE.  Write
/// protection stays off.
fn paging_enable() {
    // SAFETY: `pmap_set_page_dir` loaded the kernel's tables into CR3; they
    // are in the PAE format and map the running code, and the cache bits
    // change no mapping.
    unsafe {
        Cr4::update(|flags| {
            flags.insert(Cr4Flags::PHYSICAL_ADDRESS_EXTENSION);
        });
        Cr0::update(|flags| flags.insert(Cr0Flags::PAGING));
        Cr0::update(|flags| {
            flags
                .remove(Cr0Flags::CACHE_DISABLE | Cr0Flags::NOT_WRITE_THROUGH);
        });
    }
    if raw_cpuid::CpuId::new()
        .get_feature_info()
        .as_ref()
        .is_some_and(raw_cpuid::FeatureInfo::has_pge)
    {
        // SAFETY: the CPU reports global pages, which the kernel's tables
        // mark only for the kernel's own mappings.
        unsafe { Cr4::update(|flags| flags.insert(Cr4Flags::PAGE_GLOBAL)) };
    }
}

/// The boot message of one stage of [`cpu_setup`], which the C spelled as
/// `printf("AP=(%u) <stage> done\n", cpu)`.
fn ap_stage(cpu: c_int, stage: &CStr) {
    kprint!("AP=({}) {} done\n", cpu as c_uint, CStrArg::from(stage));
}

/// The boot path of an AP.
fn cpu_setup(cpu: c_int) -> ! {
    bootstrap::pmap_set_page_dir();
    ap_stage(cpu, c"pagedir");

    paging_enable();
    ap_stage(cpu, c"paging");

    // SAFETY: `cpu` is a CPU the machine reported, and this runs on it
    // before anything else touches its block.
    let mycpu = unsafe { CpuId::from_c_int(cpu) };
    unsafe { per_cpu::init(mycpu) };
    mp_desc_init(cpu);
    ap_stage(cpu, c"mpdesc");

    // The AP runs one CPU's copy of each descriptor table.
    gdt::ap_gdt_init(cpu);
    ap_stage(cpu, c"gdt");
    idt::ap_idt_init(cpu);
    ap_stage(cpu, c"idt");
    int_init::ap_int_init(cpu);
    ap_stage(cpu, c"int");
    ldt::ap_ldt_init(cpu);
    ap_stage(cpu, c"ldt");
    ktss::ap_ktss_init(cpu);
    ap_stage(cpu, c"ktss");

    // The slot is this CPU's to fill; the BSP's type is already recorded.
    let slot = mach_host::machine::slot(mycpu);
    slot.cpu_subtype.store(CPU_SUBTYPE_AT386, Ordering::Relaxed);
    let boot_type = mach_host::machine::slot(CpuId::BOOT)
        .cpu_type
        .load(Ordering::Relaxed);
    slot.cpu_type.store(boot_type, Ordering::Relaxed);
    // SAFETY: the FPU init runs once, on this AP.
    unsafe { fpu::init_fpu() };
    apic::lapic_setup();
    apic::lapic_enable();
    // SAFETY: this AP launches its first thread once; the call never returns.
    unsafe { crate::kern::startup::cpu_launch_first_thread(ptr::null_mut()) }
}

/// `cpu_ap_main()`: the entry the application-processor boot code calls.
pub(crate) extern "C" fn cpu_ap_main() -> ! {
    cpu_setup(cpu_id().bits() as c_int)
}

/// The CPU subtype of an AT-compatible PC.
const CPU_SUBTYPE_AT386: c_int = 1;

/// Copy the AP boot code to the page the memory map's bootstrap claimed.
fn copy_apboot() {
    let begin = ptr::addr_of!(cpuboot::apboot).addr();
    let length = ptr::addr_of!(cpuboot::apbootend).addr() - begin;
    let target = phystokv(APBOOT_ADDR.load(Ordering::Relaxed));
    // SAFETY: `APBOOT_ADDR` names the page the memory map's bootstrap
    // reserved for this copy, `apboot`/`apbootend` bracket the image, and
    // this runs on one CPU before any AP starts.
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::with_exposed_provenance::<u8>(phystokv(begin)),
            ptr::with_exposed_provenance_mut::<u8>(target),
            length,
        );
    }
}

/// Copies the AP boot code down and starts the other CPUs on it.
pub(crate) fn start_other_cpus() {
    let ncpus = kern_smp::ncpus();
    if ncpus == 1 {
        return;
    }

    copy_apboot();

    // SAFETY: raising to `splhigh` has no precondition, and nothing restores
    // the level because the BSP stays at it afterwards.
    unsafe { spl::splhigh() };

    apic::lapic_disable();
    bootstrap::pmap_make_temporary_mapping();

    for cpu in CpuId::online().skip(1) {
        mach_host::machine::slot(cpu)
            .running
            .store(0, Ordering::Relaxed);
    }

    let bsp = apic::apic_id();
    // `APBOOT_ADDR` is the physical page `copy_apboot` filled.
    smp::startup_cpus(bsp, APBOOT_ADDR.load(Ordering::Relaxed) as c_ulong);

    for cpu in CpuId::online().skip(1) {
        kprint!("Waiting for AP {}\n", cpu);

        loop {
            // Acquire: pairs with the AP's Release store in
            // `set_cpu_running`, so what it set up before is visible here.
            let running = mach_host::machine::slot(cpu)
                .running
                .load(Ordering::Acquire);
            if running != 0 {
                break;
            }
            core::hint::spin_loop();
        }
    }
    kprint!("BSP: Completed SMP init\n");

    bootstrap::pmap_remove_temporary_mapping();

    for cpu in CpuId::online().skip(1) {
        interrupt_processor(cpu);
    }

    apic::lapic_enable();
}
