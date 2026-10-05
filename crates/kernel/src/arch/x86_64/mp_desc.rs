// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/mp_desc.c:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
// Derived from i386/i386/mp_desc.h:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The interrupt stacks and the per-processor descriptor tables, which
//! `i386/i386/mp_desc.c` used to define and `i386/i386/mp_desc.h` declares.

use crate::arch::types::{AtomicVmOffset, VmOffset};
use crate::arch::x86_64::apic;
use crate::arch::x86_64::error::Error;
use crate::arch::x86_64::fpu;
use crate::arch::x86_64::model_dep;
use crate::arch::x86_64::pcb::{RealDescriptor, TaskTss};
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::spl;
use crate::arch::x86_64::{cpuboot, gdt, idt, int_init, ktss, ldt, pmap, smp};
use crate::config::MAX_NCPUS;
use crate::kern::console::{CStrArg, kprint};
use crate::kern::debug::kpanic;
use crate::kern::smp as kern_smp;
use crate::kern::smp::CpuId;
use core::arch::asm;
use core::ffi::{CStr, c_int, c_uint, c_ulong};
use core::mem::{align_of, offset_of, size_of};
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

/// The number of iterations [`simple_lock_pause`] spins, which the C kept in
/// the global `simple_lock_pause_loop`.
const PAUSE_LOOP: u32 = 100;

/// The count [`simple_lock_pause`] adds one to per call, which the C kept in
/// the global `simple_lock_pause_count`.
static PAUSE_COUNT: AtomicU32 = AtomicU32::new(0);

/// The counter the pause loop increments, which the C kept in a function-local
/// `static volatile int`.
static PAUSE_DUMMY: AtomicU32 = AtomicU32::new(0);

/// `INTSTACK_SIZE` of <`i386/vm_param.h>`: `I386_PGBYTES`, one page per
/// interrupt stack.
pub(crate) const INTSTACK_SIZE: usize = 4096;

const _: () = assert!(INTSTACK_SIZE == 4096);

/// `IDTSZ` of <i386at/idt.h>.
pub(crate) const IDTSZ: usize = 0x100;

/// `GDTSZ` of <i386/gdt.h>: `sel_idx(0x70)`, the eight-byte descriptors up to
/// the per-CPU segment.
pub(crate) const GDTSZ: usize = 14;

/// `LDTSZ` of <i386/ldt.h>.
const LDTSZ: usize = 4;

/// `struct real_gate` of <i386/seg.h>: the two words followed by the offset
/// extension and its reserved word.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct RealGate {
    /// `offset_low:16` followed by `selector:16`.
    pub offset_low_selector: u32,
    /// `word_count:8`, `access:8` and `offset_high:16`.
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

/// `struct mp_desc_table` of <`i386/mp_desc.h>`: one CPU's descriptor tables,
/// which the `gdt`, `idt`, `ktss` and `ldt` modules fill.
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

/// The interrupt stacks, which `boothdr.S` starts the boot CPU on and the
/// interrupt entry points switch to.
#[repr(C, align(4096))]
#[allow(missing_docs)]
pub(crate) struct IntStacks(pub(crate) [u8; MAX_NCPUS * INTSTACK_SIZE]);

/// `solid_intstack` of `i386/i386/mp_desc.c`.
#[unsafe(export_name = "solid_intstack")]
pub(crate) static mut SOLID_INTSTACK: IntStacks =
    IntStacks([0; MAX_NCPUS * INTSTACK_SIZE]);

/// `int_stack_base` of <`i386at/model_dep.h>`: one stack bottom per CPU.
#[unsafe(export_name = "int_stack_base")]
pub static mut INT_STACK_BASE: [VmOffset; MAX_NCPUS] = [0; MAX_NCPUS];

/// `int_stack_top` of <`i386at/model_dep.h>`: one stack top per CPU.
#[unsafe(export_name = "int_stack_top")]
pub static mut INT_STACK_TOP: [VmOffset; MAX_NCPUS] = [0; MAX_NCPUS];

/// `apboot_addr` of <`i386/model_dep.h>`: the physical page the AP boot code
/// was copied to.
pub static APBOOT_ADDR: AtomicVmOffset = AtomicVmOffset::new(0);

/// `mp_desc_table` of <`i386/mp_desc.h>`: one allocated table set per CPU other
/// than the boot CPU, which shares the `gdt.c`/`ktss.c` tables.
pub static mut MP_DESC_TABLE: [*mut MpDescTable; MAX_NCPUS] =
    [ptr::null_mut(); MAX_NCPUS];

/// `mp_ktss` of <`i386/mp_desc.h>`: the TSS of each CPU.
pub static mut MP_KTSS: [*mut TaskTss; MAX_NCPUS] =
    [ptr::null_mut(); MAX_NCPUS];

/// `mp_gdt` of <`i386/mp_desc.h>`: the GDT of each CPU.
pub static mut MP_GDT: [*mut RealDescriptor; MAX_NCPUS] =
    [ptr::null_mut(); MAX_NCPUS];

/// `phystokv()` of <`i386/vm_param.h`>.
const fn phystokv(pa: VmOffset) -> VmOffset {
    pa.wrapping_add(crate::vm::vm_kern::VM_MIN_KERNEL_ADDRESS)
}

/// `flush_instr_queue()` of <`i386/proc_reg.h>`: the jump that discards the
/// instructions the processor prefetched before a control-register change.
pub(crate) fn flush_instr_queue() {
    // SAFETY: the jump changes no machine state, its label is local to the
    // block, and it neither reads nor writes memory.
    unsafe { asm!("jmp 2f", "2:", options(nostack, nomem, preserves_flags)) };
}

/// Wait a bit for a lock another CPU holds in the opposite order, which
/// `kern/lock.h` declares.
pub(crate) fn simple_lock_pause() {
    PAUSE_COUNT.fetch_add(1, Ordering::Relaxed);
    for _ in 0..PAUSE_LOOP {
        // Nothing is published and no one reads `PAUSE_DUMMY`, so the ordering
        // is `Relaxed`; the increment itself is the delay, and a relaxed
        // atomic keeps the spin from being optimized away.
        PAUSE_DUMMY.fetch_add(1, Ordering::Relaxed);
    }
}

/// The machine-dependent processor control hook, which
/// `i386/i386/mp_desc.h` declares.
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

/// `interrupt_stack_alloc()` of <`i386/mp_desc.h`>.
pub(crate) fn interrupt_stack_alloc() {
    // SAFETY: `interrupt_stack_alloc` runs before any other CPU, and it is
    // the first reader or writer of the stacks.
    let stacks = unsafe { ptr::addr_of_mut!(SOLID_INTSTACK.0) }.cast::<u8>();
    for i in 0..MAX_NCPUS {
        let base = stacks.wrapping_add(i * INTSTACK_SIZE);
        let top = stacks.wrapping_add((i + 1) * INTSTACK_SIZE).wrapping_sub(4);
        // SAFETY: `interrupt_stack_alloc` runs once from `i386at_init`,
        // before any interrupt stack is used, and `i` is below `MAX_NCPUS`.
        unsafe {
            INT_STACK_BASE[i] = base.addr();
            INT_STACK_TOP[i] = top.addr();
        }
    }
}

/// `mp_desc_init()` of <`i386/mp_desc.h`>.
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

/// `paging_enable()` in `i386/i386/mp_desc.c`.  The C's `CR0_WP` is left off,
/// as its own comment asked.
fn paging_enable() {
    fpu::write_cr4(fpu::read_cr4() | fpu::CR4_PAE);
    fpu::write_cr0(fpu::read_cr0() | fpu::CR0_PG);
    fpu::write_cr0(fpu::read_cr0() & !(fpu::CR0_CD | fpu::CR0_NW));
    if pmap::cpu_has_feature(pmap::CPU_FEATURE_PGE) {
        fpu::write_cr4(fpu::read_cr4() | fpu::CR4_PGE);
    }
}

/// The boot message of one stage of [`cpu_setup`], which the C spelled as
/// `printf("AP=(%u) <stage> done\n", cpu)`.
fn ap_stage(cpu: c_int, stage: &CStr) {
    kprint!("AP=({}) {} done\n", cpu as c_uint, CStrArg::from(stage));
}

/// `cpu_setup()` in `i386/i386/mp_desc.c`, the boot path of an AP.
fn cpu_setup(cpu: c_int) -> ! {
    pmap::pmap_set_page_dir();
    ap_stage(cpu, c"pagedir");

    paging_enable();
    flush_instr_queue();
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

    // SAFETY: the slot is this CPU's to fill while the BSP's type is already
    // recorded.
    unsafe {
        let slot = crate::kern::machine::slot(mycpu);
        (*slot).cpu_subtype = CPU_SUBTYPE_AT386;
        (*slot).cpu_type = (*crate::kern::machine::slot(CpuId::BOOT)).cpu_type;
    }
    // SAFETY: `init_fpu` is the real C routine of `i386/i386/fpu.c`.
    unsafe { fpu::init_fpu() };
    apic::lapic_setup();
    apic::lapic_enable();
    // SAFETY: `cpu_launch_first_thread` is the real C routine of
    // `kern/startup.c`, and it never returns.
    unsafe { crate::kern::startup::cpu_launch_first_thread(ptr::null_mut()) }
}

/// `cpu_ap_main()`: the entry the application-processor boot code calls.
pub(crate) extern "C" fn cpu_ap_main() -> ! {
    cpu_setup(cpu_id().bits() as c_int)
}

/// `CPU_SUBTYPE_AT386` of <mach/machine.h>.
const CPU_SUBTYPE_AT386: c_int = 1;

/// Copy the AP boot code to the page `biosmem_bootstrap()` claimed.
fn copy_apboot() {
    let begin = ptr::addr_of!(cpuboot::apboot).addr();
    let length = ptr::addr_of!(cpuboot::apbootend).addr() - begin;
    let target = phystokv(APBOOT_ADDR.load(Ordering::Relaxed));
    // SAFETY: `apboot_addr` names the page `biosmem_bootstrap()` reserved for
    // this copy, `apboot`/`apbootend` bracket the image, and this runs on one
    // CPU before any AP starts.
    unsafe {
        ptr::copy_nonoverlapping(
            ptr::with_exposed_provenance::<u8>(phystokv(begin)),
            ptr::with_exposed_provenance_mut::<u8>(target),
            length,
        );
    }
}

/// `start_other_cpus()` of <`i386/mp_desc.h`>.
pub(crate) fn start_other_cpus() {
    let ncpus = kern_smp::ncpus();
    if ncpus == 1 {
        return;
    }

    copy_apboot();

    // SAFETY: `splhigh()` is the real asm function <i386/spl.h> declares, and
    // nothing restores the level because the BSP stays at it afterwards.
    unsafe { spl::splhigh() };

    apic::lapic_disable();
    pmap::pmap_make_temporary_mapping();

    for cpu in CpuId::online().skip(1) {
        // SAFETY: the slot is `cpu`'s own `machine_slot`, which the probe
        // filled and the machine never frees.
        unsafe { (*crate::kern::machine::slot(cpu)).running = 0 };
    }

    let bsp = apic::apic_id();
    // `apboot_addr` is the physical page `copy_apboot` filled.
    smp::startup_cpus(bsp, APBOOT_ADDR.load(Ordering::Relaxed) as c_ulong);

    for cpu in CpuId::online().skip(1) {
        kprint!("Waiting for AP {}\n", cpu);

        loop {
            // SAFETY: the slot is `cpu`'s own `machine_slot`, which the probe
            // filled and the machine never frees.
            let running =
                unsafe { (*crate::kern::machine::slot(cpu)).running };
            if running != 0 {
                break;
            }
            smp::pause();
        }
    }
    kprint!("BSP: Completed SMP init\n");

    pmap::pmap_remove_temporary_mapping();

    for cpu in CpuId::online().skip(1) {
        interrupt_processor(cpu);
    }

    apic::lapic_enable();
}
