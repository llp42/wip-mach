// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The APIC and HPET accessors, with the high-precision clock entries.
//!
//! The `ApicReg`, `ApicIoUnit`, `ApicLocalUnit`, `IoApicData`,
//! `IrqOverrideData` and `ApicInfo` records keep the hardware's and the MADT's
//! field order.

use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::config::MAX_NCPUS;
use crate::kern::console::kprint;
use crate::kern::slab::{kalloc, kfree};
use core::ffi::{c_int, c_uint};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicPtr, AtomicU8, AtomicU32, Ordering};
use mach_thread::smp::CpuId;
use volatile::{VolatilePtr, map_field};
use x86_64::instructions::interrupts;

/// The tick-period register.
const HPET_CAP_PERIOD: usize = 0x04;
/// `HPET_CFG`: the configuration register.
const HPET_CFG: usize = 0x10;
/// `HPET_COUNTER`: the main counter register.
const HPET_COUNTER: usize = 0xf0;
/// `HPET_T0_CFG`: timer 0's configuration register.
const HPET_T0_CFG: usize = 0x100;
/// `HPET_T0_COMPARATOR`: timer 0's comparator register.
const HPET_T0_COMPARATOR: usize = 0x108;

/// `FSEC_PER_NSEC`: femtoseconds in a nanosecond.
const FSEC_PER_NSEC: u32 = 1_000_000;
/// The IOAPIC entries `ApicInfo` stores.
const MAX_IOAPICS: usize = 16;
/// The IRQ overrides `ApicInfo` stores.
const MAX_IRQ_OVERRIDE: usize = 24;

/// The local APIC base MSR.
pub(crate) const APIC_MSR: u32 = 0x1b;

bitflags::bitflags! {
    /// The low word of the local APIC base MSR.  The base address bits are
    /// kept as read.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct ApicBase: u32 {
        /// This CPU is the bootstrap processor.
        const BSP = 0x100;
        /// The local APIC is in x2APIC mode.
        const X2APIC = 0x400;
        /// The local APIC is enabled.
        const ENABLE = 0x800;
        // The base address.
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// The HPET configuration register.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct HpetConfig: u32 {
        /// Start the main counter.
        const ENABLE = 1 << 0;
        /// Route timer 0 through the 8254 interrupt.
        const LEGACY_ROUTE = 1 << 1;
        // The bits the kernel leaves as it finds them.
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// An HPET timer's configuration register.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct HpetTimerConfig: u32 {
        /// Let the timer raise an interrupt.
        const INT_ENABLE = 1 << 2;
        /// Reload the comparator in periodic mode.
        const TYPE_PERIODIC = 1 << 3;
        /// Latch the comparator value.
        const VAL_SET = 1 << 6;
        /// Keep the comparator 32 bits wide.
        const MODE_32BIT = 1 << 8;
        // The bits the kernel leaves as it finds them.
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// The local APIC's spurious-vector register; the vector is the low byte.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct SpuriousVector: u32 {
        /// Software-enable the local APIC.
        const ENABLE = 0x100;
        /// Use directed end-of-interrupt.
        const DIRECTED_EOI = 0x1000;
        // The vector and the bits the kernel leaves as it finds them.
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// A local vector-table entry; the vector and delivery fields are kept as
    /// read.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Lvt: u32 {
        /// Mask the entry.
        const MASKED = 0x10000;
        /// In the timer entry: reload the count when it reaches zero.
        const TIMER_PERIODIC = 0x20000;
        // The vector and delivery fields.
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// The bits of the version and extended feature and control registers
    /// that decide the APIC-ID width.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct ApicExt: u32 {
        /// In the version register: the extended register bank exists.
        const HAS_EXT_APIC_SPACE = 1 << 31;
        /// In the extended feature register: 8-bit IDs are supported; in the
        /// extended control register: software enabled them.
        const ID_8BIT = 1 << 2;
        // The other fields of the three registers.
        const _ = !0;
    }
}

/// The spurious-vector base.
pub(crate) const IOAPIC_SPURIOUS_BASE: u32 = 0xff;

/// The IOAPIC version register index.
pub(crate) const APIC_IO_VERSION: u32 = 0x01;
/// `APIC_IO_VERSION_SHIFT`: where the version register holds the version.
pub(crate) const APIC_IO_VERSION_SHIFT: u32 = 0;
/// `APIC_IO_ENTRIES_SHIFT`: where the version register holds the entry count.
pub(crate) const APIC_IO_ENTRIES_SHIFT: u32 = 16;

bitflags::bitflags! {
    /// The one-bit fields of the ICR's low word.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct IcrFlags: u32 {
        /// The destination is a logical one, not an APIC ID.
        const LOGICAL = 1 << 11;
        /// The last IPI is still being sent.
        const PENDING = 1 << 12;
        /// The IPI asserts its level; an INIT de-asserts with it clear.
        const ASSERT = 1 << 14;
        /// The IPI is level-triggered.
        const LEVEL = 1 << 15;
        // The vector, delivery-mode and shorthand fields.
        const _ = !0;
    }
}

impl IcrFlags {
    /// The flags an IPI carries; the delivery status is the APIC's.
    const IPI: Self = Self::LOGICAL.union(Self::ASSERT).union(Self::LEVEL);
}

/// The ICR-low fields [`send_ipi`] overwrites: vector, delivery mode, the
/// IPI's flags and destination shorthand.
const ICR_LOW_FIELDS: u32 =
    0xff | (0x7 << 8) | IcrFlags::IPI.bits() | (0x3 << 18);

/// The entries of [`CPU_ID_LUT`].
const CPU_ID_LUT_SIZE: usize = 256;

/// One 128-bit register slot.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct ApicReg {
    pub r: u32,
    pub p: [u32; 3],
}

impl ApicReg {
    const ZERO: Self = Self { r: 0, p: [0; 3] };
}

/// The IOAPIC's register window.
#[repr(C)]
#[allow(missing_docs)]
pub struct ApicIoUnit {
    pub select: ApicReg,
    pub window: ApicReg,
    pub unused: [ApicReg; 2],
    pub eoi: ApicReg,
}

/// The local APIC's register page.
///
/// `icr_low` and `icr_high` are each one `ApicReg` wide, and their bitfields
/// alias its value word.
#[repr(C)]
#[allow(missing_docs)]
pub struct ApicLocalUnit {
    pub reserved0: ApicReg,
    pub reserved1: ApicReg,
    pub apic_id: ApicReg,
    pub version: ApicReg,
    pub reserved4: ApicReg,
    pub reserved5: ApicReg,
    pub reserved6: ApicReg,
    pub reserved7: ApicReg,
    pub task_pri: ApicReg,
    pub arbitration_pri: ApicReg,
    pub processor_pri: ApicReg,
    pub eoi: ApicReg,
    pub remote: ApicReg,
    pub logical_dest: ApicReg,
    pub dest_format: ApicReg,
    pub spurious_vector: ApicReg,
    pub isr: [ApicReg; 8],
    pub tmr: [ApicReg; 8],
    pub irr: [ApicReg; 8],
    pub error_status: ApicReg,
    pub reserved28: [ApicReg; 6],
    pub lvt_cmci: ApicReg,
    pub icr_low: ApicReg,
    pub icr_high: ApicReg,
    pub lvt_timer: ApicReg,
    pub lvt_thermal: ApicReg,
    pub lvt_performance_monitor: ApicReg,
    pub lvt_lint0: ApicReg,
    pub lvt_lint1: ApicReg,
    pub lvt_error: ApicReg,
    pub init_count: ApicReg,
    pub cur_count: ApicReg,
    pub reserved3a: ApicReg,
    pub reserved3b: ApicReg,
    pub reserved3c: ApicReg,
    pub reserved3d: ApicReg,
    pub divider_config: ApicReg,
    pub reserved3f: ApicReg,
    pub extended_feature: ApicReg,
    pub extended_control: ApicReg,
    pub specific_eoi: ApicReg,
}

impl ApicLocalUnit {
    /// The zero image of [`DUMMY_LAPIC`].
    const ZERO: Self = Self {
        reserved0: ApicReg::ZERO,
        reserved1: ApicReg::ZERO,
        apic_id: ApicReg::ZERO,
        version: ApicReg::ZERO,
        reserved4: ApicReg::ZERO,
        reserved5: ApicReg::ZERO,
        reserved6: ApicReg::ZERO,
        reserved7: ApicReg::ZERO,
        task_pri: ApicReg::ZERO,
        arbitration_pri: ApicReg::ZERO,
        processor_pri: ApicReg::ZERO,
        eoi: ApicReg::ZERO,
        remote: ApicReg::ZERO,
        logical_dest: ApicReg::ZERO,
        dest_format: ApicReg::ZERO,
        spurious_vector: ApicReg::ZERO,
        isr: [ApicReg::ZERO; 8],
        tmr: [ApicReg::ZERO; 8],
        irr: [ApicReg::ZERO; 8],
        error_status: ApicReg::ZERO,
        reserved28: [ApicReg::ZERO; 6],
        lvt_cmci: ApicReg::ZERO,
        icr_low: ApicReg::ZERO,
        icr_high: ApicReg::ZERO,
        lvt_timer: ApicReg::ZERO,
        lvt_thermal: ApicReg::ZERO,
        lvt_performance_monitor: ApicReg::ZERO,
        lvt_lint0: ApicReg::ZERO,
        lvt_lint1: ApicReg::ZERO,
        lvt_error: ApicReg::ZERO,
        init_count: ApicReg::ZERO,
        cur_count: ApicReg::ZERO,
        reserved3a: ApicReg::ZERO,
        reserved3b: ApicReg::ZERO,
        reserved3c: ApicReg::ZERO,
        reserved3d: ApicReg::ZERO,
        divider_config: ApicReg::ZERO,
        reserved3f: ApicReg::ZERO,
        extended_feature: ApicReg::ZERO,
        extended_control: ApicReg::ZERO,
        specific_eoi: ApicReg::ZERO,
    };
}

/// One MADT IOAPIC entry.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct IoApicData {
    pub apic_id: u8,
    pub ngsis: u8,
    pub addr: u32,
    pub gsi_base: u32,
    pub ioapic: *mut ApicIoUnit,
}

impl IoApicData {
    const ZERO: Self = Self {
        apic_id: 0,
        ngsis: 0,
        addr: 0,
        gsi_base: 0,
        ioapic: ptr::null_mut(),
    };
}

bitflags::bitflags! {
    /// The flags of a MADT IRQ override.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct OverrideFlags: u16 {
        /// The override sets the line's polarity.
        const POLARITY = 1 << 0;
        /// The line is active-low.
        const ACTIVE_LOW = 1 << 1;
        /// The override sets the line's trigger mode.
        const TRIGGER = 1 << 2;
        /// The line is level-triggered.
        const LEVEL = 1 << 3;
        // The bits the firmware reserves.
        const _ = !0;
    }
}

/// One MADT IRQ override entry.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct IrqOverrideData {
    pub bus: u8,
    pub irq: u8,
    pub gsi: u32,
    pub flags: OverrideFlags,
}

impl IrqOverrideData {
    const ZERO: Self = Self {
        bus: 0,
        irq: 0,
        gsi: 0,
        flags: OverrideFlags::empty(),
    };
}

/// The CPUs, IOAPICs and IRQ overrides the MADT named.
#[repr(C)]
#[allow(missing_docs)]
pub struct ApicInfo {
    pub ncpus: u8,
    pub nioapics: u8,
    pub nirqoverride: c_int,
    pub cpu_lapic_list: *mut u16,
    pub ioapic_list: [IoApicData; MAX_IOAPICS],
    pub irq_override_list: [IrqOverrideData; MAX_IRQ_OVERRIDE],
}

impl ApicInfo {
    const ZERO: Self = Self {
        ncpus: 0,
        nioapics: 0,
        nirqoverride: 0,
        cpu_lapic_list: ptr::null_mut(),
        ioapic_list: [IoApicData::ZERO; MAX_IOAPICS],
        irq_override_list: [IrqOverrideData::ZERO; MAX_IRQ_OVERRIDE],
    };
}

const _: () = {
    assert!(size_of::<ApicReg>() == 16);
    assert!(align_of::<ApicReg>() == 4);
    assert!(offset_of!(ApicReg, r) == 0);
    assert!(offset_of!(ApicReg, p) == 4);

    assert!(size_of::<ApicIoUnit>() == 80);
    assert!(align_of::<ApicIoUnit>() == 4);
    assert!(offset_of!(ApicIoUnit, select) == 0);
    assert!(offset_of!(ApicIoUnit, window) == 16);
    assert!(offset_of!(ApicIoUnit, unused) == 32);
    assert!(offset_of!(ApicIoUnit, eoi) == 64);

    assert!(size_of::<ApicLocalUnit>() == 1072);
    assert!(align_of::<ApicLocalUnit>() == 4);
    assert!(offset_of!(ApicLocalUnit, reserved0) == 0);
    assert!(offset_of!(ApicLocalUnit, reserved1) == 16);
    assert!(offset_of!(ApicLocalUnit, apic_id) == 32);
    assert!(offset_of!(ApicLocalUnit, version) == 48);
    assert!(offset_of!(ApicLocalUnit, task_pri) == 128);
    assert!(offset_of!(ApicLocalUnit, arbitration_pri) == 144);
    assert!(offset_of!(ApicLocalUnit, processor_pri) == 160);
    assert!(offset_of!(ApicLocalUnit, eoi) == 176);
    assert!(offset_of!(ApicLocalUnit, logical_dest) == 208);
    assert!(offset_of!(ApicLocalUnit, dest_format) == 224);
    assert!(offset_of!(ApicLocalUnit, spurious_vector) == 240);
    assert!(offset_of!(ApicLocalUnit, isr) == 256);
    assert!(offset_of!(ApicLocalUnit, tmr) == 384);
    assert!(offset_of!(ApicLocalUnit, irr) == 512);
    assert!(offset_of!(ApicLocalUnit, error_status) == 640);
    assert!(offset_of!(ApicLocalUnit, lvt_cmci) == 752);
    assert!(offset_of!(ApicLocalUnit, icr_low) == 768);
    assert!(offset_of!(ApicLocalUnit, icr_high) == 784);
    assert!(offset_of!(ApicLocalUnit, lvt_timer) == 800);
    assert!(offset_of!(ApicLocalUnit, lvt_thermal) == 816);
    assert!(offset_of!(ApicLocalUnit, lvt_performance_monitor) == 832);
    assert!(offset_of!(ApicLocalUnit, lvt_lint0) == 848);
    assert!(offset_of!(ApicLocalUnit, lvt_lint1) == 864);
    assert!(offset_of!(ApicLocalUnit, lvt_error) == 880);
    assert!(offset_of!(ApicLocalUnit, init_count) == 896);
    assert!(offset_of!(ApicLocalUnit, cur_count) == 912);
    assert!(offset_of!(ApicLocalUnit, divider_config) == 992);
    assert!(offset_of!(ApicLocalUnit, extended_feature) == 1024);
    assert!(offset_of!(ApicLocalUnit, extended_control) == 1040);
    assert!(offset_of!(ApicLocalUnit, specific_eoi) == 1056);

    assert!(size_of::<IrqOverrideData>() == 12);
    assert!(align_of::<IrqOverrideData>() == 4);
    assert!(offset_of!(IrqOverrideData, bus) == 0);
    assert!(offset_of!(IrqOverrideData, irq) == 1);
    assert!(offset_of!(IrqOverrideData, gsi) == 4);
    assert!(offset_of!(IrqOverrideData, flags) == 8);

    assert!(offset_of!(ApicInfo, ncpus) == 0);
    assert!(offset_of!(ApicInfo, nioapics) == 1);
    assert!(offset_of!(ApicInfo, nirqoverride) == 4);
    assert!(offset_of!(ApicInfo, cpu_lapic_list) == 8);
};

const _: () = {
    assert!(size_of::<IoApicData>() == 24);
    assert!(align_of::<IoApicData>() == 8);
    assert!(offset_of!(IoApicData, apic_id) == 0);
    assert!(offset_of!(IoApicData, ngsis) == 1);
    assert!(offset_of!(IoApicData, addr) == 4);
    assert!(offset_of!(IoApicData, gsi_base) == 8);
    assert!(offset_of!(IoApicData, ioapic) == 16);

    assert!(size_of::<ApicInfo>() == 688);
    assert!(align_of::<ApicInfo>() == 8);
    assert!(offset_of!(ApicInfo, ioapic_list) == 16);
    assert!(offset_of!(ApicInfo, irq_override_list) == 400);
};

/// The HPET period in nanoseconds.
static HPET_PERIOD_NSEC: AtomicU32 = AtomicU32::new(0);

/// The mapped HPET register window, or null when the machine has none.
static HPET_ADDR: AtomicPtr<u32> = AtomicPtr::new(ptr::null_mut());

/// The zero page [`LAPIC`] points at until ACPI maps the real one, so a lookup
/// before then reports the master.
static mut DUMMY_LAPIC: ApicLocalUnit = ApicLocalUnit::ZERO;

/// The mapped local-APIC page.
static LAPIC: AtomicPtr<ApicLocalUnit> = AtomicPtr::new(&raw mut DUMMY_LAPIC);

/// The APIC ID to kernel ID table.
#[unsafe(export_name = "cpu_id_lut")]
pub static mut CPU_ID_LUT: [c_int; CPU_ID_LUT_SIZE] = [0; CPU_ID_LUT_SIZE];

/// The lists the MADT parse fills.
pub static mut APIC_DATA: ApicInfo = ApicInfo::ZERO;

/// The APIC-ID bits the platform implements.  The AP boot code reads it as a
/// plain byte.
#[unsafe(export_name = "apic_id_mask")]
static APIC_ID_MASK: AtomicU8 = AtomicU8::new(0xf);

/// The mapped HPET register window.
///
/// # Invariants
///
/// `base` names the register block `acpi.rs` mapped for the HPET,
/// so the register constants above are valid byte offsets into it.
struct Hpet {
    base: NonNull<u8>,
}

impl Hpet {
    /// The HPET ACPI found and mapped, or `None` when the machine has none.
    fn new() -> Option<Self> {
        let base = HPET_ADDR.load(Ordering::Relaxed);
        let base = NonNull::new(base.cast::<u8>())?;
        Some(Self { base })
    }

    /// Read the 32-bit register at byte `offset`.
    fn read(&self, offset: usize) -> u32 {
        // SAFETY: `Hpet::new()` established that the base is the mapped HPET
        // window, and the callers pass the register constants above.
        unsafe {
            VolatilePtr::new_read_only(self.base.add(offset).cast::<u32>())
                .read()
        }
    }

    /// Write `value` to the 32-bit register at byte `offset`.
    fn write(&self, offset: usize, value: u32) {
        // SAFETY: `Hpet::new()` established that the base is the mapped HPET
        // window, and the callers pass the register constants above.
        unsafe { VolatilePtr::new(self.base.add(offset).cast::<u32>()) }
            .write(value);
    }
}

/// Whether the local APIC is still sending the last IPI.
pub(crate) fn ipi_pending() -> bool {
    let lapic = lapic();
    let icr_low = map_field!(lapic.icr_low.r).read();
    IcrFlags::from_bits_retain(icr_low).contains(IcrFlags::PENDING)
}

/// Publishes the mapped local-APIC page.
pub(crate) fn publish_lapic(unit: NonNull<ApicLocalUnit>) {
    LAPIC.store(unit.as_ptr(), Ordering::Relaxed);
}

/// Publishes the mapped HPET register window, or null for none.
pub(crate) fn publish_hpet(window: *mut u32) {
    HPET_ADDR.store(window, Ordering::Relaxed);
}

/// The registers of the mapped local-APIC page.
pub(crate) fn lapic() -> VolatilePtr<'static, ApicLocalUnit> {
    // SAFETY: `LAPIC` holds `DUMMY_LAPIC` or the page `publish_lapic()`
    // stored, never null and never freed, and only volatile accesses reach
    // either.
    unsafe {
        VolatilePtr::new(NonNull::new_unchecked(LAPIC.load(Ordering::Relaxed)))
    }
}

/// The APIC ID of the running CPU, the eight bits CPUID leaf 1 reports.
pub(crate) fn apic_id() -> u32 {
    raw_cpuid::CpuId::new()
        .get_feature_info()
        .map_or(0, |features| u32::from(features.initial_local_apic_id()))
}

/// Resets the lists and allocates the CPU table.
pub(crate) fn data_init() -> bool {
    // SAFETY: `APIC_DATA` is this module's state, written at boot only.
    unsafe {
        APIC_DATA.cpu_lapic_list = ptr::null_mut();
        APIC_DATA.ncpus = 0;
        APIC_DATA.nioapics = 0;
        APIC_DATA.nirqoverride = 0;
    }

    let Some(list) = kalloc(MAX_NCPUS * size_of::<u16>()) else {
        return false;
    };
    // SAFETY: `list` is the `MAX_NCPUS`-entry table `kalloc` just returned.
    unsafe { APIC_DATA.cpu_lapic_list = list.as_ptr().cast::<u16>() };
    true
}

/// Appends one APIC ID to the CPU list.
pub(crate) fn add_cpu(apic_id: u16) {
    // SAFETY: `data_init()` allocated the list and the callers keep `ncpus`
    // below `MAX_NCPUS`.
    unsafe {
        let index = usize::from(APIC_DATA.ncpus);
        APIC_DATA.cpu_lapic_list.add(index).write(apic_id);
        APIC_DATA.ncpus = APIC_DATA.ncpus.wrapping_add(1);
    }
}

/// Appends one IOAPIC to the list.
pub(crate) fn add_ioapic(ioapic: IoApicData) {
    // SAFETY: `APIC_DATA` is this module's state; the bound check keeps a
    // runaway entry count inside the array.
    unsafe {
        let index = usize::from(APIC_DATA.nioapics);
        if index < MAX_IOAPICS {
            (&raw mut APIC_DATA.ioapic_list)
                .cast::<IoApicData>()
                .add(index)
                .write(ioapic);
            APIC_DATA.nioapics = APIC_DATA.nioapics.wrapping_add(1);
        }
    }
}

/// Appends one IRQ override to the list.
pub(crate) fn add_irq_override(irq_over: IrqOverrideData) {
    // SAFETY: `APIC_DATA` is this module's state; the bound check keeps a
    // runaway entry count inside the array.
    unsafe {
        let Some(count) = usize::try_from(APIC_DATA.nirqoverride).ok() else {
            return;
        };
        if count < MAX_IRQ_OVERRIDE {
            (&raw mut APIC_DATA.irq_override_list)
                .cast::<IrqOverrideData>()
                .add(count)
                .write(irq_over);
            APIC_DATA.nirqoverride = APIC_DATA.nirqoverride.wrapping_add(1);
        }
    }
}

/// The override whose IRQ is `pin`.
pub(crate) fn irq_override(pin: u8) -> Option<NonNull<IrqOverrideData>> {
    // SAFETY: `APIC_DATA` is this module's state; the entries stay live for
    // the kernel's life.
    let count = unsafe { APIC_DATA.nirqoverride };
    let count = usize::try_from(count).ok()?;
    // SAFETY: `APIC_DATA` is this module's state; the raw pointer avoids a
    // reference into it.
    let list = unsafe {
        (&raw mut APIC_DATA.irq_override_list).cast::<IrqOverrideData>()
    };
    for i in 0..count {
        if i >= MAX_IRQ_OVERRIDE {
            break;
        }
        // SAFETY: `i` is below both `count` and the array's length.
        if unsafe { (*list.add(i)).irq } == pin {
            // SAFETY: `i` is below both `count` and the array's length and the
            // entry stays live in `APIC_DATA`.
            return Some(unsafe { NonNull::new_unchecked(list.add(i)) });
        }
    }
    None
}

/// The APIC ID recorded for a kernel ID, or -1 for a CPU the MADT walk did
/// not record.
pub(crate) fn cpu_apic_id(kernel_id: c_int) -> c_int {
    let Ok(index) = usize::try_from(kernel_id) else {
        return -1;
    };
    if usize::from(ncpus()) <= index {
        return -1;
    }
    // SAFETY: `index` is below `ncpus()`, and the list holds at least that
    // many entries, before `refit_cpulist()` and after.
    c_int::from(unsafe { *APIC_DATA.cpu_lapic_list.add(index) })
}

/// The IOAPIC recorded for a kernel ID.
pub(crate) fn ioapic(kernel_id: c_int) -> Option<NonNull<IoApicData>> {
    let Ok(index) = usize::try_from(kernel_id) else {
        return None;
    };
    if MAX_IOAPICS <= index {
        return None;
    }
    // SAFETY: `index` is inside `APIC_DATA.ioapic_list`, whose entries stay
    // live for the kernel's life.
    Some(unsafe {
        NonNull::new_unchecked(
            (&raw mut APIC_DATA.ioapic_list)
                .cast::<IoApicData>()
                .add(index),
        )
    })
}

/// The register window of the IOAPIC recorded for a kernel ID, or `None`
/// when there is no such IOAPIC or the MADT published no window for it.
pub(crate) fn ioapic_unit(
    kernel_id: c_int,
) -> Option<VolatilePtr<'static, ApicIoUnit>> {
    let ioapic = ioapic(kernel_id)?;
    // SAFETY: `ioapic` points into `APIC_DATA`, whose entries stay live for
    // the kernel's life.
    let unit = NonNull::new(unsafe { (*ioapic.as_ptr()).ioapic })?;
    // SAFETY: a published window is the IOAPIC's mapped register page, never
    // unmapped, and only volatile accesses reach it.
    Some(unsafe { VolatilePtr::new(unit) })
}

/// The number of CPUs the MADT named.
pub(crate) fn ncpus() -> u8 {
    // SAFETY: `APIC_DATA` is this module's state; the load only reads it.
    unsafe { APIC_DATA.ncpus }
}

/// The number of I/O APICs the MADT named.
pub(crate) fn num_ioapics() -> u8 {
    // SAFETY: `APIC_DATA` is this module's state; the load only reads it.
    unsafe { APIC_DATA.nioapics }
}

/// The APIC-ID mask the MADT parse uses.
pub(crate) fn id_mask() -> u8 {
    APIC_ID_MASK.load(Ordering::Relaxed)
}

/// Shrinks the CPU list to the CPUs found.
pub(crate) fn refit_cpulist() -> bool {
    // SAFETY: `APIC_DATA` is this module's state; the list stays allocated
    // until the kernel frees it below.
    let old_list = unsafe { APIC_DATA.cpu_lapic_list };
    if old_list.is_null() {
        return false;
    }
    let count = usize::from(ncpus());
    let Some(new_list) = kalloc(count * size_of::<u16>()) else {
        return false;
    };
    // SAFETY: `old_list` holds `count` entries, and `new_list` holds `count`
    // entries as well.
    unsafe {
        ptr::copy_nonoverlapping(
            old_list,
            new_list.as_ptr().cast::<u16>(),
            count,
        );
        APIC_DATA.cpu_lapic_list = new_list.as_ptr().cast::<u16>();
    }
    // SAFETY: `old_list` is the `MAX_NCPUS`-entry table `data_init()`
    // allocated, non-null from the check above.
    unsafe {
        kfree(
            NonNull::new_unchecked(old_list.cast::<u8>()),
            MAX_NCPUS * size_of::<u16>(),
        );
    }
    true
}

/// Fills the APIC ID to kernel ID table.
pub(crate) fn generate_cpu_id_lut() {
    for i in 0..c_int::from(ncpus()) {
        let apic_id = cpu_apic_id(i);
        if 0 <= apic_id {
            let Ok(index) = usize::try_from(apic_id) else {
                continue;
            };
            if index < CPU_ID_LUT_SIZE {
                // SAFETY: `index` is inside `cpu_id_lut`.
                unsafe {
                    (&raw mut CPU_ID_LUT).cast::<c_int>().add(index).write(i);
                }
            }
        } else {
            kprint!("apic_get_cpu_apic_id({}) failed...\n", i);
        }
    }
}

/// Lists each CPU and IOAPIC with its APIC ID.
pub(crate) fn print_info() {
    kprint!("CPUS:\n");
    for i in 0..c_int::from(ncpus()) {
        // The C stores the `int` return in a `uint16_t` before printing it.
        let lapic_id = cpu_apic_id(i) as u16;
        kprint!(
            " CPU {} - APIC ID {:x} - addr=0x{:x}\n",
            i,
            c_int::from(lapic_id),
            LAPIC.load(Ordering::Relaxed).expose_provenance(),
        );
    }
    kprint!("IOAPICS:\n");
    for i in 0..c_int::from(num_ioapics()) {
        let Some(ioapic) = ioapic(i) else {
            kprint!("ERROR: invalid IOAPIC ID {:x}\n", i);
            continue;
        };
        // SAFETY: `ioapic` points into `APIC_DATA`.
        let (apic_id, unit) =
            unsafe { ((*ioapic.as_ptr()).apic_id, (*ioapic.as_ptr()).ioapic) };
        kprint!(
            " IOAPIC {} - APIC ID {:x} - addr=0x{:x}\n",
            i,
            c_int::from(apic_id),
            unit.expose_provenance(),
        );
    }
}

/// Programs both halves of the ICR and posts them.
pub(crate) fn send_ipi(
    dest_shorthand: c_uint,
    deliv_mode: c_uint,
    flags: IcrFlags,
    vector: c_uint,
    dest_id: c_uint,
) {
    let lapic = lapic();
    let icr_low = (map_field!(lapic.icr_low.r).read() & !ICR_LOW_FIELDS)
        | (vector & 0xff)
        | ((deliv_mode & 0x7) << 8)
        | flags.intersection(IcrFlags::IPI).bits()
        | ((dest_shorthand & 0x3) << 18);
    let icr_high = (map_field!(lapic.icr_high.r).read() & 0x00ff_ffff)
        | ((dest_id & 0xff) << 24);

    map_field!(lapic.icr_high.r).write(icr_high);
    map_field!(lapic.icr_low.r).write(icr_low);
}

/// Software-enables the local APIC.
pub(crate) fn enable() {
    let lapic = lapic();
    let value = SpuriousVector::from_bits_retain(
        map_field!(lapic.spurious_vector.r).read(),
    );
    map_field!(lapic.spurious_vector.r)
        .write((value | SpuriousVector::ENABLE).bits());
}

/// Software-disables the local APIC.
fn disable() {
    let lapic = lapic();
    let value = SpuriousVector::from_bits_retain(
        map_field!(lapic.spurious_vector.r).read(),
    );
    map_field!(lapic.spurious_vector.r)
        .write((value & !SpuriousVector::ENABLE).bits());
}

/// Decides the APIC-ID width the platform keeps.
pub(crate) fn fix_id_mask() {
    let lapic = lapic();
    // The extended registers are read only once the version says they exist:
    // reading them otherwise is an illegal register access.
    let needs_workaround =
        ApicExt::from_bits_retain(map_field!(lapic.version.r).read())
            .contains(ApicExt::HAS_EXT_APIC_SPACE)
            && ApicExt::from_bits_retain(
                map_field!(lapic.extended_feature.r).read(),
            )
            .contains(ApicExt::ID_8BIT)
            && !ApicExt::from_bits_retain(
                map_field!(lapic.extended_control.r).read(),
            )
            .contains(ApicExt::ID_8BIT);

    if needs_workaround {
        kprint!("WARNING: Only 4 bit APIC ids\n");
        APIC_ID_MASK.store(0xf, Ordering::Relaxed);
        return;
    }

    kprint!("8 bit APIC ids\n");
    APIC_ID_MASK.store(0xff, Ordering::Relaxed);
}

/// Puts the local APIC into the flat, software-enabled state the kernel runs
/// it in, with interrupts off across the sequence.
///
/// Runs after [`per_cpu::init()`] of this CPU, which the block's `self_ptr`
/// records, and before any other CPU sends this one an IPI: it records the
/// APIC ID those IPIs are addressed to.
///
/// # Panics
///
/// In debug builds, panics when this CPU's per-CPU block is not
/// initialized.
pub(crate) fn setup() {
    debug_assert!(per_cpu::is_init(), "apic::setup before per_cpu::init");
    let cpu = cpu_id();
    interrupts::without_interrupts(|| {
        let lapic = lapic();

        // The ID register, not CPUID: physical destinations match what is
        // actually set there, as for the IOAPIC routes.
        let apic_id = map_field!(lapic.apic_id.r).read() >> 24;
        per_cpu::per_cpu().set_apic_id(apic_id);

        map_field!(lapic.lvt_lint0.r).update(|value| {
            (Lvt::from_bits_retain(value) | Lvt::MASKED).bits()
        });
        map_field!(lapic.lvt_lint1.r).update(|value| {
            (Lvt::from_bits_retain(value) | Lvt::MASKED).bits()
        });
        map_field!(lapic.lvt_performance_monitor.r).update(|value| {
            (Lvt::from_bits_retain(value) | Lvt::MASKED).bits()
        });
        if cpu != CpuId::BOOT {
            map_field!(lapic.lvt_timer.r).update(|value| {
                (Lvt::from_bits_retain(value) | Lvt::MASKED).bits()
            });
        }
        // The discarded reads stay: they are the C's volatile accesses.
        let _ = map_field!(lapic.task_pri.r).read();
        map_field!(lapic.task_pri.r).write(0);

        let _ = map_field!(lapic.spurious_vector.r).read();
        map_field!(lapic.spurious_vector.r).write(
            SpuriousVector::from_bits_retain(IOAPIC_SPURIOUS_BASE)
                .union(SpuriousVector::DIRECTED_EOI)
                .bits(),
        );

        map_field!(lapic.error_status.r).write(0);
    });
}

/// Acknowledges the in-service interrupt.
pub(crate) fn eoi() {
    let lapic = lapic();
    map_field!(lapic.eoi.r).write(0);
}

/// Select the IOAPIC version register and read the entry count.
///
/// # Safety
///
/// `unit` must be the mapped IOAPIC register window.
pub(crate) unsafe fn ioapic_entry_count(unit: NonNull<ApicIoUnit>) -> u8 {
    // SAFETY: the caller promises the mapped window, which only volatile
    // accesses reach.
    let unit = unsafe { VolatilePtr::new(unit) };
    map_field!(unit.select.r).write(APIC_IO_VERSION);
    let version = map_field!(unit.window.r).read();
    let entries = ((version >> APIC_IO_ENTRIES_SHIFT) & 0xff) + 1;
    // The C assigns the `uint32_t` sum to a `uint8_t` field, so the
    // 256-entry case truncates to zero.
    entries as u8
}

/// Programs the HPET for 32-bit periodic counting with interrupts off.
fn hpet_setup() {
    let Some(hpet) = Hpet::new() else {
        kprint!("HPET not available\n");
        return;
    };

    let period = hpet.read(HPET_CAP_PERIOD);
    let period_nsec = period / FSEC_PER_NSEC;
    HPET_PERIOD_NSEC.store(period_nsec, Ordering::Relaxed);
    kprint!("HPET ticks every {} nanoseconds\n", period_nsec as c_int);

    let val = HpetConfig::from_bits_retain(hpet.read(HPET_CFG))
        & !(HpetConfig::LEGACY_ROUTE | HpetConfig::ENABLE);
    hpet.write(HPET_CFG, val.bits());

    hpet.write(HPET_COUNTER, 0);

    let val = (HpetTimerConfig::from_bits_retain(hpet.read(HPET_T0_CFG))
        & !HpetTimerConfig::INT_ENABLE)
        | HpetTimerConfig::MODE_32BIT
        | HpetTimerConfig::TYPE_PERIODIC
        | HpetTimerConfig::VAL_SET;
    hpet.write(HPET_T0_CFG, val.bits());

    hpet.write(HPET_T0_COMPARATOR, u32::MAX);

    let val =
        HpetConfig::from_bits_retain(hpet.read(HPET_CFG)) | HpetConfig::ENABLE;
    hpet.write(HPET_CFG, val.bits());

    kprint!("HPET enabled\n");
}

/// Read the HPET main counter, or zero when ACPI found no timer.
fn read_counter() -> u32 {
    Hpet::new().map_or(0, |hpet| hpet.read(HPET_COUNTER))
}

/// The HPET tick period in nanoseconds.
fn counter_period_nsec() -> u32 {
    HPET_PERIOD_NSEC.load(Ordering::Relaxed)
}

/// Software-enables the local APIC.
pub(crate) fn lapic_enable() {
    enable();
}

/// Software-disables the local APIC.
pub(crate) fn lapic_disable() {
    disable();
}

/// Puts the local APIC into the state the kernel runs it in.
pub(crate) fn lapic_setup() {
    setup();
}

/// Acknowledges the in-service interrupt; the interrupt entry calls it from
/// assembly.
pub(crate) extern "C" fn lapic_eoi() {
    eoi();
}

/// Initialize the HPET.
pub(crate) fn hpet_init() {
    hpet_setup();
}

/// Read the HPET main counter, or zero when there is no HPET.
pub(crate) fn hpclock_read_counter() -> u32 {
    read_counter()
}

/// The HPET tick period in nanoseconds.
pub(crate) fn hpclock_get_counter_period_nsec() -> u32 {
    counter_period_nsec()
}
