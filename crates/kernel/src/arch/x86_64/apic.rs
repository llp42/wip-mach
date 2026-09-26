// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from i386/i386/apic.c:
//   Copyright (C) 2020 Free Software Foundation, Inc.
//   Written by Almudena Garcia Jurado-Centurion
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The APIC and HPET accessors, which `i386/i386/apic.c` used to define and
//! `i386/i386/apic.h` declares; the two `hpclock_*` entries are also declared
//! in <`kern/mach_clock.h`>.
//!
//! The `ApicReg`, `ApicIoUnit`, `ApicLocalUnit`, `IoApicData`,
//! `IrqOverrideData` and `ApicInfo` mirrors follow that header's field order,
//! so the C code that still reads `lapic->...` reaches the same offsets the
//! Rust accessors do.

use crate::arch::x86_64::acpi_parse_apic::HPET_ADDR;
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::config::MAX_NCPUS;
use crate::kern::console::kprint;
use crate::kern::slab::{kalloc, kfree};
use crate::kern::smp::CpuId;
use core::arch::asm;
use core::arch::x86_64::__cpuid;
use core::ffi::{c_int, c_uint, c_ulong};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};

/// `HPET_CAP_PERIOD` of `i386/i386/apic.c`: the tick-period register.
const HPET_CAP_PERIOD: usize = 0x04;
/// `HPET_CFG`: the configuration register.
const HPET_CFG: usize = 0x10;
/// `HPET_CFG_ENABLE`: start the main counter.
const HPET_CFG_ENABLE: u32 = 1 << 0;
/// `HPET_LEGACY_ROUTE`: route timer 0 through the 8254 interrupt.
const HPET_LEGACY_ROUTE: u32 = 1 << 1;
/// `HPET_COUNTER`: the main counter register.
const HPET_COUNTER: usize = 0xf0;
/// `HPET_T0_CFG`: timer 0's configuration register.
const HPET_T0_CFG: usize = 0x100;
/// `HPET_T0_32BIT_MODE`: keep the comparator 32 bits wide.
const HPET_T0_32BIT_MODE: u32 = 1 << 8;
/// `HPET_T0_VAL_SET`: latch the comparator value.
const HPET_T0_VAL_SET: u32 = 1 << 6;
/// `HPET_T0_TYPE_PERIODIC`: reload the comparator in periodic mode.
const HPET_T0_TYPE_PERIODIC: u32 = 1 << 3;
/// `HPET_T0_INT_ENABLE`: let timer 0 raise an interrupt.
const HPET_T0_INT_ENABLE: u32 = 1 << 2;
/// `HPET_T0_COMPARATOR`: timer 0's comparator register.
const HPET_T0_COMPARATOR: usize = 0x108;

/// `FSEC_PER_NSEC`: femtoseconds in a nanosecond.
const FSEC_PER_NSEC: u32 = 1_000_000;
/// `MAX_IOAPICS` of <i386/apic.h>: the IOAPIC entries `ApicInfo` stores.
const MAX_IOAPICS: usize = 16;
/// `MAX_IRQ_OVERRIDE` of <i386/apic.h>: the IRQ overrides `ApicInfo` stores.
const MAX_IRQ_OVERRIDE: usize = 24;

/// `LAPIC_ENABLE` of <i386/apic.h>: software-enable the local APIC.
const LAPIC_ENABLE: u32 = 0x100;
/// `LAPIC_ENABLE_DIRECTED_EOI`: use directed end-of-interrupt.
const LAPIC_ENABLE_DIRECTED_EOI: u32 = 0x1000;
/// `LAPIC_DISABLE`: mask an LVT entry.
pub(crate) const LAPIC_DISABLE: u32 = 0x10000;

/// `APIC_MSR` of <i386/apic.h>: the local APIC base MSR.
pub(crate) const APIC_MSR: u32 = 0x1b;
/// `APIC_MSR_BSP`: this CPU is the bootstrap processor.
pub(crate) const APIC_MSR_BSP: u32 = 0x100;
/// `APIC_MSR_X2APIC`: the local APIC is in x2APIC mode.
pub(crate) const APIC_MSR_X2APIC: u32 = 0x400;
/// `APIC_MSR_ENABLE`: the local APIC is enabled.
pub(crate) const APIC_MSR_ENABLE: u32 = 0x800;

/// `APIC_VERSION_HAS_EXT_APIC_SPACE`: the extended register bank exists.
const APIC_VERSION_HAS_EXT_APIC_SPACE: u32 = 1 << 31;
/// `APIC_EXT_FEATURE_HAS_8BITID`: the local APIC supports 8-bit IDs.
const APIC_EXT_FEATURE_HAS_8BITID: u32 = 1 << 2;
/// `APIC_EXT_CTRL_ENABLE_8BITID`: software enabled 8-bit IDs.
const APIC_EXT_CTRL_ENABLE_8BITID: u32 = 1 << 2;

/// `IOAPIC_SPURIOUS_BASE` of <i386at/idt.h>: the spurious-vector base.
pub(crate) const IOAPIC_SPURIOUS_BASE: u32 = 0xff;

/// `APIC_IO_VERSION` of <i386/apic.h>: the IOAPIC version register index.
pub(crate) const APIC_IO_VERSION: u32 = 0x01;
/// `APIC_IO_VERSION_SHIFT`: where the version register holds the version.
pub(crate) const APIC_IO_VERSION_SHIFT: u32 = 0;
/// `APIC_IO_ENTRIES_SHIFT`: where the version register holds the entry count.
pub(crate) const APIC_IO_ENTRIES_SHIFT: u32 = 16;

/// The ICR-low fields `apic_send_ipi()` overwrites: vector, delivery mode,
/// destination mode, level, trigger mode and destination shorthand.
const ICR_LOW_FIELDS: u32 =
    0xff | (0x7 << 8) | (1 << 11) | (1 << 14) | (1 << 15) | (0x3 << 18);

/// `SEND_PENDING` of <i386/apic.h>: the `delivery_status` bit of `icr_low`.
const SEND_PENDING: u32 = 1 << 12;

/// `cpu_id_lut` entries of `i386/i386/apic.c`.
const CPU_ID_LUT_SIZE: usize = 256;

/// `ApicReg` of <i386/apic.h>: one 128-bit register slot.
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

/// `ApicIoUnit` of <i386/apic.h>: the IOAPIC's register window.
#[repr(C)]
#[allow(missing_docs)]
pub struct ApicIoUnit {
    pub select: ApicReg,
    pub window: ApicReg,
    pub unused: [ApicReg; 2],
    pub eoi: ApicReg,
}

/// `ApicLocalUnit` of <i386/apic.h>: the local APIC's register page.
///
/// `icr_low` and `icr_high` are the header's `IcrLReg` and `IcrHReg` unions;
/// both are one `ApicReg` wide, and the unions' bitfield views alias its
/// value word.
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
    /// The zero image the C's `dummy_lapic` began with.
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

/// `IoApicData` of <i386/apic.h>: one MADT IOAPIC entry.
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

/// `IrqOverrideData` of <i386/apic.h>: one MADT IRQ override entry.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct IrqOverrideData {
    pub bus: u8,
    pub irq: u8,
    pub gsi: u32,
    pub flags: u16,
}

impl IrqOverrideData {
    const ZERO: Self = Self {
        bus: 0,
        irq: 0,
        gsi: 0,
        flags: 0,
    };
}

/// `ApicInfo` of <i386/apic.h>: the CPUs, IOAPICs and IRQ overrides the MADT
/// named.
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

/// `hpet_period_nsec` of `i386/i386/apic.c`: the HPET period in nanoseconds.
pub static mut HPET_PERIOD_NSEC: u32 = 0;

/// `dummy_lapic` of `i386/i386/apic.c`: the zero page `lapic` points at until
/// ACPI maps the real one, so a lookup before then reports the master.
static mut DUMMY_LAPIC: ApicLocalUnit = ApicLocalUnit::ZERO;

/// `lapic` of <i386/apic.h>: the mapped local-APIC page.
pub static mut LAPIC: *mut ApicLocalUnit = &raw mut DUMMY_LAPIC;

/// `cpu_id_lut` of `i386/i386/apic.c`: the APIC ID to kernel ID table.
#[unsafe(export_name = "cpu_id_lut")]
pub static mut CPU_ID_LUT: [c_int; CPU_ID_LUT_SIZE] = [0; CPU_ID_LUT_SIZE];

/// `apic_data` of `i386/i386/apic.c`: the lists the MADT parse fills.
pub static mut APIC_DATA: ApicInfo = ApicInfo::ZERO;

/// `apic_id_mask` of <i386/apic.h>: the APIC-ID bits the platform implements.
#[unsafe(export_name = "apic_id_mask")]
pub static mut APIC_ID_MASK: u8 = 0xf;

/// The mapped HPET register window.
///
/// # Invariants
///
/// `base` names the register block `acpi_parse_apic.rs` mapped for the HPET,
/// so the register constants above are valid byte offsets into it.
struct Hpet {
    base: NonNull<u8>,
}

impl Hpet {
    /// The HPET ACPI found and mapped, or `None` when the machine has none.
    fn new() -> Option<Self> {
        // SAFETY: `hpet_addr` is the C global <i386/apic.h> declares.
        let base = unsafe { HPET_ADDR };
        let base = NonNull::new(base.cast::<u8>())?;
        Some(Self { base })
    }

    /// Read the 32-bit register at byte `offset`.
    fn read(&self, offset: usize) -> u32 {
        // SAFETY: `Hpet::new()` established that the base is the mapped HPET
        // window, and the callers pass the register constants above.
        unsafe {
            ptr::read_volatile(self.base.as_ptr().add(offset).cast::<u32>())
        }
    }

    /// Write `value` to the 32-bit register at byte `offset`.
    fn write(&self, offset: usize, value: u32) {
        // SAFETY: `Hpet::new()` established that the base is the mapped HPET
        // window, and the callers pass the register constants above;
        // the volatile store is the C's `*(volatile uint32_t *) =`
        // through `HPET32()`.
        unsafe {
            ptr::write_volatile(
                self.base.as_ptr().add(offset).cast::<u32>(),
                value,
            );
        }
    }
}

/// `cpu_intr_save()` of <i386/cpu.h>: the current EFLAGS, interrupts off.
pub(crate) fn intr_save() -> c_ulong {
    let flags: c_ulong;
    // SAFETY: `pushf`, `pop` and `cli` are the instructions the C inline
    // expands to, and the stack stays balanced.
    unsafe {
        asm!(
            "pushf",
            "pop {flags}",
            "cli",
            flags = out(reg) flags,
            options(nostack),
        );
    }
    flags
}

/// `cpu_intr_restore()` of <i386/cpu.h>: put `flags` back into EFLAGS.
pub(crate) fn intr_restore(flags: c_ulong) {
    // SAFETY: `flags` came from `intr_save()`, so it holds a valid RFLAGS
    // image; the stack stays balanced.
    unsafe {
        asm!(
            "push {flags}",
            "popf",
            flags = in(reg) flags,
            options(nostack),
        );
    }
}

/// Read an APIC register's value word.
///
/// # Safety
///
/// `reg` must point into the mapped local-APIC page, as `lapic` does.
pub(crate) unsafe fn reg_read(reg: *const ApicReg) -> u32 {
    unsafe { ptr::read_volatile(&raw const (*reg).r) }
}

/// Write an APIC register's value word.
///
/// # Safety
///
/// As [`reg_read()`].
pub(crate) unsafe fn reg_write(reg: *mut ApicReg, value: u32) {
    unsafe { ptr::write_volatile(&raw mut (*reg).r, value) }
}

/// The `lapic->icr_low.delivery_status == SEND_PENDING` test the IPI sender
/// waits on.
pub(crate) fn ipi_pending() -> bool {
    let ptr = lapic_ptr();
    // SAFETY: `ptr` is the mapped local-APIC page, and the read is the C's
    // volatile access.
    unsafe { reg_read(&raw const (*ptr).icr_low) & SEND_PENDING != 0 }
}

/// Publish the mapped local-APIC page, the C's `apic_lapic_init()`.
pub(crate) fn publish_lapic(unit: *mut ApicLocalUnit) {
    // SAFETY: `lapic` is the C global, written once at boot.
    unsafe { LAPIC = unit };
}

/// The mapped local-APIC page.
pub(crate) fn lapic_ptr() -> *mut ApicLocalUnit {
    // SAFETY: `lapic` is the C global; the load only reads the pointer.
    unsafe { LAPIC }
}

/// The APIC ID of the running CPU, the eight bits CPUID leaf 1 reports in
/// EBX's high byte.
pub(crate) fn apic_id() -> u32 {
    let result = __cpuid(1);
    (result.ebx >> 24) & 0xff
}

/// `apic_data_init()` in C: reset the lists and allocate the CPU table.
pub(crate) fn data_init() -> bool {
    // SAFETY: `apic_data` is this module's state, written at boot only.
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

/// `apic_add_cpu()` in C: append one APIC ID to the CPU list.
pub(crate) fn add_cpu(apic_id: u16) {
    // SAFETY: `data_init()` allocated the list and the callers keep `ncpus`
    // below `MAX_NCPUS`.
    unsafe {
        let index = usize::from(APIC_DATA.ncpus);
        APIC_DATA.cpu_lapic_list.add(index).write(apic_id);
        APIC_DATA.ncpus = APIC_DATA.ncpus.wrapping_add(1);
    }
}

/// `apic_add_ioapic()` in C: append one IOAPIC to the list.
pub(crate) fn add_ioapic(ioapic: IoApicData) {
    // SAFETY: `apic_data` is this module's state; the bound check keeps a
    // runaway entry count inside the array, where the C would overwrite the
    // next field.
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

/// `apic_add_irq_override()` in C: append one IRQ override to the list.
pub(crate) fn add_irq_override(irq_over: IrqOverrideData) {
    // SAFETY: `apic_data` is this module's state; the bound check keeps a
    // runaway entry count inside the array, where the C would overwrite the
    // next field.
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

/// `acpi_get_irq_override()` in C: the override whose IRQ is `pin`.
pub(crate) fn irq_override(pin: u8) -> Option<NonNull<IrqOverrideData>> {
    // SAFETY: `apic_data` is this module's state; the entries stay live for
    // the kernel's life.
    let count = unsafe { APIC_DATA.nirqoverride };
    let count = usize::try_from(count).ok()?;
    // SAFETY: `apic_data` is this module's state; the raw pointer avoids a
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
            // entry stays live in `apic_data`.
            return Some(unsafe { NonNull::new_unchecked(list.add(i)) });
        }
    }
    None
}

/// `apic_get_cpu_apic_id()` in C: the APIC ID recorded for a kernel ID.
fn cpu_apic_id(kernel_id: c_int) -> c_int {
    let Ok(index) = usize::try_from(kernel_id) else {
        return -1;
    };
    if MAX_NCPUS <= index {
        return -1;
    }
    // SAFETY: `index` is below `MAX_NCPUS`, the length of the list
    // `data_init()` allocated.
    c_int::from(unsafe { *APIC_DATA.cpu_lapic_list.add(index) })
}

/// `apic_get_ioapic()` in C: the IOAPIC recorded for a kernel ID.
pub(crate) fn ioapic(kernel_id: c_int) -> Option<NonNull<IoApicData>> {
    let Ok(index) = usize::try_from(kernel_id) else {
        return None;
    };
    if MAX_IOAPICS <= index {
        return None;
    }
    // SAFETY: `index` is inside `apic_data.ioapic_list`, whose entries stay
    // live for the kernel's life.
    Some(unsafe {
        NonNull::new_unchecked(
            (&raw mut APIC_DATA.ioapic_list)
                .cast::<IoApicData>()
                .add(index),
        )
    })
}

/// `apic_get_numcpus()` in C.
pub(crate) fn ncpus() -> u8 {
    // SAFETY: `apic_data` is this module's state; the load only reads it.
    unsafe { APIC_DATA.ncpus }
}

/// `apic_get_num_ioapics()` in C.
pub(crate) fn num_ioapics() -> u8 {
    // SAFETY: `apic_data` is this module's state; the load only reads it.
    unsafe { APIC_DATA.nioapics }
}

/// The APIC-ID mask the MADT parse uses.
pub(crate) fn id_mask() -> u8 {
    // SAFETY: `apic_id_mask` is written once at boot, before the MADT parse.
    unsafe { APIC_ID_MASK }
}

/// `apic_refit_cpulist()` in C: shrink the CPU list to the CPUs found.
pub(crate) fn refit_cpulist() -> bool {
    // SAFETY: `apic_data` is this module's state; the list stays allocated
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

/// `apic_generate_cpu_id_lut()` in C: fill the APIC ID to kernel ID table.
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

/// `apic_print_info()` in C: list each CPU and IOAPIC with its APIC ID.
pub(crate) fn print_info() {
    kprint!("CPUS:\n");
    for i in 0..c_int::from(ncpus()) {
        // The C stores the `int` return in a `uint16_t` before printing it.
        let lapic_id = cpu_apic_id(i) as u16;
        kprint!(
            " CPU {} - APIC ID {:x} - addr=0x{:x}\n",
            i,
            c_int::from(lapic_id),
            lapic_ptr().expose_provenance(),
        );
    }
    kprint!("IOAPICS:\n");
    for i in 0..c_int::from(num_ioapics()) {
        let Some(ioapic) = ioapic(i) else {
            kprint!("ERROR: invalid IOAPIC ID {:x}\n", i);
            continue;
        };
        // SAFETY: `ioapic` points into `apic_data`.
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

/// `apic_send_ipi()` in C: program both halves of the ICR and post them.
pub(crate) fn send_ipi(
    dest_shorthand: c_uint,
    deliv_mode: c_uint,
    dest_mode: c_uint,
    level: c_uint,
    trig_mode: c_uint,
    vector: c_uint,
    dest_id: c_uint,
) {
    let ptr = lapic_ptr();
    // SAFETY: `ptr` is the mapped local-APIC page, and the reads and writes
    // are the C's volatile accesses.
    unsafe {
        let icr_low = (reg_read(&raw const (*ptr).icr_low) & !ICR_LOW_FIELDS)
            | (vector & 0xff)
            | ((deliv_mode & 0x7) << 8)
            | ((dest_mode & 0x1) << 11)
            | ((level & 0x1) << 14)
            | ((trig_mode & 0x1) << 15)
            | ((dest_shorthand & 0x3) << 18);
        let icr_high = (reg_read(&raw const (*ptr).icr_high) & 0x00ff_ffff)
            | ((dest_id & 0xff) << 24);

        reg_write(&raw mut (*ptr).icr_high, icr_high);
        reg_write(&raw mut (*ptr).icr_low, icr_low);
    }
}

/// `lapic_enable()` in C.
pub(crate) fn enable() {
    let ptr = lapic_ptr();
    // SAFETY: `ptr` is the mapped local-APIC page.
    unsafe {
        let value = reg_read(&raw const (*ptr).spurious_vector);
        reg_write(&raw mut (*ptr).spurious_vector, value | LAPIC_ENABLE);
    }
}

/// `lapic_disable()` in C.
fn disable() {
    let ptr = lapic_ptr();
    // SAFETY: `ptr` is the mapped local-APIC page.
    unsafe {
        let value = reg_read(&raw const (*ptr).spurious_vector);
        reg_write(&raw mut (*ptr).spurious_vector, value & !LAPIC_ENABLE);
    }
}

/// `fix_apic_id_mask()` in C: decide the APIC-ID width the platform keeps.
pub(crate) fn fix_id_mask() {
    let ptr = lapic_ptr();
    // SAFETY: `ptr` is the mapped local-APIC page; the three reads are the
    // C's volatile accesses.
    let needs_workaround = unsafe {
        let version = reg_read(&raw const (*ptr).version);
        version & APIC_VERSION_HAS_EXT_APIC_SPACE != 0
            && reg_read(&raw const (*ptr).extended_feature)
                & APIC_EXT_FEATURE_HAS_8BITID
                != 0
            && reg_read(&raw const (*ptr).extended_control)
                & APIC_EXT_CTRL_ENABLE_8BITID
                == 0
    };

    if needs_workaround {
        kprint!("WARNING: Only 4 bit APIC ids\n");
        // SAFETY: `apic_id_mask` is written once at boot, here.
        unsafe { APIC_ID_MASK = 0xf };
        return;
    }

    kprint!("8 bit APIC ids\n");
    // SAFETY: `apic_id_mask` is written once at boot, here.
    unsafe { APIC_ID_MASK = 0xff };
}

/// `lapic_setup()` in C: put the local APIC into the flat, software-enabled
/// state Mach runs it in, with interrupts off across the sequence.
///
/// Runs after [`per_cpu::init()`] of this CPU, which the block's `self_ptr`
/// records, and before any other CPU sends this one an IPI: it records the
/// APIC ID those IPIs are addressed to.
///
/// # Panics
///
/// Panics when this CPU's per-CPU block is not initialized.
pub(crate) fn setup() {
    // TODO: switch to `debug_assert!` once a profile enables
    // `debug-assertions`; `profile.dev` compiles that form out today, so
    // the check must run unconditionally.
    assert!(per_cpu::is_init(), "apic::setup before per_cpu::init");
    let cpu = cpu_id();
    let flags = intr_save();
    let ptr = lapic_ptr();

    // SAFETY: `ptr` is the mapped local-APIC page; the `let _` reads are the
    // C's `volatile uint32_t dummy` assignments.
    unsafe {
        // The ID register, not CPUID: physical destinations match what is
        // actually set there, as for the IOAPIC routes.
        let apic_id = reg_read(&raw const (*ptr).apic_id) >> 24;
        per_cpu::per_cpu().set_apic_id(apic_id);

        let value = reg_read(&raw const (*ptr).lvt_lint0);
        reg_write(&raw mut (*ptr).lvt_lint0, value | LAPIC_DISABLE);
        let value = reg_read(&raw const (*ptr).lvt_lint1);
        reg_write(&raw mut (*ptr).lvt_lint1, value | LAPIC_DISABLE);
        let value = reg_read(&raw const (*ptr).lvt_performance_monitor);
        reg_write(
            &raw mut (*ptr).lvt_performance_monitor,
            value | LAPIC_DISABLE,
        );
        if cpu != CpuId::BOOT {
            let value = reg_read(&raw const (*ptr).lvt_timer);
            reg_write(&raw mut (*ptr).lvt_timer, value | LAPIC_DISABLE);
        }
        let _ = reg_read(&raw const (*ptr).task_pri);
        reg_write(&raw mut (*ptr).task_pri, 0);

        let _ = reg_read(&raw const (*ptr).spurious_vector);
        reg_write(
            &raw mut (*ptr).spurious_vector,
            IOAPIC_SPURIOUS_BASE | LAPIC_ENABLE_DIRECTED_EOI,
        );

        reg_write(&raw mut (*ptr).error_status, 0);
    }

    intr_restore(flags);
}

/// `lapic_eoi()` in C: acknowledge the in-service interrupt.
pub(crate) fn eoi() {
    let ptr = lapic_ptr();
    // SAFETY: `ptr` is the mapped local-APIC page.
    unsafe { reg_write(&raw mut (*ptr).eoi, 0) };
}

/// Select the IOAPIC version register and read the entry count.
///
/// # Safety
///
/// `unit` must be the mapped IOAPIC register window.
pub(crate) unsafe fn ioapic_entry_count(unit: *mut ApicIoUnit) -> u8 {
    let version = unsafe {
        ptr::write_volatile(&raw mut (*unit).select.r, APIC_IO_VERSION);
        ptr::read_volatile(&raw const (*unit).window.r)
    };
    let entries = ((version >> APIC_IO_ENTRIES_SHIFT) & 0xff) + 1;
    // The C assigns the `uint32_t` sum to a `uint8_t` field, so the
    // 256-entry case truncates to zero.
    entries as u8
}

/// `hpet_init()` in C: program the HPET for 32-bit periodic counting with
/// interrupts off.
fn hpet_setup() {
    let Some(hpet) = Hpet::new() else {
        kprint!("HPET not available\n");
        return;
    };

    let period = hpet.read(HPET_CAP_PERIOD);
    let period_nsec = period / FSEC_PER_NSEC;
    // SAFETY: `hpet_period_nsec` is written once, here, at boot.
    unsafe { HPET_PERIOD_NSEC = period_nsec };
    kprint!("HPET ticks every {} nanoseconds\n", period_nsec as c_int);

    let val = hpet.read(HPET_CFG) & !(HPET_LEGACY_ROUTE | HPET_CFG_ENABLE);
    hpet.write(HPET_CFG, val);

    hpet.write(HPET_COUNTER, 0);

    let val = (hpet.read(HPET_T0_CFG) & !HPET_T0_INT_ENABLE)
        | HPET_T0_32BIT_MODE
        | HPET_T0_TYPE_PERIODIC
        | HPET_T0_VAL_SET;
    hpet.write(HPET_T0_CFG, val);

    hpet.write(HPET_T0_COMPARATOR, u32::MAX);

    let val = hpet.read(HPET_CFG) | HPET_CFG_ENABLE;
    hpet.write(HPET_CFG, val);

    kprint!("HPET enabled\n");
}

/// Read the HPET main counter, or zero when ACPI found no timer.
fn read_counter() -> u32 {
    Hpet::new().map_or(0, |hpet| hpet.read(HPET_COUNTER))
}

/// The HPET tick period in nanoseconds.
fn counter_period_nsec() -> u32 {
    // SAFETY: `hpet_period_nsec` is written once at boot, and a 32-bit load
    // is atomic.
    unsafe { HPET_PERIOD_NSEC }
}

/// `lapic_enable()` in C.
pub(crate) fn lapic_enable() {
    enable();
}

/// `lapic_disable()` in C.
pub(crate) fn lapic_disable() {
    disable();
}

/// `lapic_setup()` in C.
pub(crate) fn lapic_setup() {
    setup();
}

/// `lapic_eoi()` in C.
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
