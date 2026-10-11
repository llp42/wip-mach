// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The I/O APIC configuration and the interrupt vectors.

use crate::arch::x86_64::apic::{self, OverrideFlags};
use crate::arch::x86_64::kd::keyboard::kdintr;
use crate::arch::x86_64::per_cpu::cpu_id;
use crate::arch::x86_64::pio::Port;
use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::spl;
use crate::config::{MAX_NCPUS, NINTR};
use crate::kern::console::{CStrArg, kprint};
use core::ffi::{c_char, c_int};
use core::mem::{align_of, offset_of, size_of};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use lock::IrqSpinLock;
use lock::irq_spin_lock;
use volatile::map_field;
use x86_64::instructions::interrupts;

/// One [`IVECT`] entry, or [`None`] where the vector is unset.
pub type InterruptHandler = Option<unsafe extern "C" fn(c_int)>;

/// One line's programmed vector and trigger mode.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct IrqInfo {
    pub trigger: u8,
    pub vector: u8,
}

const _: () = {
    assert!(size_of::<IrqInfo>() == 2);
    assert!(align_of::<IrqInfo>() == 1);
    assert!(offset_of!(IrqInfo, trigger) == 0);
    assert!(offset_of!(IrqInfo, vector) == 1);
};

/// One I/O APIC redirection entry: its low and high words, as the I/O APIC
/// reads them.
#[derive(Clone, Copy)]
struct RouteEntry {
    lo: u32,
    hi: u32,
}

bitfield::bitfield! {
    /// The multi-bit fields of a redirection entry's low word: the vector
    /// and the delivery mode.  [`RouteFlags`] names its one-bit fields.
    struct RouteLow(u32);
    u32;
    vector, set_vector: 7, 0;
    delvmode, set_delvmode: 10, 8;
}

bitfield::bitfield! {
    /// A redirection entry's high word: the destination APIC.
    struct RouteHigh(u32);
    u32;
    dest, set_dest: 31, 24;
}

bitflags::bitflags! {
    /// The one-bit fields of a redirection entry's low word.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct RouteFlags: u32 {
        /// The destination is a logical one, not an APIC ID.
        const LOGICAL = 1 << 11;
        /// The pin is active-low.
        const ACTIVE_LOW = 1 << 13;
        /// The pin is level-triggered.
        const LEVEL = 1 << 15;
        /// The pin is masked.
        const MASKED = 1 << 16;
        // The vector, delivery mode and status fields.
        const _ = !0;
    }
}

impl RouteEntry {
    const ZERO: Self = Self { lo: 0, hi: 0 };

    fn vector(self) -> u8 {
        // The field is eight bits, so the narrowing is exact.
        RouteLow(self.lo).vector() as u8
    }

    fn set_vector(&mut self, value: u32) {
        let mut lo = RouteLow(self.lo);
        lo.set_vector(value);
        self.lo = lo.0;
    }

    const fn flags(self) -> RouteFlags {
        RouteFlags::from_bits_retain(self.lo)
    }

    const fn set(&mut self, flag: RouteFlags, on: bool) {
        self.lo = if on {
            self.flags().union(flag).bits()
        } else {
            self.flags().difference(flag).bits()
        };
    }

    fn set_delvmode(&mut self, value: u32) {
        let mut lo = RouteLow(self.lo);
        lo.set_delvmode(value);
        self.lo = lo.0;
    }

    fn set_dest(&mut self, value: u32) {
        let mut hi = RouteHigh(self.hi);
        hi.set_dest(value);
        self.hi = hi.0;
    }
}

/// The first vector the I/O APIC raises.
const IOAPIC_INT_BASE: u32 = 0x30;

/// The LAPIC timer divider of two.
const LAPIC_TIMER_DIVIDE_2: u32 = 0;

/// The fixed delivery mode.
const IOAPIC_FIXED: u32 = 0;

/// The interrupt-controller mode of the APIC.
const ACPI_PICMODE_APIC: c_int = 1;
/// The 8259 slave OCW port.
const PIC_SLAVE_OCW: u16 = 0xa1;
/// The 8259 master OCW port.
const PIC_MASTER_OCW: u16 = 0x21;
/// Every slave line masked.
const PICS_MASK: u8 = 0xff;
/// Every master line masked.
const PICM_MASK: u8 = 0xff;
/// The highest interrupt level.
const SPLHI: c_int = 7;

/// The handler of each interrupt line.  The interrupt stubs index it directly,
/// so this layout is the ABI.
pub static mut IVECT: [InterruptHandler; NINTR] = {
    let mut table: [InterruptHandler; NINTR] = [Some(intnull); NINTR];
    // SAFETY: the clock's entry is stored under the handler type; the
    // trampoline passes it the one `int` its own entry point ignores.
    table[0] = Some(unsafe {
        core::mem::transmute::<
            unsafe extern "C" fn(
                c_int,
                c_int,
                *const c_char,
                *mut crate::arch::x86_64::pcb::I386InterruptState,
            ),
            unsafe extern "C" fn(c_int),
        >(crate::arch::x86_64::hardclock::hardclock_entry)
    });
    table[1] = Some(kdintr);
    table[13] = Some(crate::arch::x86_64::fpu::fpintr_entry);
    table
};

/// The unit each line's handler is called with, which
/// [`interrupt`](crate::arch::x86_64::interrupt::interrupt) indexes.
pub static mut IUNIT: [c_int; NINTR] = iunit_image();

/// The initial [`IUNIT`]: each line maps to itself.
const fn iunit_image() -> [c_int; NINTR] {
    let mut table = [0; NINTR];
    let mut irq = 0;
    while irq < NINTR {
        // NINTR is 64, so the narrowing to `int` loses nothing.
        table[irq] = irq as c_int;
        irq += 1;
    }
    table
}

/// The current interrupt level of each CPU, which
/// [`spl`] reads and writes.
pub static mut CURR_IPL: [c_int; MAX_NCPUS] = [0; MAX_NCPUS];

/// Whether the interrupt system is up.
pub static SPL_INIT: AtomicBool = AtomicBool::new(false);

/// The interrupt-controller mode the platform runs in: always the APIC.
pub const PIC_MODE: c_int = ACPI_PICMODE_APIC;

/// The pin [`ioapic_configure`] remapped the timer to.
pub static TIMER_PIN: AtomicI32 = AtomicI32::new(0);

/// One entry per interrupt line.
pub static mut IRQINFO: [IrqInfo; NINTR] = [IrqInfo {
    trigger: 0,
    vector: 0,
}; NINTR];

/// The LAPIC timer ticks per Mach tick.
pub static CALIBRATED_TICKS: AtomicU32 = AtomicU32::new(0);

/// Whether the I/O APIC acknowledges a line through its EOI register.
static HAS_IRQ_SPECIFIC_EOI: AtomicBool = AtomicBool::new(false);

/// Serializes the non-atomic select/window register pairs.  An irq spin lock,
/// since interrupt handlers mask and acknowledge lines.
static IOAPIC_LOCK: IrqSpinLock<(), MachPlatform> =
    irq_spin_lock!("ioapic", ());

/// The low redirection register of `pin`.
const fn redir_low(pin: c_int) -> u32 {
    // Pins are below 64, so the offset stays far inside the register byte.
    (0x10 + pin * 2) as u32
}

/// The high redirection register of `pin`.
const fn redir_high(pin: c_int) -> u32 {
    // As `redir_low()`.
    (0x11 + pin * 2) as u32
}

/// Reads one I/O APIC register.
fn read(apic: c_int, reg: u32) -> u32 {
    let Some(unit) = apic::ioapic_unit(apic) else {
        return 0;
    };
    map_field!(unit.select.r).write(reg);
    map_field!(unit.window.r).read()
}

/// Writes one I/O APIC register.
fn write(apic: c_int, reg: u32, value: u32) {
    let Some(unit) = apic::ioapic_unit(apic) else {
        return;
    };
    map_field!(unit.select.r).write(reg);
    map_field!(unit.window.r).write(value);
}

/// Reads the redirection entry of `pin`.
fn read_entry(apic: c_int, pin: c_int) -> RouteEntry {
    RouteEntry {
        lo: read(apic, redir_low(pin)),
        hi: read(apic, redir_high(pin)),
    }
}

/// Writes the redirection entry of `pin`.  The high word goes first because
/// the mask bit lives in the low word.
fn write_entry(apic: c_int, pin: c_int, entry: RouteEntry) {
    write(apic, redir_high(pin), entry.hi);
    write(apic, redir_low(pin), entry.lo);
}

/// Changes only the low word of `pin`'s entry, so the mask bit flips without
/// rewriting the entry.
fn toggle_entry(apic: c_int, pin: c_int, masked: bool) {
    let _guard = IOAPIC_LOCK.lock();
    let mut entry = read_entry(apic, pin);
    entry.set(RouteFlags::MASKED, masked);
    write(apic, redir_low(pin), entry.lo);
}

/// The version of the I/O APIC `apic`.
fn version(apic: c_int) -> c_int {
    let raw = read(apic, apic::APIC_IO_VERSION);
    // The mask leaves eight bits, so the narrowing is exact.
    c_int::from(((raw >> apic::APIC_IO_VERSION_SHIFT) & 0xff) as u8)
}

/// The number of interrupt inputs of the I/O APIC `apic`.
fn gsis(apic: c_int) -> c_int {
    let raw = read(apic, apic::APIC_IO_VERSION);
    // The mask leaves eight bits, and the field counts entries from zero.
    c_int::from(((raw >> apic::APIC_IO_ENTRIES_SHIFT) & 0xff) as u8) + 1
}

/// The override whose IRQ is `pin`, if the MADT has one.
fn override_for(pin: c_int) -> Option<apic::IrqOverrideData> {
    let pin = u8::try_from(pin).ok()?;
    // SAFETY: `irq_override()` answers a pointer into `APIC_DATA`, whose
    // entries stay live for the kernel's life; the copy drops the borrow.
    apic::irq_override(pin).map(|over| unsafe { *over.as_ptr() })
}

/// Record one line's programmed vector and trigger for the EOI path.
fn set_irqinfo(pin: c_int, entry: RouteEntry) {
    let Ok(index) = usize::try_from(pin) else {
        return;
    };
    if NINTR <= index {
        return;
    }
    let info = IrqInfo {
        trigger: u8::from(entry.flags().contains(RouteFlags::LEVEL)),
        vector: entry.vector(),
    };
    // SAFETY: `index` is inside `irqinfo`, which only this module writes.
    unsafe { (&raw mut IRQINFO).cast::<IrqInfo>().add(index).write(info) };
}

/// The vector `irqinfo[pin]` holds, or zero when no entry was programmed.
fn irqinfo_vector(pin: c_int) -> u8 {
    let Ok(index) = usize::try_from(pin) else {
        return 0;
    };
    if NINTR <= index {
        return 0;
    }
    // SAFETY: `index` is inside `irqinfo`.
    unsafe { (*(&raw const IRQINFO).cast::<IrqInfo>().add(index)).vector }
}

/// Applies one MADT override to `entry` and answers the GSI it selects.
fn override_irq(over: &apic::IrqOverrideData, entry: &mut RouteEntry) -> u32 {
    if over.flags.contains(OverrideFlags::TRIGGER) {
        entry
            .set(RouteFlags::LEVEL, over.flags.contains(OverrideFlags::LEVEL));
    } else {
        // ISA is edge-triggered by default.
        entry.set(RouteFlags::LEVEL, over.bus != 0);
    }

    if over.flags.contains(OverrideFlags::POLARITY) {
        entry.set(
            RouteFlags::ACTIVE_LOW,
            over.flags.contains(OverrideFlags::ACTIVE_LOW),
        );
    } else if over.bus == 0 {
        // EISA is active-low for level-triggered interrupts.
        entry.set(
            RouteFlags::ACTIVE_LOW,
            entry.flags().contains(RouteFlags::LEVEL),
        );
    }

    kprint!(
        "IRQ override: pin={} gsi={} trigger={} polarity={}\n",
        c_int::from(over.irq),
        // The C passed the `uint32_t` to `%d`, which reads the same bits.
        over.gsi as c_int,
        CStrArg::from(if entry.flags().contains(RouteFlags::LEVEL) {
            c"LEVEL"
        } else {
            c"EDGE"
        }),
        CStrArg::from(if entry.flags().contains(RouteFlags::ACTIVE_LOW) {
            c"LOW"
        } else {
            c"HIGH"
        }),
    );
    over.gsi
}

/// Masks the 8259s and raises every CPU's software level.
fn disable_pic() {
    interrupts::disable();
    // SAFETY: `CURR_IPL` is the array `spl` reads;
    // the store replaces the whole MAX_NCPUS-entry image.
    unsafe { (&raw mut CURR_IPL).write([SPLHI; MAX_NCPUS]) };
    Port::new(PIC_SLAVE_OCW).write_u8(PICS_MASK);
    Port::new(PIC_MASTER_OCW).write_u8(PICM_MASK);
}

/// Times the LAPIC timer against ten clock ticks, busy-waiting on the HPET
/// rather than a wheel (the wheel is not up at calibration).
fn measure_10x_apic_hz() -> u32 {
    let lapic = apic::lapic();
    let start = u32::MAX;

    kprint!("timer calibration...");

    map_field!(lapic.init_count.r).write(start);

    let period_ns = apic::hpclock_get_counter_period_nsec();
    let hz = mach_sched::sched::CLOCK_HZ as u32;
    // Ten ticks at `CLOCK_HZ`, in HPET counts (saturating).
    let counts = if period_ns == 0 {
        0
    } else {
        ((10u64 * 1_000_000_000) / u64::from(hz) / u64::from(period_ns))
            .min(u64::from(u32::MAX)) as u32
    };
    let t0 = apic::hpclock_read_counter();
    while apic::hpclock_read_counter().wrapping_sub(t0) < counts {
        core::hint::spin_loop();
    }

    map_field!(lapic.lvt_timer.r).update(|value| {
        (apic::Lvt::from_bits_retain(value) | apic::Lvt::MASKED).bits()
    });

    kprint!(" done\n");

    // The subtraction wraps on the 32-bit counter exactly as the C's unsigned
    // arithmetic did.
    start.wrapping_sub(map_field!(lapic.cur_count.r).read())
}

/// Sets the LAPIC timer up and measures its ticks per clock tick, once.
fn calibrate_timer() {
    let lapic = apic::lapic();
    map_field!(lapic.divider_config.r).write(LAPIC_TIMER_DIVIDE_2);
    map_field!(lapic.lvt_timer.r).write(IOAPIC_INT_BASE);

    if CALIBRATED_TICKS.load(Ordering::Relaxed) == 0 {
        // SAFETY: raising to `splhigh` has no precondition, and its result is
        // only handed back to `splx()`.
        let saved = unsafe { spl::splhigh() };
        // SAFETY: lowering to `spl0` here has no lock to hold back.
        unsafe { spl::spl0() };
        let ticks = measure_10x_apic_hz() / 10;
        CALIBRATED_TICKS.store(ticks, Ordering::Relaxed);
        // SAFETY: `saved` is the level `splhigh()` returned above.
        unsafe { spl::splx(saved) };
    }
}

/// Starts this CPU's LAPIC timer, periodic at the calibrated count.
fn enable_timer() {
    let lapic = apic::lapic();
    let ticks = CALIBRATED_TICKS.load(Ordering::Relaxed);

    map_field!(lapic.init_count.r).write(ticks);
    map_field!(lapic.divider_config.r).write(LAPIC_TIMER_DIVIDE_2);
    map_field!(lapic.lvt_timer.r).write(
        (apic::Lvt::from_bits_retain(IOAPIC_INT_BASE)
            | apic::Lvt::TIMER_PERIODIC)
            .bits(),
    );
    // Buggy hardware needs the divider written again.
    map_field!(lapic.divider_config.r).write(LAPIC_TIMER_DIVIDE_2);

    kprint!("LAPIC timer configured on cpu{}\n", cpu_id());
}

/// Programs the I/O APICs from the MADT data.
fn configure() {
    let mut apic: c_int = 0;
    let version = version(apic);
    let ngsis = gsis(apic);

    if 0x20 <= version {
        // The store happens at boot and the interrupt path only reads it, so
        // the boot sequence, not the ordering, publishes the flag.
        HAS_IRQ_SPECIFIC_EOI.store(true, Ordering::Relaxed);
    }

    kprint!("IOAPIC version 0x{:x}\n", version);

    let lapic = apic::lapic();
    map_field!(lapic.spurious_vector.r).write(apic::IOAPIC_SPURIOUS_BASE);

    let mut entry = RouteEntry::ZERO;
    entry.set_delvmode(IOAPIC_FIXED);
    entry.set(RouteFlags::LOGICAL, false);
    entry.set(RouteFlags::MASKED, true);
    // The C read the APIC ID from the register, not from `apic_id_mask`,
    // because the IOAPIC uses what is actually set there.
    let apic_id = map_field!(lapic.apic_id.r).read();
    entry.set_dest(apic_id >> 24);

    let mut timer_gsi = 0;
    for pin in 0..14 {
        let mut gsi = u32::try_from(pin).unwrap_or(0);
        entry.set(RouteFlags::LEVEL, false);
        entry.set(RouteFlags::ACTIVE_LOW, false);
        if let Some(over) = override_for(pin) {
            gsi = override_irq(&over, &mut entry);
        }
        entry.set_vector(IOAPIC_INT_BASE + gsi);
        write_entry(apic, pin, entry);
        set_irqinfo(pin, entry);
        mask(pin);

        // Legacy IRQ 0 is the timer unless an override remapped it.
        if pin == 0 {
            timer_gsi = gsi;
        } else if gsi == timer_gsi {
            TIMER_PIN.store(pin, Ordering::Relaxed);
            entry.set_vector(IOAPIC_INT_BASE);
            write_entry(apic, pin, entry);
            mask(0);
        }
    }

    // 14, 15 and the PCI PIRQ A-H lines: level-triggered active-low.
    for pin in 14..ngsis {
        let mut gsi = u32::try_from(pin).unwrap_or(0);
        entry.set(RouteFlags::LEVEL, true);
        entry.set(RouteFlags::ACTIVE_LOW, true);
        if let Some(over) = override_for(pin) {
            gsi = override_irq(&over, &mut entry);
        }
        entry.set_vector(IOAPIC_INT_BASE + gsi);
        write_entry(apic, pin, entry);
        set_irqinfo(pin, entry);
        mask(pin);
    }

    kprint!("IOAPIC 0 configured with GSI 0-{}\n", ngsis - 1);

    if 1 < apic::num_ioapics() {
        apic = 1;
        let ngsis2 = gsis(apic);
        for pin in 0..ngsis2 {
            let mut gsi = u32::try_from(pin + ngsis).unwrap_or(0);
            entry.set(RouteFlags::LEVEL, true);
            entry.set(RouteFlags::ACTIVE_LOW, true);
            if let Some(over) = override_for(pin + ngsis) {
                gsi = override_irq(&over, &mut entry);
            }
            entry.set_vector(IOAPIC_INT_BASE + gsi);
            write_entry(apic, pin, entry);
            set_irqinfo(pin + ngsis, entry);
            mask(pin + ngsis);
        }

        kprint!(
            "IOAPIC 1 configured with GSI {}-{}\n",
            ngsis,
            ngsis + ngsis2 - 1,
        );
    }

    apic::setup();
    apic::enable();
}

/// Disables the line.
pub(crate) fn mask(pin: c_int) {
    toggle(0, pin, true);
}

/// Enables the line.
pub(crate) fn unmask(pin: c_int) {
    toggle(0, pin, false);
}

/// Sets or clears the mask bit of `pin`.
fn toggle(apic: c_int, pin: c_int, masked: bool) {
    toggle_entry(apic, pin, masked);
}

/// Acknowledges the line `pin`, ending the interrupt on the LAPIC.
pub(crate) fn irq_eoi(pin: c_int) {
    if pin != 0 {
        let _guard = IOAPIC_LOCK.lock();
        if !HAS_IRQ_SPECIFIC_EOI.load(Ordering::Relaxed) {
            // An IOAPIC with no specific EOI needs the pin masked and
            // edge-triggered around the acknowledgement.
            let mut entry = read_entry(0, pin);
            let old = entry;
            entry.set(RouteFlags::MASKED, true);
            entry.set(RouteFlags::LEVEL, false);
            write_entry(0, pin, entry);
            write_entry(0, pin, old);
        } else if let Some(unit) = apic::ioapic_unit(0) {
            let vector = irqinfo_vector(pin);
            map_field!(unit.eoi.r).write(u32::from(vector));
        }
    }
    apic::eoi();
}

/// Acknowledges the line `pin`; the interrupt entry calls it from assembly.
pub(crate) extern "C" fn ioapic_irq_eoi(pin: c_int) {
    irq_eoi(pin);
}

/// Masks the 8259s and raises every CPU's software level.
pub(crate) fn picdisable() {
    disable_pic();
}

/// Sets the LAPIC timer up and measures its ticks per clock tick, once.
pub(crate) fn calibrate_lapic_timer() {
    calibrate_timer();
}

/// Starts this CPU's LAPIC timer.
pub(crate) fn lapic_enable_timer() {
    enable_timer();
}

/// Programs the I/O APICs from the MADT data.
pub(crate) fn ioapic_configure() {
    configure();
}

/// Report the interrupt on a pin that has no handler.
fn null(unit: c_int) {
    kprint!("intnull({})\n", unit);
}

/// Report the interrupt on a pin that has no handler.
///
/// # Safety
///
/// No precondition: the function only formats its argument, and the C
/// prototype's contract is likewise empty.
pub(crate) unsafe extern "C" fn intnull(unit_dev: c_int) {
    null(unit_dev);
}
