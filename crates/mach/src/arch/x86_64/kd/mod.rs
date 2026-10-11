// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The keyboard/VGA console driver.

pub mod console;
pub mod display;
pub mod keyboard;
pub mod slam;
pub mod tty;

use crate::arch::x86_64::clock_platform::{MachCallout, wheel};
use crate::arch::x86_64::ioapic;
use crate::arch::x86_64::locore;
use crate::arch::x86_64::pio::Port;
use crate::arch::x86_64::pit::PortB;
use crate::arch::x86_64::platform::MachPlatform;
use crate::utils::delay::delay;
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_short};
use core::mem::{align_of, offset_of, size_of};
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use display::Vga;
use lock::IrqSpinLock;
use lock::irq_spin_lock;
use mach_kd::{Keyboard, Terminal};

pub(crate) const K_TMR2: u16 = 0x42;
pub(crate) const K_TMRCTL: u16 = 0x43;
pub(crate) const K_RDWR: u16 = 0x60;
pub(crate) const K_PORTB: u16 = 0x61;
pub(crate) const K_STATUS: u16 = 0x64;
pub(crate) const K_CMD: u16 = 0x64;
/// The keyboard-controller reset command.
pub(crate) const KC_CMD_RESET: u8 = 0xfe;
pub(crate) const K_SELTMR2: u8 = 0x80;
pub(crate) const K_RDLDTWORD: u8 = 0x30;
pub(crate) const K_TSQRWAVE: u8 = 0x06;
pub(crate) const K_TBINARY: u8 = 0x00;
pub(crate) const K_CMD_LEDS: u8 = 0xed;
pub(crate) const KC_CMD_READ: u8 = 0x20;
pub(crate) const KC_CMD_WRITE: u8 = 0x60;
pub(crate) const KBD_IRQ: c_int = 1;

bitflags::bitflags! {
    /// The keyboard controller's status register.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct KbdStatus: u8 {
        /// A byte waits in the output buffer.
        const OBUF_FUL = 0x01;
        /// The input buffer still holds a byte for the controller.
        const IBUF_FUL = 0x02;
        /// The waiting byte is an auxiliary (mouse) byte.
        const AUX_OBUF_FUL = 0x20;
        // The bits the driver does not read.
        const _ = !0;
    }
}

impl KbdStatus {
    /// Reads the status register.
    pub(crate) fn read() -> Self {
        Self::from_bits_retain(Port::new(K_STATUS).read_u8())
    }
}

bitflags::bitflags! {
    /// The keyboard controller's command byte.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct CommandByte: u8 {
        /// Raise the keyboard interrupt.
        const ENABLE_IRQ = 0x01;
        /// Disable the keyboard.
        const DISABLE = 0x10;
        // The bits the driver leaves as it finds them.
        const _ = !0;
    }
}

/// The keyboard's acknowledgement of a command or data byte.
pub(crate) const K_ACKSC: u8 = 0xfa;
/// The keyboard's request to send the last byte again.
pub(crate) const K_RESEND: u8 = 0xfe;

/// The `KDSKBDMODE` mode that queues scan codes on the kbd device.
pub(crate) const KB_EVENT: c_int = 1;

pub(crate) const EGA_START: usize = 0x000b_8000;
pub(crate) const EGA_IDX_REG: u16 = 0x3d4;
pub(crate) const EGA_IO_REG: u16 = 0x3d5;
pub(crate) const C_START: u8 = 0x0a;
pub(crate) const C_STOP: u8 = 0x0b;
pub(crate) const C_LOW: u8 = 0x0f;
pub(crate) const C_HIGH: u8 = 0x0e;
pub(crate) const C_BITMAP_START: usize = 0xa0000;

/// The priority of the internal console.
pub(crate) const CN_INTERNAL: c_short = 2;

/// Why the keyboard controller's acknowledgement is awaited.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ack {
    NotWaiting,
    SetLeds,
    Data,
}

/// A console table entry.
#[repr(C)]
// The field names keep their `cn_` prefix.
#[allow(clippy::struct_field_names)]
#[allow(missing_docs)]
pub struct ConsDev {
    pub(crate) cn_name: *mut core::ffi::c_char,
    /// # Safety
    ///
    /// [`cons::init`](crate::device::cons::init) calls this once per table
    /// entry, during the single-threaded boot before any console user runs,
    /// with the entry's own address; the callee may write the entry's
    /// `cn_pri`, `cn_dev`, and other fields.
    pub(crate) cn_probe: Option<unsafe fn(*mut Self)>,
    /// # Safety
    ///
    /// [`cons::init`](crate::device::cons::init) calls this once, during the
    /// single-threaded boot, for the table entry its matching `cn_probe`
    /// chose.
    pub(crate) cn_init: Option<unsafe fn(*mut Self)>,
    /// # Safety
    ///
    /// Called with the chosen entry's own `cn_dev`; the callee may busy
    /// wait when `wait` is nonzero and must be safe to call at any
    /// interrupt level.
    pub(crate) cn_getc: Option<unsafe fn(u16, c_int) -> c_int>,
    /// # Safety
    ///
    /// Called with the chosen entry's own `cn_dev`; the callee must be
    /// safe to call at any interrupt level, since the console is written
    /// from the panic path and from the pending-buffer flush at boot.
    pub(crate) cn_putc: Option<unsafe fn(u16, c_int)>,
    pub(crate) cn_dev: u16,
    pub(crate) cn_pri: c_short,
}

const _: () = {
    assert!(size_of::<ConsDev>() == 48);
    assert!(align_of::<ConsDev>() == align_of::<*mut core::ffi::c_char>());
    assert!(offset_of!(ConsDev, cn_name) == 0);
    assert!(offset_of!(ConsDev, cn_probe) == 8);
    assert!(offset_of!(ConsDev, cn_init) == 16);
    assert!(offset_of!(ConsDev, cn_getc) == 24);
    assert!(offset_of!(ConsDev, cn_putc) == 32);
    assert!(offset_of!(ConsDev, cn_dev) == 40);
    assert!(offset_of!(ConsDev, cn_pri) == 42);
};

/// The keyboard controller's state, and whether the driver is set up.
pub(crate) struct State {
    pub(crate) kd_initialized: bool,
    pub(crate) kd_ack: Ack,
    pub(crate) last_sent: u8,
    pub(crate) kd_nextled: u8,
}

impl State {
    const fn new() -> Self {
        Self {
            kd_initialized: false,
            kd_ack: Ack::NotWaiting,
            last_sent: 0,
            kd_nextled: 0,
        }
    }
}

pub(crate) use crate::utils::cell::SyncCell;

/// The driver's one state object: the hardware state, the terminal on the
/// display, the keyboard decoder, and the tty.
pub(crate) struct Kd {
    pub(crate) st: State,
    /// The display, under its own lock: the tty output path and the console
    /// print path both write it, and the console path runs from the keyboard
    /// interrupt handler.
    pub(crate) terminal: IrqSpinLock<Terminal<Vga>, MachPlatform>,
    /// Guarded by [`KEYBOARD`].
    pub(crate) keyboard: Keyboard,
    pub(crate) tty: crate::device::Tty,
    pub(crate) bitmap_start: usize,
}

impl Kd {
    const fn new() -> Self {
        Self {
            st: State::new(),
            terminal: irq_spin_lock!("display", Terminal::new(Vga::new(), 0)),
            keyboard: Keyboard::new(),
            tty: crate::device::Tty::new(),
            bitmap_start: C_BITMAP_START,
        }
    }
}

static KD: SyncCell<Kd> = SyncCell(UnsafeCell::new(Kd::new()));

/// Guards the keyboard controller's ports, the key map and the keyboard
/// state: the scan-code decoding, the modifier bits, the keyboard mode and
/// the pending command.  The interrupt handler holds it while it decodes a
/// scan code and hands the result on.
pub(crate) static KEYBOARD: IrqSpinLock<(), MachPlatform> =
    irq_spin_lock!("keyboard", ());

/// The one state object.
pub(crate) fn kd() -> &'static mut Kd {
    // SAFETY: the driver runs at SPLKD; nothing else accesses `KD`.
    unsafe { &mut *KD.0.get() }
}

/// The keyboard/display/parser state.
pub(crate) fn state() -> &'static mut State {
    &mut kd().st
}

/// Sets the `KDSKBDMODE` mode: [`KB_EVENT`] queues scan codes on the kbd
/// device, any other decodes them for the console tty.
pub(crate) fn set_kb_mode(mode: c_int) {
    let _keyboard = KEYBOARD.lock();
    kd().keyboard.set_event_mode(mode == KB_EVENT);
}

/// Sets up the display and the keyboard; the call is idempotent.  The
/// keyboard lock keeps the interrupt handler off the controller while it is
/// programmed.
pub(crate) fn kdinit() {
    {
        let _keyboard = KEYBOARD.lock();
        if state().kd_initialized {
            return;
        }
        let mut vga = Vga::new();
        let cursor = vga.init();
        *kd().terminal.lock() = Terminal::new(vga, cursor);

        if KbdStatus::read().contains(KbdStatus::OBUF_FUL) {
            let _ = Port::new(K_RDWR).read_u8();
        }

        keyboard::sendcmd(KC_CMD_READ);
        let mut k_comm = CommandByte::from_bits_retain(keyboard::getdata());
        k_comm &= !CommandByte::DISABLE;
        k_comm |= CommandByte::ENABLE_IRQ;
        keyboard::sendcmd(KC_CMD_WRITE);
        keyboard::senddata(k_comm.bits());
        ioapic::unmask(KBD_IRQ);
        state().kd_initialized = true;

        kd().keyboard.reset_modifiers();
        keyboard::cn_set_leds(0);
    }

    tty::ttychars_init();
}

/// Resets the display and the keyboard controller, then resets the machine.
///
/// # Safety
///
/// Called on a magic key sequence or a reboot request.
pub(crate) unsafe fn kdreboot() {
    display::reset();
    keyboard::sendcmd(KC_CMD_RESET);
    delay(1_000_000);
    // SAFETY: `kdreboot` exists to reset the machine, and
    // `cpu_shutdown` never returns.
    unsafe { locore::cpu_shutdown() };
}

/// Whether the bell sounds, until its callout turns it off.
static BELL_ON: AtomicBool = AtomicBool::new(false);

/// Sounds the bell for an eighth of a second, unless it already sounds.
pub(crate) fn ring_bell() {
    // A leaked static callout; the action is `kd_belloff`.
    static BELL: MachCallout = MachCallout::new(wheel(), bell_off_action, ());
    if BELL_ON.load(Ordering::Relaxed) {
        return;
    }
    kd_bellon();
    Pin::static_ref(&BELL)
        .start(clock::Ticks::new((mach_sched::sched::CLOCK_HZ / 8) as u64));
    BELL_ON.store(true, Ordering::Relaxed);
}

fn bell_off_action(_callout: Pin<&MachCallout>) {
    kd_belloff();
}

/// Turns the bell off: the timeout callback.
pub(crate) fn kd_belloff() {
    let status = PortB::from_bits_retain(Port::new(K_PORTB).read_u8())
        & !(PortB::SPEAKER | PortB::GATE2);
    Port::new(K_PORTB).write_u8(status.bits());
    BELL_ON.store(false, Ordering::Relaxed);
}

/// Turns the bell on.
pub(crate) fn kd_bellon() {
    Port::new(K_TMRCTL)
        .write_u8(K_SELTMR2 | K_RDLDTWORD | K_TSQRWAVE | K_TBINARY);
    Port::new(K_TMR2).write_u8((0x05dc & 0xff) as u8);
    Port::new(K_TMR2).write_u8((0x05dc >> 8) as u8);
    let status = PortB::from_bits_retain(Port::new(K_PORTB).read_u8())
        | PortB::GATE2
        | PortB::SPEAKER;
    Port::new(K_PORTB).write_u8(status.bits());
}
