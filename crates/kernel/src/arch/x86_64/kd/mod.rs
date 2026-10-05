// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386at/kd.c and i386/i386at/kd.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright Ing. C. Olivetti & C. S.p.A. 1988, 1989.
//   Copyright 1988, 1989 by Olivetti Advanced Technology Center, Inc.
//   Copyright 1988, 1989 by Intel Corporation.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The keyboard/VGA console driver.

pub mod console;
pub mod display;
pub mod esc;
pub mod keyboard;
pub mod keymap;
pub mod slam;
pub mod tty;

use crate::arch::x86_64::ioapic;
use crate::arch::x86_64::locore;
use crate::arch::x86_64::pio::Port;
use crate::utils::delay::delay;
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_short};
use core::mem::{align_of, offset_of, size_of};

/// The number of scancodes the key map covers.
pub(crate) const NUMKEYS: usize = 89;
/// The bytes one key map cell holds.
pub(crate) const NUMOUTPUT: usize = 3;
/// The bytes of a key map row: five modifier states of `NUMOUTPUT` bytes.
pub(crate) const WIDTH_KMAP: usize = 15;

/// The bytes per displayed character.
pub(crate) const ONE_SPACE: c_short = 2;
/// The bytes per screen line.
pub(crate) const ONE_LINE: c_short = 160;
/// The bytes per screen.
pub(crate) const ONE_PAGE: c_short = 4000;
/// The first byte of the last line.
pub(crate) const BOTTOM_LINE: c_short = 3840;

/// The offset of the start of the line holding `pos`.
pub(crate) const fn beg_of_line(pos: c_short) -> c_short {
    pos - pos % ONE_LINE
}

/// The column of the screen offset `pos`.
pub(crate) const fn current_column(pos: c_short) -> c_short {
    (pos % ONE_LINE) / ONE_SPACE
}

/// The key map column of a modifier state index.
pub(crate) const fn charidx(state_idx: c_int) -> usize {
    state_idx as usize * NUMOUTPUT
}

/// The escape sequence bytes, terminator excluded.
pub(crate) const K_MAXESC: usize = 32;

pub(crate) const K_TMR2: u16 = 0x42;
pub(crate) const K_TMRCTL: u16 = 0x43;
pub(crate) const K_RDWR: u16 = 0x60;
pub(crate) const K_PORTB: u16 = 0x61;
pub(crate) const K_STATUS: u16 = 0x64;
pub(crate) const K_CMD: u16 = 0x64;
/// An auxiliary (mouse) byte waits in the controller output buffer.
pub(crate) const K_AUX_OBUF_FUL: u8 = 0x20;
/// The keyboard-controller reset command.
pub(crate) const KC_CMD_RESET: u8 = 0xfe;
/// The scroll-lock scancode, which toggles the keyboard-as-mouse hack.
pub(crate) const K_SLCKSC: u8 = 0x46;
pub(crate) const K_OBUF_FUL: u8 = 0x01;
pub(crate) const K_IBUF_FUL: u8 = 0x02;
pub(crate) const K_SPKRDATA: u8 = 0x02;
pub(crate) const K_ENABLETMR2: u8 = 0x01;
pub(crate) const K_SELTMR2: u8 = 0x80;
pub(crate) const K_RDLDTWORD: u8 = 0x30;
pub(crate) const K_TSQRWAVE: u8 = 0x06;
pub(crate) const K_TBINARY: u8 = 0x00;
pub(crate) const K_CMD_LEDS: u8 = 0xed;
pub(crate) const KC_CMD_READ: u8 = 0x20;
pub(crate) const KC_CMD_WRITE: u8 = 0x60;
pub(crate) const K_CB_DISBLE: u8 = 0x10;
pub(crate) const K_CB_ENBLIRQ: u8 = 0x01;
pub(crate) const KBD_IRQ: c_int = 1;

pub(crate) const K_ESC: u8 = 0x1b;
pub(crate) const K_LF: u8 = 0x0a;
pub(crate) const K_CR: u8 = 0x0d;
pub(crate) const K_BS: u8 = 0x08;
pub(crate) const K_HT: u8 = 0x09;
pub(crate) const K_BEL: u8 = 0x07;
pub(crate) const K_SPACE: u8 = 0x20;
pub(crate) const K_UP: u8 = 0x80;
pub(crate) const K_EXTEND: u8 = 0xe0;
pub(crate) const K_ACKSC: u8 = 0xfa;
pub(crate) const K_RESEND: u8 = 0xfe;
pub(crate) const K_SCAN: u8 = 0xfe;
pub(crate) const K_DONE: u8 = 0xff;

pub(crate) const K_CTLSC: u8 = 0x1d;
pub(crate) const K_LSHSC: u8 = 0x2a;
pub(crate) const K_RSHSC: u8 = 0x36;
pub(crate) const K_ALTSC: u8 = 0x38;
pub(crate) const K_CLCKSC: u8 = 0x3a;
pub(crate) const K_NLCKSC: u8 = 0x45;
pub(crate) const K_HOMESC: u8 = 0x47;
pub(crate) const K_DELSC: u8 = 0x53;

pub(crate) const KS_NORMAL: c_int = 0x00;
pub(crate) const KS_NLKED: c_int = 0x02;
pub(crate) const KS_CLKED: c_int = 0x04;
pub(crate) const KS_ALTED: c_int = 0x08;
pub(crate) const KS_SHIFTED: c_int = 0x10;
pub(crate) const KS_CTLED: c_int = 0x20;
pub(crate) const NORM_STATE: c_int = 0;
pub(crate) const SHIFT_STATE: c_int = 1;
pub(crate) const CTRL_STATE: c_int = 2;
pub(crate) const ALT_STATE: c_int = 3;
pub(crate) const SHIFT_ALT: c_int = 4;

/// The keyboard modes: events or ASCII.
pub(crate) const KB_EVENT: c_int = 1;
pub(crate) const KB_ASCII: c_int = 2;

pub(crate) const KA_NORMAL: u8 = 0x07;
pub(crate) const KAX_REVERSE: u8 = 0x01;
pub(crate) const KAX_UNDERLINE: u8 = 0x02;
pub(crate) const KAX_BLINK: u8 = 0x04;
pub(crate) const KAX_BOLD: u8 = 0x08;
pub(crate) const KAX_DIM: u8 = 0x10;
pub(crate) const KAX_INVISIBLE: u8 = 0x20;
pub(crate) const KAX_COL_UNDERLINE: u8 = 0x0f;
pub(crate) const KAX_COL_DIM: u8 = 0x08;

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

/// The proper ANSI color order.
pub(crate) const COLOR_TABLE: [u8; 16] =
    [0, 4, 2, 6, 1, 5, 3, 7, 8, 12, 10, 14, 9, 13, 11, 15];

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

/// The key remapping ioctl payload.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub struct KbEntry {
    pub kb_state: u8,
    pub kb_index: u8,
    pub kb_value: [u8; NUMOUTPUT],
}

/// The driver's mutable state: the C file's file-scope globals.
// The `kd_*` names mirror the C file-scope globals, and the booleans are the
// C's `boolean_t` flags.
#[allow(clippy::struct_field_names, clippy::struct_excessive_bools)]
pub(crate) struct State {
    pub(crate) kd_initialized: bool,
    pub(crate) kd_extended: bool,
    pub(crate) sit_for_0: bool,

    pub(crate) kd_attr: u8,
    pub(crate) kd_color: u8,
    pub(crate) kd_attrflags: u8,
    pub(crate) kd_curpos: c_short,
    pub(crate) kd_lines: c_short,
    pub(crate) kd_cols: c_short,
    pub(crate) vid_start: *mut u8,
    pub(crate) kd_index_reg: c_short,
    pub(crate) kd_io_reg: c_short,

    pub(crate) esc_seq: [u8; K_MAXESC + 1],
    pub(crate) esc_spt: usize,

    pub(crate) kd_ack: Ack,
    pub(crate) last_sent: u8,
    pub(crate) kd_nextled: u8,
    pub(crate) kd_kbd_mouse: c_int,
    pub(crate) kd_kbd_magic_scale: c_int,
    pub(crate) kd_kbd_magic_button: c_int,
    pub(crate) magic_state: c_int,

    pub(crate) kd_bellstate: bool,
}

impl State {
    const fn new() -> Self {
        Self {
            kd_initialized: false,
            kd_extended: false,
            sit_for_0: true,
            kd_attr: KA_NORMAL,
            kd_color: KA_NORMAL,
            kd_attrflags: 0,
            kd_curpos: 0,
            kd_lines: 25,
            kd_cols: 80,
            vid_start: EGA_START as *mut u8,
            kd_index_reg: EGA_IDX_REG as c_short,
            kd_io_reg: EGA_IO_REG as c_short,
            esc_seq: [0; K_MAXESC + 1],
            esc_spt: 0,
            kd_ack: Ack::NotWaiting,
            last_sent: 0,
            kd_nextled: 0,
            kd_kbd_mouse: 0,
            kd_kbd_magic_scale: 6,
            kd_kbd_magic_button: 0,
            magic_state: KS_NORMAL,
            kd_bellstate: false,
        }
    }
}

pub(crate) use crate::utils::cell::SyncCell;

/// The driver's one state object: the keyboard, display, parser and console
/// state, the tty, and the few values other modules share.
pub(crate) struct Kd {
    pub(crate) st: State,
    pub(crate) tty: crate::device::chario::Tty,
    pub(crate) kb_mode: c_int,
    pub(crate) state_bits: c_int,
    pub(crate) bitmap_start: usize,
}

impl Kd {
    const fn new() -> Self {
        Self {
            st: State::new(),
            tty: crate::device::chario::Tty::new(),
            kb_mode: KB_ASCII,
            state_bits: KS_NORMAL,
            bitmap_start: C_BITMAP_START,
        }
    }

    /// The ascii/event switch.
    pub(crate) const fn kb_mode(&self) -> c_int {
        self.kb_mode
    }

    /// Set the keyboard mode, as `kbdsetstat()` does.
    pub(crate) const fn set_kb_mode(&mut self, mode: c_int) {
        self.kb_mode = mode;
    }

    /// The keyboard modifier state.
    pub(crate) const fn state_bits(&self) -> c_int {
        self.state_bits
    }

    /// Set the keyboard modifier state.
    pub(crate) const fn set_state_bits(&mut self, value: c_int) {
        self.state_bits = value;
    }
}

static KD: SyncCell<Kd> = SyncCell(UnsafeCell::new(Kd::new()));

/// The one state object.
pub(crate) fn kd() -> &'static mut Kd {
    // SAFETY: the driver runs at SPLKD; nothing else accesses `KD`.
    unsafe { &mut *KD.0.get() }
}

/// The keyboard/display/parser state.
pub(crate) fn state() -> &'static mut State {
    &mut kd().st
}

/// The current keyboard mode.
pub(crate) fn kb_mode() -> c_int {
    kd().kb_mode()
}

/// Set the keyboard mode.
pub(crate) fn set_kb_mode(mode: c_int) {
    kd().set_kb_mode(mode);
}

/// Sets up the display and the keyboard; interrupts are assumed disabled, and
/// the call is idempotent.
pub(crate) fn kdinit() {
    if state().kd_initialized {
        return;
    }
    {
        let s = state();
        s.esc_spt = 0;
        s.kd_attr = KA_NORMAL;
        s.kd_attrflags = 0;
        s.kd_color = KA_NORMAL;
    }
    display::xga_init();

    if Port::new(K_STATUS).read_u8() & K_OBUF_FUL != 0 {
        let _ = Port::new(K_RDWR).read_u8();
    }

    keyboard::sendcmd(KC_CMD_READ);
    let mut k_comm = keyboard::getdata();
    k_comm &= !K_CB_DISBLE;
    k_comm |= K_CB_ENBLIRQ;
    keyboard::sendcmd(KC_CMD_WRITE);
    keyboard::senddata(k_comm);
    ioapic::unmask(KBD_IRQ);
    state().kd_initialized = true;

    kd().set_state_bits(KS_NORMAL);
    keyboard::cn_set_leds(KS_NORMAL as u8);

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

/// Turns the bell off: the timeout callback.
///
/// # Safety
///
/// Called from the timeout table; `_param` is unused.
pub(crate) unsafe fn kd_belloff(_param: *mut core::ffi::c_void) {
    let status = Port::new(K_PORTB).read_u8() & !(K_SPKRDATA | K_ENABLETMR2);
    Port::new(K_PORTB).write_u8(status);
    state().kd_bellstate = false;
}

/// Turns the bell on.
pub(crate) fn kd_bellon() {
    Port::new(K_TMRCTL)
        .write_u8(K_SELTMR2 | K_RDLDTWORD | K_TSQRWAVE | K_TBINARY);
    Port::new(K_TMR2).write_u8((0x05dc & 0xff) as u8);
    Port::new(K_TMR2).write_u8((0x05dc >> 8) as u8);
    let status = Port::new(K_PORTB).read_u8() | K_ENABLETMR2 | K_SPKRDATA;
    Port::new(K_PORTB).write_u8(status);
}
