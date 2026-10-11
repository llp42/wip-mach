// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The keyboard half of the kd driver: the keyboard controller's commands and
//! acknowledgements, the scan-code interrupt, and where its decoded input
//! goes.

use super::{
    Ack, K_ACKSC, K_CMD, K_CMD_LEDS, K_RDWR, K_RESEND, KC_CMD_WRITE, KEYBOARD,
    KbdStatus, kd, kdreboot, state, tty,
};
use crate::arch::x86_64::kd_event::kd_enqsc;
use crate::arch::x86_64::kd_mouse;
use crate::arch::x86_64::model_dep::REBOOTFLAG;
use crate::arch::x86_64::pio::Port;
use crate::kern::console::kprint;
use core::ffi::c_int;
use core::sync::atomic::Ordering;
use mach_kd::Input;

/// Wait for the input buffer and send a byte to the keyboard.  The caller
/// holds [`KEYBOARD`].
pub(crate) fn senddata(ch: u8) {
    while KbdStatus::read().contains(KbdStatus::IBUF_FUL) {}
    Port::new(K_RDWR).write_u8(ch);
    state().last_sent = ch;
}

/// Wait for the input buffer and send a command to the keyboard.  The caller
/// holds [`KEYBOARD`].
pub(crate) fn sendcmd(ch: u8) {
    while KbdStatus::read().contains(KbdStatus::IBUF_FUL) {}
    Port::new(K_CMD).write_u8(ch);
}

/// Wait for a data byte from the keyboard.  The caller holds [`KEYBOARD`].
pub(crate) fn getdata() -> u8 {
    while !KbdStatus::read().contains(KbdStatus::OBUF_FUL) {}
    Port::new(K_RDWR).read_u8()
}

/// Complete a pending keyboard command.
pub(crate) fn handle_ack() {
    match state().kd_ack {
        Ack::SetLeds => {
            set_leds2();
            state().kd_ack = Ack::Data;
        }
        Ack::Data => state().kd_ack = Ack::NotWaiting,
        Ack::NotWaiting => {
            kprint!("unexpected ACK from keyboard\n");
        }
    }
}

/// Resend a missed keyboard command or data byte.
pub(crate) fn resend() {
    if state().kd_ack == Ack::NotWaiting {
        kprint!("unexpected RESEND from keyboard\n");
    } else {
        senddata(state().last_sent);
    }
}

/// Start setting the LEDs; the interrupt handler finishes on the ACK.
pub(crate) fn set_leds1(val: u8) {
    let _keyboard = KEYBOARD.lock();
    if state().kd_ack != Ack::NotWaiting {
        return;
    }
    state().kd_ack = Ack::SetLeds;
    state().kd_nextled = val;
    senddata(K_CMD_LEDS);
}

/// Send the LED byte after the command ack.
pub(crate) fn set_leds2() {
    senddata(state().kd_nextled);
}

/// Sets the LEDs, polling for each ACK.  The caller holds [`KEYBOARD`], which
/// keeps the interrupt handler from taking the ACKs.
pub(crate) fn cn_set_leds(val: u8) {
    senddata(K_CMD_LEDS);
    let _ = getdata(); // assume ACK
    senddata(val);
    let _ = getdata(); // assume ACK
}

/// Reads the keyboard controller and hands on what it read: a mouse byte to
/// the mouse, a scan code to the decoder, and what the decoder made of it to
/// the tty, the kbd device or the mouse device.
fn intr() {
    let _keyboard = KEYBOARD.lock();
    if !state().kd_initialized {
        return;
    }

    let mut safety: c_int = 1000;
    while !KbdStatus::read().contains(KbdStatus::OBUF_FUL) {
        safety -= 1;
        if safety == 0 {
            break;
        }
    }

    if KbdStatus::read().contains(KbdStatus::AUX_OBUF_FUL) {
        let sc = Port::new(K_RDWR).read_u8();
        if kd_mouse::mouse_in_use() != 0 {
            kd_mouse::mouse_handle_byte(sc);
        } else {
            kprint!("M{:x}I", c_int::from(sc));
        }
        return;
    }

    let scancode = Port::new(K_RDWR).read_u8();
    if scancode == K_RESEND {
        resend();
        return;
    } else if scancode == K_ACKSC {
        handle_ack();
        return;
    }
    let reboot_armed = REBOOTFLAG.load(Ordering::Relaxed);
    match kd().keyboard.interrupt(scancode, reboot_armed) {
        Input::Nothing => {}
        Input::Chars(chars) => {
            for &c in chars.as_bytes() {
                tty::line_rint(c);
            }
        }
        Input::Scancode(sc) => kd_enqsc(sc),
        Input::Mouse(events) => {
            for event in events.as_slice() {
                kd_mouse::mouse_event(event);
            }
        }
        // SAFETY: the keyboard asked for a reboot with ctl-alt-del.
        Input::Reboot => unsafe { kdreboot() },
    }
}

/// The keyboard interrupt handler.
///
/// # Safety
///
/// Entered from the interrupt path.
pub(crate) unsafe extern "C" fn kdintr(_vec: c_int) {
    intr();
}

/// Wait for the input buffer and write the controller command register, which
/// `kd_mouse.rs` uses for its PS/2 sequences.  The caller holds [`KEYBOARD`].
pub(crate) fn cmdreg_write(val: c_int) {
    sendcmd(KC_CMD_WRITE);
    senddata(val as u8);
}

/// Drain pending keyboard bytes, printing them; `kd_mouse.rs` closes a PS/2
/// mouse with this.  The caller holds [`KEYBOARD`].
pub(crate) fn mouse_drain() {
    while KbdStatus::read().contains(KbdStatus::IBUF_FUL) {}
    let mut i = KbdStatus::read();
    while i.contains(KbdStatus::OBUF_FUL) {
        let data = Port::new(K_RDWR).read_u8();
        kprint!(
            "kbd: S = {:x} D = {:x}\n",
            c_int::from(i.bits()),
            c_int::from(data)
        );
        i = KbdStatus::read();
    }
}
