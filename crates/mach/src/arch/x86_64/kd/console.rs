// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The kd console entry points the console table calls: probe/init and the
//! polled getc/putc, plus the bell ioctl.

use super::{
    CN_INTERNAL, ConsDev, K_ACKSC, K_RDWR, K_RESEND, KEYBOARD, KbdStatus, kd,
    kd_belloff, kd_bellon, kdinit, keyboard, state,
};
use crate::arch::x86_64::kd_mouse;
use crate::arch::x86_64::pio::Port;
use crate::kern::console::kprint;
use core::ffi::c_int;
use mach_device::r#return::{DeviceError, DeviceSuccess, IoResult};

/// The bell ioctl's on and off values.
const KD_BELLON: c_int = 1;
const KD_BELLOFF: c_int = 0;

/// Claims the console as the internal display and keyboard.
///
/// # Safety
///
/// `cp` is the console table's entry; the hardware is assumed present.
pub(crate) unsafe fn kdcnprobe(cp: *mut ConsDev) {
    let cp = unsafe { &mut *cp };
    cp.cn_dev = 0;
    cp.cn_pri = CN_INTERNAL;
}

/// Initializes the display and keyboard.
///
/// # Safety
///
/// Called once from `cninit()`.
pub(crate) unsafe fn kdcninit(_cp: *mut ConsDev) {
    kdinit();
}

/// Reads a character, spinning for one when `wait` is set, or `-1`.
///
/// # Safety
///
/// The caller must hold the console lock.  The keyboard lock keeps the
/// interrupt handler from taking the character while the controller is
/// polled.
pub(crate) unsafe fn kdcngetc(_dev: u16, wait: c_int) -> c_int {
    let _keyboard = KEYBOARD.lock();
    if wait != 0 {
        loop {
            let c = maygetc();
            if c >= 0 {
                return c;
            }
        }
    }
    maygetc()
}

/// Writes `c` to the screen; a character before `kdinit()` is dropped.
///
/// # Safety
///
/// The caller must hold `spltty`.
pub(crate) unsafe fn kdcnputc(_dev: u16, c: c_int) {
    if !state().kd_initialized {
        return;
    }
    let mut terminal = kd().terminal.lock();
    // Tab is handled by the terminal.
    if c == c_int::from(b'\n') {
        terminal.put(b'\r');
    }
    terminal.write(c as u8);
}

/// Reads a character from the keyboard controller without waiting, or `-1`.
/// The caller holds [`KEYBOARD`].
pub(crate) fn maygetc() -> c_int {
    if !state().kd_initialized {
        return -1;
    }
    kd().keyboard.start_poll();

    loop {
        if !KbdStatus::read().contains(KbdStatus::OBUF_FUL) {
            return -1;
        }

        if KbdStatus::read().contains(KbdStatus::AUX_OBUF_FUL) {
            let sc = Port::new(K_RDWR).read_u8();
            kprint!("M{:x}P", c_int::from(sc));
            continue;
        }
        let scancode = Port::new(K_RDWR).read_u8();
        if scancode == K_RESEND {
            kprint!("cngetc: resend");
            keyboard::resend();
            continue;
        } else if scancode == K_ACKSC {
            kprint!("cngetc: handle_ack");
            keyboard::handle_ack();
            continue;
        }
        let polled = kd().keyboard.poll(scancode);
        for event in polled.mouse.as_slice() {
            kd_mouse::mouse_event(event);
        }
        if let Some(c) = polled.ch {
            return c_int::from(c);
        }
    }
}

/// Turns the bell on or off.
pub(crate) fn set_bell(val: c_int, _flags: c_int) -> IoResult {
    if val == KD_BELLON {
        kd_bellon();
        Ok(DeviceSuccess::Success)
    } else if val == KD_BELLOFF {
        kd_belloff();
        Ok(DeviceSuccess::Success)
    } else {
        Err(DeviceError::InvalidOperation)
    }
}
