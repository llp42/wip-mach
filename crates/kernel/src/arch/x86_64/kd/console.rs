// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386at/kd.c and i386/i386at/kd.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright Ing. C. Olivetti & C. S.p.A. 1988, 1989.
//   Copyright 1988, 1989 by Olivetti Advanced Technology Center, Inc.
//   Copyright 1988, 1989 by Intel Corporation.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kd console entry points, which <device/cons.c> calls through `constab`:
//! probe/init and the polled getc/putc, plus the bell ioctl.

use super::keymap::KEY_MAP;
use super::{
    CN_INTERNAL, ConsDev, K_ACKSC, K_AUX_OBUF_FUL, K_CR, K_ESC, K_EXTEND,
    K_LF, K_OBUF_FUL, K_RDWR, K_RESEND, K_SCAN, K_STATUS, K_UP, NUMKEYS, esc,
    kd, kd_belloff, kd_bellon, kdinit, keyboard, state,
};
use crate::arch::x86_64::pio::Port;
use crate::device::r#return::{DeviceError, DeviceSuccess, IoResult};
use crate::kern::console::kprint;
use core::ffi::{c_int, c_uint};

/// `KD_BELLON`/`KD_BELLOFF` of <i386at/kd.h>.
const KD_BELLON: c_int = 1;
const KD_BELLOFF: c_int = 0;

/// `kdcnprobe()` in C.
///
/// # Safety
///
/// `cp` is the console table's entry; the hardware is assumed present.
pub(crate) unsafe fn kdcnprobe(cp: *mut ConsDev) {
    let cp = unsafe { &mut *cp };
    cp.cn_dev = 0;
    cp.cn_pri = CN_INTERNAL;
}

/// `kdcninit()` in C.
///
/// # Safety
///
/// Called once from `cninit()`.
pub(crate) unsafe fn kdcninit(_cp: *mut ConsDev) {
    kdinit();
}

/// `kdcngetc()` in C.
///
/// # Safety
///
/// The caller must hold the console lock and interrupts must be off while the
/// controller is polled.
pub(crate) unsafe fn kdcngetc(_dev: u16, wait: c_int) -> c_int {
    if wait != 0 {
        loop {
            let c = maygetc();
            if c >= 0 {
                return c;
            }
        }
    } else {
        maygetc()
    }
}

/// `kdcnputc()` in C: a character before `kdinit()` is dropped.
///
/// # Safety
///
/// The caller must hold `SPLKD`.
pub(crate) unsafe fn kdcnputc(_dev: u16, c: c_int) {
    if !state().kd_initialized {
        return;
    }
    // Tab is handled in kd_putc.
    if c == c_int::from(b'\n') {
        esc::putc(b'\r');
    }
    esc::putc_esc(c as u8);
}

/// `kdcnmaygetc()` in C.
pub(crate) fn maygetc() -> c_int {
    if !state().kd_initialized {
        return -1;
    }
    state().kd_extended = false;

    loop {
        if Port::new(K_STATUS).read_u8() & K_OBUF_FUL == 0 {
            return -1;
        }

        let mut up = false;
        if Port::new(K_STATUS).read_u8() & K_AUX_OBUF_FUL == K_AUX_OBUF_FUL {
            let sc = Port::new(K_RDWR).read_u8();
            kprint!("M{:x}P", c_int::from(sc));
            continue;
        }
        let mut scancode = Port::new(K_RDWR).read_u8();
        if scancode == K_EXTEND {
            state().kd_extended = true;
            continue;
        } else if scancode == K_RESEND {
            kprint!("cngetc: resend");
            keyboard::resend();
            continue;
        } else if scancode == K_ACKSC {
            kprint!("cngetc: handle_ack");
            keyboard::handle_ack();
            continue;
        }
        if scancode & K_UP != 0 {
            up = true;
            scancode &= !K_UP;
        }
        if state().kd_kbd_mouse != 0 {
            keyboard::kbd_magic(c_int::from(scancode));
        }
        if (scancode as usize) < NUMKEYS {
            let mut char_idx = keyboard::state2idx(
                kd().state_bits() as c_uint,
                state().kd_extended,
            );
            // SAFETY: `scancode` is below `NUMKEYS`, `char_idx` is a
            // `key_map` column, and the table is never written after boot.
            let mut c = unsafe { KEY_MAP[scancode as usize][char_idx] };
            if c == K_SCAN {
                char_idx += 1;
                // SAFETY: `scancode` is below `NUMKEYS`, `char_idx` is a
                // `key_map` column, and the table is never written
                // after boot; `char_idx + 1` is still a valid column.
                c = unsafe { KEY_MAP[scancode as usize][char_idx] };
                let st = keyboard::modifier(kd().state_bits(), c, up);
                kd().set_state_bits(st);
            } else if !up
                && c == K_ESC
                // SAFETY: `scancode` is below `NUMKEYS`, `char_idx` is a
                // `key_map` column, and the table is never written
                // after boot; `char_idx + 1` is a valid column.
                && unsafe { KEY_MAP[scancode as usize][char_idx + 1] } == 0x5b
            {
                // Remap some keys to the readline-like shortcuts the console
                // reader supports.
                // SAFETY: `scancode` is below `NUMKEYS`, `char_idx` is a
                // `key_map` column, and the table is never written
                // after boot; `char_idx + 2` is a valid column.
                c = unsafe { KEY_MAP[scancode as usize][char_idx + 2] };
                return match c {
                    0x48 => 0x01, // home
                    0x41 => 0x10, // up
                    0x44 => 0x02, // left
                    0x43 => 0x06, // right
                    0x42 => 0x0e, // down
                    0x59 => 0x05, // end
                    0x39 => 0x04, // delete
                    _ => c_int::from(K_ESC),
                };
            } else if !up {
                if c == K_CR {
                    c = K_LF;
                }
                return c_int::from(c) & 0o177;
            }
        }
    }
}

/// `kdsetbell()` in C: turn the bell on or off.
pub(crate) fn set_bell(val: c_int, _flags: c_int) -> IoResult {
    if val == KD_BELLON {
        kd_bellon();
        Ok(DeviceSuccess::Success)
    } else if val == KD_BELLOFF {
        // SAFETY: the timeout callback is the driver's.
        unsafe { kd_belloff(core::ptr::null_mut()) };
        Ok(DeviceSuccess::Success)
    } else {
        Err(DeviceError::InvalidOperation)
    }
}
