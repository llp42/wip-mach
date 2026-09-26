// SPDX-License-Identifier: CMU-Mach
// Derived from kern/printf.c:
//   Copyright (c) 1993 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The non-variadic leaves of `kern/printf.c`: `printnum` and `safe_gets`.

use crate::kern::console::kprint;
use core::ffi::{c_char, c_int};

/// Assemble one console line into `line`, echoing each accepted byte.
fn get_line(
    line: &mut [u8],
    getc: &mut impl FnMut() -> c_int,
    putc: &mut impl FnMut(u8),
) {
    let strmax = line.len().saturating_sub(1);
    let mut len = 0;
    loop {
        match getc() {
            0x0a | 0x0d => {
                putc(b'\n');
                if let Some(cell) = line.get_mut(len) {
                    *cell = 0;
                }
                return;
            }
            0x08 | 0x23 | 0x7f => {
                if len > 0 {
                    putc(b'\x08');
                    putc(b' ');
                    putc(b'\x08');
                    len -= 1;
                }
            }
            0x40 | 0x15 => {
                len = 0;
                putc(b'\n');
                putc(b'\r');
            }
            c if (0x20..0x7f).contains(&c) => {
                if len < strmax {
                    if let Some(cell) = line.get_mut(len) {
                        // The arm's upper bound is below 0x7f, so the byte is
                        // exact.
                        let byte = c as u8;
                        *cell = byte;
                        len += 1;
                        putc(byte);
                    }
                } else {
                    putc(b'\x07');
                }
            }
            _ => (),
        }
    }
}

/// The `safe_gets()` entry of <kern/printf.h>, which `kern/printf.c` used to
/// define.
///
/// # Safety
///
/// When `maxlen` is positive, `str` must point at `maxlen` writable bytes that
/// nothing else writes for the duration.
pub(crate) unsafe fn safe_gets(str: *mut c_char, maxlen: c_int) {
    let len = usize::try_from(maxlen).unwrap_or(0);
    // SAFETY: for a positive `maxlen` the caller promises `str` is valid for
    // that many writes; for a non-positive one the slice is empty and no byte
    // is touched.
    let line =
        unsafe { core::slice::from_raw_parts_mut(str.cast::<u8>(), len) };
    let mut getc = || {
        // SAFETY: `cngetc()` takes no argument and the console is
        // initialized before `safe_gets()` can be called.
        unsafe { crate::device::cons::getc(1) }
    };
    let mut putc = |byte: u8| {
        kprint!("{}", char::from(byte));
    };
    get_line(line, &mut getc, &mut putc);
}
