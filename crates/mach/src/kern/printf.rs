// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The non-variadic leaves of the kernel's formatted I/O: number printing and
//! line input.

use crate::kern::console::kprint;
use core::ffi::c_int;

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

/// Reads a line from the console into `line`, echoing it, with its NUL.
pub(crate) fn read_line(line: &mut [u8]) {
    let mut getc = || {
        // SAFETY: `cons::getc` takes the wait flag, and the console is
        // initialized before the bootstrap can ask for a line.
        unsafe { crate::device::cons::getc(1) }
    };
    let mut putc = |byte: u8| {
        kprint!("{}", char::from(byte));
    };
    get_line(line, &mut getc, &mut putc);
}
