// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! `write_cstr`: formatting into a fixed, NUL-terminated C string.

use core::ffi::c_char;
use core::fmt;

/// Formats `args` into `buf` as a NUL-terminated C string, truncating at
/// `buf.len() - 1` bytes.
pub(crate) fn write_cstr(buf: &mut [c_char], args: fmt::Arguments<'_>) {
    use fmt::Write;

    let mut sink = CStrSink { buf, len: 0 };
    let _ = sink.write_fmt(args);
    if let Some(cell) = sink.buf.get_mut(sink.len) {
        *cell = 0;
    }
}

/// A fixed C-string buffer as a `core::fmt` sink.
struct CStrSink<'a> {
    buf: &'a mut [c_char],
    len: usize,
}

impl fmt::Write for CStrSink<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let max = self.buf.len().saturating_sub(1);
        for &byte in s.as_bytes() {
            if self.len >= max {
                break;
            }
            if let Some(cell) = self.buf.get_mut(self.len) {
                *cell = byte as c_char;
                self.len += 1;
            }
        }
        Ok(())
    }
}
