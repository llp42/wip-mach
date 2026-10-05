// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The console formatter behind `kprint!` and `kprintln!`.
//!
//! The kernel's formatted output goes through `core::fmt`: a [`Console`]
//! writes the formatted bytes to the console one at a time, and [`CStrArg`]
//! adapts NUL-terminated strings.

use crate::device::cons;
use core::ffi::{CStr, c_char};
use core::fmt;

/// The kernel console as a `core::fmt` sink.
pub(crate) struct Console;

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &byte in s.as_bytes() {
            // SAFETY: `cons::putc` writes one byte to the console; the
            // byte-to-char conversion preserves its bits.
            unsafe { cons::putc(byte as c_char) };
        }
        Ok(())
    }
}

/// Format `args` to the console, dropping the `core::fmt` error the console
/// cannot raise.
pub(crate) fn write_fmt(args: fmt::Arguments<'_>) {
    use fmt::Write;

    let _ = Console.write_fmt(args);
}

/// Write formatted text to the console.
macro_rules! kprint {
    ($($arg:tt)*) => {
        $crate::kern::console::write_fmt(format_args!($($arg)*))
    };
}
pub(crate) use kprint;

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

/// A C string as a `{}` argument, printing its bytes as the `%s` did.
#[derive(Clone, Copy)]
pub(crate) struct CStrArg<'a>(&'a CStr);

impl CStrArg<'_> {
    /// Wraps a live C string.
    ///
    /// # Safety
    ///
    /// `p` must be null or point at a NUL-terminated string that stays
    /// readable for the duration of the formatting.
    pub(crate) const unsafe fn from_ptr(p: *const c_char) -> Self {
        if p.is_null() {
            // The C `%s` printed an empty string for a null pointer.
            Self(c"")
        } else {
            Self(unsafe { CStr::from_ptr(p) })
        }
    }
}

impl<'a> From<&'a CStr> for CStrArg<'a> {
    fn from(s: &'a CStr) -> Self {
        Self(s)
    }
}

impl fmt::Display for CStrArg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write;

        let mut bytes = self.0.to_bytes();
        if let Some(precision) = f.precision() {
            bytes = bytes.get(..precision).unwrap_or(bytes);
        }
        if let Ok(s) = core::str::from_utf8(bytes) {
            f.pad(s)
        } else {
            let mut rest = bytes;
            while !rest.is_empty() {
                match core::str::from_utf8(rest) {
                    Ok(s) => return f.write_str(s),
                    Err(e) => {
                        let valid = e.valid_up_to();
                        let (good, tail) = rest.split_at(valid);
                        // SAFETY: `valid_up_to()` bytes are valid UTF-8.
                        f.write_str(unsafe {
                            core::str::from_utf8_unchecked(good)
                        })?;
                        f.write_char('\u{fffd}')?;
                        let skip = e.error_len().unwrap_or(tail.len());
                        rest = tail.get(skip..).unwrap_or_default();
                    }
                }
            }
            Ok(())
        }
    }
}
