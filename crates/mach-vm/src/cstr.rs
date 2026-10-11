// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! `CStrArg`: a NUL-terminated string as a formatting argument.

use core::ffi::{CStr, c_char};
use core::fmt;

/// A C string as a `{}` argument, printing its bytes as the `%s` did.
#[derive(Clone, Copy)]
pub struct CStrArg<'a>(&'a CStr);

impl CStrArg<'_> {
    /// Wraps a live C string.
    ///
    /// # Safety
    ///
    /// `p` must be null or point at a NUL-terminated string that stays
    /// readable for the duration of the formatting.
    #[must_use]
    pub const unsafe fn from_ptr(p: *const c_char) -> Self {
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
