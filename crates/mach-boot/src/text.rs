// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! `Text`: a C string the console prints.

use core::ffi::{CStr, c_char};
use core::fmt::{self, Write};

/// A C string formatted as text, each byte run that is not UTF-8 shown as
/// one replacement character.
pub struct Text<'a>(pub(crate) &'a CStr);

impl Text<'_> {
    /// The string at `p`, or the empty string for null.
    ///
    /// # Safety
    ///
    /// `p` must be null or point at a NUL-terminated string that stays
    /// readable for the duration of the formatting.
    pub(crate) const unsafe fn from_ptr(p: *const c_char) -> Self {
        if p.is_null() {
            Self(c"")
        } else {
            Self(unsafe { CStr::from_ptr(p) })
        }
    }
}

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.to_bytes().utf8_chunks() {
            f.write_str(chunk.valid())?;
            if !chunk.invalid().is_empty() {
                f.write_char('\u{fffd}')?;
            }
        }
        Ok(())
    }
}
