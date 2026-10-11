// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`KCString`], an owned NUL-terminated byte string.

use crate::alloc::{Alloc, AllocError};
use crate::slice::KBoxSlice;
use core::ffi::CStr;
use core::fmt;
use core::ops::Deref;

/// Why a [`KCString`] could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes hold a NUL, which would end the string early.
    InteriorNul,
    /// Memory is short.
    Alloc(AllocError),
}

impl From<AllocError> for Error {
    fn from(error: AllocError) -> Self {
        Self::Alloc(error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InteriorNul => f.write_str("the bytes hold a NUL"),
            Self::Alloc(error) => error.fmt(f),
        }
    }
}

/// Bytes with no NUL among them, owned on the heap with a NUL after them.
pub struct KCString<A: Alloc> {
    /// The bytes and their NUL, or no block at all for an empty string
    /// built by [`Self::empty`].
    bytes: KBoxSlice<u8, A>,
}

impl<A: Alloc> KCString<A> {
    /// Returns the empty string; it allocates nothing.
    #[must_use]
    pub const fn empty(alloc: A) -> Self {
        Self {
            bytes: KBoxSlice::empty(alloc),
        }
    }

    /// Copies `bytes` onto the heap with a NUL after them.
    ///
    /// # Errors
    ///
    /// [`Error::InteriorNul`] when `bytes` hold a NUL, or [`Error::Alloc`]
    /// when memory is short.
    pub fn try_new(bytes: &[u8], alloc: A) -> Result<Self, Error> {
        if bytes.contains(&0) {
            return Err(Error::InteriorNul);
        }
        let block = KBoxSlice::try_new_zeroed(bytes.len() + 1, alloc)?;
        // SAFETY: zero is a valid `u8`.
        let mut block = unsafe { KBoxSlice::assume_init(block) };
        // The block is one longer than `bytes`, so its zeroed last byte
        // stays as the NUL.
        for (slot, &byte) in block.iter_mut().zip(bytes) {
            *slot = byte;
        }
        Ok(Self { bytes: block })
    }

    /// Copies `string` onto the heap.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short.
    pub fn try_from_c_str(
        string: &CStr,
        alloc: A,
    ) -> Result<Self, AllocError> {
        KBoxSlice::try_from_slice(string.to_bytes_with_nul(), alloc)
            .map(|bytes| Self { bytes })
    }

    /// Returns the string, borrowed.
    #[must_use]
    pub fn as_c_str(&self) -> &CStr {
        if self.bytes.is_empty() {
            return c"";
        }
        // SAFETY: a block holds the bytes and one NUL, at its end.
        unsafe { CStr::from_bytes_with_nul_unchecked(&self.bytes) }
    }
}

impl<A: Alloc> Deref for KCString<A> {
    type Target = CStr;

    fn deref(&self) -> &CStr {
        self.as_c_str()
    }
}

impl<A: Alloc> fmt::Debug for KCString<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_c_str().fmt(f)
    }
}
