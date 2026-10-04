// SPDX-License-Identifier: MIT
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Heap;

    #[test]
    fn holds_the_bytes_and_a_nul() {
        let heap = Heap::new();
        let string = KCString::try_new(b"root", &heap).unwrap();
        assert_eq!(string.as_c_str(), c"root");
        assert_eq!(string.to_bytes_with_nul(), b"root\0");
        assert_eq!(heap.live(), 1);
        drop(string);
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn an_interior_nul_is_refused_before_allocating() {
        let heap = Heap::new();
        let err = KCString::try_new(b"ro\0ot", &heap).unwrap_err();
        assert_eq!(err, Error::InteriorNul);
        assert_eq!(heap.calls(), 0);
    }

    #[test]
    fn a_failed_new_is_an_alloc_error() {
        let heap = Heap::failing_from(0);
        let err = KCString::try_new(b"root", &heap).unwrap_err();
        assert_eq!(err, Error::Alloc(AllocError));
    }

    #[test]
    fn the_empty_string_never_allocates() {
        let heap = Heap::new();
        let string = KCString::empty(&heap);
        assert_eq!(string.as_c_str(), c"");
        assert_eq!(heap.calls(), 0);
    }

    #[test]
    fn empty_bytes_still_hold_a_nul() {
        let heap = Heap::new();
        let string = KCString::try_new(b"", &heap).unwrap();
        assert_eq!(string.to_bytes_with_nul(), b"\0");
        assert_eq!(heap.live(), 1);
    }

    #[test]
    fn copies_a_c_str() {
        let heap = Heap::new();
        let string = KCString::try_from_c_str(c"module", &heap).unwrap();
        assert_eq!(&*string, c"module");
    }

    #[test]
    fn a_failed_copy_is_an_error() {
        let heap = Heap::failing_from(0);
        assert!(KCString::try_from_c_str(c"module", &heap).is_err());
    }

    #[test]
    fn debug_shows_the_string() {
        let heap = Heap::new();
        let string = KCString::try_new(b"a\"b", &heap).unwrap();
        assert_eq!(std::format!("{string:?}"), "\"a\\\"b\"");
    }

    #[test]
    fn errors_display_as_sentences() {
        assert_eq!(
            std::format!("{}", Error::InteriorNul),
            "the bytes hold a NUL"
        );
        assert_eq!(
            std::format!("{}", Error::from(AllocError)),
            "memory allocation failed"
        );
    }
}
