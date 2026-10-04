// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Fallible owning heap types over an allocator trait of their own.
//!
//! The kernel links no `alloc` crate (ADR 0017): heap memory comes from
//! an [`Alloc`] the kernel supplies, and the types here own it.  Every
//! way to obtain memory returns a `Result` and never waits; there is no
//! infallible constructor.  A failed constructor drops the value it was
//! given; a caller that must keep the value reserves first with
//! [`KBox::try_new_uninit`] and writes afterwards, when nothing can fail.
//!
//! | type | owns | freed by |
//! |---|---|---|
//! | [`KBox`] | one `T` | `T`'s layout |
//! | [`KBoxSlice`] | `len` values of `T`, fixed | the array layout |
//! | [`KVec`] | a growable run of `T` | the array layout of its capacity |
//! | [`KRawBuf`] | `size` untyped bytes | its size, at 8-byte alignment |
//! | [`KCString`] | bytes and their NUL | the array layout |
//! | [`RadixTree`] | nodes indexing `NonNull<T>` by 64-bit key | nodes, through `A` |
//!
//! The allocator is a value stored in each owner, so a zero-sized one
//! costs nothing and one that points at a cache can be shared by many.
//! A zero-sized `T` or an empty buffer never reaches the allocator.

#![cfg_attr(not(test), no_std)]

mod alloc;
mod boxed;
mod c_string;
mod radix_tree;
mod raw_buf;
mod slice;
mod vec;

#[cfg(test)]
mod test_support;

pub use alloc::{Alloc, AllocError};
pub use boxed::KBox;
pub use c_string::{Error as KCStringError, KCString};
pub use radix_tree::{
    Error as RadixTreeError, Iter as RadixTreeIter, RadixTree,
    Slot as RadixTreeSlot,
};
pub use raw_buf::KRawBuf;
pub use slice::KBoxSlice;
pub use vec::{Drain, KVec};
