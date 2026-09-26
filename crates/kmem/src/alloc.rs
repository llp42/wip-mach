// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The allocator trait and its error.

use core::alloc::Layout;
use core::fmt;
use core::num::NonZeroUsize;
use core::ptr::{self, NonNull};

/// An allocation failed: memory is short, or the size overflowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllocError;

impl fmt::Display for AllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("memory allocation failed")
    }
}

/// A source of heap memory that fails instead of waiting.
///
/// An implementation must never sleep, so that allocating is legal under
/// a spin lock (ADR 0017), and must not be called from an interrupt
/// handler.
///
/// The owners in this crate never pass a zero size; an implementation may
/// fail one.
///
/// # Safety
///
/// [`alloc`](Self::alloc) returns a block of at least `layout.size()`
/// bytes aligned to `layout.align()`, that no other live block overlaps
/// and that stays valid until it is passed to [`free`](Self::free), even
/// while the allocator value itself is moved between owners.
pub unsafe trait Alloc {
    /// Allocates a block for `layout`.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short.
    fn alloc(&self, layout: Layout) -> Result<NonNull<u8>, AllocError>;

    /// Allocates a block for `layout` with every byte zero.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short.
    fn alloc_zeroed(&self, layout: Layout) -> Result<NonNull<u8>, AllocError> {
        let block = self.alloc(layout)?;
        // SAFETY: `alloc` returned `layout.size()` writable bytes.
        unsafe { ptr::write_bytes(block.as_ptr(), 0, layout.size()) };
        Ok(block)
    }

    /// Returns a block to the allocator.
    ///
    /// # Safety
    ///
    /// `block` must be live from a call of [`alloc`](Self::alloc) or
    /// [`alloc_zeroed`](Self::alloc_zeroed) on this allocator, made with
    /// exactly this `layout`, and must not be used again.
    unsafe fn free(&self, block: NonNull<u8>, layout: Layout);
}

// SAFETY: every call forwards to `A`, which upholds the contract.
unsafe impl<A: Alloc + ?Sized> Alloc for &A {
    fn alloc(&self, layout: Layout) -> Result<NonNull<u8>, AllocError> {
        (**self).alloc(layout)
    }

    fn alloc_zeroed(&self, layout: Layout) -> Result<NonNull<u8>, AllocError> {
        (**self).alloc_zeroed(layout)
    }

    unsafe fn free(&self, block: NonNull<u8>, layout: Layout) {
        unsafe { (**self).free(block, layout) }
    }
}

/// Returns a block for `layout`; a zero size gets an aligned dangling address and
/// no call to `alloc`.
pub(crate) fn allocate<A: Alloc>(
    alloc: &A,
    layout: Layout,
    zeroed: bool,
) -> Result<NonNull<u8>, AllocError> {
    if layout.size() == 0 {
        return Ok(dangling(layout));
    }
    if zeroed {
        alloc.alloc_zeroed(layout)
    } else {
        alloc.alloc(layout)
    }
}

/// Returns a block from [`allocate`]; a zero size was never allocated.
///
/// # Safety
///
/// `block` and `layout` are as [`Alloc::free`] requires, or `layout` has a
/// zero size.
pub(crate) unsafe fn release<A: Alloc>(
    alloc: &A,
    block: NonNull<u8>,
    layout: Layout,
) {
    if layout.size() != 0 {
        // SAFETY: the block is live and `layout` is the one it came from.
        unsafe { alloc.free(block, layout) };
    }
}

/// Returns the layout of `len` values of `elem`, or an error when the size
/// overflows.
pub(crate) fn array_layout(
    elem: Layout,
    len: usize,
) -> Result<Layout, AllocError> {
    elem.size()
        .checked_mul(len)
        .ok_or(AllocError)
        .and_then(|size| {
            Layout::from_size_align(size, elem.align()).or(Err(AllocError))
        })
}

/// Returns a block for `len` values of `elem`.
pub(crate) fn allocate_array<A: Alloc>(
    alloc: &A,
    elem: Layout,
    len: usize,
    zeroed: bool,
) -> Result<NonNull<u8>, AllocError> {
    array_layout(elem, len).and_then(|layout| allocate(alloc, layout, zeroed))
}

/// Moves the first `keep` bytes of a block into a new one and frees the old.
///
/// # Safety
///
/// `old` is a live block of `old_layout` from [`allocate`] with `alloc`, and
/// `keep` is at most the size of both layouts.  On success nothing may use
/// `old` again; on failure it is untouched.
pub(crate) unsafe fn reallocate<A: Alloc>(
    alloc: &A,
    old: NonNull<u8>,
    old_layout: Layout,
    new_layout: Layout,
    keep: usize,
) -> Result<NonNull<u8>, AllocError> {
    allocate(alloc, new_layout, false).inspect(|&block| {
        // SAFETY: the blocks are distinct and both hold `keep` bytes, and
        // the old block is live and from `alloc` with `old_layout`.
        unsafe {
            ptr::copy_nonoverlapping(old.as_ptr(), block.as_ptr(), keep);
            release(alloc, old, old_layout);
        }
    })
}

fn dangling(layout: Layout) -> NonNull<u8> {
    // A power of two is never zero, so the fallback is not taken.
    let align = NonZeroUsize::new(layout.align()).unwrap_or(NonZeroUsize::MIN);
    NonNull::without_provenance(align)
}
