// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel heap, over [`kalloc`]/[`kfree`].
//!
//! The `#[global_allocator]` here backs `alloc`'s `Box`, `Vec` and friends,
//! and [`try_box`] is the fallible `Box::new` the kernel uses wherever
//! running out of memory must not panic.
//!
//! The infallible `alloc` paths (`Box::new`, `Vec::push`) panic on
//! exhaustion, so they belong at boot and in code that cannot fail anyway.
//! Everything else allocates through [`try_box`] or `Vec::try_reserve`.
//!
//! A heap box suits a fixed-size object that Rust code both owns and
//! frees: the free cannot mismatch the size, and early returns drop it.
//! Plain [`kalloc`] stays for runtime-sized buffers and for memory the IPC
//! path frees by address and size; a type with its own slab cache keeps
//! it, as the cache is visible to `host_slab_info`.
//!
//! [`kalloc`] may sleep for a free page, so the heap must not be used at
//! interrupt level, the same rule [`kalloc`] itself has.

use crate::kern::slab::{KMEM_ALIGN_MIN, kalloc, kalloc_ready, kfree};
use alloc::alloc::{GlobalAlloc, Layout, alloc};
use alloc::boxed::Box;
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};
use kmem::{Alloc, AllocError};

/// [`kalloc`]/[`kfree`] as a [`kmem::Alloc`], plus an over-allocation for
/// alignments above [`KMEM_ALIGN_MIN`], which is all a `kalloc` buffer
/// promises (slab coloring offsets objects by that much, so even a 4 KiB
/// buffer is not page-aligned).
///
/// `kmem`'s contract is that an allocation never waits, and `kalloc` does
/// not keep it: it may sleep for a free page (DEBT.md, "The allocator is
/// derived and may sleep").  Until the slab is rewritten, a `Kalloc` caller
/// must be a thread that may sleep, and never interrupt level.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Kalloc;

impl Kalloc {
    /// The `kalloc` size for `layout`: its own size, or, for a strict
    /// alignment, room to round up to it with a word below for the raw
    /// pointer.
    const fn raw_size(layout: Layout) -> Option<usize> {
        if layout.align() <= KMEM_ALIGN_MIN {
            Some(layout.size())
        } else {
            layout.size().checked_add(layout.align())
        }
    }
}

// SAFETY: `alloc` returns a live `kalloc` buffer of at least `layout.size()`
// bytes aligned to `layout.align()`, and `free` hands `kfree` back exactly
// the buffer and size `alloc` got for that layout.
unsafe impl Alloc for Kalloc {
    fn alloc(&self, layout: Layout) -> Result<NonNull<u8>, AllocError> {
        if !kalloc_ready() {
            return Err(AllocError);
        }
        let size = Self::raw_size(layout).ok_or(AllocError)?;
        let raw = kalloc(size).ok_or(AllocError)?;
        let align = layout.align();

        if align <= KMEM_ALIGN_MIN {
            return Ok(raw);
        }

        // `raw` is 8-aligned and `align` a larger power of two, so the
        // offset is in `8..=align`: the word below the result lies inside
        // the buffer, and `size` leaves `layout.size()` bytes above it.
        let offset = align - (raw.as_ptr().addr() & (align - 1));
        let ptr = raw.as_ptr().wrapping_add(offset);
        // SAFETY: the word below `ptr` lies inside the buffer, as above.
        unsafe { ptr.cast::<*mut u8>().sub(1).write(raw.as_ptr()) };
        // SAFETY: `ptr` is `raw` moved up within its buffer.
        Ok(unsafe { NonNull::new_unchecked(ptr) })
    }

    unsafe fn free(&self, block: NonNull<u8>, layout: Layout) {
        // `alloc` computed the same size for this layout, so it exists.
        let Some(size) = Self::raw_size(layout) else {
            return;
        };
        let raw = if layout.align() <= KMEM_ALIGN_MIN {
            block
        } else {
            // SAFETY: `alloc` stored the raw buffer in the word below.
            unsafe {
                NonNull::new_unchecked(
                    block.as_ptr().cast::<*mut u8>().sub(1).read(),
                )
            }
        };

        // SAFETY: `raw` is the live `kalloc` buffer of `size` bytes that
        // `alloc` made for this layout.
        unsafe { kfree(raw, size) };
    }
}

/// The allocator behind `alloc`, over [`Kalloc`].
struct KernelAllocator;

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;

// SAFETY: `Kalloc` upholds the `GlobalAlloc` contract: a null return is a
// failure, and `dealloc` gets the block and layout `alloc` returned.
unsafe impl GlobalAlloc for KernelAllocator {
    /// # Safety
    ///
    /// `layout` must have a non-zero size, the `GlobalAlloc` contract this
    /// allocator relies on to size the `kalloc` request.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Kalloc
            .alloc(layout)
            .map_or(ptr::null_mut(), NonNull::as_ptr)
    }

    /// # Safety
    ///
    /// `ptr` must have come from this allocator's [`alloc`](Self::alloc)
    /// with the exact same `layout`, and must not be used again after this
    /// call.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` is the non-null block `Kalloc::alloc` returned for
        // this layout.
        unsafe { Kalloc.free(NonNull::new_unchecked(ptr), layout) };
    }
}

/// `Box::new(value)`, but on exhaustion hands `value` back instead of
/// panicking.
///
/// # Errors
///
/// `Err(value)` if the heap cannot hold a `T`.
pub(crate) fn try_box<T>(value: T) -> Result<Box<T>, T> {
    match try_box_uninit::<T>() {
        Ok(slot) => Ok(Box::write(slot, value)),
        Err(AllocError) => Err(value),
    }
}

/// `Box::new_uninit()`, but on exhaustion fails instead of panicking; for
/// callers that must allocate before they have the value.
///
/// # Errors
///
/// [`AllocError`] if the heap cannot hold a `T`.
pub(crate) fn try_box_uninit<T>() -> Result<Box<MaybeUninit<T>>, AllocError> {
    let layout = Layout::new::<T>();

    if layout.size() == 0 {
        // A zero-sized box allocates nothing, so it cannot fail.
        return Ok(Box::new_uninit());
    }

    // SAFETY: the layout is not zero-sized.
    let ptr = unsafe { alloc(layout) }.cast::<MaybeUninit<T>>();
    if ptr.is_null() {
        return Err(AllocError);
    }

    // SAFETY: `ptr` is a fresh global-allocator block of `T`'s layout, which
    // is what a `Box<MaybeUninit<T>>` owns.
    Ok(unsafe { Box::from_raw(ptr) })
}
