// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`KRawBuf`], untyped bytes whose size travels beside the pointer.

use crate::alloc::{Alloc, AllocError, allocate, release};
use core::alloc::Layout;
use core::fmt;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ptr::{self, NonNull};
use core::slice;

/// `size` untyped bytes on the heap, freed by that size.
///
/// This is the owner for memory the IPC seam hands over by address and
/// size, where the size lives in a message field and not in a type.
pub struct KRawBuf<A: Alloc> {
    ptr: NonNull<u8>,
    size: usize,
    alloc: A,
}

// SAFETY: a `KRawBuf` owns its bytes and its allocator outright.
unsafe impl<A: Alloc + Send> Send for KRawBuf<A> {}
// SAFETY: shared access to a `KRawBuf` is shared access to its bytes.
unsafe impl<A: Alloc + Sync> Sync for KRawBuf<A> {}

impl<A: Alloc> KRawBuf<A> {
    /// Holds the alignment of every buffer: a word, which is all the kernel's
    /// general allocator promises.
    pub const ALIGN: usize = 8;

    /// Reserves `size` bytes.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short or the size overflows.
    pub fn try_new(size: usize, alloc: A) -> Result<Self, AllocError> {
        let ptr = allocate(&alloc, Self::layout(size)?, false)?;
        Ok(Self { ptr, size, alloc })
    }

    /// Reserves `size` bytes, every one zero.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short or the size overflows.
    pub fn try_new_zeroed(size: usize, alloc: A) -> Result<Self, AllocError> {
        let ptr = allocate(&alloc, Self::layout(size)?, true)?;
        Ok(Self { ptr, size, alloc })
    }

    /// Returns the address of the first byte.
    #[must_use]
    pub const fn as_ptr(&self) -> NonNull<u8> {
        self.ptr
    }

    /// Returns the size in bytes.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns the bytes, for a copy-in to fill.
    pub const fn as_uninit_bytes_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        // SAFETY: `size` writable bytes belong to the block.
        unsafe {
            slice::from_raw_parts_mut(self.ptr.as_ptr().cast(), self.size)
        }
    }

    /// Gives up ownership and returns the address, size and allocator.
    ///
    /// Rebuild with [`Self::from_raw_parts`] to free the block.
    #[must_use = "dropping the parts leaks the buffer"]
    pub fn into_raw_parts(this: Self) -> (NonNull<u8>, usize, A) {
        let this = ManuallyDrop::new(this);
        // SAFETY: `this` is not dropped, so `alloc` moves out once.
        (this.ptr, this.size, unsafe {
            ptr::read(&raw const this.alloc)
        })
    }

    /// Rebuilds a buffer from [`Self::into_raw_parts`], or from an address
    /// and size the seam carried.
    ///
    /// # Safety
    ///
    /// `ptr` and `size` must describe a live block that `alloc` allocated
    /// at [`Self::ALIGN`] alignment for exactly `size` bytes (or `size`
    /// is zero), and nothing may use it afterwards but the returned
    /// buffer.
    #[must_use = "dropping the buffer frees the block"]
    pub const unsafe fn from_raw_parts(
        ptr: NonNull<u8>,
        size: usize,
        alloc: A,
    ) -> Self {
        Self { ptr, size, alloc }
    }

    fn layout(size: usize) -> Result<Layout, AllocError> {
        Layout::from_size_align(size, Self::ALIGN).map_err(|_| AllocError)
    }
}

impl<A: Alloc> fmt::Debug for KRawBuf<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KRawBuf")
            .field("ptr", &self.ptr)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl<A: Alloc> Drop for KRawBuf<A> {
    fn drop(&mut self) {
        // SAFETY: the size passed `layout` at construction, or the
        // caller of `from_raw_parts` promised it does; the block is live
        // and came from `alloc` with this layout.
        unsafe {
            release(
                &self.alloc,
                self.ptr,
                Layout::from_size_align_unchecked(self.size, Self::ALIGN),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Heap;

    #[test]
    fn owns_and_frees_its_bytes() {
        let heap = Heap::new();
        let buf = KRawBuf::try_new(24, &heap).unwrap();
        assert_eq!(buf.size(), 24);
        assert_eq!(buf.as_ptr().addr().get() % KRawBuf::<&Heap>::ALIGN, 0);
        assert_eq!(heap.live(), 1);
        drop(buf);
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn zeroed_reads_as_zero() {
        let heap = Heap::new();
        let mut buf = KRawBuf::try_new_zeroed(8, &heap).unwrap();
        // SAFETY: the bytes are zeroed, so initialised.
        let bytes = unsafe {
            slice::from_raw_parts(
                buf.as_uninit_bytes_mut().as_ptr().cast::<u8>(),
                8,
            )
        };
        assert_eq!(bytes, &[0; 8]);
    }

    #[test]
    fn bytes_are_filled_in_place() {
        let heap = Heap::new();
        let mut buf = KRawBuf::try_new(2, &heap).unwrap();
        for (slot, byte) in buf.as_uninit_bytes_mut().iter_mut().zip([1_u8, 2])
        {
            let _ = slot.write(byte);
        }
        // SAFETY: both bytes were written.
        let bytes = unsafe { slice::from_raw_parts(buf.as_ptr().as_ptr(), 2) };
        assert_eq!(bytes, &[1, 2]);
    }

    #[test]
    fn an_empty_buffer_never_allocates() {
        let heap = Heap::new();
        let buf = KRawBuf::try_new(0, &heap).unwrap();
        assert_eq!(buf.size(), 0);
        drop(buf);
        assert_eq!(heap.calls(), 0);
    }

    #[test]
    fn failures_are_errors() {
        let heap = Heap::failing_from(0);
        assert!(KRawBuf::try_new(8, &heap).is_err());
        assert!(KRawBuf::try_new_zeroed(8, &heap).is_err());
        assert!(KRawBuf::try_new(usize::MAX, &heap).is_err());
        assert!(KRawBuf::try_new_zeroed(usize::MAX, &heap).is_err());
    }

    #[test]
    fn raw_parts_round_trip() {
        let heap = Heap::new();
        let buf = KRawBuf::try_new(16, &heap).unwrap();
        let (ptr, size, alloc) = KRawBuf::into_raw_parts(buf);
        assert_eq!(heap.live(), 1);
        // SAFETY: the parts came from `into_raw_parts`.
        drop(unsafe { KRawBuf::from_raw_parts(ptr, size, alloc) });
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn debug_names_the_size() {
        let heap = Heap::new();
        let buf = KRawBuf::try_new(4, &heap).unwrap();
        assert!(std::format!("{buf:?}").contains("size: 4"));
    }

    #[test]
    fn crosses_threads_when_its_parts_do() {
        fn send<T: Send>(_: &T) {}
        fn sync<T: Sync>(_: &T) {}
        let heap = Heap::new();
        let buf = KRawBuf::try_new(0, &heap).unwrap();
        send(&buf);
        sync(&buf);
    }
}
