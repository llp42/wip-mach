// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`KBoxSlice`], a fixed-length run of values on the heap.

use crate::alloc::{Alloc, AllocError, allocate_array, release};
use core::alloc::Layout;
use core::fmt;
use core::marker::PhantomData;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};
use core::slice;

/// `len` values of `T` owned on the heap; the length never changes.
pub struct KBoxSlice<T, A: Alloc> {
    ptr: NonNull<T>,
    len: usize,
    alloc: A,
    owns: PhantomData<T>,
}

// SAFETY: a `KBoxSlice` owns its values and its allocator outright.
unsafe impl<T: Send, A: Alloc + Send> Send for KBoxSlice<T, A> {}
// SAFETY: shared access to a `KBoxSlice` is shared access to its values.
unsafe impl<T: Sync, A: Alloc + Sync> Sync for KBoxSlice<T, A> {}

impl<T, A: Alloc> KBoxSlice<T, A> {
    /// Returns an empty slice; it allocates nothing.
    #[must_use]
    pub const fn empty(alloc: A) -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
            alloc,
            owns: PhantomData,
        }
    }

    /// Copies `src` onto the heap.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short or the size overflows.
    pub fn try_from_slice(src: &[T], alloc: A) -> Result<Self, AllocError>
    where
        T: Copy,
    {
        KBoxSlice::<MaybeUninit<T>, A>::try_new_uninit(src.len(), alloc).map(
            |slice| {
                // SAFETY: `MaybeUninit<T>` has `T`'s layout, and the regions
                // are distinct allocations of `src.len()` values.
                unsafe {
                    ptr::copy_nonoverlapping(
                        src.as_ptr(),
                        slice.ptr.as_ptr().cast::<T>(),
                        src.len(),
                    );
                    KBoxSlice::assume_init(slice)
                }
            },
        )
    }

    /// Gives up ownership and returns the address, length and allocator.
    ///
    /// Rebuild with [`Self::from_raw_parts`] to free the block.
    #[must_use = "dropping the parts leaks the slice"]
    pub fn into_raw_parts(this: Self) -> (NonNull<T>, usize, A) {
        let this = ManuallyDrop::new(this);
        // SAFETY: `this` is not dropped, so `alloc` moves out once.
        (this.ptr, this.len, unsafe {
            ptr::read(&raw const this.alloc)
        })
    }

    /// Rebuilds a slice from [`Self::into_raw_parts`].
    ///
    /// # Safety
    ///
    /// `ptr` and `len` must come from `into_raw_parts` of a slice whose
    /// allocator `alloc` is equivalent to, and nothing may use them
    /// afterwards but the returned slice.
    #[must_use = "dropping the slice frees the block"]
    pub const unsafe fn from_raw_parts(
        ptr: NonNull<T>,
        len: usize,
        alloc: A,
    ) -> Self {
        Self {
            ptr,
            len,
            alloc,
            owns: PhantomData,
        }
    }

    /// Returns the layout of the array, which construction already validated.
    const fn layout(&self) -> Layout {
        // SAFETY: `try_new_uninit` built this layout, or `len` is zero.
        unsafe {
            Layout::from_size_align_unchecked(
                size_of::<T>().unchecked_mul(self.len),
                align_of::<T>(),
            )
        }
    }
}

impl<T, A: Alloc> KBoxSlice<MaybeUninit<T>, A> {
    /// Reserves room for `len` values without a value in any of them.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short or the size overflows.
    pub fn try_new_uninit(len: usize, alloc: A) -> Result<Self, AllocError> {
        allocate_array(&alloc, Layout::new::<T>(), len, false).map(|ptr| {
            Self {
                ptr: ptr.cast(),
                len,
                alloc,
                owns: PhantomData,
            }
        })
    }

    /// Reserves room for `len` values with every byte zero.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short or the size overflows.
    pub fn try_new_zeroed(len: usize, alloc: A) -> Result<Self, AllocError> {
        allocate_array(&alloc, Layout::new::<T>(), len, true).map(|ptr| Self {
            ptr: ptr.cast(),
            len,
            alloc,
            owns: PhantomData,
        })
    }

    /// Reads the reserved block as `len` values of `T`.
    ///
    /// # Safety
    ///
    /// Every element must hold a valid `T`.
    #[must_use = "dropping the slice drops the values"]
    pub unsafe fn assume_init(this: Self) -> KBoxSlice<T, A> {
        let (ptr, len, alloc) = Self::into_raw_parts(this);
        KBoxSlice {
            ptr: ptr.cast(),
            len,
            alloc,
            owns: PhantomData,
        }
    }
}

impl<T, A: Alloc> Deref for KBoxSlice<T, A> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        // SAFETY: `len` values of `T` are live at `ptr`.
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl<T, A: Alloc> DerefMut for KBoxSlice<T, A> {
    fn deref_mut(&mut self) -> &mut [T] {
        // SAFETY: as `deref`, and `&mut self` is unique.
        unsafe { slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl<T, A: Alloc> Drop for KBoxSlice<T, A> {
    fn drop(&mut self) {
        // SAFETY: `len` values are live, and the block came from `alloc`
        // with the array layout.
        unsafe {
            ptr::drop_in_place(ptr::slice_from_raw_parts_mut(
                self.ptr.as_ptr(),
                self.len,
            ));
            release(&self.alloc, self.ptr.cast(), self.layout());
        }
    }
}

impl<T: fmt::Debug, A: Alloc> fmt::Debug for KBoxSlice<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Heap, Tracked};
    use core::cell::Cell;

    #[test]
    fn copies_a_slice() {
        let heap = Heap::new();
        let s = KBoxSlice::try_from_slice(&[1_u32, 2, 3], &heap).unwrap();
        assert_eq!(&*s, &[1, 2, 3]);
        assert_eq!(heap.live(), 1);
        drop(s);
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn mutates_in_place() {
        let heap = Heap::new();
        let mut s = KBoxSlice::try_from_slice(&[1_u8, 2], &heap).unwrap();
        s[0] = 9;
        assert_eq!(&*s, &[9, 2]);
    }

    #[test]
    fn a_failed_copy_is_an_error() {
        let heap = Heap::failing_from(0);
        assert!(KBoxSlice::try_from_slice(&[1_u8], &heap).is_err());
    }

    #[test]
    fn empty_allocates_nothing() {
        let heap = Heap::new();
        let s = KBoxSlice::<u64, _>::empty(&heap);
        assert!(s.is_empty());
        drop(s);
        assert_eq!(heap.calls(), 0);
    }

    #[test]
    fn a_zero_length_copy_allocates_nothing() {
        let heap = Heap::new();
        let s = KBoxSlice::<u8, _>::try_from_slice(&[], &heap).unwrap();
        assert!(s.is_empty());
        assert_eq!(heap.calls(), 0);
    }

    #[test]
    fn uninit_is_filled_through_the_slice() {
        let heap = Heap::new();
        let mut s = KBoxSlice::<MaybeUninit<u16>, _>::try_new_uninit(3, &heap)
            .unwrap();
        for (i, slot) in s.iter_mut().enumerate() {
            let _ = slot.write(u16::try_from(i).unwrap());
        }
        // SAFETY: all three were written.
        let s = unsafe { KBoxSlice::assume_init(s) };
        assert_eq!(&*s, &[0, 1, 2]);
    }

    #[test]
    fn zeroed_reads_as_zero() {
        let heap = Heap::new();
        let s =
            KBoxSlice::<MaybeUninit<u8>, _>::try_new_zeroed(5, &heap).unwrap();
        // SAFETY: all-zero is a valid `u8`.
        let s = unsafe { KBoxSlice::assume_init(s) };
        assert_eq!(&*s, &[0; 5]);
    }

    #[test]
    fn a_failed_reservation_is_an_error() {
        let heap = Heap::failing_from(0);
        assert!(
            KBoxSlice::<MaybeUninit<u8>, _>::try_new_zeroed(4, &heap).is_err()
        );
    }

    #[test]
    fn a_size_overflow_is_an_error() {
        let heap = Heap::new();
        assert_eq!(
            KBoxSlice::<MaybeUninit<u64>, _>::try_new_uninit(
                usize::MAX,
                &heap
            )
            .unwrap_err(),
            AllocError,
        );
        assert_eq!(
            KBoxSlice::<MaybeUninit<u64>, _>::try_new_zeroed(
                usize::MAX,
                &heap
            )
            .unwrap_err(),
            AllocError,
        );
        assert_eq!(heap.calls(), 0);
    }

    #[test]
    fn drops_every_element() {
        let heap = Heap::new();
        let drops = Cell::new(0);
        let mut s =
            KBoxSlice::<MaybeUninit<Tracked<'_>>, _>::try_new_uninit(3, &heap)
                .unwrap();
        for slot in s.iter_mut() {
            let _ = slot.write(Tracked::new(&drops));
        }
        // SAFETY: all three were written.
        drop(unsafe { KBoxSlice::assume_init(s) });
        assert_eq!(drops.get(), 3);
    }

    #[test]
    fn raw_parts_round_trip() {
        let heap = Heap::new();
        let s = KBoxSlice::try_from_slice(&[4_u8, 5], &heap).unwrap();
        let (ptr, len, alloc) = KBoxSlice::into_raw_parts(s);
        assert_eq!(heap.live(), 1);
        // SAFETY: the parts came from `into_raw_parts`.
        let s = unsafe { KBoxSlice::from_raw_parts(ptr, len, alloc) };
        assert_eq!(&*s, &[4, 5]);
    }

    #[test]
    fn debug_shows_the_elements() {
        let heap = Heap::new();
        let s = KBoxSlice::try_from_slice(&[1_u8, 2], &heap).unwrap();
        assert_eq!(std::format!("{s:?}"), "[1, 2]");
    }

    #[test]
    fn crosses_threads_when_its_parts_do() {
        fn send<T: Send>(_: &T) {}
        fn sync<T: Sync>(_: &T) {}
        let heap = Heap::new();
        let s = KBoxSlice::<u8, _>::empty(&heap);
        send(&s);
        sync(&s);
    }
}
