// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`KBox`], one owned value on the heap.

use crate::alloc::{Alloc, AllocError, allocate, release};
use core::alloc::Layout;
use core::fmt;
use core::marker::PhantomData;
use core::mem::{ManuallyDrop, MaybeUninit};
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};

/// One `T` owned on the heap, freed through its allocator when dropped.
pub struct KBox<T, A: Alloc> {
    ptr: NonNull<T>,
    alloc: A,
    owns: PhantomData<T>,
}

// SAFETY: a `KBox` owns its `T` and its allocator outright.
unsafe impl<T: Send, A: Alloc + Send> Send for KBox<T, A> {}
// SAFETY: shared access to a `KBox` is shared access to its `T` only.
unsafe impl<T: Sync, A: Alloc + Sync> Sync for KBox<T, A> {}

impl<T, A: Alloc> KBox<T, A> {
    /// Moves `value` onto the heap.
    ///
    /// A failure drops `value`; reserve with [`Self::try_new_uninit`] to
    /// keep it.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short.
    pub fn try_new(value: T, alloc: A) -> Result<Self, AllocError> {
        Self::try_new_uninit(alloc).map(|slot| KBox::write(slot, value))
    }

    /// Reserves room for a `T` without a value to put in it yet.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short.
    pub fn try_new_uninit(
        alloc: A,
    ) -> Result<KBox<MaybeUninit<T>, A>, AllocError> {
        allocate(&alloc, Layout::new::<T>(), false).map(|ptr| KBox {
            ptr: ptr.cast(),
            alloc,
            owns: PhantomData,
        })
    }

    /// Reserves room for a `T` with every byte zero.
    ///
    /// # Errors
    ///
    /// [`AllocError`] when memory is short.
    pub fn try_new_zeroed(
        alloc: A,
    ) -> Result<KBox<MaybeUninit<T>, A>, AllocError> {
        allocate(&alloc, Layout::new::<T>(), true).map(|ptr| KBox {
            ptr: ptr.cast(),
            alloc,
            owns: PhantomData,
        })
    }

    /// Gives up ownership and returns the address of the value.
    ///
    /// The allocator is not dropped, so nothing it holds is released;
    /// rebuild the box with [`Self::from_raw`] to free the block.
    #[must_use = "dropping the pointer leaks the box"]
    pub fn into_raw(this: Self) -> *mut T {
        let this = ManuallyDrop::new(this);
        this.ptr.as_ptr()
    }

    /// Gives up ownership for the rest of the kernel's life.
    #[must_use = "dropping the reference leaks the box"]
    pub fn leak<'a>(this: Self) -> &'a mut T
    where
        A: 'a,
    {
        // SAFETY: `into_raw` yields a valid, unique pointer that nothing
        // frees any more.
        unsafe { &mut *Self::into_raw(this) }
    }

    /// Rebuilds a box from the address [`Self::into_raw`] returned.
    ///
    /// # Safety
    ///
    /// `ptr` must come from `into_raw` of a `KBox<T, A>` whose allocator
    /// `alloc` is equivalent to, and nothing may use it afterwards but the
    /// returned box.
    #[must_use = "dropping the box frees the block"]
    pub const unsafe fn from_raw(ptr: *mut T, alloc: A) -> Self {
        Self {
            // SAFETY: `ptr` came from a live box, so it is not null.
            ptr: unsafe { NonNull::new_unchecked(ptr) },
            alloc,
            owns: PhantomData,
        }
    }
}

impl<T, A: Alloc> KBox<MaybeUninit<T>, A> {
    /// Puts `value` into a reserved box; nothing here can fail.
    #[must_use = "dropping the box drops the value"]
    pub fn write(this: Self, value: T) -> KBox<T, A> {
        let this = ManuallyDrop::new(this);
        // SAFETY: the block is `T`-sized and `T`-aligned, and `this` is not
        // dropped, so `alloc` moves out once.
        unsafe {
            this.ptr.cast::<T>().write(value);
            KBox {
                ptr: this.ptr.cast(),
                alloc: ptr::read(&raw const this.alloc),
                owns: PhantomData,
            }
        }
    }

    /// Reads the reserved block as a `T`.
    ///
    /// # Safety
    ///
    /// The block must hold a valid `T`, written through a pointer or by
    /// [`Self::try_new_zeroed`] when zero is one.
    #[must_use = "dropping the box drops the value"]
    pub unsafe fn assume_init(this: Self) -> KBox<T, A> {
        let this = ManuallyDrop::new(this);
        // SAFETY: `this` is not dropped, so `alloc` moves out once.
        unsafe {
            KBox {
                ptr: this.ptr.cast(),
                alloc: ptr::read(&raw const this.alloc),
                owns: PhantomData,
            }
        }
    }
}

impl<T, A: Alloc> Deref for KBox<T, A> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the block holds a valid `T` for the box's life.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T, A: Alloc> DerefMut for KBox<T, A> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: as `deref`, and `&mut self` is unique.
        unsafe { self.ptr.as_mut() }
    }
}

impl<T, A: Alloc> Drop for KBox<T, A> {
    fn drop(&mut self) {
        // SAFETY: the block holds a valid `T` and came from `alloc` with
        // `T`'s layout.
        unsafe {
            ptr::drop_in_place(self.ptr.as_ptr());
            release(&self.alloc, self.ptr.cast(), Layout::new::<T>());
        }
    }
}

impl<T: fmt::Debug, A: Alloc> fmt::Debug for KBox<T, A> {
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
    fn holds_a_value() {
        let heap = Heap::new();
        let mut b = KBox::try_new(41_u32, &heap).unwrap();
        *b += 1;
        assert_eq!(*b, 42);
        assert_eq!(heap.live(), 1);
        drop(b);
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn a_failed_new_drops_the_value() {
        let heap = Heap::failing_from(0);
        let drops = Cell::new(0);
        let err = KBox::try_new(Tracked::new(&drops), &heap);
        assert_eq!(err.unwrap_err(), AllocError);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn drops_its_value_once() {
        let heap = Heap::new();
        let drops = Cell::new(0);
        drop(KBox::try_new(Tracked::new(&drops), &heap).unwrap());
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn reserving_keeps_the_value_across_failure() {
        let heap = Heap::failing_from(0);
        let drops = Cell::new(0);
        let value = Tracked::new(&drops);
        assert!(KBox::<Tracked<'_>, _>::try_new_uninit(&heap).is_err());
        assert_eq!(drops.get(), 0);
        drop(value);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    fn write_fills_a_reservation() {
        let heap = Heap::new();
        let slot = KBox::<u64, _>::try_new_uninit(&heap).unwrap();
        let b = KBox::write(slot, 7);
        assert_eq!(*b, 7);
    }

    #[test]
    fn zeroed_reads_as_zero() {
        let heap = Heap::new();
        let slot = KBox::<[u8; 16], _>::try_new_zeroed(&heap).unwrap();
        // SAFETY: all-zero is a valid `[u8; 16]`.
        let b = unsafe { KBox::assume_init(slot) };
        assert_eq!(*b, [0; 16]);
    }

    #[test]
    fn a_zeroed_failure_is_an_error() {
        let heap = Heap::failing_from(0);
        assert!(KBox::<[u8; 16], _>::try_new_zeroed(&heap).is_err());
    }

    #[test]
    fn a_zero_sized_value_never_allocates() {
        let heap = Heap::new();
        let b = KBox::try_new((), &heap).unwrap();
        assert_eq!(heap.calls(), 0);
        drop(b);
        assert_eq!(heap.calls(), 0);
    }

    #[test]
    fn raw_parts_round_trip() {
        let heap = Heap::new();
        let raw = KBox::into_raw(KBox::try_new(5_u16, &heap).unwrap());
        assert_eq!(heap.live(), 1);
        // SAFETY: `raw` came from `into_raw` and `&heap` is the allocator.
        let b = unsafe { KBox::from_raw(raw, &heap) };
        assert_eq!(*b, 5);
        drop(b);
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn leak_keeps_the_block() {
        let heap = Heap::new();
        let r = KBox::leak(KBox::try_new(9_u8, &heap).unwrap());
        assert_eq!(*r, 9);
        assert_eq!(heap.live(), 1);
        heap.forget_live();
    }

    #[test]
    fn debug_shows_the_value() {
        let heap = Heap::new();
        let b = KBox::try_new(3_u8, &heap).unwrap();
        assert_eq!(std::format!("{b:?}"), "3");
    }

    #[test]
    fn crosses_threads_when_its_parts_do() {
        fn send<T: Send>(_: &T) {}
        fn sync<T: Sync>(_: &T) {}
        let heap = Heap::new();
        let b = KBox::try_new((), &heap).unwrap();
        send(&b);
        sync(&b);
    }

    #[test]
    fn display_of_the_error_is_a_sentence() {
        assert_eq!(std::format!("{AllocError}"), "memory allocation failed");
    }
}
