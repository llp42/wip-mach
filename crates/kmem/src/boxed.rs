// SPDX-License-Identifier: GPL-2.0-or-later
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
    /// The block must hold a valid `T`, written through the pointer the
    /// box handed out.
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
