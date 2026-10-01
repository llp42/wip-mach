// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The guards of a [`Lock`]: [`Guard`], for an exclusive hold, and
//! [`SharedGuard`], for a shared one.
//!
//! A guard holds its lock's raw lock from before it exists until it
//! drops, and is the only way to the data.  Under loom, it also holds the
//! record of its access to the data, so that loom sees each hold's
//! accesses begin after the last one's ended.  Neither guard is `Send`:
//! the raw lock, the sections it entered and the order checker's record
//! belong to the thread that took it.

use crate::lock::{Lock, RawLock, RawSharedLock};
use core::fmt;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ops::{Deref, DerefMut};

/// Runs a closure when dropped, so that a lock released for a closure is
/// taken back even as a panic unwinds out of it.
struct Retake<F: FnMut()>(F);

impl<F: FnMut()> Drop for Retake<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// Exclusive access to a [`Lock`]'s data; releases the lock when dropped.
///
/// Not `Send`.
#[must_use = "the lock is released as soon as the guard is dropped"]
pub struct Guard<'a, R: RawLock, T> {
    lock: &'a Lock<R, T>,
    /// Loom's record of this guard's access to the data, for as long as
    /// the guard holds the lock.
    #[cfg(loom)]
    access: ManuallyDrop<loom::cell::MutPtr<T>>,
    not_send: PhantomData<*const ()>,
}

// SAFETY: a shared reference to the guard lends only `&T`, which `T: Sync`
// lets other threads read while the lock stays held.
unsafe impl<R: RawLock + Sync, T: Sync> Sync for Guard<'_, R, T> {}

impl<'a, R: RawLock, T> Guard<'a, R, T> {
    /// # Panics
    ///
    /// In debug builds, if the order checker's record says the running
    /// thread does not hold `lock.raw`.
    ///
    /// # Safety
    ///
    /// The running thread holds `lock.raw`, and hands its unlock to the
    /// returned guard.
    #[cfg(not(loom))]
    pub(crate) unsafe fn new(lock: &'a Lock<R, T>) -> Self {
        lock.raw.assert_held();
        Self {
            lock,
            not_send: PhantomData,
        }
    }

    /// # Safety
    ///
    /// The running thread holds `lock.raw`, and hands its unlock to the
    /// returned guard.
    #[cfg(loom)]
    pub(crate) unsafe fn new(lock: &'a Lock<R, T>) -> Self {
        lock.raw.assert_held();
        Self {
            lock,
            access: Self::track(lock),
            not_send: PhantomData,
        }
    }

    /// Starts loom's record of an access to `lock`'s data.
    #[cfg(loom)]
    fn track(lock: &Lock<R, T>) -> ManuallyDrop<loom::cell::MutPtr<T>> {
        ManuallyDrop::new(lock.data.get_mut())
    }

    /// Returns a guard for a lock the running thread took through its raw
    /// lock, which the guard then unlocks when dropped.
    ///
    /// # Panics
    ///
    /// In debug builds, if the order checker's record says the running
    /// thread does not hold the lock.
    ///
    /// # Safety
    ///
    /// The running thread holds the raw lock: it took it with
    /// [`RawLock::lock`] or a successful [`RawLock::try_lock`], and has not
    /// unlocked it since.
    pub unsafe fn adopt(lock: &'a Lock<R, T>) -> Self {
        unsafe { Self::new(lock) }
    }

    /// Releases the lock, runs `f`, and takes the lock back, returning what
    /// `f` returned.
    ///
    /// Other threads may take the lock, and change the data, while `f`
    /// runs; the guard stays borrowed, so `f` cannot reach the data.  If
    /// `f` panics, the lock is taken back as the panic unwinds, before the
    /// guard drops.  Leaves and re-enters the raw lock's section, if it
    /// has one, and may sleep or spin to retake the lock.
    ///
    /// # Panics
    ///
    /// As the raw lock's `lock`, for the retake.  The guard is left
    /// released when that panics.
    pub fn unlocked<U>(&mut self, f: impl FnOnce() -> U) -> U {
        // SAFETY: the guard is borrowed until the retake below, so it is
        // neither used nor dropped while the lock is released.
        unsafe { self.release() };
        let _retake = Retake(|| self.retake());
        f()
    }

    /// Releases the lock, keeping the guard.
    ///
    /// # Panics
    ///
    /// In debug builds, if the order checker's record says the running
    /// thread does not hold the lock.
    ///
    /// # Safety
    ///
    /// The guard holds its lock, and is not used again until
    /// [`Self::retake`], unless it is being dropped.
    pub(crate) unsafe fn release(&mut self) {
        self.lock.raw.assert_held();
        #[cfg(loom)]
        unsafe {
            ManuallyDrop::drop(&mut self.access);
        }
        unsafe { self.lock.raw.unlock() };
    }

    /// Takes the lock back after [`Self::release`].
    #[cfg_attr(
        not(loom),
        allow(
            clippy::needless_pass_by_ref_mut,
            reason = "loom's access record is replaced here, and the borrow \
                      keeps the released guard unused meanwhile"
        )
    )]
    pub(crate) fn retake(&mut self) {
        self.lock.raw.lock();
        #[cfg(loom)]
        {
            self.access = Self::track(self.lock);
        }
    }

    /// Gives up the hold without releasing it, and returns the lock: the
    /// caller then owns the raw lock's hold.
    pub(crate) fn disarm(self) -> &'a Lock<R, T> {
        #[cfg_attr(not(loom), allow(unused_mut))]
        let mut this = ManuallyDrop::new(self);
        #[cfg(loom)]
        {
            // SAFETY: dropped once, here, and unused after, since the
            // guard itself is never dropped; the access ends before the
            // next holder's begins.
            unsafe { ManuallyDrop::drop(&mut this.access) };
        }
        this.lock
    }

    #[cfg(not(loom))]
    fn data(&self) -> *mut T {
        self.lock.data.with_mut(|data| data)
    }

    #[cfg(loom)]
    fn data(&self) -> *mut T {
        self.access.with(|data| data)
    }
}

impl<R: RawLock, T> Deref for Guard<'_, R, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the guard holds the lock, so no other thread reaches the
        // data, and `&self` lends it only shared.
        unsafe { &*self.data() }
    }
}

impl<R: RawLock, T> DerefMut for Guard<'_, R, T> {
    fn deref_mut(&mut self) -> &mut T {
        // `&mut self` is only ever on the thread that took the lock, since
        // the guard is not `Send`; `deref` may be on another, as the guard
        // is `Sync`.
        self.lock.raw.assert_held();
        // SAFETY: the guard holds the lock, so no other thread reaches the
        // data, and `&mut self` lends it only once.
        unsafe { &mut *self.data() }
    }
}

impl<R: RawLock, T> Drop for Guard<'_, R, T> {
    fn drop(&mut self) {
        // SAFETY: the guard holds the lock, on the thread that took it,
        // since the guard is not `Send`, and is used no more after this.
        unsafe { self.release() };
    }
}

impl<R: RawLock, T: fmt::Debug> fmt::Debug for Guard<'_, R, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

/// Shared access to a [`Lock`]'s data; releases the shared hold when
/// dropped.
///
/// Not `Send`.
#[must_use = "the lock is released as soon as the guard is dropped"]
pub struct SharedGuard<'a, R: RawSharedLock, T> {
    lock: &'a Lock<R, T>,
    /// Loom's record of this guard's access to the data, for as long as
    /// the guard holds the lock.
    #[cfg(loom)]
    access: ManuallyDrop<loom::cell::ConstPtr<T>>,
    not_send: PhantomData<*const ()>,
}

// SAFETY: a shared reference to the guard lends only `&T`, which `T: Sync`
// lets other threads read while the lock stays held.
unsafe impl<R: RawSharedLock + Sync, T: Sync> Sync for SharedGuard<'_, R, T> {}

impl<'a, R: RawSharedLock, T> SharedGuard<'a, R, T> {
    /// # Panics
    ///
    /// In debug builds, if the order checker's record says the running
    /// thread does not hold `lock.raw` shared.
    ///
    /// # Safety
    ///
    /// The running thread holds `lock.raw` shared, and hands its unlock to
    /// the returned guard.
    #[cfg(not(loom))]
    pub(crate) unsafe fn new(lock: &'a Lock<R, T>) -> Self {
        lock.raw.assert_held_shared();
        Self {
            lock,
            not_send: PhantomData,
        }
    }

    /// # Safety
    ///
    /// The running thread holds `lock.raw` shared, and hands its unlock to
    /// the returned guard.
    #[cfg(loom)]
    pub(crate) unsafe fn new(lock: &'a Lock<R, T>) -> Self {
        lock.raw.assert_held_shared();
        Self {
            lock,
            access: Self::track(lock),
            not_send: PhantomData,
        }
    }

    /// Starts loom's record of an access to `lock`'s data.
    #[cfg(loom)]
    fn track(lock: &Lock<R, T>) -> ManuallyDrop<loom::cell::ConstPtr<T>> {
        ManuallyDrop::new(lock.data.get())
    }

    /// Releases the shared hold, runs `f`, and takes the lock shared again,
    /// returning what `f` returned.
    ///
    /// As [`Guard::unlocked`]: a writer may take the lock, and change the
    /// data, while `f` runs.
    ///
    /// # Panics
    ///
    /// As the raw lock's `lock_shared`, for the retake.  The guard is left
    /// released when that panics.
    pub fn unlocked<U>(&mut self, f: impl FnOnce() -> U) -> U {
        // SAFETY: the guard is borrowed until the retake below, so it is
        // neither used nor dropped while the lock is released.
        unsafe { self.release() };
        let _retake = Retake(|| self.retake());
        f()
    }

    /// Releases the shared hold, keeping the guard.
    ///
    /// # Panics
    ///
    /// In debug builds, if the order checker's record says the running
    /// thread does not hold the lock shared.
    ///
    /// # Safety
    ///
    /// The guard holds its lock shared, and is not used again until
    /// [`Self::retake`], unless it is being dropped.
    unsafe fn release(&mut self) {
        self.lock.raw.assert_held_shared();
        #[cfg(loom)]
        unsafe {
            ManuallyDrop::drop(&mut self.access);
        }
        unsafe { self.lock.raw.unlock_shared() };
    }

    /// Takes the lock shared again after [`Self::release`].
    #[cfg_attr(
        not(loom),
        allow(
            clippy::needless_pass_by_ref_mut,
            reason = "loom's access record is replaced here, and the borrow \
                      keeps the released guard unused meanwhile"
        )
    )]
    fn retake(&mut self) {
        self.lock.raw.lock_shared();
        #[cfg(loom)]
        {
            self.access = Self::track(self.lock);
        }
    }

    #[cfg(not(loom))]
    fn data(&self) -> *const T {
        self.lock.data.with(|data| data)
    }

    #[cfg(loom)]
    fn data(&self) -> *const T {
        self.access.with(|data| data)
    }
}

impl<'a, R: RawSharedLock, T: Sync> SharedGuard<'a, R, T> {
    /// Returns a guard for a lock the running thread took shared through
    /// its raw lock, which the guard then unlocks when dropped.
    ///
    /// # Panics
    ///
    /// In debug builds, if the order checker's record says the running
    /// thread does not hold the lock shared.
    ///
    /// # Safety
    ///
    /// The running thread holds the raw lock shared: it took it with
    /// [`RawSharedLock::lock_shared`] or a successful
    /// [`RawSharedLock::try_lock_shared`], and has not unlocked it since.
    pub unsafe fn adopt(lock: &'a Lock<R, T>) -> Self {
        unsafe { Self::new(lock) }
    }
}

impl<R: RawSharedLock, T> Deref for SharedGuard<'_, R, T> {
    type Target = T;

    fn deref(&self) -> &T {
        // SAFETY: the guard holds the lock shared, so no thread writes the
        // data.
        unsafe { &*self.data() }
    }
}

impl<R: RawSharedLock, T> Drop for SharedGuard<'_, R, T> {
    fn drop(&mut self) {
        // SAFETY: the guard holds the lock shared, on the thread that took
        // it, since the guard is not `Send`, and is used no more after
        // this.
        unsafe { self.release() };
    }
}

impl<R: RawSharedLock, T: fmt::Debug> fmt::Debug for SharedGuard<'_, R, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
