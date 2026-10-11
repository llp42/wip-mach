// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! [`Bucket`]: one entry of the table of waiters, a lock and the sorted
//! list of the threads waiting on the keys that hash to it.

use crate::platform::Platform;
use crate::waiter::{Waiter, WaiterQueue};
use core::cell::UnsafeCell;
use core::pin::Pin;
use core::ptr::NonNull;
use lock::RawMutex;

/// An entry in the hash table of waiters.
pub struct Bucket<P: Platform> {
    /// The waiters, which only the holder of `lock` reaches.
    waiters: UnsafeCell<WaiterQueue>,
    /// Every bucket's lock is made here, so every bucket's lock is the
    /// same lock; no path holds two.
    pub lock: RawMutex<P::Lock>,
}

impl<P: Platform> Bucket<P> {
    /// A bucket with no waiter.
    pub const fn new() -> Self {
        Self {
            waiters: UnsafeCell::new(WaiterQueue::new()),
            lock: RawMutex::named("gsync bucket"),
        }
    }

    /// The waiters of `bucket`, pinned for one operation.
    ///
    /// # Safety
    ///
    /// `bucket` must not move while the result lives, and the caller must
    /// hold its lock for as long as it uses the result.
    pub unsafe fn waiters<'a>(
        bucket: *const Self,
    ) -> Pin<&'a mut WaiterQueue> {
        // SAFETY: the bucket does not move, and the lock the caller holds
        // keeps anything else from reaching the list.
        unsafe { Pin::new_unchecked(&mut *(*bucket).waiters.get()) }
    }

    /// Unlinks `waiter` and wakes its thread; clearing `queued` resets the
    /// link.
    ///
    /// # Safety
    ///
    /// `waiter` must be linked into this bucket's list, and the caller must
    /// hold the bucket locked.
    pub unsafe fn wake(&self, waiter: NonNull<Waiter>) {
        unsafe {
            Self::waiters(self).remove_ptr(waiter);
            (*waiter.as_ptr()).queued = false;
            // SAFETY: the waiter's thread was marked waiting before it
            // blocked, and the wakeup takes the thread lock itself.
            P::wake_thread(NonNull::new_unchecked((*waiter.as_ptr()).thread));
        }
    }
}
