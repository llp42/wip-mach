// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The spin lock the segments, the CPU pools and VM's objects, page queues
//! and maps' side fields hold.
//!
//! It neither masks interrupts nor tracks its holder, so a thread may hold
//! two of them at once, as the shadow-chain walks do.

use core::mem;
use lock::SpinMutex;

/// A simple spin lock: a plain [`SpinMutex`], taken and released at
/// separate sites, with no guard.
///
/// The records that hold one keep the C's `simple_lock_data_t`, an
/// `unsigned int`, so the lock keeps its size and alignment.
#[repr(C, align(4))]
pub struct SimpleLock(SpinMutex<()>, [u8; 3]);

const _: () = assert!(size_of::<SimpleLock>() == size_of::<u32>());
const _: () = assert!(align_of::<SimpleLock>() == align_of::<u32>());

impl SimpleLock {
    /// An unlocked lock, the image a C `static` began with.
    #[must_use]
    pub const fn new() -> Self {
        Self(SpinMutex::new(()), [0; 3])
    }

    /// Initializes the lock unheld: the caller's proof that no one holds
    /// it, not an ordering, is what makes the store safe.
    pub fn init(&self) {
        // SAFETY: the caller promises no one holds the lock.
        unsafe { self.0.force_unlock() };
    }

    /// Whether the lock is currently held, as a non-synchronizing query.
    /// The answer may be stale by the time the caller acts on it.
    pub fn is_locked(&self) -> bool {
        self.0.is_locked()
    }

    /// Acquires the lock, spinning while it is held.  The holder releases
    /// it with [`unlock`](Self::unlock), wherever that is.
    pub fn lock(&self) {
        mem::forget(self.0.lock());
    }

    /// Takes the lock when it is free.
    #[must_use]
    pub fn try_lock(&self) -> bool {
        self.0.try_lock().map(mem::forget).is_some()
    }

    /// Releases the lock, publishing everything its holder wrote to the
    /// next successful locker.
    pub fn unlock(&self) {
        // SAFETY: the C-shaped callers release only a lock they hold.
        unsafe { self.0.force_unlock() };
    }
}

impl Default for SimpleLock {
    fn default() -> Self {
        Self::new()
    }
}
