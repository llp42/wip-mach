// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The plain spin lock: [`RawSpinMutex`], and [`SpinMutex`] over it.
//!
//! A test-and-set lock whose holder enters no section and is outside the
//! order checker, so it names no [`Platform`](crate::Platform) and fits a
//! `#[repr(C)]` record beside the data it guards.  It leaves interrupts
//! alone, so **no interrupt handler may ever take it**: a handler that
//! interrupted the holder on the same CPU would spin forever.

use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use lock_api::RawMutex as _;

/// The raw plain spin lock: one test-and-set flag, barging.
///
/// A waiter may be beaten to a freed lock by a thread that never waited,
/// so a waiter can starve.  It is the lock for leaf data nothing nests;
/// where a waiter must be served in arrival order, take a
/// [`TicketLock`](crate::TicketLock).
///
/// One byte.  Embeddable in `#[repr(C)]` structures, and unlockable in
/// another function than the one that locked it, but on the same thread.
#[repr(transparent)]
pub struct RawSpinMutex(AtomicBool);

// SAFETY: the flag admits one holder at a time, taking it with acquire and
// releasing it with release.  The guard is not `Send`, so the thread that
// unlocks is the one that locked.
unsafe impl lock_api::RawMutex for RawSpinMutex {
    /// The free flag.
    const INIT: Self = Self(AtomicBool::new(false));

    /// Not `Send`, as the guard of every lock here: a hold is released on
    /// the thread that took it, and one marker keeps the rule uniform.
    type GuardMarker = lock_api::GuardNoSend;

    /// Takes the lock, spinning until it is free; never sleeps.  A waiter
    /// may be barged past.
    fn lock(&self) {
        while !self.try_lock() {
            core::hint::spin_loop();
        }
    }

    /// Takes the lock if it is free, without waiting.  Nothing queues, so
    /// a freed lock may go to any caller.
    fn try_lock(&self) -> bool {
        self.0
            .compare_exchange(
                false,
                true,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    /// Releases the lock, publishing everything its holder wrote to the
    /// next successful locker.
    unsafe fn unlock(&self) {
        self.0.store(false, Ordering::Release);
    }

    /// Overrides the trait's default, which takes and releases the lock
    /// to answer, and would race a holder for a query.
    fn is_locked(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl fmt::Debug for RawSpinMutex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawSpinMutex")
            .field("locked", &self.is_locked())
            .finish_non_exhaustive()
    }
}

/// A plain spin lock over a `T`: waiters spin and may be barged past, and
/// the holder must not sleep until its guard drops.
///
/// Never sleeps and enters no section, so it may be taken anywhere but in
/// an interrupt handler, which must use an [`IrqSpinLock`](crate::IrqSpinLock)
/// instead: an interrupt that spun on its own CPU's holder would never
/// return.  Outside the order checker, so a thread may hold two at once.
pub type SpinMutex<T> = lock_api::Mutex<RawSpinMutex, T>;
