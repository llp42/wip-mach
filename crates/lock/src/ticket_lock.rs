// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The ticket lock: [`RawTicketLock`], and [`TicketLock`] over it.
//!
//! Waiters take a ticket and are served in the order they arrived, so no
//! waiter starves.  The holder enters no section and is outside the order
//! checker, so it names no [`Platform`](crate::Platform).  It leaves
//! interrupts alone, so **no interrupt handler may ever take it**.

use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};
use lock_api::RawMutex as _;

/// The high half of the ticket word holds the next ticket to hand out and
/// the low half the ticket now served.
const NEXT_SHIFT: u32 = 16;
const ONE_TICKET: u32 = 1 << NEXT_SHIFT;
const SERVING: u32 = ONE_TICKET - 1;

/// Returns whether both halves of the ticket word are equal, so that no
/// ticket is outstanding and none is being served.
const fn is_free(word: u32) -> bool {
    word >> NEXT_SHIFT == word & SERVING
}

/// Hands out the next ticket and spins, only reading, until it is served.
///
/// # Panics
///
/// In debug builds, if 65535 threads hold or wait for the lock already.
fn take(word: &AtomicU32) {
    let taken = word.fetch_add(ONE_TICKET, Ordering::Acquire);
    let ticket = taken >> NEXT_SHIFT;
    let mut serving = taken & SERVING;
    debug_assert!(
        ticket.wrapping_sub(serving) & SERVING != SERVING,
        "a ticket lock is held or waited for by 65535 threads: the next \
         would see it free",
    );
    while serving != ticket {
        core::hint::spin_loop();
        serving = word.load(Ordering::Acquire) & SERVING;
    }
}

/// Takes a ticket if no ticket is outstanding and the one being served
/// has been served.
fn try_take(word: &AtomicU32) -> bool {
    let seen = word.load(Ordering::Relaxed);
    is_free(seen)
        && word
            .compare_exchange(
                seen,
                seen.wrapping_add(ONE_TICKET),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
}

/// Serves the next ticket, releasing the lock.
///
/// # Safety
///
/// The caller holds the lock.
///
/// # Panics
///
/// In debug builds, if the lock is free.
unsafe fn serve_next(word: &AtomicU32) {
    // The holder is the only writer of the now-serving half, so a relaxed
    // read sees the ticket it was served, and advancing the half by hand
    // keeps a wrap from carrying into the next ticket.
    let seen = word.load(Ordering::Relaxed);
    debug_assert!(!is_free(seen), "a ticket lock is unlocked while free");
    let serving = seen & SERVING;
    if serving == SERVING {
        let _ = word.fetch_sub(SERVING, Ordering::Release);
    } else {
        let _ = word.fetch_add(1, Ordering::Release);
    }
}

/// The raw ticket lock: a ticket word whose waiters are served in arrival
/// order.
///
/// One 32-bit word.  Embeddable in `#[repr(C)]` structures, and
/// unlockable in another function than the one that locked it, but on the
/// same thread.
///
/// Each half wraps at 2^16, so at most 65535 threads may hold or wait for
/// the lock at once; a spin-lock waiter keeps its CPU, so the CPU count
/// bounds them.
#[repr(transparent)]
pub struct RawTicketLock(AtomicU32);

// SAFETY: the ticket word admits one holder at a time, taking it with
// acquire and releasing it with release.  The guard is not `Send`, so the
// thread that unlocks is the one that locked.
unsafe impl lock_api::RawMutex for RawTicketLock {
    /// The free word: no ticket taken, none serving.
    const INIT: Self = Self(AtomicU32::new(0));

    /// Not `Send`, as the guard of every lock here: a hold is released on
    /// the thread that took it, and one marker keeps the rule uniform.
    type GuardMarker = lock_api::GuardNoSend;

    /// Takes the lock, spinning until it is free; never sleeps.
    ///
    /// # Panics
    ///
    /// In debug builds, if 65535 threads hold or wait for it already.
    fn lock(&self) {
        take(&self.0);
    }

    /// Takes the lock if it is free, without waiting.  It fails while any
    /// thread holds the lock or waits for it.
    fn try_lock(&self) -> bool {
        try_take(&self.0)
    }

    /// Releases the lock, publishing everything its holder wrote to the
    /// next successful locker.
    ///
    /// # Panics
    ///
    /// In debug builds, if the lock is free.
    unsafe fn unlock(&self) {
        // SAFETY: the caller holds the lock, as the trait requires.
        unsafe { serve_next(&self.0) };
    }

    /// Overrides the trait's default, which takes and releases the lock
    /// to answer: on a ticket that would move the 65535-waiter bound.
    fn is_locked(&self) -> bool {
        !is_free(self.0.load(Ordering::Relaxed))
    }
}

impl fmt::Debug for RawTicketLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawTicketLock")
            .field("locked", &self.is_locked())
            .finish_non_exhaustive()
    }
}

/// A ticket lock over a `T`: waiters spin in arrival order, and the holder
/// must not sleep until its guard drops.
///
/// Never sleeps and enters no section, so it may be taken anywhere but in
/// an interrupt handler, which must use an [`IrqSpinLock`](crate::IrqSpinLock)
/// instead.  Outside the order checker, so a thread may hold two at once.
pub type TicketLock<T> = lock_api::Mutex<RawTicketLock, T>;
