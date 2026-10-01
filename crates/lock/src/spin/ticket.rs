// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The ticket lock under every spin lock.
//!
//! One 32-bit word holds two 16-bit counters: the next ticket in the high
//! half and the ticket now served in the low half.  A waiter takes the
//! next ticket and spins, only reading, until its number is served, so
//! waiters are served in the order they took their tickets.  The lock is
//! free while both halves are equal.

#[cfg(not(loom))]
use core::mem::size_of;

use crate::sync::{AtomicU32, Ordering, const_fn, spin_loop};

const NEXT_SHIFT: u32 = 16;
const ONE_TICKET: u32 = 1 << NEXT_SHIFT;
const SERVING: u32 = ONE_TICKET - 1;

#[cfg(not(loom))]
const _: () = assert!(size_of::<Ticket>() == 4);

/// A 4-byte ticket lock that knows nothing of sections or the order
/// checker.
///
/// Each counter wraps at 2^16, so at most 65535 threads may hold or wait
/// for it at once, since one more would make it look free; a spin-lock
/// waiter keeps its CPU, so the CPU count bounds them.
///
/// Only the holder writes the now-serving half, and the next-ticket half
/// only ever grows: adding to it wraps out of the word instead of carrying
/// into the other half.
#[repr(transparent)]
pub(crate) struct Ticket(AtomicU32);

const fn is_free(word: u32) -> bool {
    word >> NEXT_SHIFT == word & SERVING
}

impl Ticket {
    const_fn! {
        pub(crate) const fn new() -> Self {
            Self(AtomicU32::new(0))
        }
    }

    /// Takes the lock, spinning until it is free.
    ///
    /// # Panics
    ///
    /// In debug builds, if 65535 threads hold or wait for it already.
    pub(crate) fn lock(&self) {
        let word = self.0.fetch_add(ONE_TICKET, Ordering::Acquire);
        let ticket = word >> NEXT_SHIFT;
        let mut serving = word & SERVING;
        debug_assert!(
            ticket.wrapping_sub(serving) & SERVING != SERVING,
            "ticket lock held or waited for by 65535 threads: the next \
             would see it free",
        );
        while serving != ticket {
            spin_loop();
            serving = self.0.load(Ordering::Acquire) & SERVING;
        }
    }

    /// Takes the lock if it is free, without waiting.
    pub(crate) fn try_lock(&self) -> bool {
        let word = self.0.load(Ordering::Relaxed);
        is_free(word)
            && self
                .0
                .compare_exchange(
                    word,
                    word.wrapping_add(ONE_TICKET),
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_ok()
    }

    /// Serves the next ticket.
    ///
    /// # Panics
    ///
    /// In debug builds, if the lock is free.
    ///
    /// # Safety
    ///
    /// The caller holds the lock.
    pub(crate) unsafe fn unlock(&self) {
        // The holder is the only writer of the now-serving half, so a
        // relaxed read sees the ticket it was served, and advancing the
        // half by hand keeps a wrap from carrying into the next ticket.
        let word = self.0.load(Ordering::Relaxed);
        debug_assert!(!is_free(word), "ticket lock unlocked while free");
        let serving = word & SERVING;
        if serving == SERVING {
            let _ = self.0.fetch_sub(SERVING, Ordering::Release);
        } else {
            let _ = self.0.fetch_add(1, Ordering::Release);
        }
    }

    /// Returns whether a thread holds the lock; stale as soon as read.
    pub(crate) fn is_locked(&self) -> bool {
        !is_free(self.0.load(Ordering::Relaxed))
    }
}

#[cfg(all(test, not(loom), debug_assertions))]
mod tests {
    use super::{NEXT_SHIFT, SERVING, Ticket};
    use core::sync::atomic::Ordering;

    #[test]
    #[should_panic = "ticket lock unlocked while free"]
    fn unlock_of_a_free_ticket_panics() {
        let ticket = Ticket::new();
        // SAFETY: none; the debug check is expected to catch it.
        unsafe { ticket.unlock() };
    }

    #[test]
    #[should_panic = "held or waited for by 65535 threads"]
    fn ticket_for_the_last_thread_the_word_can_tell_apart_panics() {
        let ticket = Ticket::new();
        // 65535 tickets out, none served: the next would wrap onto the
        // served one, and the lock would look free.
        ticket.0.store(SERVING << NEXT_SHIFT, Ordering::Relaxed);
        ticket.lock();
    }
}
