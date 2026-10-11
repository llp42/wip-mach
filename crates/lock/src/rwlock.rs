// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The sleeping reader-writer lock: [`RawRwLock`], and [`RwLock`] over it.
//!
//! One word holds [`CONTESTED`], [`WRITER`] and either the writer's
//! [`ThreadRef`] or the reader count.  The lock is fair: once a thread
//! queues, every newcomer, reader or writer, queues too, and the queue is
//! served first come, first served, with no preference for either side.
//! A release hands off: if the first waiter is a writer, it alone gets the
//! lock; if a reader, it and every reader ahead of the first waiting
//! writer get it together.  A writer may downgrade to a reader, but a
//! reader never upgrades.

#[cfg(debug_assertions)]
use crate::checker;
use crate::platform::{Platform, ThreadRef};
use crate::wait::{self, Token};
use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicUsize, Ordering, fence};
use lock_api::RawRwLock as _;

/// Set while threads may be queued on the lock, so newcomers queue behind
/// them and the release hands the lock off.  Set only beside a holder,
/// but for the moment between the last reader's leaving and its handoff.
const CONTESTED: usize = 1;
/// Set while a writer holds the lock; the high bits are then its address.
const WRITER: usize = 2;
/// The low bits of the word, below every writer's alignment.
const FLAGS: usize = ThreadRef::ALIGN - 1;
/// The high bits: the writer's address, or the reader count.
const HOLDERS: usize = !FLAGS;
/// One reader in the count.
const ONE_READER: usize = ThreadRef::ALIGN;

/// The token of a parked reader.
const READ: Token = 0;
/// The token of a parked writer.
const WRITE: Token = 1;

/// The raw sleeping reader-writer lock: one word.
///
/// Embeddable in `#[repr(C)]` structures, and unlockable in another
/// function than the one that locked it, but on the same thread.  It
/// never enters a section, so it must not be locked inside one: a waiter
/// may sleep.  One word and its name.
/// Generic over the [`Platform`] it sleeps and names its holder through.
#[repr(C)]
pub struct RawRwLock<P: Platform> {
    state: AtomicUsize,
    platform: PhantomData<fn() -> P>,
    /// What this lock is, for the order checker.  Debug builds only, so a
    /// release build keeps the lock one word.
    #[cfg(debug_assertions)]
    pub name: &'static str,
}

impl<P: Platform> RawRwLock<P> {
    /// Returns a lock named `name`, for the order checker.
    #[must_use]
    pub const fn named(name: &'static str) -> Self {
        // A release build has no field to keep it in.
        #[cfg(not(debug_assertions))]
        let _ = name;
        Self {
            state: AtomicUsize::new(0),
            platform: PhantomData,
            #[cfg(debug_assertions)]
            name,
        }
    }
}

// SAFETY: the word admits many readers or one writer, taking a shared or
// exclusive hold with acquire and releasing it with release, and an
// exclusive hold excludes every reader.  The guard is not `Send`, so the
// thread that unlocks is the one that locked.
unsafe impl<P: Platform> lock_api::RawRwLock for RawRwLock<P> {
    /// The free word.
    ///
    const INIT: Self = {
        #[cfg(not(debug_assertions))]
        assert!(
            size_of::<Self>() == size_of::<usize>(),
            "an rwlock outgrew its word"
        );
        Self::named("unnamed")
    };

    /// Not `Send`, as the guard of every lock here: a hold is released on
    /// the thread that took it, and one marker keeps the rule uniform.
    type GuardMarker = lock_api::GuardNoSend;

    /// Takes the lock shared, sleeping while a writer holds it or any
    /// thread waits for it.
    ///
    /// May sleep, so never call it inside a section.
    ///
    /// # Panics
    ///
    /// In debug builds, if the order checker finds the acquisition could
    /// deadlock.
    fn lock_shared(&self) {
        #[cfg(debug_assertions)]
        checker::acquire::<P>(self.addr(), checker::Kind::Read, self.name);
        if !self.read_fast() {
            self.read_slow();
        }
    }

    /// Takes the lock shared if no writer holds it and no thread waits for
    /// it, without waiting; never sleeps.
    fn try_lock_shared(&self) -> bool {
        let taken = self.read_fast();
        #[cfg(debug_assertions)]
        if taken {
            checker::try_acquired::<P>(
                self.addr(),
                checker::Kind::Read,
                self.name,
            );
        }
        taken
    }

    /// Releases a shared hold; the last reader out hands the lock off.
    /// Never sleeps.
    ///
    /// # Panics
    ///
    /// In debug builds, if the running thread does not hold the lock
    /// shared, or the lock's word counts no reader.
    ///
    /// # Safety
    ///
    /// The running thread holds the lock shared, and has not released or
    /// downgraded it since.
    unsafe fn unlock_shared(&self) {
        #[cfg(debug_assertions)]
        checker::release::<P>(self.addr(), checker::Kind::Read);
        let state = self.state.fetch_sub(ONE_READER, Ordering::Release);
        debug_assert!(
            state & WRITER == 0 && state & HOLDERS != 0,
            "shared unlock of a lock whose word counts no reader",
        );
        if state & HOLDERS == ONE_READER && state & CONTESTED != 0 {
            // Orders every reader's hold before the next holder's, which
            // takes the lock from this thread alone.
            fence(Ordering::Acquire);
            self.hand_off();
        }
    }

    /// Takes the lock exclusive, sleeping until it is handed over.
    ///
    /// May sleep, so never call it inside a section.
    ///
    /// # Panics
    ///
    /// As [`Self::lock_shared`].
    fn lock_exclusive(&self) {
        #[cfg(debug_assertions)]
        checker::acquire::<P>(self.addr(), checker::Kind::Write, self.name);
        if !self.write_fast() {
            self.write_slow();
        }
    }

    /// Takes the lock exclusive if no one holds it and no thread waits for
    /// it, without waiting; never sleeps.
    fn try_lock_exclusive(&self) -> bool {
        let taken = self.write_fast();
        #[cfg(debug_assertions)]
        if taken {
            checker::try_acquired::<P>(
                self.addr(),
                checker::Kind::Write,
                self.name,
            );
        }
        taken
    }

    /// Releases an exclusive hold and hands the lock off; never sleeps.
    ///
    /// # Panics
    ///
    /// In debug builds, if the running thread does not hold the lock
    /// exclusive, or the lock's word does not name it as the writer.
    ///
    /// # Safety
    ///
    /// The running thread holds the lock exclusive, and has not released
    /// or downgraded it since.
    unsafe fn unlock_exclusive(&self) {
        #[cfg(debug_assertions)]
        checker::release::<P>(self.addr(), checker::Kind::Write);
        let writer = P::current().addr() | WRITER;
        if let Err(state) = self.state.compare_exchange(
            writer,
            0,
            Ordering::Release,
            Ordering::Relaxed,
        ) {
            debug_assert!(
                state == writer | CONTESTED,
                "exclusive unlock of a lock whose word does not name the \
                 running thread as its writer",
            );
            self.hand_off();
        }
    }

    /// Overrides the trait's default, which takes and releases the lock
    /// to answer: that would move the queue and the reader count.
    fn is_locked(&self) -> bool {
        self.state.load(Ordering::Relaxed) & HOLDERS != 0
    }

    /// Overrides the trait's default, which tries a *shared* hold to
    /// answer.  The writer bit is set while a writer holds, including the
    /// moment a release hands the lock to a queued writer.
    fn is_locked_exclusive(&self) -> bool {
        self.state.load(Ordering::Relaxed) & WRITER != 0
    }
}

// SAFETY: `downgrade` holds the lock across the transition, so no thread
// sees it free, and the running thread is the writer the word names.
unsafe impl<P: Platform> lock_api::RawRwLockDowngrade for RawRwLock<P> {
    /// Turns an exclusive hold into a shared one, with no instant at which
    /// the lock is free, and grants it too to the queued readers ahead of
    /// the first queued writer; never sleeps.
    ///
    /// # Safety
    ///
    /// As for [`lock_api::RawRwLock::unlock_exclusive`]; the running thread
    /// then holds the lock shared.
    unsafe fn downgrade(&self) {
        #[cfg(debug_assertions)]
        checker::downgrade::<P>(self.addr());
        let writer = P::current().addr() | WRITER;
        if let Err(state) = self.state.compare_exchange(
            writer,
            ONE_READER,
            Ordering::Release,
            Ordering::Relaxed,
        ) {
            debug_assert!(
                state == writer | CONTESTED,
                "downgrade of a lock whose word does not name the running \
                 thread as its writer",
            );
            self.downgrade_slow();
        }
    }
}

impl<P: Platform> RawRwLock<P> {
    /// Takes a shared hold if it needs no waiting, without recording it.
    fn read_fast(&self) -> bool {
        let state = self.state.load(Ordering::Relaxed);
        state & (CONTESTED | WRITER) == 0
            && self
                .state
                .compare_exchange(
                    state,
                    state + ONE_READER,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                )
                .is_ok()
    }

    /// Queues for a shared hold.
    #[cold]
    fn read_slow(&self) {
        while !self.read_fast() && !self.queue(READ) {}
        // A handoff counts the reader in before it wakes it.
        debug_assert!(
            self.is_held_shared(),
            "rwlock handed to a reader its word does not count",
        );
    }

    /// Takes an exclusive hold if the lock is free, without recording it.
    fn write_fast(&self) -> bool {
        self.state
            .compare_exchange(
                0,
                P::current().addr() | WRITER,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    /// Queues for an exclusive hold.
    #[cold]
    fn write_slow(&self) {
        while !self.write_fast() && !self.queue(WRITE) {}
        // A handoff writes the writer in before it wakes it.
        debug_assert!(
            self.is_held_by_current_writer(),
            "rwlock handed to a writer its word does not name",
        );
    }

    /// Parks the running thread as a waiter of `token`.
    ///
    /// Returns false if the lock changed before the thread could queue,
    /// to be tried again.
    fn queue(&self, token: Token) -> bool {
        let state = self.state.load(Ordering::Relaxed);
        // Only a held lock not yet marked is; a race lost here leaves the
        // word as the check below then finds it.
        let _ = (state & HOLDERS != 0 && state & CONTESTED == 0).then(|| {
            self.state.compare_exchange(
                state,
                state | CONTESTED,
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
        });
        wait::park::<P>(self.addr().addr(), token, &mut || {
            // A contested word is released only by a handoff, under
            // this bucket lock, which then finds this thread.
            self.state.load(Ordering::Acquire) & CONTESTED != 0
        })
    }

    /// Grants the downgraded lock to the queued readers it lets in.
    #[cold]
    fn downgrade_slow(&self) {
        let _ = wait::unpark::<P>(
            self.addr().addr(),
            &mut |token| token == READ,
            &mut |result| {
                let contested = if result.have_more { CONTESTED } else { 0 };
                let readers = (1 + result.unparked) * ONE_READER;
                let _ =
                    self.state.swap(readers | contested, Ordering::Release);
            },
        );
    }

    /// Returns whether the word counts a reader and names no writer.
    fn is_held_shared(&self) -> bool {
        let state = self.state.load(Ordering::Relaxed);
        state & WRITER == 0 && state & HOLDERS != 0
    }

    /// Returns whether the word names the running thread as the writer.
    fn is_held_by_current_writer(&self) -> bool {
        self.state.load(Ordering::Relaxed) & !CONTESTED
            == P::current().addr() | WRITER
    }

    /// Hands the released, contested lock to its top waiter: a writer
    /// alone, or a reader with every reader ahead of the first queued
    /// writer.  Frees it if no thread got as far as queueing.
    #[cold]
    fn hand_off(&self) {
        let first = Cell::new(None);
        let _ = wait::unpark::<P>(
            self.addr().addr(),
            &mut |token| {
                let take = first
                    .get()
                    .is_none_or(|first| first == READ && token == READ);
                first.set(first.get().or(Some(token)));
                take
            },
            &mut |result| {
                let writer = first.get() == Some(WRITE);
                let contested = if result.have_more { CONTESTED } else { 0 };
                let word = result.first.map_or(0, |next| {
                    let holders = if writer {
                        next.addr() | WRITER
                    } else {
                        result.unparked * ONE_READER
                    };
                    holders | contested
                });
                // Release, for a later holder that takes the freed word
                // with no handoff to order it after this one.  A swap, so
                // that it is ordered after every marking of the word.
                let _ = self.state.swap(word, Ordering::Release);
            },
        );
    }

    /// The lock's identity: its wait-table key, and the order checker's
    /// name for it.
    const fn addr(&self) -> *const () {
        core::ptr::from_ref(self).cast()
    }
}

impl<P: Platform> fmt::Debug for RawRwLock<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawRwLock")
            .field("locked", &self.is_locked())
            .finish_non_exhaustive()
    }
}

/// A sleeping reader-writer lock over a `T`: many readers or one writer;
/// waiters sleep, and are served first come, first served.
///
/// It never enters a section, so it must not be locked inside one, nor from
/// an interrupt handler.  [`lock_api::RwLock::write`] and
/// [`lock_api::RwLock::try_write`] take it exclusive;
/// [`lock_api::RwLock::read`] and [`lock_api::RwLock::try_read`] take it
/// shared.  A writer's guard may
/// [`downgrade`](lock_api::RwLockWriteGuard::downgrade) to a reader's.
///
/// Its debug checker's order-graph node is the lock's
/// [`name`](RawRwLock::name); locks built with
/// [`new`](lock_api::RwLock::new) are all one node.
pub type RwLock<T, P> = lock_api::RwLock<RawRwLock<P>, T>;
