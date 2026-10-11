// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The sleeping mutex: [`RawMutex`], and [`Mutex`] over it.
//!
//! One word holds the owner's address, with a contested flag below it.  A
//! contender spins while the owner is on a CPU, then sleeps in the wait
//! table; a contended release hands the lock to its first waiter, so no
//! waiter starves and no running thread can barge in.  It never enters a
//! section, so it must not be locked inside one.

#[cfg(debug_assertions)]
use crate::checker;
use crate::platform::{Platform, ThreadRef};
use crate::wait;
use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicUsize, Ordering};
use lock_api::RawMutex as _;

/// Set when threads may be queued on the lock, so a release hands off.
const CONTESTED: usize = 1;
/// The low bits of the word, below every thread's alignment.
const FLAGS: usize = ThreadRef::ALIGN - 1;
/// How many times a contender spins while the owner is on a CPU before it
/// gives up and sleeps.
const SPIN_LIMIT: u32 = 1 << 10;

/// The raw sleeping mutex: one word holding its owner.
///
/// Embeddable in `#[repr(C)]` structures, and unlockable in another
/// function than the one that locked it, but on the owner's thread.  One
/// word and its name.
///
/// Generic over the [`Platform`] it sleeps and names its owner through.
#[repr(C)]
pub struct RawMutex<P: Platform> {
    /// The owner's address, or 0 when free, with [`CONTESTED`] below it.
    state: AtomicUsize,
    platform: PhantomData<fn() -> P>,
    /// What this lock is, for the order checker.  Debug builds only, so a
    /// release build keeps the lock one word.
    #[cfg(debug_assertions)]
    pub name: &'static str,
}

impl<P: Platform> RawMutex<P> {
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

// SAFETY: the word holds the owner, which a lock swaps in with acquire and
// out with release, and a handoff writes the next owner in with release
// before it wakes it.  The guard is not `Send`, so the thread that unlocks
// is the one the word names.
unsafe impl<P: Platform> lock_api::RawMutex for RawMutex<P> {
    /// The free word: no owner, no contest.
    ///
    const INIT: Self = {
        #[cfg(not(debug_assertions))]
        assert!(
            size_of::<Self>() == size_of::<usize>(),
            "a mutex outgrew its word"
        );
        Self::named("unnamed")
    };

    /// Not `Send`, as the guard of every lock here: a hold is released on
    /// the thread that took it, and one marker keeps the rule uniform.
    type GuardMarker = lock_api::GuardNoSend;

    /// Takes the mutex, sleeping until it is handed over.
    ///
    /// May sleep, so never call it inside a section.
    ///
    /// # Panics
    ///
    /// In debug builds, if the order checker finds the acquisition could
    /// deadlock.
    fn lock(&self) {
        #[cfg(debug_assertions)]
        checker::acquire::<P>(self.addr(), checker::Kind::Mutex, self.name);
        let me = P::current().addr();
        if self
            .state
            .compare_exchange(0, me, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            self.lock_slow(me);
        }
        // A handoff writes its waiter in as the owner before it wakes it,
        // and the platform names a thread the same way every time.
        debug_assert!(
            self.is_owned_by_current(),
            "mutex locked, but its word does not name the running thread \
             as the owner",
        );
    }

    /// Takes the mutex if it is free and no thread waits for it, without
    /// waiting; never sleeps.
    fn try_lock(&self) -> bool {
        let taken = self
            .state
            .compare_exchange(
                0,
                P::current().addr(),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok();
        #[cfg(debug_assertions)]
        if taken {
            checker::try_acquired::<P>(
                self.addr(),
                checker::Kind::Mutex,
                self.name,
            );
        }
        taken
    }

    /// Releases the mutex, handing it to its first waiter, if any; never
    /// sleeps.
    ///
    /// # Panics
    ///
    /// In debug builds, if the running thread does not own the mutex.
    ///
    /// # Safety
    ///
    /// The running thread owns the mutex.
    unsafe fn unlock(&self) {
        debug_assert!(
            self.is_owned_by_current(),
            "mutex unlocked by a thread that does not own it",
        );
        #[cfg(debug_assertions)]
        checker::release::<P>(self.addr(), checker::Kind::Mutex);
        let me = P::current().addr();
        if let Err(state) = self.state.compare_exchange(
            me,
            0,
            Ordering::Release,
            Ordering::Relaxed,
        ) {
            debug_assert!(
                state == me | CONTESTED,
                "mutex word is neither its owner's nor its owner's with \
                 the contested flag",
            );
            self.unlock_slow();
        }
    }

    /// Overrides the trait's default, which takes and releases the lock
    /// to answer: that would wake a waiter and lose the handoff.
    fn is_locked(&self) -> bool {
        self.state.load(Ordering::Relaxed) & !FLAGS != 0
    }
}

impl<P: Platform> RawMutex<P> {
    /// Spins while the owner is on a CPU, then sleeps until it is handed
    /// the lock.
    #[cold]
    fn lock_slow(&self, me: usize) {
        let mut spins = 0;
        loop {
            // Acquire, so that the owner's thread record, which
            // `is_running` reads, is seen as the owner made it before it
            // wrote itself in with release.
            let state = self.state.load(Ordering::Acquire);
            if state == 0
                && self
                    .state
                    .compare_exchange(
                        0,
                        me,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_ok()
            {
                return;
            }
            if state & CONTESTED == 0
                && spins < SPIN_LIMIT
                && ThreadRef::from_addr(state).is_some_and(P::is_running)
            {
                spins += 1;
                core::hint::spin_loop();
                continue;
            }
            // Sleeping owner, spun out, or waiters queued already.  Only a
            // held lock not yet marked is; a race lost here leaves the word
            // as the check below then finds it, and this thread tries
            // again.
            let _ = (state != 0 && state & CONTESTED == 0).then(|| {
                self.state.compare_exchange(
                    state,
                    state | CONTESTED,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
            });
            let handed_over =
                wait::park::<P>(self.addr().addr(), 0, &mut || {
                    let state = self.state.load(Ordering::Acquire);
                    state & CONTESTED != 0 && state & !FLAGS != 0
                });
            if handed_over {
                return;
            }
        }
    }

    /// Hands the contested mutex to its first waiter, or frees it if no
    /// thread got as far as queueing.
    #[cold]
    fn unlock_slow(&self) {
        let _ = wait::unpark_one::<P>(self.addr().addr(), &mut |result| {
            let contested = if result.have_more { CONTESTED } else { 0 };
            let word = result.first.map_or(0, |next| next.addr() | contested);
            // Release, for a later owner that takes the freed word with no
            // handoff to order it after this one.  A swap, so that it is
            // ordered after every marking of the word, not merely
            // concurrent with it.
            let _ = self.state.swap(word, Ordering::Release);
        });
    }

    /// Returns whether the running thread owns the mutex.
    fn is_owned_by_current(&self) -> bool {
        self.state.load(Ordering::Relaxed) & !FLAGS == P::current().addr()
    }

    /// The lock's identity: its wait-table key, and the order checker's
    /// name for it.
    const fn addr(&self) -> *const () {
        core::ptr::from_ref(self).cast()
    }
}

impl<P: Platform> fmt::Debug for RawMutex<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawMutex")
            .field("locked", &self.is_locked())
            .finish_non_exhaustive()
    }
}

/// A sleeping mutex over a `T`: one owner at a time, and contenders
/// sleep.
///
/// A contended unlock hands the mutex to the first waiter.  It never
/// enters a section, so it must not be locked inside one, nor from an
/// interrupt handler.
///
/// Its debug checker's order-graph node is the lock's
/// [`name`](RawMutex::name); locks built by [`new`](lock_api::Mutex::new)
/// are all one node, and [`mutex!`](crate::mutex) names one.
pub type Mutex<T, P> = lock_api::Mutex<RawMutex<P>, T>;

/// Builds an [`Mutex`] whose debug checker's order-graph node is `name`.
///
/// ```text
/// static KEYBOARD: IrqSpinLock<(), MachPlatform> =
///     lock::irq_spin_lock!("keyboard", ());
/// ```
///
/// A lock built with [`new`](lock_api::Mutex::new) is named
/// `"unnamed"`, and every such lock is one node of the graph; give one
/// `""` to keep it out of the graph altogether.
#[macro_export]
macro_rules! mutex {
    ($name:expr, $data:expr $(,)?) => {
        $crate::lock_api::Mutex::from_raw(
            $crate::RawMutex::named($name),
            $data,
        )
    };
}
