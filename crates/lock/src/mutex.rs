// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The sleeping mutex: [`Mutex`], and the raw [`RawMutex`] under it.
//!
//! The lock word holds the owner's [`ThreadRef`], with [`CONTESTED`] in
//! its low bits once threads may be queued.  A contender spins while the
//! owner runs, for a bounded time, then parks in the wait table.  A
//! contested unlock hands off: it writes its first waiter in as the new
//! owner before waking it, so no running thread can take the lock in
//! between and the owner in the word is always the true one.
//!
//! Every write of an owner into the word releases, and a parking thread
//! reads it with acquire.

#[cfg(debug_assertions)]
use crate::checker;
use crate::guard::Guard;
use crate::lock::{Lock, RawLock};
use crate::platform::{Platform, ThreadRef};
use crate::sync::{AtomicUsize, Ordering, const_fn, spin_loop};
use crate::wait;
use core::fmt;
use core::marker::PhantomData;
#[cfg(debug_assertions)]
use core::panic::Location;

/// Set, beside an owner, while threads may be queued on the lock: the
/// unlock must hand it off.  The owner changes only under the lock's
/// bucket lock while it is set, and the word never holds it alone.
const CONTESTED: usize = 1;
/// The low bits of the word, below every owner's alignment.
const FLAGS: usize = ThreadRef::ALIGN - 1;
/// How many times a contender polls a running owner before it parks;
/// `is_running` is only a hint, and an owner may run for long.
const SPIN_LIMIT: u32 = 1 << 10;

/// The raw sleeping mutex: one word holding its owner.
///
/// Embeddable in `#[repr(C)]` structures, and unlockable in another
/// function than the one that locked it, but on the owner's thread.  It
/// never enters a section, so it must not be locked inside one: a
/// contender may sleep.  One word in release builds; debug builds add the
/// lock class.
#[repr(C)]
pub struct RawMutex<P: Platform> {
    /// The owner's address, or 0 when free, with [`CONTESTED`] below it.
    state: AtomicUsize,
    #[cfg(debug_assertions)]
    class: checker::Class,
    platform: PhantomData<fn() -> P>,
}

impl<P: Platform> RawMutex<P> {
    /// Fails the build, once [`Self::new`] instantiates it, if a release
    /// lock outgrows its word; the type is generic, so a free `const _`
    /// cannot name it.
    #[cfg(not(any(debug_assertions, loom)))]
    const ONE_WORD: () = assert!(size_of::<Self>() == size_of::<usize>());

    const_fn! {
        /// Returns an unlocked mutex of the caller's lock class.
        #[must_use]
        #[track_caller]
        pub const fn new() -> Self {
            #[cfg(not(any(debug_assertions, loom)))]
            let () = Self::ONE_WORD;
            Self {
                state: AtomicUsize::new(0),
                #[cfg(debug_assertions)]
                class: Location::caller(),
                platform: PhantomData,
            }
        }
    }

    /// Takes the mutex, sleeping until it is handed over.
    ///
    /// May sleep, so never call it inside a section.
    ///
    /// # Panics
    ///
    /// In debug builds, if the order checker finds the acquisition could
    /// deadlock: it closes a lock-order cycle, the running thread already
    /// holds the lock or a lock of the same class, or it is in a section
    /// or holds a spinning lock.
    pub fn lock(&self) {
        #[cfg(debug_assertions)]
        checker::acquire::<P>(self.addr(), self.class, checker::Kind::Mutex);
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
                spin_loop();
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
            let handed_over = wait::park::<P>(
                self.addr().addr(),
                0,
                &mut || {
                    let state = self.state.load(Ordering::Acquire);
                    state & CONTESTED != 0 && state & !FLAGS != 0
                },
                &mut || {},
            );
            if handed_over {
                return;
            }
        }
    }

    /// Takes the mutex if it is free and no thread waits for it, without
    /// waiting; never sleeps.
    ///
    /// # Panics
    ///
    /// In debug builds, if the running thread already holds a lock of the
    /// same class.
    #[must_use = "the mutex is held only if this returns true"]
    pub fn try_lock(&self) -> bool {
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
                self.class,
                checker::Kind::Mutex,
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
    /// The running thread owns the mutex: it took it with [`Self::lock`]
    /// or a successful [`Self::try_lock`] and has not unlocked it since.
    pub unsafe fn unlock(&self) {
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

    /// Returns whether some thread owns the mutex; stale as soon as read.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.state.load(Ordering::Relaxed) & !FLAGS != 0
    }

    /// Returns whether the running thread owns the mutex.
    #[must_use]
    pub fn is_owned_by_current(&self) -> bool {
        self.state.load(Ordering::Relaxed) & !FLAGS == P::current().addr()
    }

    /// The lock's identity: its wait-table key, and the order checker's
    /// name for it.
    const fn addr(&self) -> *const () {
        core::ptr::from_ref(self).cast()
    }
}

impl<P: Platform> Default for RawMutex<P> {
    #[track_caller]
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Platform> fmt::Debug for RawMutex<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawMutex")
            .field("locked", &self.is_locked())
            .finish_non_exhaustive()
    }
}

// SAFETY: the word holds the owner, which a lock swaps in with acquire and
// out with release, and a handoff writes the next owner in with release
// before it wakes it.
unsafe impl<P: Platform> RawLock for RawMutex<P> {
    fn lock(&self) {
        Self::lock(self);
    }

    fn try_lock(&self) -> bool {
        Self::try_lock(self)
    }

    unsafe fn unlock(&self) {
        unsafe { Self::unlock(self) };
    }

    fn assert_held(&self) {
        #[cfg(debug_assertions)]
        checker::assert_held::<P>(self.addr(), checker::Kind::Mutex);
    }
}

/// A sleeping mutex over a `T`: one owner at a time, and contenders
/// sleep.
///
/// A contended unlock hands the mutex to the first waiter.  It never
/// enters a section, so it must not be locked inside one, nor from an
/// interrupt handler.
pub type Mutex<T, P> = Lock<RawMutex<P>, T>;

/// Access to a [`Mutex`]'s data; unlocks when dropped.
pub type MutexGuard<'a, T, P> = Guard<'a, RawMutex<P>, T>;

#[cfg(all(test, not(loom)))]
mod tests {
    use super::{Mutex, RawMutex};
    use crate::platform::Platform;
    use crate::test_support::{Host, spawn_parked};
    use std::cell::Cell;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn unlock_hands_off_before_the_waiter_runs() {
        let lock = Mutex::<u32, Host>::new(0);
        let owned = Barrier::new(2);
        thread::scope(|scope| {
            let guard = lock.lock();
            let (_, waiter) = spawn_parked(scope, || {
                let mut count = lock.lock();
                *count += 1;
                // Holds on until the test thread has tried to barge in.
                let _ = owned.wait();
            });
            drop(guard);
            assert!(lock.try_lock().is_none());
            let _ = owned.wait();
            waiter.join().unwrap();
        });
        assert_eq!(lock.into_inner(), 1);
    }

    #[test]
    fn waiters_run_in_arrival_order() {
        let lock = Mutex::<Vec<usize>, Host>::default();
        thread::scope(|scope| {
            let guard = lock.lock();
            let waiters: Vec<_> = (1..=3)
                .map(|id| {
                    let lock = &lock;
                    spawn_parked(scope, move || lock.lock().push(id)).1
                })
                .collect();
            drop(guard);
            // Queues behind every waiter left: no barging past them.
            lock.lock().push(4);
            for waiter in waiters {
                waiter.join().unwrap();
            }
        });
        assert_eq!(lock.into_inner(), [1, 2, 3, 4]);
    }

    #[test]
    fn unwinding_waiter_leaves_the_queue() {
        let lock = Mutex::<(), Host>::new(());
        thread::scope(|scope| {
            let guard = lock.lock();
            let (waiter, unwinding) = spawn_parked(scope, || {
                Host::panic_in_next_park();
                drop(lock.lock());
            });
            // Wakes it with no unlock behind, so it panics out of its wait.
            Host::unpark(waiter);
            assert!(unwinding.join().is_err());
            drop(guard);
        });
        assert!(lock.try_lock().is_some());
    }

    #[test]
    fn woken_waiter_that_unwinds_has_left_the_queue_already() {
        let lock = Mutex::<(), Host>::new(());
        thread::scope(|scope| {
            let guard = lock.lock();
            let (_, unwinding) = spawn_parked(scope, || {
                Host::panic_in_next_park();
                drop(lock.lock());
            });
            // The handoff wakes it for good, and it panics all the same.
            drop(guard);
            assert!(unwinding.join().is_err());
        });
    }

    const THREADS: usize = 4;
    const ROUNDS: usize = 10_000;

    fn take(lock: &RawMutex<Host>) {
        lock.lock();
    }

    fn give(lock: &RawMutex<Host>) {
        // SAFETY: `take` locked it on this thread.
        unsafe { lock.unlock() };
    }

    #[test]
    fn raw_lock_unlocks_in_another_function() {
        let lock = RawMutex::<Host>::new();
        take(&lock);
        assert!(lock.is_locked());
        assert!(lock.is_owned_by_current());
        give(&lock);
        assert!(!lock.is_locked());
        assert!(!lock.is_owned_by_current());
    }

    #[test]
    fn raw_owner_is_in_no_section() {
        let lock = RawMutex::<Host>::default();
        lock.lock();
        assert_eq!(Host::irq_quiet_depth(), 0);
        // SAFETY: locked above, on this thread.
        unsafe { lock.unlock() };
        assert_eq!(Host::irq_quiet_depth(), 0);
    }

    #[test]
    fn raw_try_lock_fails_while_held() {
        let lock = RawMutex::<Host>::new();
        assert!(lock.try_lock());
        assert!(!lock.try_lock());
        thread::scope(|scope| {
            let other = scope.spawn(|| {
                (
                    lock.try_lock(),
                    lock.is_locked(),
                    lock.is_owned_by_current(),
                )
            });
            assert_eq!(other.join().unwrap(), (false, true, false));
        });
        // SAFETY: the first `try_lock` took it on this thread.
        unsafe { lock.unlock() };
        assert!(!lock.is_locked());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "mutex unlocked by a thread that does not own it"]
    fn unlock_by_a_non_owner_panics() {
        let lock = RawMutex::<Host>::new();
        // SAFETY: none; the debug check is expected to catch it.
        unsafe { lock.unlock() };
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "mutex word is neither its owner's"]
    fn unlock_of_a_word_with_an_unknown_flag_panics() {
        let lock = RawMutex::<Host>::new();
        lock.lock();
        lock.state
            .store(Host::current().addr() | 2, Ordering::Relaxed);
        // SAFETY: none; the debug check is expected to catch it.
        unsafe { lock.unlock() };
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "mutex locked, but its word does not name the running \
                      thread"]
    fn waiter_woken_with_no_handoff_panics() {
        use crate::test_support::{resume_panic_of, wake_without_handoff};

        let lock = Mutex::<(), Host>::new(());
        thread::scope(|scope| {
            let _guard = lock.lock();
            let (_, waiter) = spawn_parked(scope, || drop(lock.lock()));
            wake_without_handoff(lock.raw().addr().addr());
            resume_panic_of(waiter);
        });
    }

    #[test]
    fn raw_lock_debug_shows_whether_locked() {
        let lock = RawMutex::<Host>::new();
        assert_eq!(format!("{lock:?}"), "RawMutex { locked: false, .. }");
        lock.lock();
        assert_eq!(format!("{lock:?}"), "RawMutex { locked: true, .. }");
        // SAFETY: locked above, on this thread.
        unsafe { lock.unlock() };
    }

    #[test]
    fn lock_excludes_under_contention() {
        let lock = Mutex::<usize, Host>::new(0);
        let inside = AtomicBool::new(false);
        let work = || {
            for _ in 0..ROUNDS {
                let mut count = lock.lock();
                assert!(!inside.swap(true, Ordering::Relaxed));
                *count += 1;
                inside.store(false, Ordering::Relaxed);
            }
            Host::irq_quiet_depth()
        };
        thread::scope(|scope| {
            let workers: Vec<_> =
                (0..THREADS).map(|_| scope.spawn(work)).collect();
            for worker in workers {
                assert_eq!(worker.join().unwrap(), 0);
            }
        });
        assert_eq!(lock.into_inner(), THREADS * ROUNDS);
    }

    #[test]
    fn contender_parks_while_the_owner_holds_on() {
        let lock = Mutex::<u32, Host>::new(0);
        thread::scope(|scope| {
            let mut guard = lock.lock();
            // Returns once the contender has parked, though this thread
            // runs throughout: the contender spins out instead of waiting
            // for the owner to sleep.
            let (_, contender) = spawn_parked(scope, || *lock.lock() += 1);
            *guard += 10;
            drop(guard);
            contender.join().unwrap();
        });
        assert_eq!(lock.into_inner(), 11);
    }

    #[test]
    fn contenders_park_behind_a_parked_owner() {
        let lock = Mutex::<u32, Host>::new(0);
        let owner = Mutex::<(), Host>::new(());
        let held = Barrier::new(THREADS + 2);
        thread::scope(|scope| {
            let blocker = owner.lock();
            let holder = scope.spawn(|| {
                let mut count = lock.lock();
                let _ = held.wait();
                // Parks behind the test thread, so the contenders see a
                // sleeping owner and park without spinning.
                drop(owner.lock());
                *count += 1;
            });
            let contenders: Vec<_> = (0..THREADS)
                .map(|_| {
                    scope.spawn(|| {
                        let _ = held.wait();
                        *lock.lock() += 1;
                    })
                })
                .collect();
            let _ = held.wait();
            thread::sleep(Duration::from_millis(50));
            drop(blocker);
            holder.join().unwrap();
            for contender in contenders {
                contender.join().unwrap();
            }
        });
        assert_eq!(lock.into_inner(), u32::try_from(THREADS).unwrap() + 1);
    }

    #[test]
    fn guard_lends_its_data_to_other_threads() {
        let lock = Mutex::<u32, Host>::new(7);
        let guard = lock.lock();
        let seen =
            thread::scope(|scope| scope.spawn(|| *guard).join().unwrap());
        assert_eq!(seen, 7);
    }

    #[test]
    fn try_lock_fails_while_held() {
        let lock = Mutex::<u32, Host>::new(1);
        let mut guard = lock.try_lock().unwrap();
        *guard = 2;
        assert!(lock.try_lock().is_none());
        drop(guard);
        assert_eq!(*lock.try_lock().unwrap(), 2);
    }

    #[test]
    fn get_mut_and_into_inner_reach_the_data() {
        let mut lock = Mutex::<Vec<u32>, Host>::default();
        lock.get_mut().push(3);
        lock.lock().push(4);
        assert_eq!(lock.into_inner(), [3, 4]);
    }

    #[test]
    fn debug_never_blocks() {
        let lock = Mutex::<u32, Host>::new(5);
        assert_eq!(format!("{lock:?}"), "Lock { data: 5, .. }");
        let guard = lock.lock();
        assert_eq!(format!("{guard:?}"), "5");
        assert_eq!(format!("{lock:?}"), "Lock { data: <locked>, .. }");
        drop(guard);
    }

    #[test]
    fn mutex_is_sync_for_send_data() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Mutex<Cell<u32>, Host>>();
    }

    #[test]
    fn raw_mutex_is_a_word_plus_a_class_in_debug() {
        #[cfg(debug_assertions)]
        let size = 16;
        #[cfg(not(debug_assertions))]
        let size = 8;
        assert_eq!(size_of::<RawMutex<Host>>(), size);
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use super::Mutex;
    use crate::test_support::Host;
    use loom::sync::Arc;
    use loom::thread;

    #[test]
    fn handoff_among_three_threads_loses_no_wakeup() {
        let mut model = loom::model::Builder::new();
        model.preemption_bound = Some(2);
        model.check(|| {
            let lock = Arc::new(Mutex::<usize, Host>::new(0));
            let others: Vec<_> = (0..2)
                .map(|_| {
                    let lock = Arc::clone(&lock);
                    thread::spawn(move || *lock.lock() += 1)
                })
                .collect();
            *lock.lock() += 1;
            for other in others {
                other.join().unwrap();
            }
            assert_eq!(*lock.lock(), 3);
        });
    }

    #[test]
    fn lock_parks_and_hands_writes_on() {
        loom::model(|| {
            let lock = Arc::new(Mutex::<usize, Host>::new(0));
            let other = {
                let lock = Arc::clone(&lock);
                thread::spawn(move || *lock.lock() += 1)
            };
            *lock.lock() += 1;
            other.join().unwrap();
            assert_eq!(*lock.lock(), 2);
        });
    }
}
