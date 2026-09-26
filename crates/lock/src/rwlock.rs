// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The sleeping reader-writer lock: [`RwLock`], and the raw [`RawRwLock`]
//! under it.
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
use crate::guard::{Guard, SharedGuard};
use crate::lock::{Lock, RawLock, RawSharedLock};
use crate::platform::{Platform, ThreadRef};
use crate::sync::{AtomicUsize, Ordering, const_fn, fence};
use crate::wait::{self, Token};
use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
#[cfg(debug_assertions)]
use core::panic::Location;

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
/// may sleep.  One word in release builds; debug builds add the lock
/// class.
#[repr(C)]
pub struct RawRwLock<P: Platform> {
    state: AtomicUsize,
    #[cfg(debug_assertions)]
    class: checker::Class,
    platform: PhantomData<fn() -> P>,
}

impl<P: Platform> RawRwLock<P> {
    /// Fails the build, once [`Self::new`] instantiates it, if a release
    /// lock outgrows its word; the type is generic, so a free `const _`
    /// cannot name it.
    #[cfg(not(any(debug_assertions, loom)))]
    const ONE_WORD: () = assert!(size_of::<Self>() == size_of::<usize>());

    const_fn! {
        /// Returns an unlocked lock of the caller's lock class.
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

    /// Takes the lock shared, sleeping while a writer holds it or any
    /// thread waits for it.
    ///
    /// May sleep, so never call it inside a section.
    ///
    /// # Panics
    ///
    /// In debug builds, if the order checker finds the acquisition could
    /// deadlock: it closes a lock-order cycle, the running thread already
    /// holds the lock or a lock of the same class, or it is in a section
    /// or holds a spinning lock.
    pub fn read(&self) {
        #[cfg(debug_assertions)]
        checker::acquire::<P>(self.addr(), self.class, checker::Kind::Read);
        if !self.read_fast() {
            self.read_slow();
        }
    }

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

    #[cold]
    fn read_slow(&self) {
        while !self.read_fast() && !self.queue(READ) {}
    }

    /// Takes the lock shared if no writer holds it and no thread waits for
    /// it, without waiting; never sleeps.
    ///
    /// May fail, rarely, while it could be taken but its word is changing.
    ///
    /// # Panics
    ///
    /// In debug builds, if the running thread already holds a lock of the
    /// same class.
    #[must_use = "the lock is held only if this returns true"]
    pub fn try_read(&self) -> bool {
        let taken = self.read_fast();
        #[cfg(debug_assertions)]
        if taken {
            checker::try_acquired::<P>(
                self.addr(),
                self.class,
                checker::Kind::Read,
            );
        }
        taken
    }

    /// Releases a shared hold; the last reader out hands the lock off.
    /// Never sleeps.
    ///
    /// # Safety
    ///
    /// The running thread holds the lock shared: it took it with
    /// [`Self::read`], a successful [`Self::try_read`] or
    /// [`Self::downgrade`], and has not unlocked it since.
    pub unsafe fn unlock_read(&self) {
        #[cfg(debug_assertions)]
        checker::release::<P>(self.addr());
        let state = self.state.fetch_sub(ONE_READER, Ordering::Release);
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
    /// As [`Self::read`].
    pub fn write(&self) {
        #[cfg(debug_assertions)]
        checker::acquire::<P>(self.addr(), self.class, checker::Kind::Write);
        if !self.write_fast() {
            self.write_slow();
        }
    }

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

    #[cold]
    fn write_slow(&self) {
        while !self.write_fast() && !self.queue(WRITE) {}
    }

    /// Marks the lock contested and parks the running thread on it, and
    /// returns true once a release has handed it the lock.
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
        wait::park::<P>(
            self.addr().addr(),
            token,
            &mut || {
                // A contested word is released only by a handoff, under
                // this bucket lock, which then finds this thread.
                self.state.load(Ordering::Acquire) & CONTESTED != 0
            },
            &mut || {},
        )
    }

    /// Takes the lock exclusive if no one holds it and no thread waits for
    /// it, without waiting; never sleeps.
    ///
    /// # Panics
    ///
    /// In debug builds, if the running thread already holds a lock of the
    /// same class.
    #[must_use = "the lock is held only if this returns true"]
    pub fn try_write(&self) -> bool {
        let taken = self.write_fast();
        #[cfg(debug_assertions)]
        if taken {
            checker::try_acquired::<P>(
                self.addr(),
                self.class,
                checker::Kind::Write,
            );
        }
        taken
    }

    /// Releases an exclusive hold and hands the lock off; never sleeps.
    ///
    /// # Safety
    ///
    /// The running thread holds the lock exclusive: it took it with
    /// [`Self::write`] or a successful [`Self::try_write`] and has not
    /// unlocked or downgraded it since.
    pub unsafe fn unlock_write(&self) {
        #[cfg(debug_assertions)]
        checker::release::<P>(self.addr());
        if self
            .state
            .compare_exchange(
                P::current().addr() | WRITER,
                0,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_err()
        {
            self.hand_off();
        }
    }

    /// Turns an exclusive hold into a shared one, with no instant at which
    /// the lock is free, and grants it too to the queued readers ahead of
    /// the first queued writer; never sleeps.
    ///
    /// # Safety
    ///
    /// As for [`Self::unlock_write`]; the running thread then holds the
    /// lock shared.
    pub unsafe fn downgrade(&self) {
        #[cfg(debug_assertions)]
        checker::downgrade::<P>(self.addr());
        if self
            .state
            .compare_exchange(
                P::current().addr() | WRITER,
                ONE_READER,
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_err()
        {
            self.downgrade_slow();
        }
    }

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

    /// Returns whether some thread holds the lock, shared or exclusive;
    /// stale as soon as read.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.state.load(Ordering::Relaxed) & HOLDERS != 0
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

impl<P: Platform> Default for RawRwLock<P> {
    #[track_caller]
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Platform> fmt::Debug for RawRwLock<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawRwLock")
            .field("locked", &self.is_locked())
            .finish_non_exhaustive()
    }
}

// SAFETY: the word admits either one writer or any number of readers, and
// every release, of a writer or the last reader, is ordered before the
// next holder's acquire.
unsafe impl<P: Platform> RawLock for RawRwLock<P> {
    fn lock(&self) {
        self.write();
    }

    fn try_lock(&self) -> bool {
        self.try_write()
    }

    unsafe fn unlock(&self) {
        unsafe { self.unlock_write() };
    }

    fn assert_held(&self) {
        #[cfg(debug_assertions)]
        checker::assert_held::<P>(self.addr(), checker::Kind::Write);
    }
}

// SAFETY: as for the exclusive hold.
unsafe impl<P: Platform> RawSharedLock for RawRwLock<P> {
    fn lock_shared(&self) {
        self.read();
    }

    fn try_lock_shared(&self) -> bool {
        self.try_read()
    }

    unsafe fn unlock_shared(&self) {
        unsafe { self.unlock_read() };
    }

    fn assert_held_shared(&self) {
        #[cfg(debug_assertions)]
        checker::assert_held::<P>(self.addr(), checker::Kind::Read);
    }
}

/// A sleeping reader-writer lock over a `T`: many readers or one writer;
/// waiters sleep, and are served first come, first served.
///
/// It never enters a section, so it must not be locked inside one, nor from
/// an interrupt handler.  [`Lock::write`] and [`Lock::try_write`] take it
/// exclusive; [`Lock::read`] and [`Lock::try_read`] take it shared.
pub type RwLock<T, P> = Lock<RawRwLock<P>, T>;

/// Shared access to a [`RwLock`]'s data; unlocks when dropped.
pub type RwLockReadGuard<'a, T, P> = SharedGuard<'a, RawRwLock<P>, T>;

/// Exclusive access to a [`RwLock`]'s data; unlocks when dropped.
pub type RwLockWriteGuard<'a, T, P> = Guard<'a, RawRwLock<P>, T>;

impl<'a, T, P: Platform> Guard<'a, RawRwLock<P>, T> {
    /// Turns the exclusive hold into a shared one, with no instant at
    /// which the lock is free, and lets in the queued readers ahead of
    /// the first queued writer; never sleeps.
    pub fn downgrade(self) -> SharedGuard<'a, RawRwLock<P>, T> {
        let lock = self.disarm();
        // SAFETY: the guard held the lock exclusive, on the thread that
        // took it, and its hold is now this function's; the shared hold
        // goes to the new guard.
        unsafe {
            lock.raw.downgrade();
            SharedGuard::new(lock)
        }
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::{RawRwLock, RwLock};
    use crate::SharedGuard;
    use crate::lock::{RawLock, RawSharedLock};
    use crate::test_support::{Host, spawn_parked};
    use std::cell::Cell;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    const THREADS: usize = 4;
    const ROUNDS: usize = 5_000;

    /// Long enough for a blocked thread to have parked.
    const SETTLE: Duration = Duration::from_millis(50);

    /// Returns whether another thread can take `lock` shared at once,
    /// which it then releases.
    fn shared_elsewhere(lock: &RawRwLock<Host>) -> bool {
        thread::scope(|scope| {
            scope
                .spawn(|| {
                    let taken = lock.try_read();
                    if taken {
                        // SAFETY: taken shared just above, on this thread.
                        unsafe { lock.unlock_read() };
                    }
                    taken
                })
                .join()
                .unwrap()
        })
    }

    #[test]
    fn raw_readers_share_and_exclude_a_writer() {
        let lock = RawRwLock::<Host>::new();
        lock.read();
        assert!(shared_elsewhere(&lock));
        assert!(lock.is_locked());
        assert!(!lock.try_write());
        // SAFETY: taken shared above, on this thread.
        unsafe { lock.unlock_read() };
        assert!(!lock.is_locked());
    }

    #[test]
    fn raw_writer_excludes_everyone() {
        let lock = RawRwLock::<Host>::default();
        lock.write();
        assert!(lock.is_locked());
        assert!(!lock.try_read());
        assert!(!lock.try_write());
        assert!(!shared_elsewhere(&lock));
        assert_eq!(Host::irq_quiet_depth(), 0);
        // SAFETY: taken exclusive above, on this thread.
        unsafe { lock.unlock_write() };
        assert!(lock.try_write());
        // SAFETY: `try_write` took it exclusive on this thread.
        unsafe { lock.downgrade() };
        assert!(shared_elsewhere(&lock));
        assert!(!lock.try_write());
        // SAFETY: the downgrade left a shared hold on this thread.
        unsafe { lock.unlock_read() };
        assert!(!lock.is_locked());
    }

    #[test]
    fn guards_lend_their_data_to_other_threads() {
        let lock = RwLock::<u32, Host>::new(7);
        let write = lock.write();
        let seen =
            thread::scope(|scope| scope.spawn(|| *write).join().unwrap());
        assert_eq!(seen, 7);
        let read = write.downgrade();
        let seen =
            thread::scope(|scope| scope.spawn(|| *read).join().unwrap());
        assert_eq!(seen, 7);
    }

    #[test]
    fn raw_lock_debug_shows_whether_locked() {
        let lock = RawRwLock::<Host>::new();
        assert_eq!(format!("{lock:?}"), "RawRwLock { locked: false, .. }");
        lock.read();
        assert_eq!(format!("{lock:?}"), "RawRwLock { locked: true, .. }");
        // SAFETY: taken shared above, on this thread.
        unsafe { lock.unlock_read() };
    }

    #[test]
    fn readers_hold_at_once() {
        let lock = RwLock::<u32, Host>::new(7);
        let all_in = Barrier::new(THREADS);
        thread::scope(|scope| {
            let readers: Vec<_> = (0..THREADS)
                .map(|_| {
                    scope.spawn(|| {
                        let value = lock.read();
                        // Every reader reaches the barrier while holding.
                        let _ = all_in.wait();
                        *value
                    })
                })
                .collect();
            for reader in readers {
                assert_eq!(reader.join().unwrap(), 7);
            }
        });
    }

    #[test]
    fn writer_excludes_under_contention() {
        let lock = RwLock::<usize, Host>::new(0);
        let readers = AtomicUsize::new(0);
        let writers = AtomicUsize::new(0);
        thread::scope(|scope| {
            let workers: Vec<_> = (0..THREADS)
                .map(|thread| {
                    scope.spawn({
                        let (lock, readers, writers) =
                            (&lock, &readers, &writers);
                        move || {
                            for round in 0..ROUNDS {
                                if (thread + round) % 3 == 0 {
                                    let mut count = lock.write();
                                    assert_eq!(
                                        writers
                                            .fetch_add(1, Ordering::Relaxed),
                                        0
                                    );
                                    assert_eq!(
                                        readers.load(Ordering::Relaxed),
                                        0
                                    );
                                    *count += 1;
                                    let _ = writers
                                        .fetch_sub(1, Ordering::Relaxed);
                                } else {
                                    let count = lock.read();
                                    let _ = readers
                                        .fetch_add(1, Ordering::Relaxed);
                                    assert_eq!(
                                        writers.load(Ordering::Relaxed),
                                        0
                                    );
                                    let _ = *count;
                                    let _ = readers
                                        .fetch_sub(1, Ordering::Relaxed);
                                }
                            }
                        }
                    })
                })
                .collect();
            for worker in workers {
                worker.join().unwrap();
            }
        });
        let expected = (0..THREADS)
            .map(|thread| {
                (0..ROUNDS)
                    .filter(|round| (thread + round) % 3 == 0)
                    .count()
            })
            .sum::<usize>();
        assert_eq!(lock.into_inner(), expected);
    }

    #[test]
    fn queued_writer_blocks_new_readers() {
        let lock = RwLock::<Vec<usize>, Host>::default();
        thread::scope(|scope| {
            let first = lock.read();
            let (_, writer) = spawn_parked(scope, || lock.write().push(1));
            assert!(lock.try_read().is_none());
            let (_, reader) = spawn_parked(scope, || lock.read().len());
            drop(first);
            writer.join().unwrap();
            assert_eq!(reader.join().unwrap(), 1);
        });
    }

    #[test]
    fn queued_reader_blocks_a_later_writer() {
        let lock = RwLock::<Vec<usize>, Host>::default();
        let reading = Barrier::new(2);
        thread::scope(|scope| {
            let first = lock.write();
            let (_, reader) = spawn_parked(scope, || {
                let log = lock.read();
                let _ = reading.wait();
                let _ = reading.wait();
                log.len()
            });
            let (_, writer) = spawn_parked(scope, || lock.write().push(1));
            drop(first);
            let _ = reading.wait();
            assert!(lock.try_write().is_none());
            assert!(lock.try_read().is_none());
            let _ = reading.wait();
            assert_eq!(reader.join().unwrap(), 0);
            writer.join().unwrap();
        });
        assert_eq!(lock.into_inner(), [1]);
    }

    #[test]
    fn readers_ahead_of_a_writer_are_granted_together() {
        let lock = RwLock::<Vec<usize>, Host>::default();
        let all_in = Barrier::new(THREADS);
        thread::scope(|scope| {
            let first = lock.write();
            let readers: Vec<_> = (0..THREADS)
                .map(|_| {
                    let (lock, all_in) = (&lock, &all_in);
                    spawn_parked(scope, move || {
                        let log = lock.read();
                        // Every reader holds at once, the writer queued
                        // between them notwithstanding.
                        let _ = all_in.wait();
                        log.len()
                    })
                    .1
                })
                .collect();
            let (_, writer) = spawn_parked(scope, || lock.write().push(1));
            drop(first);
            for reader in readers {
                assert_eq!(reader.join().unwrap(), 0);
            }
            writer.join().unwrap();
        });
    }

    #[test]
    fn downgrade_grants_the_readers_ahead_of_the_first_writer() {
        let lock = RwLock::<Vec<usize>, Host>::default();
        let reading = Barrier::new(2);
        thread::scope(|scope| {
            let mut first = lock.write();
            let (_, early) = spawn_parked(scope, || {
                let log = lock.read();
                let _ = reading.wait();
                log.len()
            });
            let (_, writer) = spawn_parked(scope, || lock.write().push(2));
            let (_, late) = spawn_parked(scope, || lock.read().len());
            first.push(1);
            let first = first.downgrade();
            // The early reader is in beside this one; the late one waits
            // behind the writer.
            let _ = reading.wait();
            assert!(lock.try_read().is_none());
            drop(first);
            assert_eq!(early.join().unwrap(), 1);
            writer.join().unwrap();
            assert_eq!(late.join().unwrap(), 2);
        });
    }

    #[test]
    fn writers_wake_one_at_a_time() {
        let lock = RwLock::<u32, Host>::new(0);
        thread::scope(|scope| {
            let first = lock.write();
            let writers: Vec<_> = (0..THREADS)
                .map(|_| scope.spawn(|| *lock.write() += 1))
                .collect();
            thread::sleep(SETTLE);
            drop(first);
            for writer in writers {
                writer.join().unwrap();
            }
        });
        assert_eq!(lock.into_inner(), u32::try_from(THREADS).unwrap());
    }

    #[test]
    fn downgrade_lets_parked_readers_in() {
        let lock = RwLock::<u32, Host>::new(0);
        thread::scope(|scope| {
            let mut value = lock.write();
            let readers: Vec<_> =
                (0..THREADS).map(|_| scope.spawn(|| *lock.read())).collect();
            thread::sleep(SETTLE);
            *value = 5;
            let value = value.downgrade();
            assert!(lock.try_write().is_none());
            // The readers finish while this thread still holds its read.
            for reader in readers {
                assert_eq!(reader.join().unwrap(), 5);
            }
            assert_eq!(*value, 5);
        });
        assert!(lock.try_write().is_some());
    }

    #[test]
    fn woken_writer_downgrade_lets_parked_readers_in() {
        let lock = RwLock::<u32, Host>::new(0);
        let downgraded = Barrier::new(2);
        let reader_in = Barrier::new(2);
        thread::scope(|scope| {
            let first = lock.read();
            let (_, writer) = spawn_parked(scope, || {
                let mut guard = lock.write();
                *guard += 1;
                let guard = guard.downgrade();
                let _ = downgraded.wait();
                // Held until the parked reader is in beside it.
                let _ = reader_in.wait();
                drop(guard);
                Host::parks()
            });
            let (_, reader) = spawn_parked(scope, || {
                let seen = *lock.read();
                let _ = reader_in.wait();
                (seen, Host::parks())
            });
            drop(first);
            let _ = downgraded.wait();
            let (seen, reader_parks) = reader.join().unwrap();
            assert_eq!(seen, 1);
            assert!(reader_parks > 0);
            assert!(writer.join().unwrap() > 0);
        });
    }

    #[test]
    fn downgrade_leaves_readers_behind_a_waiting_writer() {
        let lock = RwLock::<u32, Host>::new(0);
        thread::scope(|scope| {
            let value = lock.write();
            let writer = scope.spawn(|| *lock.write() += 1);
            thread::sleep(SETTLE);
            let reader = scope.spawn(|| *lock.read());
            thread::sleep(SETTLE);
            let value = value.downgrade();
            assert!(lock.try_read().is_none());
            drop(value);
            writer.join().unwrap();
            assert_eq!(reader.join().unwrap(), 1);
        });
    }

    #[test]
    fn get_mut_and_into_inner_reach_the_data() {
        let mut lock = RwLock::<Vec<u32>, Host>::default();
        lock.get_mut().push(3);
        lock.write().push(4);
        assert_eq!(*lock.read(), [3, 4]);
        assert_eq!(lock.into_inner(), [3, 4]);
    }

    #[test]
    fn debug_never_blocks() {
        let lock = RwLock::<u32, Host>::new(5);
        assert_eq!(format!("{lock:?}"), "Lock { data: 5, .. }");
        let read = lock.read();
        assert_eq!(format!("{read:?}"), "5");
        assert_eq!(format!("{lock:?}"), "Lock { data: <locked>, .. }");
        drop(read);
        let write = lock.write();
        assert_eq!(format!("{write:?}"), "5");
        assert_eq!(format!("{lock:?}"), "Lock { data: <locked>, .. }");
        drop(write);
    }

    #[test]
    fn rwlock_is_sync_for_send_data() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RwLock<u32, Host>>();
        assert_send_sync::<RwLock<Cell<u32>, Host>>();
    }

    #[test]
    fn data_that_is_not_sync_is_written_from_other_threads() {
        let lock = RwLock::<Cell<u32>, Host>::new(Cell::new(0));
        thread::scope(|scope| {
            drop(scope.spawn(|| lock.write().set(5)));
        });
        assert_eq!(lock.into_inner().get(), 5);
    }

    #[test]
    fn try_read_takes_a_free_lock_shared() {
        let lock = RwLock::<u32, Host>::new(7);
        let read = lock.try_read().unwrap();
        assert_eq!(*read, 7);
        assert!(lock.try_write().is_none());
    }

    #[test]
    fn shared_unlocked_lets_a_writer_in() {
        let lock = RwLock::<u32, Host>::new(1);
        let mut read = lock.read();
        read.unlocked(|| {
            thread::scope(|scope| {
                drop(scope.spawn(|| *lock.write() += 10));
            });
        });
        assert_eq!(*read, 11);
        assert!(lock.try_write().is_none());
    }

    #[test]
    fn shared_adopt_takes_over_a_raw_shared_lock() {
        let lock = RwLock::<u32, Host>::new(3);
        lock.raw().lock_shared();
        // SAFETY: this thread took the raw lock shared above.
        let read = unsafe { SharedGuard::adopt(&lock) };
        assert_eq!(*read, 3);
        assert!(lock.try_write().is_none());
        drop(read);
        assert!(!lock.raw().is_locked());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "Read lock is not held by the running thread"]
    fn shared_adopt_of_a_lock_held_only_exclusive_panics() {
        let lock = RwLock::<u32, Host>::new(3);
        let _write = lock.write();
        // SAFETY: none; the debug check is expected to catch it.
        drop(unsafe { SharedGuard::adopt(&lock) });
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "Write lock is not held by the running thread"]
    fn assert_held_panics_for_a_reader() {
        let raw = RawRwLock::<Host>::new();
        raw.read();
        raw.assert_held();
    }

    #[test]
    fn assert_held_shared_follows_a_downgrade() {
        let raw = RawRwLock::<Host>::new();
        raw.write();
        raw.assert_held();
        // SAFETY: taken exclusive above, on this thread.
        unsafe { raw.downgrade() };
        raw.assert_held_shared();
        // SAFETY: the downgrade left a shared hold on this thread.
        unsafe { raw.unlock_read() };
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "Read lock is not held by the running thread"]
    fn assert_held_shared_panics_for_a_writer() {
        let raw = RawRwLock::<Host>::new();
        raw.write();
        raw.assert_held_shared();
    }

    #[test]
    fn raw_rwlock_is_a_word_plus_a_class_in_debug() {
        #[cfg(debug_assertions)]
        let size = 16;
        #[cfg(not(debug_assertions))]
        let size = 8;
        assert_eq!(size_of::<RawRwLock<Host>>(), size);
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use super::RwLock;
    use crate::test_support::Host;
    use loom::sync::Arc;
    use loom::thread;

    #[test]
    fn writer_hands_off_to_a_writer_and_a_reader() {
        let mut model = loom::model::Builder::new();
        model.preemption_bound = Some(2);
        model.check(|| {
            let lock = Arc::new(RwLock::<u32, Host>::new(0));
            let writer = {
                let lock = Arc::clone(&lock);
                thread::spawn(move || *lock.write() += 1)
            };
            let reader = {
                let lock = Arc::clone(&lock);
                thread::spawn(move || *lock.read())
            };
            *lock.write() += 1;
            writer.join().unwrap();
            let seen = reader.join().unwrap();
            assert!(seen <= 2, "{seen}");
            assert_eq!(*lock.read(), 2);
        });
    }

    #[test]
    fn the_last_reader_orders_every_read_before_the_writer() {
        let mut model = loom::model::Builder::new();
        model.preemption_bound = Some(2);
        model.check(|| {
            let lock = Arc::new(RwLock::<u32, Host>::new(0));
            let reader = {
                let lock = Arc::clone(&lock);
                thread::spawn(move || *lock.read())
            };
            let writer = {
                let lock = Arc::clone(&lock);
                thread::spawn(move || *lock.write() += 1)
            };
            let seen = *lock.read();
            assert!(seen <= 1, "{seen}");
            let other = reader.join().unwrap();
            assert!(other <= 1, "{other}");
            writer.join().unwrap();
            assert_eq!(*lock.read(), 1);
        });
    }

    #[test]
    fn downgrade_lets_a_reader_in_beside_the_writer() {
        loom::model(|| {
            let lock = Arc::new(RwLock::<u32, Host>::new(0));
            let mut value = lock.write();
            let reader = {
                let lock = Arc::clone(&lock);
                thread::spawn(move || *lock.read())
            };
            *value = 1;
            let value = value.downgrade();
            assert_eq!(*value, 1);
            drop(value);
            assert_eq!(reader.join().unwrap(), 1);
        });
    }

    #[test]
    fn reader_sees_all_or_nothing_of_a_writer() {
        loom::model(|| {
            let lock = Arc::new(RwLock::<(u32, u32), Host>::new((0, 0)));
            let writer = {
                let lock = Arc::clone(&lock);
                thread::spawn(move || {
                    let mut pair = lock.write();
                    pair.0 += 1;
                    pair.1 += 1;
                })
            };
            let pair = *lock.read();
            assert!(pair == (0, 0) || pair == (1, 1), "{pair:?}");
            writer.join().unwrap();
            assert_eq!(*lock.read(), (1, 1));
        });
    }
}
