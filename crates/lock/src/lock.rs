// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The generic lock, [`Lock`], and the raw-lock traits under it.
//!
//! A [`Lock`] pairs the data with a raw lock, and lends the data only
//! through a [`Guard`] or a [`SharedGuard`], which hold the raw lock.
//! [`SpinLock`](crate::SpinLock), [`IrqSpinLock`](crate::IrqSpinLock),
//! [`Mutex`](crate::Mutex) and [`RwLock`](crate::RwLock) are aliases of it.
//! The order-checker hooks and the handoff live in the raw locks, so a raw
//! lock used directly is checked as well.

use crate::guard::{Guard, SharedGuard};
use crate::platform::Platform;
use crate::spin::{RawIrqSpinLock, RawSpinLock};
use crate::sync::{UnsafeCell, const_fn};
use crate::{RawMutex, RawRwLock};
use core::fmt;

/// A raw lock with one exclusive holder at a time, and no data.
///
/// Locks and unlocks through `&self`, so the unlock may be in another
/// function than the lock, but on the thread that took it.  A [`Lock`]
/// pairs one with the data it guards.
///
/// # Safety
///
/// Implementors provide mutual exclusion between [`Self::lock`] or a
/// successful [`Self::try_lock`] and the matching [`Self::unlock`]: the
/// locking acquires and the unlocking releases, so a holder sees every
/// write of the holder before it.
pub unsafe trait RawLock {
    /// Takes the lock, waiting until it is free.
    fn lock(&self);

    /// Takes the lock if it is free, without waiting.
    #[must_use = "the lock is held only if this returns true"]
    fn try_lock(&self) -> bool;

    /// Releases the lock.
    ///
    /// # Safety
    ///
    /// The running thread holds the lock: it took it with [`Self::lock`]
    /// or a successful [`Self::try_lock`] and has not unlocked it since.
    unsafe fn unlock(&self);

    /// Checks that the running thread holds the lock, in debug builds; does
    /// nothing in release builds.
    ///
    /// A lock without an owner, as a spin lock, has only the order
    /// checker's record of the thread's holds to ask.
    ///
    /// # Panics
    ///
    /// In debug builds, if the running thread does not hold the lock.
    fn assert_held(&self);
}

/// A raw lock that many threads may hold shared, beside its exclusive
/// hold.
///
/// # Safety
///
/// Implementors provide mutual exclusion between a shared hold and an
/// exclusive one of the same lock, and the same visibility as for
/// [`RawLock`]: the exclusive holders see every write of the holders
/// before them, shared or exclusive.
pub unsafe trait RawSharedLock {
    /// Takes the lock shared, waiting until no thread holds it exclusive.
    fn lock_shared(&self);

    /// Takes the lock shared if that needs no waiting.
    #[must_use = "the lock is held only if this returns true"]
    fn try_lock_shared(&self) -> bool;

    /// Releases a shared hold.
    ///
    /// # Safety
    ///
    /// The running thread holds the lock shared: it took it with
    /// [`Self::lock_shared`] or a successful [`Self::try_lock_shared`] and
    /// has not unlocked it since.
    unsafe fn unlock_shared(&self);

    /// Checks that the running thread holds the lock shared, in debug
    /// builds; does nothing in release builds.
    ///
    /// # Panics
    ///
    /// In debug builds, if the running thread does not hold the lock
    /// shared.
    fn assert_held_shared(&self);
}

/// A `T` behind the raw lock `R`: the data is reached only through a guard
/// that holds `R`.
///
/// [`SpinLock`](crate::SpinLock), [`IrqSpinLock`](crate::IrqSpinLock),
/// [`Mutex`](crate::Mutex) and [`RwLock`](crate::RwLock) are the locks the
/// crate offers; each fixes its raw lock, and so its interrupt policy and
/// its waiting.  It is `Sync` for any `T: Send`; the shared hold of a
/// [`RawSharedLock`] hands out `&T` to many threads, so [`Self::read`]
/// asks for `T: Sync` besides.
pub struct Lock<R, T> {
    pub(crate) raw: R,
    pub(crate) data: UnsafeCell<T>,
}

// SAFETY: the raw lock lets one thread at a time reach the data exclusive,
// and `T: Send` lets that thread be any thread.  Shared access is granted
// only where `T: Sync`, by `read` and by adopting a shared hold.
unsafe impl<R: RawLock + Sync, T: Send> Sync for Lock<R, T> {}

impl<R, T> Lock<R, T> {
    const_fn! {
        /// Returns an unlocked lock over a raw lock of the caller's making,
        /// holding `value`.
        ///
        /// A lock over one of the crate's raw locks is built by `new`,
        /// which also gives it the caller's lock class.
        #[must_use]
        pub const fn from_raw(raw: R, value: T) -> Self {
            Self {
                raw,
                data: UnsafeCell::new(value),
            }
        }
    }

    /// Returns the raw lock.
    ///
    /// For a caller that takes the raw lock itself, and hands the hold to a
    /// guard with [`Guard::adopt`] or [`SharedGuard::adopt`].
    #[must_use]
    pub const fn raw(&self) -> &R {
        &self.raw
    }

    /// Returns the data, with no locking: `&mut self` already rules out
    /// every guard.
    pub fn get_mut(&mut self) -> &mut T {
        // SAFETY: `&mut self` rules out every guard and every other
        // reference to the data.
        self.data.with_mut(|data| unsafe { &mut *data })
    }

    /// Returns the data, consuming the lock.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

/// Defines `new` for a lock over each raw lock named: a trait cannot make a
/// raw lock in a `const fn` that records the caller's construction site.
macro_rules! constructors {
    ($($Raw:ident),*) => {$(
        impl<T, P: Platform> Lock<$Raw<P>, T> {
            const_fn! {
                /// Returns an unlocked lock of the caller's lock class,
                /// holding `value`.
                #[must_use]
                #[track_caller]
                pub const fn new(value: T) -> Self {
                    Self::from_raw($Raw::new(), value)
                }
            }
        }
    )*};
}

constructors!(RawSpinLock, RawIrqSpinLock, RawMutex, RawRwLock);

impl<R: RawLock, T> Lock<R, T> {
    /// Takes the lock, waiting until it is free.
    ///
    /// Whether the wait spins or sleeps, and what the thread is in while it
    /// holds the lock, is the raw lock's.
    ///
    /// # Panics
    ///
    /// As the raw lock's `lock`.
    pub fn lock(&self) -> Guard<'_, R, T> {
        self.raw.lock();
        // SAFETY: this thread took the lock on the line above.
        unsafe { Guard::new(self) }
    }

    /// Takes the lock if it is free, without waiting.
    pub fn try_lock(&self) -> Option<Guard<'_, R, T>> {
        if self.raw.try_lock() {
            // SAFETY: this thread took the lock just above.
            Some(unsafe { Guard::new(self) })
        } else {
            None
        }
    }
}

impl<R: RawLock + RawSharedLock, T> Lock<R, T> {
    /// Takes the lock exclusive, waiting until it is free: the same as
    /// [`Self::lock`], named for the writer of a shared lock.
    ///
    /// # Panics
    ///
    /// As the raw lock's `lock`.
    pub fn write(&self) -> Guard<'_, R, T> {
        self.lock()
    }

    /// Takes the lock exclusive if it is free, without waiting: the same as
    /// [`Self::try_lock`].
    pub fn try_write(&self) -> Option<Guard<'_, R, T>> {
        self.try_lock()
    }
}

impl<R: RawSharedLock, T: Sync> Lock<R, T> {
    /// Takes the lock shared, waiting until no thread holds it exclusive.
    ///
    /// # Panics
    ///
    /// As the raw lock's `lock_shared`.
    pub fn read(&self) -> SharedGuard<'_, R, T> {
        self.raw.lock_shared();
        // SAFETY: this thread took the lock shared on the line above.
        unsafe { SharedGuard::new(self) }
    }

    /// Takes the lock shared if that needs no waiting.
    pub fn try_read(&self) -> Option<SharedGuard<'_, R, T>> {
        if self.raw.try_lock_shared() {
            // SAFETY: this thread took the lock shared just above.
            Some(unsafe { SharedGuard::new(self) })
        } else {
            None
        }
    }
}

impl<R: Default, T: Default> Default for Lock<R, T> {
    #[track_caller]
    fn default() -> Self {
        Self::from_raw(R::default(), T::default())
    }
}

/// Shows the data if the lock is free, and `<locked>` if not, including
/// when the running thread holds it, and when only readers do; never
/// sleeps.
impl<R: RawLock, T: fmt::Debug> fmt::Debug for Lock<R, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = f.debug_struct("Lock");
        let out = match self.try_lock() {
            Some(guard) => out.field("data", &&*guard),
            None => out.field("data", &format_args!("<locked>")),
        };
        out.finish_non_exhaustive()
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::{RawLock, RawSharedLock};
    use crate::test_support::Host;
    use crate::{RawIrqSpinLock, RawMutex, RawRwLock, RawSpinLock};
    use std::thread;

    fn exclusive_round_trip<R: RawLock>(raw: &R) {
        raw.lock();
        assert!(!raw.try_lock());
        // SAFETY: locked above, on this thread.
        unsafe { raw.unlock() };
        assert!(raw.try_lock());
        // SAFETY: `try_lock` took it on this thread.
        unsafe { raw.unlock() };
    }

    #[test]
    fn every_raw_lock_locks_exclusively_through_the_trait() {
        exclusive_round_trip(&RawSpinLock::<Host>::new());
        exclusive_round_trip(&RawIrqSpinLock::<Host>::new());
        exclusive_round_trip(&RawMutex::<Host>::new());
        exclusive_round_trip(&RawRwLock::<Host>::new());
    }

    #[test]
    fn raw_rwlock_shares_through_the_trait() {
        let raw = RawRwLock::<Host>::new();
        raw.lock_shared();
        thread::scope(|scope| {
            scope
                .spawn(|| {
                    assert!(raw.try_lock_shared());
                    // SAFETY: taken shared just above, on this thread.
                    unsafe { raw.unlock_shared() };
                })
                .join()
                .unwrap();
        });
        assert!(!RawLock::try_lock(&raw));
        // SAFETY: taken shared above, on this thread.
        unsafe { raw.unlock_shared() };
        assert!(RawLock::try_lock(&raw));
        // SAFETY: `try_lock` took it exclusive on this thread.
        unsafe { RawLock::unlock(&raw) };
    }

    /// Tests one lock flavour, whose holder is in `$held` irq-quiet
    /// sections, through its guard.
    macro_rules! guard_tests {
        ($flavour:ident, $Raw:ident, $Lock:ident, $held:literal) => {
            mod $flavour {
                use crate::test_support::Host;
                use crate::{Guard, RawLock, $Lock, $Raw};
                use std::panic::{AssertUnwindSafe, catch_unwind};
                use std::thread;

                #[test]
                fn unlocked_lets_another_thread_take_the_lock() {
                    let lock = $Lock::<u32, Host>::new(1);
                    let mut guard = lock.lock();
                    let seen = guard.unlocked(|| {
                        thread::scope(|scope| {
                            scope
                                .spawn(|| {
                                    let mut other = lock.lock();
                                    *other += 10;
                                    *other
                                })
                                .join()
                                .unwrap()
                        })
                    });
                    assert_eq!(seen, 11);
                    assert_eq!(*guard, 11);
                }

                #[test]
                fn unlocked_leaves_the_section_and_enters_it_again() {
                    let lock = $Lock::<(), Host>::new(());
                    let mut guard = lock.lock();
                    assert_eq!(Host::irq_quiet_depth(), $held);
                    assert_eq!(guard.unlocked(Host::irq_quiet_depth), 0);
                    assert_eq!(Host::irq_quiet_depth(), $held);
                }

                #[test]
                fn unlocked_takes_the_lock_back_as_a_panic_unwinds() {
                    let lock = $Lock::<u32, Host>::new(1);
                    let mut guard = lock.lock();
                    let panicked = catch_unwind(AssertUnwindSafe(|| {
                        guard.unlocked(|| panic!("out of the closure"))
                    }));
                    assert!(panicked.is_err());
                    assert!(lock.try_lock().is_none());
                    drop(guard);
                    assert_eq!(*lock.try_lock().unwrap(), 1);
                }

                #[test]
                fn adopt_takes_over_a_raw_lock_taken_by_hand() {
                    let lock = $Lock::<u32, Host>::new(3);
                    lock.raw().lock();
                    // SAFETY: this thread took the raw lock above.
                    let mut guard = unsafe { Guard::adopt(&lock) };
                    *guard += 1;
                    drop(guard);
                    assert!(!lock.raw().is_locked());
                    assert_eq!(*lock.lock(), 4);
                }

                #[test]
                #[cfg(debug_assertions)]
                #[should_panic = "lock is not held by the running thread"]
                fn adopt_of_a_lock_the_thread_does_not_hold_panics() {
                    let lock = $Lock::<u32, Host>::new(3);
                    // SAFETY: none; the debug check is expected to catch it.
                    drop(unsafe { Guard::adopt(&lock) });
                }

                #[test]
                fn assert_held_passes_for_the_holder() {
                    let raw = $Raw::<Host>::new();
                    raw.lock();
                    raw.assert_held();
                    // SAFETY: locked above, on this thread.
                    unsafe { raw.unlock() };
                }

                #[test]
                #[cfg(debug_assertions)]
                #[should_panic = "lock is not held by the running thread"]
                fn assert_held_panics_for_a_free_lock() {
                    $Raw::<Host>::new().assert_held();
                }

                #[test]
                #[cfg(debug_assertions)]
                fn assert_held_panics_on_a_thread_that_is_not_the_holder() {
                    let raw = $Raw::<Host>::new();
                    raw.lock();
                    let checked = thread::scope(|scope| {
                        scope
                            .spawn(|| {
                                catch_unwind(AssertUnwindSafe(|| {
                                    raw.assert_held();
                                }))
                            })
                            .join()
                            .unwrap()
                    });
                    assert!(checked.is_err());
                    // SAFETY: locked above, on this thread.
                    unsafe { raw.unlock() };
                }
            }
        };
    }

    guard_tests!(spin_lock, RawSpinLock, SpinLock, 0);
    guard_tests!(irq_spin_lock, RawIrqSpinLock, IrqSpinLock, 1);
    guard_tests!(mutex, RawMutex, Mutex, 0);
    guard_tests!(rwlock_write, RawRwLock, RwLock, 0);
}

#[cfg(all(test, loom))]
mod loom_tests {
    use crate::test_support::Host;
    use crate::{Mutex, RwLock, SpinLock};
    use loom::sync::Arc;
    use loom::thread;

    /// Models one exclusive flavour: another thread's hold falls in the
    /// window `unlocked` opens, and the guard's accesses stay ordered
    /// around it.  Unbounded, a sleeping lock's retake takes many seconds
    /// to explore; three preemptions still find a misordered access.
    macro_rules! unlocked_models {
        ($flavour:ident, $Lock:ident) => {
            mod $flavour {
                use super::*;

                #[test]
                fn unlocked_orders_the_accesses_around_another_holder() {
                    let mut model = loom::model::Builder::new();
                    model.preemption_bound = Some(3);
                    model.check(|| {
                        let lock = Arc::new($Lock::<usize, Host>::new(0));
                        let other = {
                            let lock = Arc::clone(&lock);
                            thread::spawn(move || *lock.lock() += 10)
                        };
                        let mut guard = lock.lock();
                        *guard += 1;
                        guard.unlocked(|| {});
                        *guard += 1;
                        drop(guard);
                        other.join().unwrap();
                        assert_eq!(*lock.lock(), 12);
                    });
                }
            }
        };
    }

    unlocked_models!(spin_lock, SpinLock);
    unlocked_models!(mutex, Mutex);

    #[test]
    fn shared_unlocked_orders_the_reads_around_a_writer() {
        let mut model = loom::model::Builder::new();
        model.preemption_bound = Some(3);
        model.check(|| {
            let lock = Arc::new(RwLock::<usize, Host>::new(0));
            let writer = {
                let lock = Arc::clone(&lock);
                thread::spawn(move || *lock.write() += 1)
            };
            let mut read = lock.read();
            let before = *read;
            read.unlocked(|| {});
            let after = *read;
            assert!(before <= after && after <= 1, "{before} then {after}");
            drop(read);
            writer.join().unwrap();
            assert_eq!(*lock.read(), 1);
        });
    }
}
