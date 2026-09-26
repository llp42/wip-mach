// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The condition variable, [`Condvar`].
//!
//! A waiter queues on the condition variable's address while it still
//! holds its lock, and only then releases the lock and sleeps; a notifier
//! that changed the condition under the same lock therefore finds it
//! queued.  The lock may be a [`Mutex`](crate::Mutex), a
//! [`SpinLock`](crate::SpinLock), an [`IrqSpinLock`](crate::IrqSpinLock)
//! or the write side of an [`RwLock`](crate::RwLock): any lock whose
//! [`Guard`] the waiter holds.

use crate::guard::Guard;
use crate::lock::RawLock;
use crate::platform::Platform;
use crate::sync::{AtomicBool, Ordering, const_fn};
use crate::wait;
use core::fmt;
use core::marker::PhantomData;
use core::mem::ManuallyDrop;

/// A condition variable: threads sleep on it, holding no lock, until
/// another thread notifies them.
///
/// A woken waiter competes for its lock again, and another thread may
/// take the lock first and change the condition, so a waiter re-checks
/// its condition in a loop, as [`Self::wait_while`] does.  A waiter wakes
/// only when notified.  There are no timeouts.
pub struct Condvar<P: Platform> {
    /// Set, under the bucket lock, while threads may be queued; lets a
    /// notify with no waiters skip the wait table.
    parked: AtomicBool,
    platform: PhantomData<fn() -> P>,
}

impl<P: Platform> Condvar<P> {
    const_fn! {
        /// Returns a condition variable no thread waits on.
        #[must_use]
        pub const fn new() -> Self {
            Self {
                parked: AtomicBool::new(false),
                platform: PhantomData,
            }
        }
    }

    /// Releases `guard`'s lock and sleeps until notified, then takes the
    /// lock back and returns the guard.
    ///
    /// Sleeps, so the running thread must be in no section but the one
    /// the guard's own lock holds, which it leaves while it sleeps.  The
    /// condition may no longer hold on return.
    ///
    /// # Panics
    ///
    /// If the platform, or the order checker, refuses to sleep: as when
    /// the running thread is in a section it entered itself.  The guard is
    /// not dropped on the way out, so its lock is left as the panic found
    /// it: released after such a refusal, still held if something
    /// panicked before the wait let the lock go.
    pub fn wait<'a, R: RawLock, T>(
        &self,
        guard: Guard<'a, R, T>,
    ) -> Guard<'a, R, T> {
        let mut guard = ManuallyDrop::new(guard);
        let _ = wait::park::<P>(
            self.key(),
            0,
            &mut || {
                self.parked.store(true, Ordering::Relaxed);
                true
            },
            // SAFETY: the guard holds its lock, and is not used again
            // until it retakes it below.
            &mut || unsafe { guard.release() },
        );
        guard.retake();
        ManuallyDrop::into_inner(guard)
    }

    /// Waits, as [`Self::wait`], for as long as `condition` holds of the
    /// guarded data, and returns the guard once it does not.
    ///
    /// # Panics
    ///
    /// As [`Self::wait`].
    pub fn wait_while<'a, R: RawLock, T>(
        &self,
        mut guard: Guard<'a, R, T>,
        mut condition: impl FnMut(&mut T) -> bool,
    ) -> Guard<'a, R, T> {
        while condition(&mut *guard) {
            guard = self.wait(guard);
        }
        guard
    }

    /// Wakes the longest waiting thread, if any, and returns whether there
    /// was one.
    ///
    /// Never sleeps; may be called from anywhere, including an irq-quiet
    /// section.
    #[allow(
        clippy::must_use_candidate,
        reason = "the wake is the point; the count is only a hint"
    )]
    pub fn notify_one(&self) -> bool {
        if !self.parked.load(Ordering::Relaxed) {
            return false;
        }
        wait::unpark_one::<P>(self.key(), &mut |result| self.settle(result))
            .unparked
            != 0
    }

    /// Wakes every waiting thread and returns how many there were.
    ///
    /// Never sleeps; may be called from anywhere, including an irq-quiet
    /// section.
    #[allow(
        clippy::must_use_candidate,
        reason = "the wake is the point; the count is only a hint"
    )]
    pub fn notify_all(&self) -> usize {
        if !self.parked.load(Ordering::Relaxed) {
            return 0;
        }
        wait::unpark_all::<P>(self.key(), &mut |result| self.settle(result))
            .unparked
    }

    /// Clears [`Self::parked`] once no thread is queued; runs under the
    /// bucket lock, where no thread can queue meanwhile.
    fn settle(&self, result: wait::UnparkResult) {
        if !result.have_more {
            self.parked.store(false, Ordering::Relaxed);
        }
    }

    fn key(&self) -> usize {
        core::ptr::from_ref(self).addr()
    }
}

impl<P: Platform> Default for Condvar<P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<P: Platform> fmt::Debug for Condvar<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Condvar").finish_non_exhaustive()
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::Condvar;
    use crate::section::IrqQuiet;
    use crate::test_support::{Host, yield_until};
    use std::thread;

    const ROUNDS: u32 = 1000;
    const WAITERS: usize = 4;

    /// Tests one lock type, whose holder is in `$depth` irq-quiet
    /// sections.
    macro_rules! condvar_tests {
        ($name:ident, $Lock:ident, $depth:expr) => {
            mod $name {
                use super::{
                    Condvar, Host, IrqQuiet, ROUNDS, WAITERS, thread,
                    yield_until,
                };
                use crate::$Lock;

                fn depth() -> usize {
                    Host::irq_quiet_depth()
                }

                #[test]
                fn hands_values_from_producer_to_consumer() {
                    let slot = $Lock::<Option<u32>, Host>::new(None);
                    let changed = Condvar::<Host>::new();
                    thread::scope(|scope| {
                        let consumer = scope.spawn(|| {
                            let mut sum = 0;
                            for _ in 0..ROUNDS {
                                let mut value = changed
                                    .wait_while(slot.lock(), |value| {
                                        value.is_none()
                                    });
                                assert_eq!(depth(), $depth);
                                sum += value.take().unwrap();
                                drop(value);
                                let _ = changed.notify_one();
                            }
                            (sum, depth())
                        });
                        for round in 1..=ROUNDS {
                            let mut value = changed
                                .wait_while(slot.lock(), |value| {
                                    value.is_some()
                                });
                            *value = Some(round);
                            drop(value);
                            let _ = changed.notify_one();
                        }
                        let (sum, after) = consumer.join().unwrap();
                        assert_eq!(sum, ROUNDS * (ROUNDS + 1) / 2);
                        assert_eq!(after, 0);
                    });
                }

                #[test]
                fn notify_all_wakes_every_waiter() {
                    let state = $Lock::<(usize, bool), Host>::new((0, false));
                    let ready = Condvar::<Host>::new();
                    thread::scope(|scope| {
                        let waiters: Vec<_> = (0..WAITERS)
                            .map(|_| {
                                scope.spawn(|| {
                                    let mut state = state.lock();
                                    state.0 += 1;
                                    let state = ready
                                        .wait_while(state, |state| !state.1);
                                    assert!(state.1);
                                })
                            })
                            .collect();
                        // A waiter counts itself in while it still holds
                        // the lock, and is queued before it lets go.
                        yield_until(|| state.lock().0 >= WAITERS);
                        let mut state = state.lock();
                        state.1 = true;
                        assert_eq!(ready.notify_all(), WAITERS);
                        drop(state);
                        for waiter in waiters {
                            waiter.join().unwrap();
                        }
                    });
                    assert_eq!(ready.notify_all(), 0);
                }

                #[test]
                fn notify_one_wakes_one_waiter_at_a_time() {
                    // (waiters queued, wakes handed out)
                    let state = $Lock::<(usize, usize), Host>::new((0, 0));
                    let wake = Condvar::<Host>::new();
                    thread::scope(|scope| {
                        let waiters: Vec<_> = (0..WAITERS)
                            .map(|_| {
                                scope.spawn(|| {
                                    let mut state = state.lock();
                                    state.0 += 1;
                                    let mut state = wake
                                        .wait_while(state, |state| {
                                            state.1 == 0
                                        });
                                    state.1 -= 1;
                                })
                            })
                            .collect();
                        yield_until(|| state.lock().0 >= WAITERS);
                        // Each wake leaves at least one waiter queued for
                        // the next: a woken waiter that finds no wake left
                        // queues again.
                        for _ in 0..WAITERS {
                            state.lock().1 += 1;
                            assert!(wake.notify_one());
                        }
                        for waiter in waiters {
                            waiter.join().unwrap();
                        }
                    });
                    assert!(!wake.notify_one());
                }

                #[test]
                fn notify_from_an_irq_quiet_section_wakes_a_waiter() {
                    let state =
                        $Lock::<(bool, bool), Host>::new((false, false));
                    let ready = Condvar::<Host>::new();
                    thread::scope(|scope| {
                        let waiter = scope.spawn(|| {
                            let mut state = state.lock();
                            state.0 = true;
                            drop(ready.wait_while(state, |state| !state.1));
                        });
                        yield_until(|| state.lock().0);
                        state.lock().1 = true;
                        let section = IrqQuiet::<Host>::enter();
                        assert!(ready.notify_one());
                        drop(section);
                        waiter.join().unwrap();
                    });
                    assert!(!ready.notify_one());
                }
            }
        };
    }

    condvar_tests!(mutex, Mutex, 0);
    condvar_tests!(spin_lock, SpinLock, 0);
    condvar_tests!(irq_spin_lock, IrqSpinLock, 1);
    condvar_tests!(rwlock, RwLock, 0);

    #[test]
    fn a_reader_gets_in_while_a_write_guard_waits() {
        let state = crate::RwLock::<(bool, bool), Host>::new((false, false));
        let ready = Condvar::<Host>::new();
        thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                let mut state = state.write();
                state.0 = true;
                drop(ready.wait_while(state, |state| !state.1));
            });
            // The waiter's write is visible to a reader only once it has
            // let the lock go to wait, and queued before that.
            yield_until(|| state.read().0);
            state.write().1 = true;
            assert!(ready.notify_one());
            waiter.join().unwrap();
        });
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic = "may sleep inside an irq-quiet section"
    )]
    #[cfg_attr(not(debug_assertions), should_panic = "park inside a section")]
    fn wait_inside_the_callers_section_panics() {
        let lock = crate::IrqSpinLock::<(), Host>::new(());
        let condvar = Condvar::<Host>::default();
        let _section = IrqQuiet::<Host>::enter();
        drop(condvar.wait(lock.lock()));
    }

    #[test]
    fn debug_shows_the_type() {
        let condvar = Condvar::<Host>::new();
        assert_eq!(format!("{condvar:?}"), "Condvar { .. }");
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    use super::Condvar;
    use crate::test_support::Host;
    use crate::{Mutex, SpinLock};
    use loom::sync::Arc;
    use loom::thread;

    #[test]
    fn notify_racing_a_mutex_wait_is_not_lost() {
        // Unbounded, the waiter's mutex relock takes minutes to explore;
        // three preemptions still find a lost wakeup.
        let mut model = loom::model::Builder::new();
        model.preemption_bound = Some(3);
        model.check(|| {
            let shared = Arc::new((
                Mutex::<bool, Host>::new(false),
                Condvar::<Host>::new(),
            ));
            let notifier = {
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    let (lock, ready) = &*shared;
                    *lock.lock() = true;
                    let _ = ready.notify_one();
                })
            };
            let (lock, ready) = &*shared;
            let done = ready.wait_while(lock.lock(), |done| !*done);
            assert!(*done);
            drop(done);
            notifier.join().unwrap();
        });
    }

    #[test]
    fn notify_racing_a_spin_lock_wait_is_not_lost() {
        loom::model(|| {
            let shared = Arc::new((
                SpinLock::<bool, Host>::new(false),
                Condvar::<Host>::new(),
            ));
            let notifier = {
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    let (lock, ready) = &*shared;
                    *lock.lock() = true;
                    let _ = ready.notify_one();
                })
            };
            let (lock, ready) = &*shared;
            let done = ready.wait_while(lock.lock(), |done| !*done);
            assert!(*done);
            drop(done);
            notifier.join().unwrap();
        });
    }
}
