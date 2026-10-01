// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Spin locks: [`SpinLock`] and [`IrqSpinLock`], and the raw
//! [`RawSpinLock`] and [`RawIrqSpinLock`] under them.
//!
//! Every flavour is a ticket lock, served first come, first served, and
//! never sleeps.  An irq spin lock's holder stays in an irq-quiet section
//! from before it spins until it unlocks, so no interrupt handler on its
//! CPU spins on it meanwhile; a plain spin lock enters no section, and
//! so must never be taken by an interrupt handler.

pub(crate) mod ticket;

#[cfg(debug_assertions)]
use crate::checker;
use crate::guard::Guard;
use crate::lock::{Lock, RawLock};
use crate::platform::Platform;
use crate::section;
use crate::sync::const_fn;
use core::fmt;
use core::marker::PhantomData;
#[cfg(debug_assertions)]
use core::panic::Location;
use ticket::Ticket;

/// Defines one spin-lock flavour's raw lock, whose holder is in the section
/// named by `$enter`/`$exit`, if any.
macro_rules! spin_lock {
    (
        $(#[$raw_doc:meta])*
        raw $Raw:ident;
        kind $kind:ident;
        $(section $enter:ident, $exit:ident;)?
    ) => {
        $(#[$raw_doc])*
        #[repr(C)]
        pub struct $Raw<P: Platform> {
            ticket: Ticket,
            #[cfg(debug_assertions)]
            class: checker::Class,
            platform: PhantomData<fn() -> P>,
        }

        impl<P: Platform> $Raw<P> {
            /// Fails the build, once [`Self::new`] instantiates it, if a
            /// release lock outgrows its ticket word; the type is generic,
            /// so a free `const _` cannot name it.
            #[cfg(not(any(debug_assertions, loom)))]
            const ONE_WORD: () = assert!(size_of::<Self>() == 4);

            const_fn! {
                /// Returns an unlocked lock of the caller's lock class.
                #[must_use]
                #[track_caller]
                pub const fn new() -> Self {
                    #[cfg(not(any(debug_assertions, loom)))]
                    let () = Self::ONE_WORD;
                    Self {
                        ticket: Ticket::new(),
                        #[cfg(debug_assertions)]
                        class: Location::caller(),
                        platform: PhantomData,
                    }
                }
            }

            /// Takes the lock, spinning until it is free; never sleeps.
            ///
            /// Enters the lock's section, if it has one, before it spins,
            /// and stays in it until [`Self::unlock`].
            ///
            /// # Panics
            ///
            /// In debug builds, if the order checker finds the acquisition
            /// could deadlock: it closes a lock-order cycle, the running
            /// thread already holds the lock, or it already holds a lock of
            /// the same class.
            pub fn lock(&self) {
                $(section::$enter::<P>();)?
                #[cfg(debug_assertions)]
                checker::acquire::<P>(
                    self.addr(),
                    self.class,
                    checker::Kind::$kind,
                );
                self.ticket.lock();
            }

            /// Takes the lock if it is free, without spinning.
            ///
            /// On success the running thread is in the lock's section, if
            /// it has one, until [`Self::unlock`]; on failure it is not.
            ///
            /// # Panics
            ///
            /// In debug builds, if the running thread already holds a lock
            /// of the same class.
            #[must_use = "the lock is held only if this returns true"]
            pub fn try_lock(&self) -> bool {
                $(section::$enter::<P>();)?
                if self.ticket.try_lock() {
                    #[cfg(debug_assertions)]
                    checker::try_acquired::<P>(
                        self.addr(),
                        self.class,
                        checker::Kind::$kind,
                    );
                    true
                } else {
                    $(
                        // SAFETY: the section was entered above, on this
                        // thread.
                        unsafe { section::$exit::<P>() };
                    )?
                    false
                }
            }

            /// Releases the lock, then leaves the lock's section, if it has
            /// one.
            ///
            /// # Panics
            ///
            /// In debug builds, if the running thread does not hold the
            /// lock, or the lock is free.
            ///
            /// # Safety
            ///
            /// The running thread holds the lock: it took it with
            /// [`Self::lock`] or a successful [`Self::try_lock`] and has
            /// not unlocked it since.
            pub unsafe fn unlock(&self) {
                #[cfg(debug_assertions)]
                checker::release::<P>(self.addr(), checker::Kind::$kind);
                unsafe {
                    self.ticket.unlock();
                    $(section::$exit::<P>();)?
                }
            }

            /// Returns whether some thread holds the lock; stale as soon
            /// as read.
            #[must_use]
            pub fn is_locked(&self) -> bool {
                self.ticket.is_locked()
            }

            #[cfg(debug_assertions)]
            const fn addr(&self) -> *const () {
                core::ptr::from_ref(self).cast()
            }
        }

        // SAFETY: the ticket lock admits one holder at a time, taking it
        // with acquire and releasing it with release.
        unsafe impl<P: Platform> RawLock for $Raw<P> {
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
                checker::assert_held::<P>(
                    self.addr(),
                    checker::Kind::$kind,
                );
            }
        }

        impl<P: Platform> Default for $Raw<P> {
            #[track_caller]
            fn default() -> Self {
                Self::new()
            }
        }

        impl<P: Platform> fmt::Debug for $Raw<P> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($Raw))
                    .field("locked", &self.is_locked())
                    .finish_non_exhaustive()
            }
        }
    };
}

spin_lock! {
    /// The raw spin lock: a ticket lock whose holder enters no section.
    ///
    /// Embeddable in `#[repr(C)]` structures, and unlockable in another
    /// function than the one that locked it, but on the same thread.  One
    /// 32-bit word in release builds; debug builds add the lock class.
    raw RawSpinLock;
    kind Spin;
}

spin_lock! {
    /// The raw irq spin lock: a ticket lock whose holder is in an
    /// [irq-quiet section](section::IrqQuiet), and so the only raw lock an
    /// interrupt handler may share with threads.
    ///
    /// Embeddable in `#[repr(C)]` structures, and unlockable in another
    /// function than the one that locked it, but on the same thread.  One
    /// 32-bit word in release builds; debug builds add the lock class.
    raw RawIrqSpinLock;
    kind IrqSpin;
    section enter_irq_quiet, exit_irq_quiet;
}

/// A spin lock over a `T`: waiters spin, and the holder must not sleep
/// until its guard drops.
///
/// Never sleeps, so it may be taken anywhere but in an interrupt handler,
/// which must use an [`IrqSpinLock`] instead: an interrupt that spun on its
/// own CPU's holder would never return.
pub type SpinLock<T, P> = Lock<RawSpinLock<P>, T>;

/// Access to a [`SpinLock`]'s data; unlocks when dropped.
pub type SpinLockGuard<'a, T, P> = Guard<'a, RawSpinLock<P>, T>;

/// An irq spin lock over a `T`: waiters spin, and the holder is in an
/// [irq-quiet section](section::IrqQuiet) until its guard drops.
///
/// The only lock an interrupt handler may share with threads.
pub type IrqSpinLock<T, P> = Lock<RawIrqSpinLock<P>, T>;

/// Access to an [`IrqSpinLock`]'s data; unlocks, and leaves the section,
/// when dropped.
pub type IrqSpinLockGuard<'a, T, P> = Guard<'a, RawIrqSpinLock<P>, T>;

#[cfg(all(test, not(loom)))]
mod tests {
    /// Tests one flavour, whose holder is in `$held` irq-quiet sections.
    macro_rules! spin_lock_tests {
        ($flavour:ident, $Raw:ident, $Lock:ident, $held:literal) => {
            mod $flavour {
                use crate::spin::{$Lock, $Raw};
                use crate::test_support::Host;
                use std::cell::Cell;
                use std::sync::atomic::{AtomicBool, Ordering};
                use std::thread;

                const THREADS: usize = 4;
                const ROUNDS: usize = 10_000;

                fn take(lock: &$Raw<Host>) {
                    lock.lock();
                }

                fn give(lock: &$Raw<Host>) {
                    // SAFETY: `take` locked it on this thread.
                    unsafe { lock.unlock() };
                }

                #[test]
                fn raw_lock_unlocks_in_another_function() {
                    let lock = $Raw::<Host>::new();
                    take(&lock);
                    assert!(lock.is_locked());
                    give(&lock);
                    assert!(!lock.is_locked());
                }

                #[test]
                fn raw_holder_is_in_its_section() {
                    let lock = $Raw::<Host>::default();
                    lock.lock();
                    assert_eq!(Host::irq_quiet_depth(), $held);
                    // SAFETY: locked above, on this thread.
                    unsafe { lock.unlock() };
                    assert_eq!(Host::irq_quiet_depth(), 0);
                }

                #[test]
                fn raw_try_lock_fails_while_held() {
                    let lock = $Raw::<Host>::new();
                    assert!(lock.try_lock());
                    assert_eq!(Host::irq_quiet_depth(), $held);
                    assert!(!lock.try_lock());
                    assert_eq!(Host::irq_quiet_depth(), $held);
                    // SAFETY: the first `try_lock` took it on this thread.
                    unsafe { lock.unlock() };
                    assert_eq!(Host::irq_quiet_depth(), 0);
                }

                #[test]
                fn raw_lock_survives_ticket_wrap() {
                    let lock = $Raw::<Host>::new();
                    for _ in 0..(1 << 17) + 3 {
                        lock.lock();
                        // SAFETY: locked on the line above.
                        unsafe { lock.unlock() };
                    }
                    assert!(!lock.is_locked());
                    assert!(lock.try_lock());
                    assert!(lock.is_locked());
                    // SAFETY: `try_lock` took it on this thread.
                    unsafe { lock.unlock() };
                }

                #[test]
                fn raw_lock_debug_shows_whether_locked() {
                    let lock = $Raw::<Host>::new();
                    let name = stringify!($Raw);
                    assert_eq!(
                        format!("{lock:?}"),
                        format!("{name} {{ locked: false, .. }}"),
                    );
                    lock.lock();
                    assert_eq!(
                        format!("{lock:?}"),
                        format!("{name} {{ locked: true, .. }}"),
                    );
                    // SAFETY: locked above, on this thread.
                    unsafe { lock.unlock() };
                }

                #[test]
                fn lock_excludes_under_contention() {
                    let lock = $Lock::<usize, Host>::new(0);
                    let inside = AtomicBool::new(false);
                    let work = || {
                        for _ in 0..ROUNDS {
                            let mut count = lock.lock();
                            assert!(!inside.swap(true, Ordering::Relaxed));
                            *count += 1;
                            inside.store(false, Ordering::Relaxed);
                        }
                    };
                    thread::scope(|scope| {
                        let workers: Vec<_> =
                            (0..THREADS).map(|_| scope.spawn(work)).collect();
                        for worker in workers {
                            worker.join().unwrap();
                        }
                    });
                    assert_eq!(lock.into_inner(), THREADS * ROUNDS);
                }

                #[test]
                fn guard_holds_the_section_until_dropped() {
                    let lock = $Lock::<u32, Host>::new(7);
                    let guard = lock.lock();
                    assert_eq!(Host::irq_quiet_depth(), $held);
                    assert_eq!(*guard, 7);
                    drop(guard);
                    assert_eq!(Host::irq_quiet_depth(), 0);
                }

                #[test]
                fn guard_lends_its_data_to_other_threads() {
                    let lock = $Lock::<u32, Host>::new(7);
                    let guard = lock.lock();
                    let seen = std::thread::scope(|scope| {
                        scope.spawn(|| *guard).join().unwrap()
                    });
                    assert_eq!(seen, 7);
                }

                #[test]
                fn try_lock_fails_while_held() {
                    let lock = $Lock::<u32, Host>::new(1);
                    let mut guard = lock.try_lock().unwrap();
                    *guard = 2;
                    assert!(lock.try_lock().is_none());
                    thread::scope(|scope| {
                        let other = scope.spawn(|| {
                            (
                                lock.try_lock().is_none(),
                                Host::irq_quiet_depth(),
                            )
                        });
                        assert_eq!(other.join().unwrap(), (true, 0));
                    });
                    assert_eq!(Host::irq_quiet_depth(), $held);
                    drop(guard);
                    assert_eq!(Host::irq_quiet_depth(), 0);
                    assert_eq!(*lock.try_lock().unwrap(), 2);
                }

                #[test]
                fn get_mut_and_into_inner_reach_the_data() {
                    let mut lock = $Lock::<Vec<u32>, Host>::default();
                    lock.get_mut().push(3);
                    lock.lock().push(4);
                    assert_eq!(lock.into_inner(), [3, 4]);
                }

                #[test]
                fn debug_never_blocks() {
                    let lock = $Lock::<u32, Host>::new(5);
                    assert_eq!(format!("{lock:?}"), "Lock { data: 5, .. }");
                    let guard = lock.lock();
                    assert_eq!(format!("{guard:?}"), "5");
                    assert_eq!(
                        format!("{lock:?}"),
                        "Lock { data: <locked>, .. }",
                    );
                    drop(guard);
                }

                #[test]
                fn lock_is_sync_for_send_data() {
                    fn assert_send_sync<T: Send + Sync>() {}
                    assert_send_sync::<$Lock<Cell<u32>, Host>>();
                }

                #[test]
                fn raw_lock_is_a_ticket_plus_a_class_in_debug() {
                    #[cfg(debug_assertions)]
                    let size = 16;
                    #[cfg(not(debug_assertions))]
                    let size = 4;
                    assert_eq!(size_of::<$Raw<Host>>(), size);
                }
            }
        };
    }

    spin_lock_tests!(spin_lock, RawSpinLock, SpinLock, 0);
    spin_lock_tests!(irq_spin_lock, RawIrqSpinLock, IrqSpinLock, 1);
}

#[cfg(all(test, loom))]
mod loom_tests {
    /// Models one flavour, whose holder is in `$held` irq-quiet sections.
    macro_rules! spin_lock_models {
        ($flavour:ident, $Raw:ident, $Lock:ident, $held:literal) => {
            mod $flavour {
                use crate::spin::{$Lock, $Raw};
                use crate::test_support::Host;
                use loom::cell::UnsafeCell;
                use loom::sync::Arc;
                use loom::thread;

                #[test]
                fn raw_lock_hands_writes_to_the_next_holder() {
                    loom::model(|| {
                        let shared = Arc::new((
                            $Raw::<Host>::new(),
                            UnsafeCell::new(0),
                        ));
                        let add_one = {
                            let shared = Arc::clone(&shared);
                            move || {
                                let (lock, count) = &*shared;
                                lock.lock();
                                // SAFETY: the lock is held.
                                count.with_mut(|count| unsafe { *count += 1 });
                                // SAFETY: locked above, on this thread.
                                unsafe { lock.unlock() };
                            }
                        };
                        let other = thread::spawn(add_one.clone());
                        add_one();
                        other.join().unwrap();
                        let (lock, count) = &*shared;
                        lock.lock();
                        // SAFETY: the lock is held.
                        assert_eq!(count.with(|count| unsafe { *count }), 2);
                        // SAFETY: locked above, on this thread.
                        unsafe { lock.unlock() };
                    });
                }

                #[test]
                fn lock_excludes_and_hands_writes_on() {
                    loom::model(|| {
                        let lock = Arc::new($Lock::<usize, Host>::new(0));
                        let add_one = {
                            let lock = Arc::clone(&lock);
                            move || {
                                let mut count = lock.lock();
                                assert_eq!(Host::irq_quiet_depth(), $held);
                                *count += 1;
                                drop(count);
                                assert_eq!(Host::irq_quiet_depth(), 0);
                            }
                        };
                        let other = thread::spawn(add_one.clone());
                        add_one();
                        other.join().unwrap();
                        assert_eq!(*lock.lock(), 2);
                    });
                }

                #[test]
                fn successful_try_lock_sees_the_last_holder() {
                    loom::model(|| {
                        let lock = Arc::new($Lock::<usize, Host>::new(0));
                        let other = {
                            let lock = Arc::clone(&lock);
                            thread::spawn(move || *lock.lock() += 1)
                        };
                        if let Some(mut count) = lock.try_lock() {
                            *count += 10;
                        }
                        assert_eq!(Host::irq_quiet_depth(), 0);
                        other.join().unwrap();
                        let count = *lock.lock();
                        assert!(count == 1 || count == 11, "{count}");
                    });
                }
            }
        };
    }

    spin_lock_models!(spin_lock, RawSpinLock, SpinLock, 0);
    spin_lock_models!(irq_spin_lock, RawIrqSpinLock, IrqSpinLock, 1);
}
