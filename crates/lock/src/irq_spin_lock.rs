// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The irq spin lock: [`RawIrqSpinLock`], and [`IrqSpinLock`] over it.
//!
//! A ticket lock whose holder is in an irq-quiet section from before it
//! spins until it unlocks, so no interrupt handler on its CPU spins on it
//! meanwhile.  It is the only lock an interrupt handler may share with
//! threads.

#[cfg(debug_assertions)]
use crate::checker;
use crate::platform::Platform;
use core::fmt;
use core::marker::PhantomData;
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
        "an irq spin lock is held or waited for by 65535 threads: the next \
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
    debug_assert!(!is_free(seen), "an irq spin lock is unlocked while free");
    let serving = seen & SERVING;
    if serving == SERVING {
        let _ = word.fetch_sub(SERVING, Ordering::Release);
    } else {
        let _ = word.fetch_add(1, Ordering::Release);
    }
}

/// Enters an irq-quiet section with no guard, for a raw lock whose unlock
/// may run in another function.
fn enter_irq_quiet<P: Platform>() {
    P::irq_quiet_enter();
    #[cfg(debug_assertions)]
    checker::section_enter::<P>();
}

/// Leaves an irq-quiet section entered with [`enter_irq_quiet`].
///
/// # Safety
///
/// The running thread entered an irq-quiet section that it has not left.
unsafe fn exit_irq_quiet<P: Platform>() {
    #[cfg(debug_assertions)]
    checker::section_exit::<P>();
    unsafe { P::irq_quiet_exit() };
}

/// The raw irq spin lock: a ticket lock whose holder is in an
/// irq-quiet section.
///
/// Embeddable in `#[repr(C)]` structures, and unlockable in another
/// function than the one that locked it, but on the same thread.  The
/// ticket word and its name.
///
/// Generic over the [`Platform`] that quiets its CPU's interrupts; a lock
/// with no section needs no platform and names none.
#[repr(C)]
pub struct RawIrqSpinLock<P: Platform> {
    ticket: AtomicU32,
    platform: PhantomData<fn() -> P>,
    /// What this lock is, for the order checker.  Debug builds only, so a
    /// release build keeps the lock one word.
    #[cfg(debug_assertions)]
    pub name: &'static str,
}

impl<P: Platform> RawIrqSpinLock<P> {
    /// Returns a lock named `name`, for the order checker.
    #[must_use]
    pub const fn named(name: &'static str) -> Self {
        // A release build has no field to keep it in.
        #[cfg(not(debug_assertions))]
        let _ = name;
        Self {
            ticket: AtomicU32::new(0),
            platform: PhantomData,
            #[cfg(debug_assertions)]
            name,
        }
    }
}

// SAFETY: the ticket word admits one holder at a time, taking it with
// acquire and releasing it with release.  The guard is not `Send`, so the
// thread that unlocks is the one that locked — which also keeps the
// irq-quiet section on the CPU that entered it.
unsafe impl<P: Platform> lock_api::RawMutex for RawIrqSpinLock<P> {
    /// The free word.
    ///
    const INIT: Self = {
        #[cfg(not(debug_assertions))]
        assert!(size_of::<Self>() == 4, "an irq spin lock outgrew its word");
        Self::named("unnamed")
    };

    /// Not `Send`: a hold is in an irq-quiet section on the CPU that took
    /// it, and dropping the guard elsewhere would leave that CPU quiet
    /// forever.  The marker of every lock here, so the rule never varies.
    type GuardMarker = lock_api::GuardNoSend;

    /// Takes the lock, spinning until it is free; never sleeps.
    ///
    /// Enters the irq-quiet section before it spins, and stays in it until
    /// [`Self::unlock`].
    ///
    /// # Panics
    ///
    /// In debug builds, if the order checker finds the acquisition could
    /// deadlock, or if 65535 threads hold or wait for it already.
    fn lock(&self) {
        enter_irq_quiet::<P>();
        #[cfg(debug_assertions)]
        checker::acquire::<P>(
            core::ptr::from_ref(self).cast(),
            checker::Kind::IrqSpin,
            self.name,
        );
        take(&self.ticket);
    }

    /// Takes the lock if it is free, without spinning.
    ///
    /// On success the running thread is in the irq-quiet section until
    /// [`Self::unlock`]; on failure it is not.
    fn try_lock(&self) -> bool {
        enter_irq_quiet::<P>();
        if try_take(&self.ticket) {
            #[cfg(debug_assertions)]
            checker::try_acquired::<P>(
                core::ptr::from_ref(self).cast(),
                checker::Kind::IrqSpin,
                self.name,
            );
            true
        } else {
            // SAFETY: the section was entered above, on this thread.
            unsafe { exit_irq_quiet::<P>() };
            false
        }
    }

    /// Releases the lock, then leaves the irq-quiet section.
    ///
    /// # Panics
    ///
    /// In debug builds, if the running thread does not hold the lock, or
    /// the lock is free.
    ///
    /// # Safety
    ///
    /// The running thread holds the lock, and leaves the section on the
    /// CPU that entered it.
    unsafe fn unlock(&self) {
        #[cfg(debug_assertions)]
        checker::release::<P>(
            core::ptr::from_ref(self).cast(),
            checker::Kind::IrqSpin,
        );
        unsafe {
            serve_next(&self.ticket);
            exit_irq_quiet::<P>();
        }
    }

    /// Overrides the trait's default, which takes and releases the lock
    /// to answer: on a ticket that would move the 65535-waiter bound.
    fn is_locked(&self) -> bool {
        !is_free(self.ticket.load(Ordering::Relaxed))
    }
}

impl<P: Platform> fmt::Debug for RawIrqSpinLock<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawIrqSpinLock")
            .field("locked", &self.is_locked())
            .finish_non_exhaustive()
    }
}

/// An irq spin lock over a `T`: waiters spin in arrival order, and the
/// holder is in an irq-quiet section until its guard drops.
///
/// The only lock an interrupt handler may share with threads.
///
/// Its debug checker's order-graph node is the lock's
/// [`name`](RawIrqSpinLock::name); locks built by
/// [`new`](lock_api::Mutex::new) are all one node, and
/// [`irq_spin_lock!`](crate::irq_spin_lock) names one.
pub type IrqSpinLock<T, P> = lock_api::Mutex<RawIrqSpinLock<P>, T>;

/// Builds an [`IrqSpinLock`] whose debug checker's order-graph node is `name`.
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
macro_rules! irq_spin_lock {
    ($name:expr, $data:expr $(,)?) => {
        $crate::lock_api::Mutex::from_raw(
            $crate::RawIrqSpinLock::named($name),
            $data,
        )
    };
}
