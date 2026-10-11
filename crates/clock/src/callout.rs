// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The safe layer over a [`HashedWheel`]: a [`Callout`] owns its record, is
//! bound to one wheel, and cannot be freed while that wheel can reach
//! it.
//!
//! A callout is `!Unpin` and [`Callout::start`] takes it pinned, so its
//! address holds while it is armed.  Its `Drop` stops it and waits
//! until it is idle, its action returned; pinning guarantees a pinned
//! value's memory is not reused before its `Drop` runs, so the wheel
//! never reaches a freed record.  A callout that is leaked instead stays
//! valid forever.

use crate::hashed_wheel::{HashedWheel, Record, TickSource};
use crate::platform::Locking;
use crate::types::Ticks;
use core::pin::Pin;
use core::ptr::NonNull;

/// The expiry action of a [`Callout`].
///
/// It runs from [`HashedWheel::advance`] with the wheel unlocked, in whatever
/// context that runs, and may start or stop any callout on the wheel,
/// its own included.
///
/// It must not block: [`Callout::cancel`] spins until it returns, and the
/// kernel is non-preemptible, so nothing takes the CPU from the spinner
/// and an action that blocked may never get a CPU back to return on.
pub type CalloutAction<'w, P, T> = fn(Pin<&Callout<'w, P, T>>);

/// A timer record bound to one wheel, with its action and the data the
/// action works on.
///
/// Dropping a callout stops it, and waits for its action if that is
/// running on another CPU.  A drop from inside its own action, or from
/// an interrupt taken during the `advance` running it, never returns.
pub struct Callout<'w, P: TickSource + Locking, T> {
    record: Record,
    wheel: Pin<&'w HashedWheel<P>>,
    action: CalloutAction<'w, P, T>,
    data: T,
}

impl<'w, P: TickSource + Locking, T> Callout<'w, P, T> {
    /// A stopped callout on `wheel` that runs `action` when it expires.
    pub const fn new(
        wheel: Pin<&'w HashedWheel<P>>,
        action: CalloutAction<'w, P, T>,
        data: T,
    ) -> Self {
        Self {
            record: Record::idle(),
            wheel,
            action,
            data,
        }
    }

    /// The data the action works on.
    pub const fn data(&self) -> &T {
        &self.data
    }

    /// The wheel the callout is bound to.
    pub const fn hashed_wheel(&self) -> Pin<&'w HashedWheel<P>> {
        self.wheel
    }

    fn record(&self) -> NonNull<Record> {
        NonNull::from(&self.record)
    }

    /// Arms the callout for `interval` ticks from the wheel's current
    /// tick, or re-arms it if it is armed.
    ///
    /// A zero interval is one tick.  A callout started while its action
    /// runs is armed at once, and is not idle until that action has
    /// returned.
    pub fn start(self: Pin<&Self>, interval: Ticks)
    where
        Self: Sync,
    {
        let ctx = core::ptr::from_ref(self.get_ref()).cast_mut().cast();
        // SAFETY: the record is pinned inside the callout and is never on
        // another wheel; `Drop` keeps it live until it is idle.  `expire`
        // takes the callout it is registered with, and `Self: Sync` lets
        // it run on another CPU.
        unsafe {
            self.wheel.start(self.record(), interval, Self::expire, ctx);
        };
    }

    /// Disarms the callout, returning whether that prevented a pending
    /// expiry.
    ///
    /// An action that is already running keeps running; the callout is
    /// not idle until it returns.
    #[must_use]
    pub fn stop(&self) -> bool {
        // SAFETY: the record is live and on no wheel but this one.
        unsafe { self.wheel.stop(self.record()) }
    }

    /// Whether the callout is stopped and no action of it is running.
    pub fn is_idle(&self) -> bool {
        // SAFETY: the record is live and on no wheel but this one.
        unsafe { self.wheel.is_idle(self.record()) }
    }

    /// Disarms the callout and spins until no action of it is running.
    ///
    /// A running action that restarts its callout is stopped again.
    /// Called from the callout's own action, or from an interrupt taken
    /// during the `advance` running it, it never returns.
    pub fn cancel(&self) {
        loop {
            let _ = self.stop();
            if self.is_idle() {
                return;
            }
            core::hint::spin_loop();
        }
    }

    /// Runs the callout's action.
    ///
    /// # Safety
    ///
    /// `ctx` must point at a live, pinned callout of this type.
    unsafe fn expire(ctx: *mut ()) {
        let callout = unsafe { Pin::new_unchecked(&*ctx.cast::<Self>()) };
        (callout.action)(callout);
    }
}

impl<P: TickSource + Locking, T> Drop for Callout<'_, P, T> {
    fn drop(&mut self) {
        // A running action may hold `&Self` on another CPU until this
        // returns.  The record makes `Self` `!Unpin`, so this `&mut` is
        // not treated as unique; Rust has not yet made that a guarantee.
        self.cancel();
    }
}
