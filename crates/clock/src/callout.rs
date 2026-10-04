// SPDX-License-Identifier: MIT
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Host;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use lock::{IrqSpinLock, Platform, ThreadRef};

    /// A tick source the tests drive by hand.
    struct Source {
        ticks: AtomicU64,
    }

    impl Source {
        const fn new() -> Self {
            Self {
                ticks: AtomicU64::new(0),
            }
        }

        fn bump(&self) {
            self.ticks.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl TickSource for Source {
        fn now(&self) -> Ticks {
            Ticks::new(self.ticks.load(Ordering::Relaxed))
        }
    }

    impl Locking for Source {
        type Lock = Host;
    }

    type TestHashedWheel<'s> = Pin<Box<HashedWheel<&'s Source>>>;
    type TestCallout<'w, 's, T> = Callout<'w, &'s Source, T>;

    fn hashed_wheel(source: &Source) -> TestHashedWheel<'_> {
        Box::pin(HashedWheel::new(source, source.now()))
    }

    /// Bumps the source once and advances until caught up.
    fn tick(wheel: &TestHashedWheel<'_>, source: &Source) {
        source.bump();
        while wheel.as_ref().advance() {}
    }

    fn count(callout: Pin<&TestCallout<'_, '_, AtomicU64>>) {
        callout.data().fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn a_callout_fires_once_and_goes_idle() {
        let source = Source::new();
        let wheel = hashed_wheel(&source);
        let callout = core::pin::pin!(Callout::new(
            wheel.as_ref(),
            count,
            AtomicU64::new(0)
        ));
        assert!(callout.is_idle());
        callout.as_ref().start(Ticks::new(2));
        assert!(!callout.is_idle());
        tick(&wheel, &source);
        assert_eq!(callout.data().load(Ordering::Relaxed), 0);
        tick(&wheel, &source);
        assert_eq!(callout.data().load(Ordering::Relaxed), 1);
        assert!(callout.is_idle());
        tick(&wheel, &source);
        assert_eq!(callout.data().load(Ordering::Relaxed), 1);
    }

    #[test]
    fn stop_and_cancel_prevent_the_action() {
        let source = Source::new();
        let wheel = hashed_wheel(&source);
        let callout = core::pin::pin!(Callout::new(
            wheel.as_ref(),
            count,
            AtomicU64::new(0)
        ));
        callout.as_ref().start(Ticks::new(1));
        assert!(callout.stop());
        assert!(!callout.stop());
        callout.as_ref().start(Ticks::new(1));
        callout.cancel();
        callout.cancel();
        tick(&wheel, &source);
        assert_eq!(callout.data().load(Ordering::Relaxed), 0);
        assert!(core::ptr::eq(
            callout.hashed_wheel().get_ref(),
            wheel.as_ref().get_ref()
        ));
    }

    /// Restarts its callout until it has run three times.
    fn periodic(callout: Pin<&TestCallout<'_, '_, AtomicU64>>) {
        if callout.data().fetch_add(1, Ordering::Relaxed) < 2 {
            callout.start(Ticks::new(1));
        }
    }

    #[test]
    fn an_action_may_restart_its_callout() {
        let source = Source::new();
        let wheel = hashed_wheel(&source);
        let callout = core::pin::pin!(Callout::new(
            wheel.as_ref(),
            periodic,
            AtomicU64::new(0)
        ));
        callout.as_ref().start(Ticks::new(1));
        for _ in 0..5 {
            tick(&wheel, &source);
        }
        assert_eq!(callout.data().load(Ordering::Relaxed), 3);
        assert!(callout.is_idle());
    }

    #[test]
    fn dropping_an_armed_callout_unlinks_it() {
        let source = Source::new();
        let wheel = hashed_wheel(&source);
        let survivor = core::pin::pin!(Callout::new(
            wheel.as_ref(),
            count,
            AtomicU64::new(0)
        ));
        survivor.as_ref().start(Ticks::new(1));
        let dropped =
            Box::pin(Callout::new(wheel.as_ref(), count, AtomicU64::new(0)));
        dropped.as_ref().start(Ticks::new(1));
        drop(dropped);
        tick(&wheel, &source);
        assert_eq!(survivor.data().load(Ordering::Relaxed), 1);
    }

    /// What [`hold`] needs: the thread that drops its callout, whether it
    /// restarts its callout, and how far it got.
    struct Gate<'s> {
        dropper: ThreadRef,
        restart: bool,
        started: AtomicBool,
        returned: &'s AtomicBool,
    }

    /// Holds its action, restarted first if its gate says so, until
    /// whoever drops the callout has found it running at least twice, so
    /// the drop has spun.
    fn hold(callout: Pin<&TestCallout<'_, '_, Gate<'_>>>) {
        let gate = callout.data();
        if gate.restart {
            callout.start(Ticks::new(1));
        }
        let enters = Host::irq_quiet_entries(gate.dropper);
        gate.started.store(true, Ordering::SeqCst);
        // `stop`, `is_idle`, a spin, then `stop` again: each takes the
        // wheel's lock.
        while Host::irq_quiet_entries(gate.dropper) < enters + 3 {
            core::hint::spin_loop();
        }
        gate.returned.store(true, Ordering::SeqCst);
    }

    /// Drops a callout while its action runs on another thread, and
    /// checks the drop waited for it.
    fn drop_while_running(restart: bool) {
        let source = Source::new();
        let wheel = hashed_wheel(&source);
        let returned = AtomicBool::new(false);
        let gate = Gate {
            dropper: Host::current(),
            restart,
            started: AtomicBool::new(false),
            returned: &returned,
        };
        let callout = Box::pin(Callout::new(wheel.as_ref(), hold, gate));
        callout.as_ref().start(Ticks::new(1));
        source.bump();
        let waited = std::thread::scope(|scope| {
            scope.spawn(|| while wheel.as_ref().advance() {});
            while !callout.data().started.load(Ordering::SeqCst) {
                core::hint::spin_loop();
            }
            drop(callout);
            let waited = returned.load(Ordering::SeqCst);
            // Releases an action a drop failed to wait for, so the test
            // fails instead of hanging.
            let release = IrqSpinLock::<(), Host>::new(());
            for _ in 0..3 {
                drop(release.lock());
            }
            waited
        });
        assert!(waited);
    }

    #[test]
    fn dropping_a_running_callout_waits_for_its_action() {
        drop_while_running(false);
    }

    #[test]
    fn dropping_a_restarted_running_callout_waits_for_its_action() {
        drop_while_running(true);
    }

    /// Fails to compile if `Callout` is `Unpin`: both impls then apply
    /// and the call is ambiguous.
    #[test]
    fn a_callout_is_not_unpin() {
        trait AmbiguousIfUnpin<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfUnpin<()> for T {}
        impl<T: ?Sized + Unpin> AmbiguousIfUnpin<u8> for T {}
        <TestCallout<'static, 'static, ()> as AmbiguousIfUnpin<_>>::check();
    }

    /// The tick source of [`STATIC_HASHED_WHEEL`].
    static STATIC_SOURCE: Source = Source::new();

    /// A wheel built at compile time.
    static STATIC_HASHED_WHEEL: HashedWheel<&Source> =
        HashedWheel::new(&STATIC_SOURCE, Ticks::ZERO);

    /// A callout built at compile time.
    static STATIC_CALLOUT: TestCallout<'static, 'static, AtomicU64> =
        Callout::new(
            Pin::static_ref(&STATIC_HASHED_WHEEL),
            count,
            AtomicU64::new(0),
        );

    #[test]
    fn a_callout_can_be_a_static() {
        Pin::static_ref(&STATIC_CALLOUT).start(Ticks::new(1));
        STATIC_SOURCE.bump();
        assert!(Pin::static_ref(&STATIC_HASHED_WHEEL).advance());
        assert_eq!(STATIC_CALLOUT.data().load(Ordering::Relaxed), 1);
    }
}
