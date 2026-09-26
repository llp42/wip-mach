// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The machine clock: the monotonic and wall domains, the tick count,
//! the `adjtime`-style adjustment and the time page.
//!
//! One [`Clock`] runs per machine and only one CPU calls
//! [`tick`](Clock::tick).  It is also a [`TickSource`] and a
//! [`Critical`], so a [`HashedWheel`] can run on it directly.  Wheels are
//! separate objects with no shared state, so the crate never counts
//! CPUs.  A [`Callout`] is the way to arm one: it owns its record and
//! cannot be freed while its wheel can reach it.

#![cfg_attr(not(test), no_std)]

mod adjust;
pub mod callout;
mod critical;
pub mod hashed_wheel;
pub mod platform;
#[cfg(test)]
mod test_support;
mod timer;
pub mod types;

pub use callout::{Callout, CalloutAction};
pub use hashed_wheel::{HashedWheel, TickSource};
pub use platform::{Calendar, Critical, Platform, TimeCounter, TimePage};
pub use timer::{TIMER_RATE, Timer, TimerSave};
pub use types::{HZ, Instant, TICK, TICK_NANOS, Ticks, WallTime};

use adjust::Adjustment;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::time::Duration;
use critical::CriticalLock;

fn saturating_nanos(value: Duration) -> u64 {
    u64::try_from(value.as_nanos()).unwrap_or(u64::MAX)
}

/// The clock's mutable state, guarded by its critical lock.
struct State {
    adjust: Adjustment,
}

/// The machine clock.
///
/// CPU 0 (or whichever CPU the kernel designates) calls
/// [`tick`](Self::tick); every other use is a read.  The tick count is
/// the hard time wheels derive their deadlines from.
pub struct Clock<P: Platform> {
    platform: P,
    mono: AtomicU64,
    wall: AtomicU64,
    elapsed: AtomicU64,
    last_hpc: AtomicU32,
    state: CriticalLock<State>,
}

impl<P: Platform> Clock<P> {
    /// A clock at tick zero with a stopped wall clock.
    pub const fn new(platform: P) -> Self {
        Self {
            platform,
            mono: AtomicU64::new(0),
            wall: AtomicU64::new(0),
            elapsed: AtomicU64::new(0),
            last_hpc: AtomicU32::new(0),
            state: CriticalLock::new(State {
                adjust: Adjustment::new(),
            }),
        }
    }

    /// Advances one tick by `nominal` before adjustment.
    ///
    /// Runs exactly once per clock tick on one CPU; a missed or extra
    /// call miscounts time.  The tick count advances by one, the domains
    /// by the adjusted delta, and the time page is published.
    pub fn tick(&self, nominal: Duration) {
        let usec = i32::try_from(nominal.as_micros()).unwrap_or(i32::MAX);
        let (critical, mut state) = self.state.lock(&self.platform);
        let delta = state.adjust.next(usec);
        let delta = Duration::from_micros(u64::try_from(delta).unwrap_or(0));
        let nanos = saturating_nanos(delta);
        self.mono.fetch_add(nanos, Ordering::Relaxed);
        self.wall.fetch_add(nanos, Ordering::Relaxed);
        self.elapsed.fetch_add(1, Ordering::Relaxed);
        let hpc = self.platform.counter();
        drop(state);
        self.last_hpc.store(hpc, Ordering::Release);
        drop(critical);
        self.platform.publish(self.wall(), self.mono());
    }

    /// The interpolated monotonic clock.
    pub fn mono(&self) -> Instant {
        Instant::from_nanos(self.interpolated(&self.mono))
    }

    /// The interpolated wall clock.
    pub fn wall(&self) -> WallTime {
        WallTime::from_nanos(self.interpolated(&self.wall))
    }

    /// The tick the clock has advanced to.
    pub fn elapsed_ticks(&self) -> Ticks {
        Ticks::new(self.elapsed.load(Ordering::Relaxed))
    }

    /// Replaces the wall clock with `now` and programs the RTC.
    pub fn set_wall(&self, now: WallTime) {
        let (critical, _state) = self.state.lock(&self.platform);
        self.wall.store(now.as_nanos(), Ordering::Relaxed);
        drop(critical);
        self.platform.set_rtc(
            i64::try_from(now.as_nanos() / 1_000_000_000).unwrap_or(i64::MAX),
        );
        self.platform.publish(self.wall(), self.mono());
    }

    /// Replaces the clock adjustment with `nanos`, returning the previous
    /// adjustment.
    pub fn set_adjustment(&self, nanos: i64) -> i64 {
        let (critical, mut state) = self.state.lock(&self.platform);
        let old = state.adjust.set(nanos);
        drop(state);
        drop(critical);
        old
    }

    /// The interpolated value of an atomic base, retrying while a tick
    /// publishes.
    fn interpolated(&self, base: &AtomicU64) -> u64 {
        loop {
            let last = self.last_hpc.load(Ordering::Acquire);
            let value = base.load(Ordering::Relaxed);
            let now = self.platform.counter();
            if self.last_hpc.load(Ordering::Acquire) == last {
                return value.saturating_add(counter_delta_nanos(
                    last,
                    now,
                    self.platform.counter_period_nsec(),
                ));
            }
        }
    }
}

impl<P: Platform> TickSource for Clock<P> {
    fn now(&self) -> Ticks {
        self.elapsed_ticks()
    }
}

impl<P: Platform> Critical for Clock<P> {
    type Guard = P::Guard;

    fn enter_critical(&self) -> P::Guard {
        self.platform.enter_critical()
    }
}

/// The nanoseconds between the last tick's counter reading and `now`,
/// bounded below one tick.
fn counter_delta_nanos(last: u32, now: u32, period_nsec: u32) -> u64 {
    let ns = now.wrapping_sub(last).wrapping_mul(period_nsec);
    if u64::from(ns) >= TICK_NANOS {
        TICK_NANOS - 1
    } else {
        u64::from(ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Fake, NoCritical};
    use core::pin::Pin;

    #[test]
    fn clock_tick_advances_interpolates_and_publishes() {
        let clock = Clock::new(Fake::with_period_nsec(10));
        assert_eq!(clock.elapsed_ticks(), Ticks::ZERO);
        clock.tick(TICK);
        assert_eq!(clock.elapsed_ticks(), Ticks::new(1));
        assert_eq!(clock.mono(), Instant::from_nanos(TICK_NANOS));
        assert_eq!(clock.wall(), WallTime::from_nanos(TICK_NANOS));
        assert_eq!(clock.platform.published().0.as_nanos(), TICK_NANOS);
        assert_eq!(clock.platform.published().1.as_nanos(), TICK_NANOS);

        clock.platform.set_counter(3);
        assert_eq!(clock.mono().as_nanos(), TICK_NANOS + 30);
        assert_eq!(clock.wall().as_nanos(), TICK_NANOS + 30);

        clock.platform.set_counter(1_000_000);
        assert_eq!(clock.mono().as_nanos(), 2 * TICK_NANOS - 1);
    }

    #[test]
    fn clock_set_wall_programs_the_rtc() {
        let clock = Clock::new(Fake::with_period_nsec(1));
        clock.tick(TICK);
        let epoch = WallTime::from_nanos(1_700_000_000_000_000_000);
        clock.set_wall(epoch);
        assert_eq!(clock.wall(), epoch);
        assert_eq!(clock.mono(), Instant::from_nanos(TICK_NANOS));
        assert_eq!(clock.platform.rtc_seconds(), 1_700_000_000);
        assert_eq!(clock.platform.published().0, epoch);
    }

    #[test]
    fn clock_adjustment_bends_the_tick_and_returns_the_old() {
        let clock = Clock::new(Fake::with_period_nsec(1));
        assert_eq!(clock.set_adjustment(1_000_000), 0);
        clock.tick(TICK);
        assert_eq!(clock.mono().as_nanos(), TICK_NANOS + 5_000);
        // One tick drained its tickdelta of the outstanding 1000 us.
        assert_eq!(clock.set_adjustment(0), 995_000);
    }

    #[test]
    fn clock_is_a_tick_source() {
        let clock = Clock::new(Fake::with_period_nsec(1));
        assert_eq!(TickSource::now(&clock), Ticks::ZERO);
        clock.tick(TICK);
        assert_eq!(TickSource::now(&clock), Ticks::new(1));
    }

    #[test]
    fn a_wheel_runs_on_the_clock() {
        fn fire(callout: Pin<&Callout<'_, &Clock<Fake>, AtomicU32>>) {
            callout.data().fetch_add(1, Ordering::Relaxed);
        }

        let clock = Clock::new(Fake::with_period_nsec(1));
        let wheel =
            core::pin::pin!(HashedWheel::new(&clock, clock.elapsed_ticks()));
        let callout = core::pin::pin!(Callout::new(
            wheel.as_ref(),
            fire,
            AtomicU32::new(0)
        ));
        callout.as_ref().start(Ticks::new(1));
        clock.tick(TICK);
        assert!(wheel.as_ref().advance());
        assert_eq!(callout.data().load(Ordering::Relaxed), 1);
    }

    #[test]
    fn reads_retry_when_a_tick_lands_mid_read() {
        struct Stale {
            clock: std::sync::OnceLock<&'static Clock<Self>>,
            calls: AtomicU32,
        }

        impl TimeCounter for Stale {
            fn counter(&self) -> u32 {
                if self.calls.fetch_add(1, Ordering::Relaxed) == 0
                    && let Some(clock) = self.clock.get()
                {
                    clock.last_hpc.store(1, Ordering::Release);
                }
                0
            }

            fn counter_period_nsec(&self) -> u32 {
                1
            }
        }

        impl Critical for Stale {
            type Guard = NoCritical;

            fn enter_critical(&self) -> NoCritical {
                NoCritical
            }
        }

        impl Calendar for Stale {
            fn set_rtc(&self, _seconds: i64) {}
        }

        impl TimePage for Stale {
            fn publish(&self, _wall: WallTime, _uptime: Instant) {}
        }

        let clock: &'static Clock<Stale> =
            Box::leak(Box::new(Clock::new(Stale {
                clock: std::sync::OnceLock::new(),
                calls: AtomicU32::new(0),
            })));
        assert!(clock.platform.clock.set(clock).is_ok());
        clock.set_wall(WallTime::ZERO);
        assert_eq!(clock.mono(), Instant::from_nanos(TICK_NANOS - 1));
    }
}
