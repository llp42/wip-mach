// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The machine clock: the monotonic and wall domains, the tick count,
//! the `adjtime`-style adjustment and the time page.
//!
//! One [`Clock`] runs per machine and only one CPU calls
//! [`tick`](Clock::tick).  It is also a [`TickSource`] and names its
//! [`Locking`] platform, so a [`HashedWheel`] can run on it directly.
//! Wheels are separate objects with no shared state, so the crate never
//! counts CPUs.  A [`Callout`] is the way to arm one: it owns its record
//! and cannot be freed while its wheel can reach it.

#![no_std]

mod adjust;
pub mod callout;
pub mod hashed_wheel;
pub mod platform;
mod timer;
pub mod types;

pub use callout::{Callout, CalloutAction};
pub use hashed_wheel::{HashedWheel, TickSource};
pub use platform::{Calendar, Locking, Platform, TimeCounter, TimePage};
pub use timer::{TIMER_RATE, Timer, TimerSave};
pub use types::{HZ, Instant, TICK, TICK_NANOS, Ticks, WallTime};

use adjust::Adjustment;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use core::time::Duration;
use lock::IrqSpinLock;
use lock::irq_spin_lock;

fn saturating_nanos(value: Duration) -> u64 {
    u64::try_from(value.as_nanos()).unwrap_or(u64::MAX)
}

/// The clock's mutable state, guarded by its irq spin lock.
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
    state: IrqSpinLock<State, P::Lock>,
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
            state: irq_spin_lock!(
                "clock",
                State {
                    adjust: Adjustment::new(),
                }
            ),
        }
    }

    /// Advances one tick by `nominal` before adjustment.
    ///
    /// Runs exactly once per clock tick on one CPU; a missed or extra
    /// call miscounts time.  The tick count advances by one, the domains
    /// by the adjusted delta, and the time page is published.
    pub fn tick(&self, nominal: Duration) {
        let usec = i32::try_from(nominal.as_micros()).unwrap_or(i32::MAX);
        let mut state = self.state.lock();
        let delta = state.adjust.next(usec);
        let delta = Duration::from_micros(u64::try_from(delta).unwrap_or(0));
        let nanos = saturating_nanos(delta);
        self.mono.fetch_add(nanos, Ordering::Relaxed);
        self.wall.fetch_add(nanos, Ordering::Relaxed);
        self.elapsed.fetch_add(1, Ordering::Relaxed);
        let hpc = self.platform.counter();
        self.last_hpc.store(hpc, Ordering::Release);
        drop(state);
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
        let state = self.state.lock();
        self.wall.store(now.as_nanos(), Ordering::Relaxed);
        drop(state);
        self.platform.set_rtc(
            i64::try_from(now.as_nanos() / 1_000_000_000).unwrap_or(i64::MAX),
        );
        self.platform.publish(self.wall(), self.mono());
    }

    /// Replaces the clock adjustment with `nanos`, returning the previous
    /// adjustment.
    pub fn set_adjustment(&self, nanos: i64) -> i64 {
        self.state.lock().adjust.set(nanos)
    }

    /// The outstanding gradual adjustment, in nanoseconds.
    pub fn adjustment(&self) -> i64 {
        self.state.lock().adjust.get()
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

impl<P: Platform> Locking for Clock<P> {
    type Lock = P::Lock;
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
