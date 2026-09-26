// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The fake platform the host tests drive.

use crate::platform::{Calendar, Critical, TimeCounter, TimePage};
use crate::types::{Instant, WallTime};
use core::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};

/// A platform whose hardware the tests control.
#[derive(Default)]
pub struct Fake {
    counter: AtomicU32,
    period_nsec: AtomicU32,
    rtc: AtomicI64,
    published_wall: AtomicU64,
    published_uptime: AtomicU64,
}

impl Fake {
    /// A fake at counter zero with the given counter unit.
    pub(crate) fn with_period_nsec(period_nsec: u32) -> Self {
        Self {
            period_nsec: AtomicU32::new(period_nsec),
            ..Self::default()
        }
    }

    /// Sets the counter value.
    pub(crate) fn set_counter(&self, value: u32) {
        self.counter.store(value, Ordering::Relaxed);
    }

    /// The seconds last programmed into the RTC.
    pub(crate) fn rtc_seconds(&self) -> i64 {
        self.rtc.load(Ordering::Relaxed)
    }

    /// The last pair published to the time page.
    pub(crate) fn published(&self) -> (WallTime, Instant) {
        (
            WallTime::from_nanos(self.published_wall.load(Ordering::Relaxed)),
            Instant::from_nanos(self.published_uptime.load(Ordering::Relaxed)),
        )
    }
}

/// The no-op critical guard of [`Fake`].
pub struct NoCritical;

impl Drop for NoCritical {
    fn drop(&mut self) {}
}

impl TimeCounter for Fake {
    fn counter(&self) -> u32 {
        self.counter.load(Ordering::Relaxed)
    }

    fn counter_period_nsec(&self) -> u32 {
        self.period_nsec.load(Ordering::Relaxed)
    }
}

impl Critical for Fake {
    type Guard = NoCritical;

    fn enter_critical(&self) -> NoCritical {
        NoCritical
    }
}

impl Calendar for Fake {
    fn set_rtc(&self, seconds: i64) {
        self.rtc.store(seconds, Ordering::Relaxed);
    }
}

impl TimePage for Fake {
    fn publish(&self, wall: WallTime, uptime: Instant) {
        self.published_wall
            .store(wall.as_nanos(), Ordering::Relaxed);
        self.published_uptime
            .store(uptime.as_nanos(), Ordering::Relaxed);
    }
}
