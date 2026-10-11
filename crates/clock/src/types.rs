// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Machine-independent time units: ticks, uptime and wall time.

use core::time::Duration;

/// The clock interrupt's frequency, in ticks per second.
pub const HZ: u64 = 100;

/// The nanoseconds a nominal tick advances the clocks by.
pub const TICK_NANOS: u64 = 1_000_000_000 / HZ;

/// The nominal duration of one clock tick.
pub const TICK: Duration = Duration::from_nanos(TICK_NANOS);

/// A count of clock ticks.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ticks(u64);

impl Ticks {
    /// The zero tick count.
    pub const ZERO: Self = Self(0);

    /// A tick count with the given raw value.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// The raw tick count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Adds two tick counts, wrapping around at [`u64::MAX`].
    #[must_use]
    pub const fn wrapping_add(self, other: Self) -> Self {
        Self(self.0.wrapping_add(other.0))
    }

    /// The whole ticks a duration spans, rounded up.
    #[must_use]
    pub const fn from_milliseconds_ceil(milliseconds: u64) -> Self {
        Self(milliseconds.saturating_mul(HZ).div_ceil(1_000))
    }

    /// The duration the tick count spans, saturating at
    /// [`Duration::MAX`](core::time::Duration).
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        Duration::from_nanos(self.0.saturating_mul(TICK_NANOS))
    }
}

/// The monotonic clock: nanoseconds since boot.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Instant(u64);

impl Instant {
    /// The boot instant.
    pub const ZERO: Self = Self(0);

    /// An instant with the given nanoseconds since boot.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// The nanoseconds since boot.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// The duration since boot.
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        Duration::from_nanos(self.0)
    }

    /// Adds a duration, saturating at [`u64::MAX`] nanoseconds.
    #[must_use]
    pub fn saturating_add(self, delta: Duration) -> Self {
        Self(self.0.saturating_add(
            u64::try_from(delta.as_nanos()).unwrap_or(u64::MAX),
        ))
    }
}

/// The wall clock: nanoseconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct WallTime(u64);

impl WallTime {
    /// The Unix epoch.
    pub const ZERO: Self = Self(0);

    /// A wall time with the given nanoseconds since the Unix epoch.
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// The nanoseconds since the Unix epoch.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// The duration since the Unix epoch.
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        Duration::from_nanos(self.0)
    }

    /// Adds a duration, saturating at [`u64::MAX`] nanoseconds.
    #[must_use]
    pub fn saturating_add(self, delta: Duration) -> Self {
        Self(self.0.saturating_add(
            u64::try_from(delta.as_nanos()).unwrap_or(u64::MAX),
        ))
    }
}
