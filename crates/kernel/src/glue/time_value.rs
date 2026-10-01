// SPDX-License-Identifier: CMU-Mach
// Derived from include/mach/time_value.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The time records of `include/mach/time_value.h`.

use core::ffi::{c_int, c_long};
use core::mem::offset_of;
use core::time::Duration;

/// `TIME_NANOS_MAX` in <`mach/time_value.h>`: one second in nanoseconds, the
/// carry bound of the `time_value64` macros.
pub const TIME_NANOS_MAX: i64 = 1_000_000_000;

/// `MACH_ADJTIME_NSECS_OMIT` in <`mach/time_value.h>`: the nanoseconds component
/// that asks `host_adjust_time64()` to report the outstanding adjustment
/// without changing it.
pub const MACH_ADJTIME_NSECS_OMIT: i64 = TIME_NANOS_MAX;

/// `struct rpc_time_value` of <`mach/time_value.h`> as the kernel compiles it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct RpcTimeValue {
    pub seconds: c_long,
    pub microseconds: c_int,
}

/// `struct time_value` of <`mach/time_value.h>`: the legacy seconds/microseconds
/// record the kernel interfaces use.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct TimeValue {
    pub seconds: c_long,
    pub microseconds: c_int,
}

/// `struct time_value64` of <`mach/time_value.h>`: 64-bit seconds and
/// nanoseconds.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct TimeValue64 {
    pub seconds: i64,
    pub nanoseconds: i64,
}

impl TimeValue64 {
    /// The `time_value64_add_nanos()` macro of <`mach/time_value.h>`: add
    /// `nanos` and carry one whole second.
    #[must_use]
    pub const fn add_nanos(self, nanos: i64) -> Self {
        let nanoseconds = self.nanoseconds.wrapping_add(nanos);
        if nanoseconds >= TIME_NANOS_MAX {
            Self {
                seconds: self.seconds.wrapping_add(1),
                nanoseconds: nanoseconds.wrapping_sub(TIME_NANOS_MAX),
            }
        } else {
            Self {
                seconds: self.seconds,
                nanoseconds,
            }
        }
    }

    /// The `time_value64_add()` macro of <`mach/time_value.h>`: add the whole
    /// seconds, then the nanoseconds with their carry.
    #[must_use]
    pub const fn add(self, addend: Self) -> Self {
        Self {
            seconds: self.seconds.wrapping_add(addend.seconds),
            nanoseconds: self.nanoseconds,
        }
        .add_nanos(addend.nanoseconds)
    }

    /// The `time_value64_sub()` macro of <`mach/time_value.h>`: subtract
    /// `subtrahend`, borrowing one second when the nanoseconds go negative.
    #[must_use]
    pub const fn sub(self, subtrahend: Self) -> Self {
        let nanoseconds =
            self.nanoseconds.wrapping_sub(subtrahend.nanoseconds);
        if nanoseconds < 0 {
            Self {
                seconds: self
                    .seconds
                    .wrapping_sub(subtrahend.seconds)
                    .wrapping_sub(1),
                nanoseconds: nanoseconds.wrapping_add(TIME_NANOS_MAX),
            }
        } else {
            Self {
                seconds: self.seconds.wrapping_sub(subtrahend.seconds),
                nanoseconds,
            }
        }
    }

    /// The whole record as nanoseconds since the epoch (or since boot).
    #[must_use]
    pub const fn to_nanos(self) -> u64 {
        let seconds = if self.seconds < 0 { 0 } else { self.seconds as u64 };
        let nanos =
            if self.nanoseconds < 0 { 0 } else { self.nanoseconds as u64 };
        seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(nanos)
    }

    /// The record for `nanos` nanoseconds since the epoch (or since boot).
    #[must_use]
    pub const fn from_nanos(nanos: u64) -> Self {
        Self {
            seconds: (nanos / 1_000_000_000) as i64,
            nanoseconds: (nanos % 1_000_000_000) as i64,
        }
    }
}

/// `mapped_time_value_t` of <`mach/time_value.h>`: the clock page the user side
/// maps, read with the double-check idiom the header documents.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MappedTimeValue {
    /// `seconds`: the microsecond clock's seconds.
    pub seconds: c_int,
    /// `microseconds`: the microsecond clock's fraction.
    pub microseconds: c_int,
    /// `check_seconds`: a reader's copy of `seconds`.
    pub check_seconds: c_int,
    /// `time_value`: the wall-clock time.
    pub time_value: TimeValue64,
    /// `check_seconds64`: a reader's copy of `time_value.seconds`.
    pub check_seconds64: i64,
    /// `uptime_value`: the time since boot.
    pub uptime_value: TimeValue64,
    /// `check_upseconds64`: a reader's copy of `uptime_value.seconds`.
    pub check_upseconds64: i64,
}

/// The `convert_time_value_to_user()` inline of <`mach/time_value.h`>.
impl From<TimeValue> for RpcTimeValue {
    fn from(value: TimeValue) -> Self {
        Self {
            seconds: value.seconds,
            microseconds: value.microseconds,
        }
    }
}

/// The `convert_time_value_from_user()` inline of <`mach/time_value.h`>.
impl From<RpcTimeValue> for TimeValue {
    fn from(value: RpcTimeValue) -> Self {
        Self {
            seconds: value.seconds,
            microseconds: value.microseconds,
        }
    }
}

/// The `TIME_VALUE_TO_TIME_VALUE64()` macro of <`mach/time_value.h`>.
impl From<TimeValue> for TimeValue64 {
    #[expect(clippy::useless_conversion)]
    fn from(value: TimeValue) -> Self {
        Self {
            seconds: i64::from(value.seconds),
            nanoseconds: i64::from(value.microseconds) * 1000,
        }
    }
}

/// The `TIME_VALUE64_TO_TIME_VALUE()` macro of <`mach/time_value.h`>.
impl From<TimeValue64> for TimeValue {
    fn from(value: TimeValue64) -> Self {
        Self {
            seconds: value.seconds,
            microseconds: (value.nanoseconds / 1000) as c_int,
        }
    }
}

/// Why a [`TimeValue64`] is not a [`Duration`], and the other way round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeValueError {
    /// The seconds are negative, which a `Duration` cannot hold.
    Negative,
    /// The nanoseconds are negative or at least one second, which the C macros
    /// renormalize away.
    NanosecondsOutOfRange,
    /// The seconds exceed `i64`, which a `time_value64_t` cannot hold.
    SecondsOverflow,
}

/// A `time_value64_t` becomes a `Duration` only when the C side left it
/// normalized and non-negative.
impl TryFrom<TimeValue64> for Duration {
    type Error = TimeValueError;

    fn try_from(value: TimeValue64) -> Result<Self, Self::Error> {
        let seconds = u64::try_from(value.seconds)
            .map_err(|_| TimeValueError::Negative)?;
        let nanoseconds = u32::try_from(value.nanoseconds)
            .map_err(|_| TimeValueError::NanosecondsOutOfRange)?;
        if i64::from(nanoseconds) >= TIME_NANOS_MAX {
            return Err(TimeValueError::NanosecondsOutOfRange);
        }
        Ok(Self::new(seconds, nanoseconds))
    }
}

/// A `Duration` is always a `time_value64_t` until its seconds stop fitting
/// `i64`.
impl TryFrom<Duration> for TimeValue64 {
    type Error = TimeValueError;

    fn try_from(value: Duration) -> Result<Self, Self::Error> {
        let seconds = i64::try_from(value.as_secs())
            .map_err(|_| TimeValueError::SecondsOverflow)?;
        Ok(Self {
            seconds,
            nanoseconds: i64::from(value.subsec_nanos()),
        })
    }
}

const _: () = {
    assert!(size_of::<RpcTimeValue>() == 16);
    assert!(align_of::<RpcTimeValue>() == 8);
    assert!(offset_of!(RpcTimeValue, seconds) == 0);
    assert!(offset_of!(RpcTimeValue, microseconds) == 8);
    assert!(size_of::<TimeValue>() == 16);
    assert!(align_of::<TimeValue>() == 8);
    assert!(offset_of!(TimeValue, seconds) == 0);
    assert!(offset_of!(TimeValue, microseconds) == 8);
};

const _: () = assert!(size_of::<TimeValue64>() == 16);
const _: () = assert!(offset_of!(TimeValue64, seconds) == 0);
const _: () = assert!(offset_of!(TimeValue64, nanoseconds) == 8);
const _: () = assert!(align_of::<TimeValue64>() == 8);

const _: () = {
    assert!(size_of::<MappedTimeValue>() == 64);
    assert!(offset_of!(MappedTimeValue, seconds) == 0);
    assert!(offset_of!(MappedTimeValue, microseconds) == 4);
    assert!(offset_of!(MappedTimeValue, check_seconds) == 8);
    assert!(offset_of!(MappedTimeValue, time_value) == 16);
    assert!(offset_of!(MappedTimeValue, check_seconds64) == 32);
    assert!(offset_of!(MappedTimeValue, uptime_value) == 40);
    assert!(offset_of!(MappedTimeValue, check_upseconds64) == 56);
};
