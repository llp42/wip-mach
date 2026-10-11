// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The time records of the Mach interface.
//!
//! `time_value64` is the seconds-and-nanoseconds record task and thread
//! accounting keeps; the older seconds-and-microseconds records are the
//! ones the interfaces still carry.

use core::ffi::{c_int, c_long};
use core::mem::{offset_of, size_of};
use zerocopy::{Immutable, IntoBytes};

/// One second in nanoseconds, the carry bound of the `time_value64` macros.
pub const TIME_NANOS_MAX: i64 = 1_000_000_000;

/// `struct time_value64`: 64-bit seconds and nanoseconds.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, IntoBytes, Immutable)]
#[allow(missing_docs)]
pub struct TimeValue64 {
    pub seconds: i64,
    pub nanoseconds: i64,
}

impl TimeValue64 {
    /// Adds `nanos`, carrying one whole second.
    #[must_use]
    const fn add_nanos(self, nanos: i64) -> Self {
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

    /// Adds the whole seconds, then the nanoseconds with their carry.
    #[must_use]
    pub const fn add(self, addend: Self) -> Self {
        Self {
            seconds: self.seconds.wrapping_add(addend.seconds),
            nanoseconds: self.nanoseconds,
        }
        .add_nanos(addend.nanoseconds)
    }

    /// Subtracts `subtrahend`, borrowing one second when the nanoseconds go
    /// negative.
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
        let seconds = if self.seconds < 0 {
            0
        } else {
            self.seconds as u64
        };
        let nanos = if self.nanoseconds < 0 {
            0
        } else {
            self.nanoseconds as u64
        };
        seconds.saturating_mul(1_000_000_000).saturating_add(nanos)
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

const _: () = assert!(size_of::<TimeValue64>() == 16);
const _: () = assert!(offset_of!(TimeValue64, seconds) == 0);
const _: () = assert!(offset_of!(TimeValue64, nanoseconds) == 8);
const _: () = assert!(align_of::<TimeValue64>() == 8);

/// `struct rpc_time_value`: the time value RPCs carry, as the kernel compiles
/// it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, IntoBytes, Immutable)]
#[allow(missing_docs)]
pub struct RpcTimeValue {
    pub seconds: c_long,
    pub microseconds: c_int,
    /// The C compiler's tail padding, kept zero so no stale kernel byte
    /// reaches a task.
    padding: c_int,
}

/// `struct time_value`: the legacy seconds/microseconds record the kernel
/// interfaces use.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, IntoBytes, Immutable)]
#[allow(missing_docs)]
pub struct TimeValue {
    pub seconds: c_long,
    pub microseconds: c_int,
    /// The C compiler's tail padding, kept zero so no stale kernel byte
    /// reaches a task.
    padding: c_int,
}

/// Converts the value to the form RPCs carry.
impl From<TimeValue> for RpcTimeValue {
    fn from(value: TimeValue) -> Self {
        Self {
            seconds: value.seconds,
            microseconds: value.microseconds,
            padding: 0,
        }
    }
}

/// Converts the value from the form RPCs carry.
impl From<RpcTimeValue> for TimeValue {
    fn from(value: RpcTimeValue) -> Self {
        Self {
            seconds: value.seconds,
            microseconds: value.microseconds,
            padding: 0,
        }
    }
}

/// Widens the microseconds to nanoseconds.
impl From<TimeValue> for TimeValue64 {
    #[expect(clippy::useless_conversion)]
    fn from(value: TimeValue) -> Self {
        Self {
            seconds: i64::from(value.seconds),
            nanoseconds: i64::from(value.microseconds) * 1000,
        }
    }
}

/// Narrows the nanoseconds to microseconds, truncating.
impl From<TimeValue64> for TimeValue {
    fn from(value: TimeValue64) -> Self {
        Self {
            seconds: value.seconds,
            microseconds: (value.nanoseconds / 1000) as c_int,
            padding: 0,
        }
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
