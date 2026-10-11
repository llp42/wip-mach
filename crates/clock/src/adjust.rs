// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The gradual clock adjustment (`adjtime`).

use crate::types::HZ;

/// The ordinary drain step, in microseconds: `500 / HZ` at 100 Hz.
#[expect(clippy::cast_possible_truncation, reason = "HZ is 100")]
const TICKADJ: i32 = (500 / HZ) as i32;

/// The outstanding adjustment above which the step is tenfold, in
/// microseconds.
const BIGADJ: i32 = 1_000_000;

/// The tenfold drain step.
const BIG_TICKADJ: i32 = TICKADJ * 10;

/// The outstanding adjustment and its per-tick step.
#[expect(
    clippy::redundant_pub_crate,
    reason = "keep the declared crate visibility"
)]
pub(crate) struct Adjustment {
    /// `timedelta`: the outstanding adjustment, in microseconds.
    timedelta: i32,
    /// `tickdelta`: the step applied while it drains, in microseconds.
    tickdelta: i32,
}

impl Adjustment {
    /// No adjustment.
    pub(crate) const fn new() -> Self {
        Self {
            timedelta: 0,
            tickdelta: 0,
        }
    }

    /// Consumes the outstanding adjustment and returns the microseconds
    /// this tick advances by.
    pub(crate) const fn next(&mut self, usec: i32) -> i32 {
        if self.timedelta == 0 {
            return usec;
        }

        if self.timedelta < 0 {
            if usec > self.tickdelta {
                self.timedelta = self.timedelta.wrapping_add(self.tickdelta);
                usec - self.tickdelta
            } else {
                self.timedelta =
                    self.timedelta.wrapping_add(usec).wrapping_sub(1);
                1
            }
        } else {
            let delta = usec.wrapping_add(self.tickdelta);
            self.timedelta = self.timedelta.wrapping_sub(self.tickdelta);
            delta
        }
    }

    /// The outstanding adjustment, in nanoseconds.
    pub(crate) fn get(&self) -> i64 {
        i64::from(self.timedelta) * 1000
    }

    /// Replaces the adjustment with `nanos`, returning the previous one.
    pub(crate) fn set(&mut self, nanos: i64) -> i64 {
        let old = self.get();
        let mut ndelta = nanos / 1000;

        // A new step is chosen only when no adjustment is draining;
        // otherwise the outstanding one keeps its step until it drains
        // to zero.
        if self.timedelta == 0 {
            self.tickdelta =
                if ndelta > i64::from(BIGADJ) || ndelta < -i64::from(BIGADJ) {
                    BIG_TICKADJ
                } else {
                    TICKADJ
                };
        }

        let tickdelta = i64::from(self.tickdelta);
        if ndelta % tickdelta != 0 {
            ndelta = ndelta / tickdelta * tickdelta;
        }

        #[expect(
            clippy::cast_possible_truncation,
            reason = "the stored tick delta is the low `i32` of the remainder"
        )]
        let timedelta = ndelta as i32;
        self.timedelta = timedelta;
        old
    }
}
