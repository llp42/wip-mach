// SPDX-License-Identifier: MIT
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A 100 Hz tick, in microseconds.
    const TICK_US: i32 = 10_000;

    #[test]
    fn no_adjustment_returns_the_nominal_tick() {
        let mut adjust = Adjustment::new();
        assert_eq!(adjust.next(TICK_US), TICK_US);
        assert_eq!(adjust.get(), 0);
    }

    #[test]
    fn positive_adjustment_drains_over_its_step_count() {
        let mut adjust = Adjustment::new();
        assert_eq!(adjust.set(30_000_000), 0);
        assert_eq!(adjust.get(), 30_000_000);
        let mut ticks = 0;
        while adjust.get() != 0 {
            assert_eq!(adjust.next(TICK_US), TICK_US + TICKADJ);
            ticks += 1;
        }
        assert_eq!(ticks, 6_000);
        assert_eq!(adjust.next(TICK_US), TICK_US);
    }

    #[test]
    fn negative_adjustment_drains_over_its_step_count() {
        let mut adjust = Adjustment::new();
        assert_eq!(adjust.set(-30_000_000), 0);
        assert_eq!(adjust.get(), -30_000_000);
        let mut ticks = 0;
        while adjust.get() != 0 {
            assert_eq!(adjust.next(TICK_US), TICK_US - TICKADJ);
            ticks += 1;
        }
        assert_eq!(ticks, 6_000);
        assert_eq!(adjust.next(TICK_US), TICK_US);
    }

    #[test]
    fn short_ticks_defer_a_negative_correction() {
        let mut adjust = Adjustment::new();
        adjust.set(-30_000_000);
        assert_eq!(adjust.next(TICKADJ), 1);
        assert_eq!(adjust.get(), -29_996_000);
        assert_eq!(adjust.next(0), 1);
        assert_eq!(adjust.get(), -29_997_000);
    }

    #[test]
    fn set_replaces_the_adjustment_and_returns_the_previous_one() {
        let mut adjust = Adjustment::new();
        assert_eq!(adjust.set(30_000_000), 0);
        assert_eq!(adjust.set(-20_000_000), 30_000_000);
        assert_eq!(adjust.get(), -20_000_000);
        assert_eq!(adjust.set(0), -20_000_000);
        assert_eq!(adjust.get(), 0);
    }

    #[test]
    fn a_large_positive_request_selects_the_tenfold_step() {
        let mut adjust = Adjustment::new();
        adjust.set(2_000_000_000);
        assert_eq!(adjust.next(TICK_US), TICK_US + BIG_TICKADJ);
    }

    #[test]
    fn a_large_negative_request_selects_the_tenfold_step() {
        let mut adjust = Adjustment::new();
        adjust.set(-2_000_000_000);
        assert_eq!(adjust.next(TICK_US), TICK_US - BIG_TICKADJ);
    }

    #[test]
    fn the_bigadj_boundary_keeps_the_ordinary_step() {
        let mut adjust = Adjustment::new();
        adjust.set(1_000_000_000);
        assert_eq!(adjust.next(TICK_US), TICK_US + TICKADJ);
    }

    #[test]
    fn rounding_truncates_toward_zero_on_both_signs() {
        let mut positive = Adjustment::new();
        positive.set(1_000_001_000);
        assert_eq!(positive.get(), 1_000_000_000);

        let mut negative = Adjustment::new();
        negative.set(-1_000_001_000);
        assert_eq!(negative.get(), -1_000_000_000);
    }

    #[test]
    fn an_extreme_tick_wraps_like_the_i32_domain() {
        let mut adjust = Adjustment::new();
        adjust.set(1_000_000);
        assert_eq!(adjust.next(i32::MAX), i32::MIN + 4);
    }
}
