// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The statistical CPU timers: per-thread user and system time.

use core::sync::atomic::{Ordering, fence};
use core::time::Duration;

/// The timer's tick rate, in microseconds per second.
pub const TIMER_RATE: u32 = 1_000_000;

/// `TIMER_LOW_FULL`: the microsecond count's carry bit.
const TIMER_LOW_FULL: u32 = 0x8000_0000;

/// The statistical CPU timer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Timer {
    low_bits: u32,
    high_bits: u32,
    high_bits_check: u32,
}

impl Timer {
    /// A zeroed timer.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            low_bits: 0,
            high_bits: 0,
            high_bits_check: 0,
        }
    }

    /// Zeroes every field.
    pub const fn init(&mut self) {
        *self = Self::zeroed();
    }

    /// Adds `usec` microseconds, carrying into the seconds count.
    pub fn bump(&mut self, usec: u32) {
        self.low_bits = self.low_bits.wrapping_add(usec);
        if self.low_bits & TIMER_LOW_FULL != 0 {
            self.normalize();
        }
    }

    /// Folds whole seconds out of the microsecond count.
    pub fn normalize(&mut self) {
        let high_increment = self.low_bits / TIMER_RATE;
        self.high_bits_check =
            self.high_bits_check.wrapping_add(high_increment);
        // The SeqCst fence publishes the new check before the low count is
        // reduced, pairing with the second fence in `grab`.
        fence(Ordering::SeqCst);
        self.low_bits %= TIMER_RATE;
        // The SeqCst fence publishes the reduced low count before the new
        // high count, pairing with the first fence in `grab`.
        fence(Ordering::SeqCst);
        self.high_bits = self.high_bits.wrapping_add(high_increment);
    }

    /// The timer's value as a duration.
    #[must_use]
    pub fn read(&self) -> Duration {
        let mut save = TimerSave::default();
        grab(self, &mut save);
        to_duration(save)
    }
}

/// A saved timer reading.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TimerSave {
    low: u32,
    high: u32,
}

impl TimerSave {
    /// The microseconds elapsed since this reading, which is updated to
    /// the current timer value.
    ///
    /// # Safety
    ///
    /// `timer` and `self` must be the live pair of one thread, and the
    /// caller must serialize updates to them, as the thread lock does.
    pub unsafe fn delta(&mut self, timer: &Timer) -> u32 {
        let low = timer.low_bits;
        if self.high == timer.high_bits_check {
            let elapsed = low.wrapping_sub(self.low);
            self.low = low;
            elapsed
        } else {
            delta(timer, self)
        }
    }
}

/// One reading attempt; returns whether `high_bits_check` confirmed the
/// `(high, low)` pair.
fn try_grab(timer: &Timer, save: &mut TimerSave) -> bool {
    // SAFETY: the owning CPU writes these fields while the reader runs,
    // so the reads are volatile; the fences order them against each
    // other, pairing with `normalize`.
    unsafe {
        save.high =
            core::ptr::read_volatile(core::ptr::addr_of!(timer.high_bits));
        // The fence orders the high read before the low read.
        fence(Ordering::SeqCst);
        save.low =
            core::ptr::read_volatile(core::ptr::addr_of!(timer.low_bits));
        // The fence orders the low read before the check read.
        fence(Ordering::SeqCst);
        save.high
            == core::ptr::read_volatile(core::ptr::addr_of!(
                timer.high_bits_check
            ))
    }
}

/// Reads a coherent `(high, low)` pair from `timer` into `save`, retrying
/// until `high_bits_check` confirms it.
fn grab(timer: &Timer, save: &mut TimerSave) {
    while !try_grab(timer, save) {}
}

/// Takes the difference between `save` and the live `timer`, updating
/// `save` to the fresh reading.
fn delta(timer: &Timer, save: &mut TimerSave) -> u32 {
    let mut new_save = TimerSave::default();
    grab(timer, &mut new_save);
    let result = new_save
        .high
        .wrapping_sub(save.high)
        .wrapping_mul(TIMER_RATE)
        .wrapping_add(new_save.low)
        .wrapping_sub(save.low);
    *save = new_save;
    result
}

/// Converts a saved reading into a [`Duration`].
fn to_duration(save: TimerSave) -> Duration {
    let seconds = u64::from(save.high.wrapping_add(save.low / TIMER_RATE));
    let nanos = (save.low % TIMER_RATE) * 1000;
    Duration::new(seconds, nanos)
}
