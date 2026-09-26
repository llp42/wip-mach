// SPDX-License-Identifier: MIT
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

#[cfg(test)]
mod tests {
    use super::*;

    const HALF: u32 = TIMER_LOW_FULL;

    #[test]
    fn zeroed_and_default_agree() {
        assert_eq!(Timer::zeroed(), Timer::default());
        assert_eq!(TimerSave::default(), TimerSave { low: 0, high: 0 });
    }

    #[test]
    fn init_zeroes_every_field() {
        let mut timer = Timer {
            low_bits: 1,
            high_bits: 2,
            high_bits_check: 3,
        };
        timer.init();
        assert_eq!(timer, Timer::zeroed());
        assert_eq!(timer.read(), Duration::ZERO);
    }

    #[test]
    fn bump_without_carry_adds_microseconds() {
        let mut timer = Timer::zeroed();
        timer.bump(999_999);
        assert_eq!(
            timer,
            Timer {
                low_bits: 999_999,
                high_bits: 0,
                high_bits_check: 0,
            }
        );
        assert_eq!(timer.read(), Duration::from_micros(999_999));
    }

    #[test]
    fn bump_at_the_carry_bit_normalizes() {
        let mut timer = Timer::zeroed();
        timer.bump(HALF);
        assert_eq!(timer.low_bits, 483_648);
        assert_eq!(timer.high_bits, 2_147);
        assert_eq!(timer.high_bits_check, 2_147);
        assert_eq!(timer.read(), Duration::from_micros(u64::from(HALF)));
    }

    #[test]
    fn read_after_several_carries_stays_exact() {
        let mut timer = Timer::zeroed();
        for _ in 0..5 {
            timer.bump(HALF);
        }
        assert_eq!(timer.high_bits, 10_737);
        assert_eq!(timer.low_bits, 418_240);
        assert_eq!(timer.read(), Duration::from_micros(u64::from(HALF) * 5));
    }

    #[test]
    fn read_converts_seconds_and_nanos() {
        let timer = Timer {
            low_bits: 1_234,
            high_bits: 7,
            high_bits_check: 7,
        };
        assert_eq!(timer.read(), Duration::new(7, 1_234_000));
    }

    #[test]
    fn read_folds_an_unreduced_microsecond_count() {
        let timer = Timer {
            low_bits: 1_500_000,
            high_bits: 2,
            high_bits_check: 2,
        };
        assert_eq!(timer.read(), Duration::new(3, 500_000_000));
    }

    #[test]
    fn normalize_carries_whole_seconds() {
        let mut timer = Timer {
            low_bits: TIMER_RATE * 3 + 7,
            high_bits: 5,
            high_bits_check: 5,
        };
        timer.normalize();
        assert_eq!(timer.low_bits, 7);
        assert_eq!(timer.high_bits, 8);
        assert_eq!(timer.high_bits_check, 8);
        assert_eq!(timer.read(), Duration::new(8, 7_000));
    }

    #[test]
    fn normalize_wraps_the_seconds_count() {
        let mut timer = Timer {
            low_bits: TIMER_RATE,
            high_bits: u32::MAX,
            high_bits_check: u32::MAX,
        };
        timer.normalize();
        assert_eq!(timer.low_bits, 0);
        assert_eq!(timer.high_bits, 0);
        assert_eq!(timer.high_bits_check, 0);
        assert_eq!(timer.read(), Duration::ZERO);
    }

    #[test]
    fn bump_wraps_the_microsecond_count() {
        let mut timer = Timer {
            low_bits: u32::MAX - 1,
            high_bits: 0,
            high_bits_check: 0,
        };
        timer.bump(1);
        assert_eq!(timer.low_bits, 967_295);
        assert_eq!(timer.high_bits, 4_294);
        assert_eq!(timer.read(), Duration::from_micros(u64::from(u32::MAX)));
    }

    #[test]
    fn bump_past_u32_max_wraps_without_carrying() {
        let mut timer = Timer {
            low_bits: u32::MAX,
            high_bits: 0,
            high_bits_check: 0,
        };
        timer.bump(1);
        assert_eq!(timer.low_bits, 0);
        assert_eq!(timer.high_bits, 0);
    }

    #[test]
    fn an_incoherent_reading_is_rejected() {
        let timer = Timer {
            low_bits: 9,
            high_bits: 2,
            high_bits_check: 1,
        };
        let mut save = TimerSave::default();
        assert!(!try_grab(&timer, &mut save));
        let coherent = Timer {
            high_bits_check: 2,
            ..timer
        };
        assert!(try_grab(&coherent, &mut save));
        assert_eq!(save, TimerSave { low: 9, high: 2 });
    }

    #[test]
    fn read_retries_while_the_check_is_stale() {
        use std::cell::UnsafeCell;
        use std::sync::atomic::AtomicBool;
        use std::thread;

        struct Shared(UnsafeCell<Timer>);

        // SAFETY: the writer publishes one field while the reader only
        // accepts a pair its retry loop saw as coherent.
        unsafe impl Sync for Shared {}

        let shared = Shared(UnsafeCell::new(Timer {
            low_bits: 5,
            high_bits: 1,
            high_bits_check: 0,
        }));
        let entered = AtomicBool::new(false);

        thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let shared = &shared;
                entered.store(true, Ordering::Release);
                // SAFETY: the writer's store only ends the retry loop,
                // after which the pair reads coherently.
                unsafe { (*shared.0.get()).read() }
            });
            while !entered.load(Ordering::Acquire) {
                thread::yield_now();
            }
            thread::sleep(Duration::from_millis(50));
            // SAFETY: this is the same cell the reader retries inside.
            unsafe {
                (*shared.0.get()).high_bits_check = 1;
            }
            assert_eq!(reader.join().unwrap(), Duration::new(1, 5_000));
        });
    }

    #[test]
    fn delta_fast_path_uses_the_check() {
        let timer = Timer {
            low_bits: 12,
            high_bits: 3,
            high_bits_check: 3,
        };
        let mut save = TimerSave { low: 5, high: 3 };
        // SAFETY: the test owns the timer and the save and mutates
        // neither while the call runs.
        let elapsed = unsafe { save.delta(&timer) };
        assert_eq!(elapsed, 7);
        assert_eq!(save, TimerSave { low: 12, high: 3 });
    }

    #[test]
    fn delta_fast_path_wraps_the_microsecond_difference() {
        let timer = Timer {
            low_bits: 3,
            high_bits: 1,
            high_bits_check: 1,
        };
        let mut save = TimerSave {
            low: u32::MAX,
            high: 1,
        };
        // SAFETY: the test owns the timer and the save and mutates
        // neither while the call runs.
        let elapsed = unsafe { save.delta(&timer) };
        assert_eq!(elapsed, 4);
        assert_eq!(save, TimerSave { low: 3, high: 1 });
    }

    #[test]
    fn delta_slow_path_grabs_a_fresh_reading() {
        let timer = Timer {
            low_bits: 1,
            high_bits: 4,
            high_bits_check: 4,
        };
        let mut save = TimerSave {
            low: 999_999,
            high: 3,
        };
        // SAFETY: the test owns the timer and the save and mutates
        // neither while the call runs.
        let elapsed = unsafe { save.delta(&timer) };
        assert_eq!(elapsed, 2);
        assert_eq!(save, TimerSave { low: 1, high: 4 });
    }

    #[test]
    fn delta_slow_path_wraps_the_seconds_counter() {
        let timer = Timer {
            low_bits: 5,
            high_bits: 0,
            high_bits_check: 0,
        };
        let mut save = TimerSave {
            low: 0,
            high: u32::MAX,
        };
        // SAFETY: the test owns the timer and the save and mutates
        // neither while the call runs.
        let elapsed = unsafe { save.delta(&timer) };
        assert_eq!(elapsed, 1_000_005);
        assert_eq!(save, TimerSave { low: 5, high: 0 });
    }

    #[test]
    fn derives_cover_both_types() {
        let timer = Timer::zeroed();
        let copy = timer;
        #[allow(clippy::clone_on_copy)]
        let clone = timer.clone();
        assert_eq!(copy, clone);
        assert_ne!(
            copy,
            Timer {
                low_bits: 1,
                ..Timer::zeroed()
            }
        );
        assert!(format!("{copy:?}").contains("Timer"));

        let save = TimerSave::default();
        #[allow(clippy::clone_on_copy)]
        let save_clone = save.clone();
        assert_eq!(save, save_clone);
        assert_ne!(save, TimerSave { low: 1, high: 0 });
        assert!(format!("{save:?}").contains("TimerSave"));
    }
}
