// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The statistical timers.

use crate::cell::SyncCell;
use crate::time_value::TimeValue64;
use crate::timer_save::TimerSave;
use core::cell::UnsafeCell;
use core::ffi::c_uint;
use core::mem::{offset_of, size_of};
use core::ptr;
use core::sync::atomic::{Ordering, fence};
use mach_page::smp::MAX_NCPUS;

/// The timer's tick rate, in microseconds per second.
pub const TIMER_RATE: c_uint = 1_000_000;

/// The statistical CPU timer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timer {
    /// `low_bits`: the microsecond count.
    pub low_bits: c_uint,
    /// `high_bits`: the seconds count.
    pub high_bits: c_uint,
    /// `high_bits_check`: a reader's copy of `high_bits`.
    pub high_bits_check: c_uint,
    /// `tstamp`: the last reading's timestamp.
    pub tstamp: c_uint,
}

/// The timer each CPU charges.
static CURRENT_TIMER: SyncCell<[*mut Timer; MAX_NCPUS]> =
    SyncCell(UnsafeCell::new([ptr::null_mut(); MAX_NCPUS]));

/// The timer each CPU runs on.
static KERNEL_TIMER: SyncCell<[Timer; MAX_NCPUS]> =
    SyncCell(UnsafeCell::new([Timer::zeroed(); MAX_NCPUS]));

impl Timer {
    /// The all-zero timer a static begins with.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            low_bits: 0,
            high_bits: 0,
            high_bits_check: 0,
            tstamp: 0,
        }
    }

    /// Zeroes every field.
    pub const fn init(&mut self) {
        self.low_bits = 0;
        self.high_bits = 0;
        self.tstamp = 0;
        self.high_bits_check = 0;
    }

    /// Folds whole seconds out of the microsecond count.
    pub fn normalize(&mut self) {
        let high_increment = self.low_bits / TIMER_RATE;
        self.high_bits_check =
            self.high_bits_check.wrapping_add(high_increment);
        // The SeqCst fence publishes the new check before the low count is
        // reduced, pairing with the second fence in `grab()`.
        fence(Ordering::SeqCst);
        self.low_bits %= TIMER_RATE;
        // The SeqCst fence publishes the new check before the new high count,
        // pairing with the first fence in `grab()`.
        fence(Ordering::SeqCst);
        self.high_bits = self.high_bits.wrapping_add(high_increment);
    }

    /// Adds `usec` microseconds, carrying into the seconds count once the low
    /// word fills.
    pub fn bump(&mut self, usec: c_uint) {
        self.low_bits = self.low_bits.wrapping_add(usec);
        if self.low_bits >= TIMER_RATE {
            self.normalize();
        }
    }
}

/// Reads a coherent pair of fields from `timer` into `save`.
fn grab(timer: &Timer, save: &mut TimerSave) {
    loop {
        save.high = timer.high_bits;
        // The SeqCst fence orders the high read before the low read.
        fence(Ordering::SeqCst);
        save.low = timer.low_bits;
        // The SeqCst fence orders the low read before the check read, so the
        // check is as late as the C barrier put it.
        fence(Ordering::SeqCst);
        if save.high == timer.high_bits_check {
            break;
        }
    }
}

/// Takes the difference between `save` and the live `timer`, updating `save`
/// to the reading.
pub(crate) fn delta(timer: &Timer, save: &mut TimerSave) -> c_uint {
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

/// The reading in `save` as a time value.
fn to_time_value(save: TimerSave) -> TimeValue64 {
    TimeValue64 {
        seconds: i64::from(save.high.wrapping_add(save.low / TIMER_RATE)),
        nanoseconds: i64::from(save.low % TIMER_RATE * 1000),
    }
}

/// Reads `timer` as seconds and nanoseconds.
#[must_use]
pub fn read(timer: &Timer) -> TimeValue64 {
    let mut save = TimerSave::default();
    grab(timer, &mut save);
    to_time_value(save)
}

/// Zeroes every kernel timer and clears every current-timer pointer.
///
/// # Safety
///
/// The caller must run this once at boot, before any other code accesses
/// `KERNEL_TIMER` or `CURRENT_TIMER`.
pub unsafe fn init_timers() {
    unsafe {
        let timers = KERNEL_TIMER.0.get().cast::<Timer>();
        let current = CURRENT_TIMER.0.get().cast::<*mut Timer>();

        for i in 0..MAX_NCPUS {
            (*timers.add(i)).init();
            current.add(i).write(ptr::null_mut());
        }
    }
}

const _: () = assert!(size_of::<Timer>() == 16);
const _: () = assert!(align_of::<Timer>() == 4);
const _: () = assert!(offset_of!(Timer, low_bits) == 0);
const _: () = assert!(offset_of!(Timer, high_bits) == 4);
const _: () = assert!(offset_of!(Timer, high_bits_check) == 8);
const _: () = assert!(offset_of!(Timer, tstamp) == 12);
