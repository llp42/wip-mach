// SPDX-License-Identifier: CMU-Mach
// Derived from kern/timer.c and kern/timer.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The statistical timers, which `kern/timer.c` used to define for
//! `kern/timer.h`.

use crate::config::MAX_NCPUS;
use crate::glue::time_value::TimeValue64;
use crate::kern::thread::Thread;
use crate::utils::cell::SyncCell;
use core::cell::UnsafeCell;
use core::ffi::c_uint;
use core::mem::offset_of;
use core::ptr;
use core::sync::atomic::{Ordering, fence};

/// `TIMER_RATE` in <kern/timer.h>: the timer's tick rate, in microseconds per
/// second.
pub(crate) const TIMER_RATE: c_uint = 1_000_000;

/// `struct timer` of <kern/timer.h>: the statistical CPU timer.
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

/// `struct timer_save` of <kern/timer.h>: a saved timer reading.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct TimerSave {
    pub low: c_uint,
    pub high: c_uint,
}

/// `current_timer[NCPUS]` of kern/timer.c: the timer each CPU charges.
static CURRENT_TIMER: SyncCell<[*mut Timer; MAX_NCPUS]> =
    SyncCell(UnsafeCell::new([ptr::null_mut(); MAX_NCPUS]));

/// `kernel_timer[NCPUS]` of kern/timer.c: the timer each CPU runs on.
static KERNEL_TIMER: SyncCell<[Timer; MAX_NCPUS]> =
    SyncCell(UnsafeCell::new([Timer::zeroed(); MAX_NCPUS]));

impl Timer {
    /// The zero image a C `static` of `struct timer` began with.
    const fn zeroed() -> Self {
        Self {
            low_bits: 0,
            high_bits: 0,
            high_bits_check: 0,
            tstamp: 0,
        }
    }

    /// Zero every field, as `timer_init()` of <kern/timer.c> did.
    pub const fn init(&mut self) {
        self.low_bits = 0;
        self.high_bits = 0;
        self.tstamp = 0;
        self.high_bits_check = 0;
    }

    /// Fold whole seconds out of the microsecond count, as `timer_normalize()`
    /// of <kern/timer.c> did.
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

    /// Add `usec` microseconds, carrying into the seconds count once the
    /// low word fills (`timer_bump()` of <kern/timer.h>).
    pub fn bump(&mut self, usec: c_uint) {
        self.low_bits = self.low_bits.wrapping_add(usec);
        if self.low_bits >= TIMER_RATE {
            self.normalize();
        }
    }
}

impl TimerSave {
    /// The ticks elapsed since this reading, which is updated to the current
    /// timer value.
    ///
    /// # Safety
    ///
    /// `timer` and `self` must be the live pair of one thread, and the caller
    /// must serialize updates to them, as the thread lock does.
    #[must_use]
    pub unsafe fn delta(&mut self, timer: &Timer) -> c_uint {
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

/// Read a coherent pair of fields from `timer` into `save`, as `timer_grab()`
/// of <kern/timer.c> did.
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

/// Take the difference between `save` and the live `timer`, updating `save` to
/// the reading, as `timer_delta()` of <kern/timer.c> did.
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

/// The `TIMER_TO_TIME_VALUE64` macro of kern/timer.c.
fn to_time_value(save: TimerSave) -> TimeValue64 {
    TimeValue64 {
        seconds: i64::from(save.high.wrapping_add(save.low / TIMER_RATE)),
        nanoseconds: i64::from(save.low % TIMER_RATE * 1000),
    }
}

/// Read `timer` as seconds and nanoseconds, as `timer_read()` of
/// <kern/timer.c> did.
pub(crate) fn read(timer: &Timer) -> TimeValue64 {
    let mut save = TimerSave::default();
    grab(timer, &mut save);
    to_time_value(save)
}

/// Read a thread's user and system times, as `thread_read_times()` of
/// <kern/timer.c> did.
pub(crate) fn read_times(thread: &Thread) -> (TimeValue64, TimeValue64) {
    (read(&thread.user_timer), read(&thread.system_timer))
}

/// Zero every kernel timer and clear every current-timer pointer, as
/// `init_timers()` of kern/timer.c did.
///
/// # Safety
///
/// The caller must run this once at boot, before any other code accesses
/// [`KERNEL_TIMER`] or [`CURRENT_TIMER`].
pub(crate) unsafe fn init_timers() {
    unsafe {
        let timers = KERNEL_TIMER.0.get().cast::<Timer>();
        let current = CURRENT_TIMER.0.get().cast::<*mut Timer>();

        for i in 0..MAX_NCPUS {
            (*timers.add(i)).init();
            current.add(i).write(ptr::null_mut());
        }
    }

    // The C `start_timer()` is an empty macro in <kern/timer.h>, so its call
    // after the loop expands to nothing.
}

const _: () = assert!(size_of::<Timer>() == 16);
const _: () = assert!(align_of::<Timer>() == 4);
const _: () = assert!(offset_of!(Timer, low_bits) == 0);
const _: () = assert!(offset_of!(Timer, high_bits) == 4);
const _: () = assert!(offset_of!(Timer, high_bits_check) == 8);
const _: () = assert!(offset_of!(Timer, tstamp) == 12);

const _: () = assert!(size_of::<TimerSave>() == 8);
const _: () = assert!(align_of::<TimerSave>() == 4);
const _: () = assert!(offset_of!(TimerSave, low) == 0);
const _: () = assert!(offset_of!(TimerSave, high) == 4);
