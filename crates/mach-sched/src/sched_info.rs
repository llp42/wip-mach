// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! `SchedInfo`: the scheduling record a thread embeds, and the priority
//! computations on it.

use crate::policy::POLICY_TIMESHARE;
use crate::run_queue::RunQueue;
use crate::sched::{NRQS, PRI_SHIFT, SCHED_SHIFT, sched_tick};
use crate::time_value::TimeValue64;
use crate::timer::{Timer, read};
use crate::timer_save::TimerSave;
use collections::tail_queue;
use core::ffi::{c_int, c_long, c_uint};
use core::ptr;

/// One `(5/8)**n` approximation, as two shifts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shift {
    shift1: c_int,
    shift2: c_int,
}

/// The shift pairs.
const WAIT_SHIFT: [Shift; 32] = [
    Shift {
        shift1: 1,
        shift2: 1,
    },
    Shift {
        shift1: 1,
        shift2: 3,
    },
    Shift {
        shift1: 1,
        shift2: -3,
    },
    Shift {
        shift1: 2,
        shift2: -7,
    },
    Shift {
        shift1: 3,
        shift2: 5,
    },
    Shift {
        shift1: 3,
        shift2: -5,
    },
    Shift {
        shift1: 4,
        shift2: -8,
    },
    Shift {
        shift1: 5,
        shift2: 7,
    },
    Shift {
        shift1: 5,
        shift2: -7,
    },
    Shift {
        shift1: 6,
        shift2: -10,
    },
    Shift {
        shift1: 7,
        shift2: 10,
    },
    Shift {
        shift1: 7,
        shift2: -9,
    },
    Shift {
        shift1: 8,
        shift2: -11,
    },
    Shift {
        shift1: 9,
        shift2: 12,
    },
    Shift {
        shift1: 9,
        shift2: -11,
    },
    Shift {
        shift1: 10,
        shift2: -13,
    },
    Shift {
        shift1: 11,
        shift2: 14,
    },
    Shift {
        shift1: 11,
        shift2: -13,
    },
    Shift {
        shift1: 12,
        shift2: -15,
    },
    Shift {
        shift1: 13,
        shift2: 17,
    },
    Shift {
        shift1: 13,
        shift2: -15,
    },
    Shift {
        shift1: 14,
        shift2: -17,
    },
    Shift {
        shift1: 15,
        shift2: 19,
    },
    Shift {
        shift1: 16,
        shift2: 18,
    },
    Shift {
        shift1: 16,
        shift2: -19,
    },
    Shift {
        shift1: 17,
        shift2: 22,
    },
    Shift {
        shift1: 18,
        shift2: 20,
    },
    Shift {
        shift1: 18,
        shift2: -20,
    },
    Shift {
        shift1: 19,
        shift2: 26,
    },
    Shift {
        shift1: 20,
        shift2: 22,
    },
    Shift {
        shift1: 20,
        shift2: -22,
    },
    Shift {
        shift1: 21,
        shift2: -27,
    },
];

/// One `(usage >> shift1) +/- (usage >> -shift2)` step of the C.
const fn decay_usage(usage: c_uint, shift: Shift) -> c_uint {
    if shift.shift2 > 0 {
        (usage >> (shift.shift1 as u32)) + (usage >> (shift.shift2 as u32))
    } else {
        (usage >> (shift.shift1 as u32)) - (usage >> ((-shift.shift2) as u32))
    }
}

/// The scheduling record a thread embeds: its run-queue link, its
/// priorities and policy, the usage that ages them, and its CPU timers.
///
/// The scheduler's run queues hold these records; the thread that embeds
/// one is the scheduler's caller's to recover.
pub struct SchedInfo {
    /// `links`: the run-queue link, which the thread's wait, reaper and
    /// swap-in queues share.
    pub links: tail_queue::Link,
    /// `runq`: the run queue the record is on, or null.
    pub runq: *mut RunQueue,
    /// `priority`: the base priority.
    pub priority: c_int,
    /// `max_priority`: the highest base priority allowed.
    pub max_priority: c_int,
    /// `sched_pri`: the computed priority.
    pub sched_pri: c_int,
    /// `sched_data`: for use by the policy.
    pub sched_data: c_int,
    /// `policy`: the scheduling policy.
    pub policy: c_int,
    /// `depress_priority`: the priority when depressed, or negative.
    pub depress_priority: c_int,
    /// `cpu_usage`: the decaying CPU usage, in percent.
    pub cpu_usage: c_uint,
    /// `sched_usage`: the load-weighted CPU usage.
    pub sched_usage: c_uint,
    /// `sched_stamp`: the last priority update time.
    pub sched_stamp: c_uint,
    /// `cpu_delta`: the CPU usage since the last update.
    pub cpu_delta: c_uint,
    /// `sched_delta`: the weighted CPU usage since the last update.
    pub sched_delta: c_uint,
    /// The time charged in user mode.
    pub user_timer: Timer,
    /// The time charged in kernel mode.
    pub system_timer: Timer,
    /// The user timer at the last delta.
    pub user_timer_save: TimerSave,
    /// The system timer at the last delta.
    pub system_timer_save: TimerSave,
}

impl SchedInfo {
    /// A record on no run queue, with every count and priority zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            links: tail_queue::Link::new(),
            runq: ptr::null_mut(),
            priority: 0,
            max_priority: 0,
            sched_pri: 0,
            sched_data: 0,
            policy: 0,
            depress_priority: 0,
            cpu_usage: 0,
            sched_usage: 0,
            sched_stamp: 0,
            cpu_delta: 0,
            sched_delta: 0,
            user_timer: Timer::zeroed(),
            system_timer: Timer::zeroed(),
            user_timer_save: TimerSave { low: 0, high: 0 },
            system_timer_save: TimerSave { low: 0, high: 0 },
        }
    }

    /// Charges the time the timers gained since the last delta to the usage,
    /// weighting the scheduler's share by `load`, the processor set's
    /// `sched_load`.
    ///
    /// # Safety
    ///
    /// The caller must hold the owning thread's lock at splsched, as
    /// `update_priority()` and the quantum expiry do.
    pub unsafe fn timer_delta(&mut self, load: c_long) {
        // SAFETY: the thread lock serializes the timers and their saves.
        let delta = unsafe {
            let system = self.system_timer_save.delta(&self.system_timer);
            let user = self.user_timer_save.delta(&self.user_timer);
            system.wrapping_add(user)
        };
        // The C multiplies an `unsigned` by a `long` and stores the product
        // into an `unsigned`, so only the low 32 bits survive; the truncating
        // cast is exact for that.
        let scaled = delta.wrapping_mul(load as c_uint);
        self.cpu_delta = self.cpu_delta.wrapping_add(delta);
        self.sched_delta = self.sched_delta.wrapping_add(scaled);
    }

    /// Ages the usage by the ticks since the last update, and recomputes the
    /// priority of a timesharing record that is not depressed.  `load` is the
    /// processor set's `sched_load`.
    ///
    /// # Safety
    ///
    /// The caller must hold the owning thread's lock at splsched.
    pub unsafe fn update_priority(&mut self, load: c_long) {
        let ticks = sched_tick().wrapping_sub(self.sched_stamp);
        self.sched_stamp = self.sched_stamp.wrapping_add(ticks);
        // SAFETY: the caller holds the thread lock.
        unsafe { self.timer_delta(load) };

        if ticks > 30 {
            self.cpu_usage = 0;
            self.sched_usage = 0;
        } else {
            self.cpu_usage = self.cpu_usage.wrapping_add(self.cpu_delta);
            self.sched_usage = self.sched_usage.wrapping_add(self.sched_delta);
            // The reset branch above keeps `ticks` at most 30.
            let shift = WAIT_SHIFT[ticks as usize];
            self.cpu_usage = decay_usage(self.cpu_usage, shift);
            self.sched_usage = decay_usage(self.sched_usage, shift);
        }
        self.cpu_delta = 0;
        self.sched_delta = 0;

        if self.policy == POLICY_TIMESHARE && self.depress_priority < 0 {
            self.sched_pri = self.priority_computation();
        }
    }

    /// The priority the base priority and the usage give.
    #[must_use]
    pub const fn priority_computation(&self) -> c_int {
        let usage = self.sched_usage >> (PRI_SHIFT + SCHED_SHIFT);
        // The C adds an `unsigned` to the `int` priority and stores the sum
        // back into an `int`, so the result wraps.
        let pri = self.priority.wrapping_add(usage as c_int);
        // The C clamps with `if (pri > NRQS - 1)`; a negative sum is left
        // alone, exactly as the C leaves it.
        if pri > NRQS as c_int - 1 {
            NRQS as c_int - 1
        } else {
            pri
        }
    }

    /// Recomputes the scheduled priority, without moving the record between
    /// run queues: the caller knows it is timesharing and not depressed.
    pub const fn compute_my_priority(&mut self) {
        self.sched_pri = self.priority_computation();
    }

    /// The user and system times charged so far.
    #[must_use]
    pub fn read_times(&self) -> (TimeValue64, TimeValue64) {
        (read(&self.user_timer), read(&self.system_timer))
    }
}

impl Default for SchedInfo {
    fn default() -> Self {
        Self::new()
    }
}
