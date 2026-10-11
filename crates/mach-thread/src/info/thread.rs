// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The basic and scheduling information `thread_info()` reports, and the
//! conversions that fill them from the kernel's thread record.

use crate::platform::Platform;
use crate::sched_prim::update_priority;
use crate::thread::Thread;
use crate::types::ThreadState;
use core::ffi::{c_int, c_uint};
use core::mem::{offset_of, size_of};
use mach_sched::policy::POLICY_FIXEDPRI;
use mach_sched::sched::sched_tick;
use mach_sched::time_value::{RpcTimeValue, TimeValue, TimeValue64};
use mach_sched::timer::TIMER_RATE;
use zerocopy::{Immutable, IntoBytes};

/// `TH_USAGE_SCALE`: the scale of the `cpu_usage` field.
const TH_USAGE_SCALE: c_uint = 1000;
/// The `TH_STATE_*` values `run_state` reports.
const TH_STATE_RUNNING: c_int = 1;
const TH_STATE_STOPPED: c_int = 2;
const TH_STATE_WAITING: c_int = 3;
const TH_STATE_UNINTERRUPTIBLE: c_int = 4;
const TH_STATE_HALTED: c_int = 5;

/// `TH_FLAGS_*`: the flags of a thread's basic information.
///
/// The newtype is declared outside `bitflags!` so that it can derive the
/// byte view the record it sits in needs.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
pub struct ThreadInfoFlags(c_int);

bitflags::bitflags! {
    impl ThreadInfoFlags: c_int {
        /// `TH_FLAGS_SWAPPED`: the thread's kernel stack is swapped out.
        const SWAPPED = 0x1;
        /// `TH_FLAGS_IDLE`: the thread is a processor's idle thread.
        const IDLE = 0x2;
    }
}

/// The basic information `thread_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
pub struct ThreadBasicInfo {
    /// The user run time.
    pub user_time: RpcTimeValue,
    /// The system run time.
    pub system_time: RpcTimeValue,
    /// `cpu_usage`: scaled by `TH_USAGE_SCALE`.
    pub cpu_usage: c_int,
    /// The base scheduling priority.
    pub base_priority: c_int,
    /// The current scheduling priority.
    pub cur_priority: c_int,
    /// The run state, a `TH_STATE_*` value.
    pub run_state: c_int,
    /// The swapped and idle flags.
    pub flags: ThreadInfoFlags,
    /// The thread's suspend count.
    pub suspend_count: c_int,
    /// How long the thread has slept, in scheduler ticks.
    pub sleep_time: c_int,
    /// The C compiler's alignment hole, kept zero so no stale kernel byte
    /// reaches a task.
    padding: c_int,
    /// When the thread was created.
    pub creation_time: RpcTimeValue,
    /// The user run time, with nanoseconds.
    pub user_time64: TimeValue64,
    /// The system run time, with nanoseconds.
    pub system_time64: TimeValue64,
    /// When the thread was created, with nanoseconds.
    pub creation_time64: TimeValue64,
}

impl ThreadBasicInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
    /// The words through the legacy time fields: the count the legacy
    /// flavor reports.
    pub const LEGACY_WORDS: usize =
        offset_of!(Self, user_time64) / size_of::<c_int>();
}

/// The scheduling information `thread_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
pub struct ThreadSchedInfo {
    /// The scheduling policy.
    pub policy: c_int,
    /// The policy's data: the quantum, in milliseconds, of a fixed-priority thread.
    pub data: c_int,
    /// The base priority.
    pub base_priority: c_int,
    /// The highest priority.
    pub max_priority: c_int,
    /// The current priority.
    pub cur_priority: c_int,
    /// Whether the priority is depressed.
    pub depressed: c_int,
    /// The priority the thread was depressed from.
    pub depress_priority: c_int,
    /// The last processor the thread ran on.
    pub last_processor: c_int,
}

impl ThreadSchedInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
}

impl ThreadBasicInfo {
    /// Fills the record from a live thread, taking its `lock`; a thread
    /// whose scheduling is stale is caught up first.
    ///
    /// # Safety
    ///
    /// `thread` must point at a live thread.
    pub unsafe fn capture<P: Platform>(thread: *mut Thread<P>) -> Self {
        // SAFETY: `thread` is live; the lock taken below covers every field
        // read, and `update_priority()` runs at splsched with the lock
        // held, as it requires.
        unsafe {
            let s = P::splsched();
            (*thread).lock.lock();

            if !(*thread).state().intersects(ThreadState::RUN)
                && (*thread).sched.sched_stamp != sched_tick()
            {
                update_priority(thread);
            }

            let (user_time, system_time) = (*thread).sched.read_times();
            let creation_time = P::read_time_stamp((*thread).creation_time);

            let usage =
                (*thread).sched.cpu_usage / (TIMER_RATE / TH_USAGE_SCALE);
            // The C stored the `unsigned` quotient into an `integer_t`; the
            // `as` keeps the low bits as the C conversion did.
            let cpu_usage = (usage * 3 / 5) as c_int;

            let state = (*thread).state();
            let mut flags = ThreadInfoFlags::empty();
            flags.set(
                ThreadInfoFlags::SWAPPED,
                state.intersects(ThreadState::SWAPPED),
            );
            flags.set(
                ThreadInfoFlags::IDLE,
                state.intersects(ThreadState::IDLE),
            );

            let run_state = if state.intersects(ThreadState::HALTED) {
                TH_STATE_HALTED
            } else if state.intersects(ThreadState::RUN) {
                TH_STATE_RUNNING
            } else if state.intersects(ThreadState::UNINT) {
                TH_STATE_UNINTERRUPTIBLE
            } else if state.intersects(ThreadState::SUSP) {
                TH_STATE_STOPPED
            } else if state.intersects(ThreadState::WAIT) {
                TH_STATE_WAITING
            } else {
                0
            };

            let info = Self {
                user_time: RpcTimeValue::from(TimeValue::from(user_time)),
                system_time: RpcTimeValue::from(TimeValue::from(system_time)),
                cpu_usage,
                base_priority: (*thread).sched.priority,
                cur_priority: (*thread).sched.sched_pri,
                run_state,
                flags,
                suspend_count: (*thread).user_stop_count,
                sleep_time: if run_state == TH_STATE_RUNNING {
                    0
                } else {
                    // The C stored the `unsigned` difference into an
                    // `integer_t`; the `as` keeps the low bits.
                    sched_tick().wrapping_sub((*thread).sched.sched_stamp)
                        as c_int
                },
                padding: 0,
                creation_time: RpcTimeValue::from(TimeValue::from(
                    creation_time,
                )),
                // The C wrote `user_time` into `system_time64`; the copy is
                // kept.
                user_time64: user_time,
                system_time64: user_time,
                creation_time64: creation_time,
            };

            (*thread).lock.unlock();
            P::splx(s);

            info
        }
    }
}

impl<P: Platform> From<&Thread<P>> for ThreadSchedInfo {
    /// Takes the thread's `lock` for the reads.
    fn from(thread: &Thread<P>) -> Self {
        let s = P::splsched();
        thread.lock.lock();

        let data = if thread.sched.policy == POLICY_FIXEDPRI {
            thread
                .sched
                .sched_data
                .wrapping_mul(mach_sched::sched::TICK)
                / 1000
        } else {
            0
        };
        let last_processor = if thread.last_processor.is_null() {
            0
        } else {
            // SAFETY: the field holds a live processor or null.
            unsafe { (*thread.last_processor).cpu_id.bits() as c_int }
        };

        let info = Self {
            policy: thread.sched.policy,
            data,
            base_priority: thread.sched.priority,
            max_priority: thread.sched.max_priority,
            cur_priority: thread.sched.sched_pri,
            depressed: c_int::from(thread.sched.depress_priority >= 0),
            depress_priority: thread.sched.depress_priority,
            last_processor,
        };

        thread.lock.unlock();
        // SAFETY: restores the level taken above.
        unsafe { P::splx(s) };

        info
    }
}

// struct thread_basic_info {
//  /* Deprecated, please use user_time64 */
//  rpc_time_value_t  user_time;      /* user run time */
//  /* Deprecated, please use system_time64 */
//  rpc_time_value_t  system_time;    /* system run time */
//  integer_t         cpu_usage;      /* scaled cpu usage percentage */
//  integer_t         base_priority;  /* base scheduling priority */
//  integer_t         cur_priority;   /* current scheduling priority */
//  integer_t         run_state;      /* run state (see below) */
//  integer_t         flags;          /* various flags (see below) */
//  integer_t         suspend_count;  /* suspend count for thread */
//  integer_t         sleep_time;     /* number of seconds that thread
//                                       has been sleeping */
//  /* Deprecated, please use creation_time64 */
//  rpc_time_value_t  creation_time;  /* time stamp of creation */
//  time_value64_t    user_time64;    /* user run time */
//  time_value64_t    system_time64;  /* system run time */
//  time_value64_t    creation_time64; /* time stamp of creation */
// };
const _: () = assert!(size_of::<ThreadBasicInfo>() == 128);
const _: () = assert!(offset_of!(ThreadBasicInfo, user_time) == 0);
const _: () = assert!(offset_of!(ThreadBasicInfo, system_time) == 16);
const _: () = assert!(offset_of!(ThreadBasicInfo, cpu_usage) == 32);
const _: () = assert!(offset_of!(ThreadBasicInfo, run_state) == 44);
const _: () = assert!(offset_of!(ThreadBasicInfo, sleep_time) == 56);
const _: () = assert!(offset_of!(ThreadBasicInfo, creation_time) == 64);
const _: () = assert!(offset_of!(ThreadBasicInfo, user_time64) == 80);
const _: () = assert!(offset_of!(ThreadBasicInfo, system_time64) == 96);
const _: () = assert!(offset_of!(ThreadBasicInfo, creation_time64) == 112);

// struct thread_sched_info {
//  integer_t  policy;            /* scheduling policy */
//  integer_t  data;              /* associated data */
//  integer_t  base_priority;     /* base priority */
//  integer_t  max_priority;      /* max priority */
//  integer_t  cur_priority;      /* current priority */
// /*boolean_t*/integer_t  depressed;  /* depressed ? */
//  integer_t  depress_priority;  /* priority depressed from */
//  integer_t  last_processor;    /* last processor used by the thread */
// };
const _: () = assert!(size_of::<ThreadSchedInfo>() == 32);
const _: () = assert!(offset_of!(ThreadSchedInfo, policy) == 0);
const _: () = assert!(offset_of!(ThreadSchedInfo, last_processor) == 28);
