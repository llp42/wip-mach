// SPDX-License-Identifier: CMU-Mach
// SPDX-FileCopyrightText: 1991,1990,1989,1988,1987 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from GNU Mach (commit c5701c1c1c8f330f7a790a4a0bc6b3434213722b)
// original files: include/mach/thread_info.h

//! The basic and scheduling information `thread_info()` reports, and the
//! conversions that fill them from the kernel's thread record.

use crate::arch::x86_64::spl;
use crate::kern::host_time::read_time_stamp;
use crate::kern::machine;
use crate::kern::policy::POLICY_FIXEDPRI;
use crate::kern::sched_prim::{sched_tick, update_priority};
use crate::kern::thread::{
    TH_HALTED, TH_IDLE, TH_RUN, TH_SUSP, TH_SWAPPED, TH_UNINT, TH_WAIT, Thread,
};
use crate::kern::timer::{TIMER_RATE, read_times};
use crate::mig::time_value::{RpcTimeValue, TimeValue, TimeValue64};
use core::ffi::{c_int, c_uint};
use core::mem::{offset_of, size_of};
use core::ptr;

/// `TH_USAGE_SCALE`: the scale of the `cpu_usage` field.
const TH_USAGE_SCALE: c_uint = 1000;
/// The `TH_STATE_*` values `run_state` reports.
const TH_STATE_RUNNING: c_int = 1;
const TH_STATE_STOPPED: c_int = 2;
const TH_STATE_WAITING: c_int = 3;
const TH_STATE_UNINTERRUPTIBLE: c_int = 4;
const TH_STATE_HALTED: c_int = 5;
/// The `TH_FLAGS_*` bits `flags` reports.
const TH_FLAGS_SWAPPED: c_int = 0x1;
const TH_FLAGS_IDLE: c_int = 0x2;

/// The basic information `thread_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ThreadBasicInfo {
    pub user_time: RpcTimeValue,
    pub system_time: RpcTimeValue,
    /// `cpu_usage`: scaled by `TH_USAGE_SCALE`.
    pub cpu_usage: c_int,
    pub base_priority: c_int,
    pub cur_priority: c_int,
    pub run_state: c_int,
    pub flags: c_int,
    pub suspend_count: c_int,
    pub sleep_time: c_int,
    pub creation_time: RpcTimeValue,
    pub user_time64: TimeValue64,
    pub system_time64: TimeValue64,
    pub creation_time64: TimeValue64,
}

impl ThreadBasicInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub(crate) const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
    /// The words through the legacy time fields: the count the legacy
    /// flavor reports.
    pub(crate) const LEGACY_WORDS: usize =
        offset_of!(Self, user_time64) / size_of::<c_int>();
}

/// The scheduling information `thread_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ThreadSchedInfo {
    pub policy: c_int,
    pub data: c_int,
    pub base_priority: c_int,
    pub max_priority: c_int,
    pub cur_priority: c_int,
    pub depressed: c_int,
    pub depress_priority: c_int,
    pub last_processor: c_int,
}

impl ThreadSchedInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub(crate) const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
}

impl ThreadBasicInfo {
    /// Fills the record from a live thread, taking its `lock`; a thread
    /// whose scheduling is stale is caught up first.
    ///
    /// # Safety
    ///
    /// `thread` must point at a live thread.
    pub(crate) unsafe fn capture(thread: *mut Thread) -> Self {
        // SAFETY: `thread` is live; the lock taken below covers every field
        // read, and `update_priority()` runs at splsched with the lock
        // held, as it requires.
        unsafe {
            let s = spl::splsched();
            (*thread).lock.lock();

            if (*thread).state() & TH_RUN == 0
                && (*thread).sched_stamp != sched_tick()
            {
                update_priority(thread);
            }

            let (user_time, system_time) = read_times(&*thread);
            let mut creation_time = TimeValue64::default();
            read_time_stamp(
                ptr::addr_of!((*thread).creation_time),
                ptr::addr_of_mut!(creation_time),
            );

            let usage = (*thread).cpu_usage / (TIMER_RATE / TH_USAGE_SCALE);
            // The C stored the `unsigned` quotient into an `integer_t`; the
            // `as` keeps the low bits as the C conversion did.
            let cpu_usage = (usage * 3 / 5) as c_int;

            let state = (*thread).state();
            let mut flags = 0;
            if state & TH_SWAPPED != 0 {
                flags |= TH_FLAGS_SWAPPED;
            }
            if state & TH_IDLE != 0 {
                flags |= TH_FLAGS_IDLE;
            }

            let run_state = if state & TH_HALTED != 0 {
                TH_STATE_HALTED
            } else if state & TH_RUN != 0 {
                TH_STATE_RUNNING
            } else if state & TH_UNINT != 0 {
                TH_STATE_UNINTERRUPTIBLE
            } else if state & TH_SUSP != 0 {
                TH_STATE_STOPPED
            } else if state & TH_WAIT != 0 {
                TH_STATE_WAITING
            } else {
                0
            };

            let info = Self {
                user_time: RpcTimeValue::from(TimeValue::from(user_time)),
                system_time: RpcTimeValue::from(TimeValue::from(system_time)),
                cpu_usage,
                base_priority: (*thread).priority,
                cur_priority: (*thread).sched_pri,
                run_state,
                flags,
                suspend_count: (*thread).user_stop_count,
                sleep_time: if run_state == TH_STATE_RUNNING {
                    0
                } else {
                    // The C stored the `unsigned` difference into an
                    // `integer_t`; the `as` keeps the low bits.
                    sched_tick().wrapping_sub((*thread).sched_stamp) as c_int
                },
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
            spl::splx(s);

            info
        }
    }
}

impl From<&Thread> for ThreadSchedInfo {
    /// Takes the thread's `lock` for the reads.
    fn from(thread: &Thread) -> Self {
        // SAFETY: the kernel runs with `%gs` based at the running CPU's
        // per-CPU block, as `splsched()` requires.
        let s = unsafe { spl::splsched() };
        thread.lock.lock();

        let data = if thread.policy == POLICY_FIXEDPRI {
            thread.sched_data.wrapping_mul(machine::TICK) / 1000
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
            policy: thread.policy,
            data,
            base_priority: thread.priority,
            max_priority: thread.max_priority,
            cur_priority: thread.sched_pri,
            depressed: c_int::from(thread.depress_priority >= 0),
            depress_priority: thread.depress_priority,
            last_processor,
        };

        thread.lock.unlock();
        // SAFETY: restores the level taken above.
        unsafe { spl::splx(s) };

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
