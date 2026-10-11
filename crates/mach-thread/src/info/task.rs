// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The basic, event and thread-time information `task_info()` reports, and
//! the conversions that fill them from the kernel's task record.

use crate::platform::Platform;
use crate::task::{Task, add_time64, kernel_task};
use core::ffi::{c_int, c_uint, c_ulong};
use core::mem::{offset_of, size_of};
use core::ptr;
use mach_sched::time_value::{RpcTimeValue, TimeValue, TimeValue64};
use mach_vm::types::PAGE_SIZE;
use mach_vm::vm_map::VmMap;
use zerocopy::{Immutable, IntoBytes};

/// The basic information `task_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
pub struct TaskBasicInfo {
    /// The task's suspend count.
    pub suspend_count: c_int,
    /// The base scheduling priority.
    pub base_priority: c_int,
    /// `virtual_size`: the map size in bytes.
    pub virtual_size: usize,
    /// `resident_size`: the resident bytes, rounded up to pages.
    pub resident_size: usize,
    /// The user run time of the task's dead threads.
    pub user_time: RpcTimeValue,
    /// The system run time of the task's dead threads.
    pub system_time: RpcTimeValue,
    /// When the task was created.
    pub creation_time: RpcTimeValue,
    /// The user run time, with nanoseconds.
    pub user_time64: TimeValue64,
    /// The system run time, with nanoseconds.
    pub system_time64: TimeValue64,
    /// When the task was created, with nanoseconds.
    pub creation_time64: TimeValue64,
}

impl TaskBasicInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
    /// The words through the legacy time fields: the count the legacy
    /// flavor reports.
    pub const LEGACY_WORDS: usize =
        offset_of!(Self, user_time64) / size_of::<c_int>();
}

/// The event information `task_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
pub struct TaskEventsInfo {
    /// The page faults.
    pub faults: c_ulong,
    /// The zero-filled pages.
    pub zero_fills: c_ulong,
    /// The reactivated pages.
    pub reactivations: c_ulong,
    /// The actual page-ins.
    pub pageins: c_ulong,
    /// The copy-on-write faults.
    pub cow_faults: c_ulong,
    /// The messages sent.
    pub messages_sent: c_ulong,
    /// The messages received.
    pub messages_received: c_ulong,
}

impl TaskEventsInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
}

/// The live-thread time information `task_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, IntoBytes, Immutable)]
pub struct TaskThreadTimesInfo {
    /// The user run time of the task's live threads.
    pub user_time: RpcTimeValue,
    /// The system run time of the task's live threads.
    pub system_time: RpcTimeValue,
    /// The user run time, with nanoseconds.
    pub user_time64: TimeValue64,
    /// The system run time, with nanoseconds.
    pub system_time64: TimeValue64,
}

impl TaskThreadTimesInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
    /// The words through the legacy time fields: the count the legacy
    /// flavor reports.
    pub const LEGACY_WORDS: usize =
        offset_of!(Self, user_time64) / size_of::<c_int>();
}

impl<P: Platform> From<&Task<P>> for TaskBasicInfo {
    /// Takes the task's `lock` for the reads.
    fn from(task: &Task<P>) -> Self {
        // `kernel_task()` is live from `task::init` on, and any other live
        // task's map is live.
        let map = if ptr::eq(ptr::from_ref(task), kernel_task().cast_const()) {
            // SAFETY: `kernel_map` is live from the VM bootstrap on.
            P::state().kernel_map()
        } else {
            task.map.cast::<VmMap<P>>()
        };

        // SAFETY: the map is live, so its size field and pmap are too.
        let (virtual_size, resident) =
            unsafe { ((*map).size, P::pmap_resident_count((*map).pmap)) };
        // The C cast the non-negative page count to `rpc_vm_size_t`; the
        // count fits `usize`, and the product wraps in the C too.
        let resident_size = (resident as usize).wrapping_mul(PAGE_SIZE);

        task.lock.lock();
        // The task's lock is held, so its creation stamp is stable.
        let creation_time64 = P::read_time_stamp(task.creation_time);
        let info = Self {
            suspend_count: task.user_stop_count,
            base_priority: task.priority,
            virtual_size,
            resident_size,
            user_time: RpcTimeValue::from(TimeValue::from(
                task.total_user_time,
            )),
            system_time: RpcTimeValue::from(TimeValue::from(
                task.total_system_time,
            )),
            creation_time: RpcTimeValue::from(TimeValue::from(
                creation_time64,
            )),
            user_time64: task.total_user_time,
            system_time64: task.total_system_time,
            creation_time64,
        };
        task.lock.unlock();

        info
    }
}

impl<P: Platform> From<&Task<P>> for TaskEventsInfo {
    /// Takes the task's `lock` for the reads.
    fn from(task: &Task<P>) -> Self {
        task.lock.lock();
        let info = Self {
            faults: task.faults,
            zero_fills: task.zero_fills,
            reactivations: task.reactivations,
            pageins: task.pageins,
            cow_faults: task.cow_faults,
            messages_sent: task.messages_sent,
            messages_received: task.messages_received,
        };
        task.lock.unlock();

        info
    }
}

impl<P: Platform> From<&Task<P>> for TaskThreadTimesInfo {
    /// Takes the task's `lock` and every thread's `lock` for the reads.
    fn from(task: &Task<P>) -> Self {
        let mut user = TimeValue64::default();
        let mut system = TimeValue64::default();

        task.lock.lock();
        let mut cursor = task.thread_list.cursor_front();
        while let Some(thread) = cursor.current_ptr() {
            cursor.move_next();
            let thread = thread.as_ptr();

            let s = P::splsched();
            // SAFETY: the task lock is held, so every list entry is a live
            // thread.
            unsafe {
                (*thread).lock.lock();
            }
            let (user_time, system_time) =
                unsafe { (*thread).sched.read_times() };
            // SAFETY: the thread lock taken above.
            unsafe {
                (*thread).lock.unlock();
            }
            // SAFETY: restores the level taken above.
            unsafe { P::splx(s) };

            add_time64(&mut user, user_time);
            add_time64(&mut system, system_time);
        }
        task.lock.unlock();

        Self {
            user_time: RpcTimeValue::from(TimeValue::from(user)),
            system_time: RpcTimeValue::from(TimeValue::from(system)),
            user_time64: user,
            system_time64: system,
        }
    }
}

// struct task_basic_info {
//  integer_t           suspend_count;   /* suspend count for task */
//  integer_t           base_priority;   /* base scheduling priority */
//  rpc_vm_size_t       virtual_size;    /* number of virtual pages */
//  rpc_vm_size_t       resident_size;   /* number of resident pages */
//  /* Deprecated, please use user_time64 */
//  rpc_time_value_t    user_time;       /* total user run time for
//                                          terminated threads */
//  /* Deprecated, please use system_time64 */
//  rpc_time_value_t    system_time;     /* total system run time for
//                                          terminated threads */
//  /* Deprecated, please use creation_time64 */
//  rpc_time_value_t    creation_time;   /* creation time stamp */
//  time_value64_t      user_time64;     /* total user run time for
//                                          terminated threads */
//  time_value64_t      system_time64;   /* total system run time for
//                                          terminated threads */
//  time_value64_t      creation_time64; /* creation time stamp */
// };
const _: () = assert!(size_of::<TaskBasicInfo>() == 120);
const _: () = assert!(offset_of!(TaskBasicInfo, suspend_count) == 0);
const _: () = assert!(offset_of!(TaskBasicInfo, base_priority) == 4);
const _: () = assert!(offset_of!(TaskBasicInfo, virtual_size) == 8);
const _: () = assert!(offset_of!(TaskBasicInfo, resident_size) == 16);
const _: () = assert!(offset_of!(TaskBasicInfo, user_time) == 24);
const _: () = assert!(offset_of!(TaskBasicInfo, system_time) == 40);
const _: () = assert!(offset_of!(TaskBasicInfo, creation_time) == 56);
const _: () = assert!(offset_of!(TaskBasicInfo, user_time64) == 72);
const _: () = assert!(offset_of!(TaskBasicInfo, system_time64) == 88);
const _: () = assert!(offset_of!(TaskBasicInfo, creation_time64) == 104);

// struct task_events_info {
//  rpc_long_natural_t  faults;       /* number of page faults */
//  rpc_long_natural_t  zero_fills;   /* number of zero fill pages */
//  rpc_long_natural_t  reactivations; /* number of reactivated pages */
//  rpc_long_natural_t  pageins;      /* number of actual pageins */
//  rpc_long_natural_t  cow_faults;   /* number of copy-on-write faults */
//  rpc_long_natural_t  messages_sent; /* number of messages sent */
//  rpc_long_natural_t  messages_received; /* number of messages received */
// };
const _: () = assert!(size_of::<TaskEventsInfo>() == 56);
const _: () = assert!(offset_of!(TaskEventsInfo, faults) == 0);
const _: () = assert!(offset_of!(TaskEventsInfo, messages_received) == 48);

// struct task_thread_times_info {
//  /* Deprecated, please use user_time64 */
//  rpc_time_value_t  user_time;    /* total user run time for
//                                     live threads */
//  /* Deprecated, please use system_time64 */
//  rpc_time_value_t  system_time;  /* total system run time for
//                                     live threads */
//  time_value64_t    user_time64;  /* total user run time for
//                                     live threads */
//  time_value64_t    system_time64; /* total system run time for
//                                     live threads */
// };
const _: () = assert!(size_of::<TaskThreadTimesInfo>() == 64);
const _: () = assert!(offset_of!(TaskThreadTimesInfo, user_time64) == 32);
