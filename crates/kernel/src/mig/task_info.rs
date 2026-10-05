// SPDX-License-Identifier: CMU-Mach
// SPDX-FileCopyrightText: 1993-1987 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from GNU Mach (commit c5701c1c1c8f330f7a790a4a0bc6b3434213722b)
// original files: include/mach/task_info.h

//! The basic, event and thread-time information `task_info()` reports, and
//! the conversions that fill them from the kernel's task record.

use crate::arch::vm_param::PAGE_SIZE;
use crate::arch::x86_64::spl;
use crate::kern::host_time::read_time_stamp;
use crate::kern::task::{Task, add_time64, kernel_task, resident_count};
use crate::kern::timer::read_times;
use crate::mig::time_value::{RpcTimeValue, TimeValue, TimeValue64};
use crate::vm::vm_kern::KERNEL_MAP;
use crate::vm::vm_map::VmMap;
use core::ffi::{c_int, c_uint, c_ulong};
use core::mem::{offset_of, size_of};
use core::ptr;

/// The basic information `task_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TaskBasicInfo {
    pub suspend_count: c_int,
    pub base_priority: c_int,
    /// `virtual_size`: the map size in bytes.
    pub virtual_size: usize,
    /// `resident_size`: the resident bytes, rounded up to pages.
    pub resident_size: usize,
    pub user_time: RpcTimeValue,
    pub system_time: RpcTimeValue,
    pub creation_time: RpcTimeValue,
    pub user_time64: TimeValue64,
    pub system_time64: TimeValue64,
    pub creation_time64: TimeValue64,
}

impl TaskBasicInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub(crate) const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
    /// The words through the legacy time fields: the count the legacy
    /// flavor reports.
    pub(crate) const LEGACY_WORDS: usize =
        offset_of!(Self, user_time64) / size_of::<c_int>();
}

/// The event information `task_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TaskEventsInfo {
    pub faults: c_ulong,
    pub zero_fills: c_ulong,
    pub reactivations: c_ulong,
    pub pageins: c_ulong,
    pub cow_faults: c_ulong,
    pub messages_sent: c_ulong,
    pub messages_received: c_ulong,
}

impl TaskEventsInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub(crate) const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
}

/// The live-thread time information `task_info()` reports.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TaskThreadTimesInfo {
    pub user_time: RpcTimeValue,
    pub system_time: RpcTimeValue,
    pub user_time64: TimeValue64,
    pub system_time64: TimeValue64,
}

impl TaskThreadTimesInfo {
    /// The `c_int` words the record spans: the count its flavor reports.
    pub(crate) const WORDS: c_uint =
        (size_of::<Self>() / size_of::<c_int>()) as c_uint;
    /// The words through the legacy time fields: the count the legacy
    /// flavor reports.
    pub(crate) const LEGACY_WORDS: usize =
        offset_of!(Self, user_time64) / size_of::<c_int>();
}

impl From<&Task> for TaskBasicInfo {
    /// Takes the task's `lock` for the reads.
    fn from(task: &Task) -> Self {
        // `kernel_task()` is live from `task_init()` on, and any other live
        // task's map is live.
        let map = if ptr::eq(ptr::from_ref(task), kernel_task().cast_const()) {
            // SAFETY: `kernel_map` is live from the VM bootstrap on.
            unsafe { KERNEL_MAP }.cast::<VmMap>()
        } else {
            task.map.cast::<VmMap>()
        };

        // SAFETY: the map is live, so its size field and pmap are too.
        let (virtual_size, resident) =
            unsafe { ((*map).size, resident_count((*map).pmap)) };
        // The C cast the non-negative page count to `rpc_vm_size_t`; the
        // count fits `usize`, and the product wraps in the C too.
        let resident_size = (resident as usize).wrapping_mul(PAGE_SIZE);

        task.lock.lock();
        let mut creation_time64 = TimeValue64::default();
        // SAFETY: the task is live and its lock is held, so its creation
        // stamp is stable.
        unsafe {
            read_time_stamp(
                ptr::addr_of!(task.creation_time),
                ptr::addr_of_mut!(creation_time64),
            );
        }
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

impl From<&Task> for TaskEventsInfo {
    /// Takes the task's `lock` for the reads.
    fn from(task: &Task) -> Self {
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

impl From<&Task> for TaskThreadTimesInfo {
    /// Takes the task's `lock` and every thread's `lock` for the reads.
    fn from(task: &Task) -> Self {
        let mut user = TimeValue64::default();
        let mut system = TimeValue64::default();

        task.lock.lock();
        let mut cursor = task.thread_list.cursor_front();
        while let Some(thread) = cursor.current_ptr() {
            cursor.move_next();
            let thread = thread.as_ptr();

            // SAFETY: the kernel runs with `%gs` based at the running
            // CPU's per-CPU block, as `splsched()` requires.
            let s = unsafe { spl::splsched() };
            // SAFETY: the task lock is held, so every list entry is a live
            // thread.
            unsafe {
                (*thread).lock.lock();
            }
            let (user_time, system_time) = read_times(unsafe { &*thread });
            // SAFETY: the thread lock taken above.
            unsafe {
                (*thread).lock.unlock();
            }
            // SAFETY: restores the level taken above.
            unsafe { spl::splx(s) };

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
