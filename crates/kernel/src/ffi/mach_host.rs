// SPDX-License-Identifier: CMU-Mach
// Derived from include/mach/mach_host.defs:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// Derived from kern/host.c, kern/ipc_host.c, kern/mach_clock.c,
// kern/machine.c, kern/processor.c, kern/syscall_subr.c, kern/task.c,
// kern/thread.c and vm/vm_user.c:
//   Copyright (c) 1993,1992,1991,1990,1989,1988 Carnegie Mellon University.
//   Copyright (c) 1994-1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The <`mach/mach_host.defs`> server entries, all 44 routines, which
//! `kern/mach_host.srv` presents.
//!
//! The cores stay in the `crate::kern` and `crate::vm` modules.

use crate::arch::types::{VmOffset, VmSize};
use crate::config::{KERNEL_VERSION, KERNEL_VERSION_MAX, MAX_NCPUS};
use crate::ffi::host_info::{
    self, HOST_INFO_MAX, HostBasicInfo, HostLoadInfo, HostSchedInfo,
};
use crate::ffi::processor_info::ProcessorBasicInfo;
use crate::ffi::processor_set_info::{
    ProcessorSetBasicInfo, ProcessorSetSchedInfo,
};
use crate::glue::time_value::{TimeValue, TimeValue64};
use crate::kern::host::{self, Host, processor_ports, processor_set_priv};
use crate::kern::ipc_host;
use crate::kern::mach_clock as clock;
use crate::kern::machine;
use crate::kern::processor::{self, Processor, ProcessorSet};
use crate::kern::syscall_subr;
use crate::kern::task::{self, Task};
use crate::kern::thread::{Thread, default_pset};
use crate::kern::types::KernError;
use crate::vm::error::kern_return;
use crate::vm::types::VmProt;
use crate::vm::vm_map::VmMap;
use crate::vm::vm_user;
use core::ffi::{c_int, c_uint, c_void};
use core::ptr::{self, NonNull};
use core::slice;

const _: () = assert!(KERNEL_VERSION.len() < KERNEL_VERSION_MAX);

/// `host_processors()` of kern/host.c, the routine <`mach/mach_host.defs`>
/// declares.
///
/// # Safety
///
/// `host` must be `HOST_NULL` or the live host pointer the generated server
/// converted the request port into; `processor_list` and `countp` must be
/// valid out-parameters.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_processors(
    host: *mut Host,
    processor_list: *mut *mut VmOffset,
    countp: *mut c_uint,
) -> c_int {
    match host::processors(NonNull::new(host)) {
        Ok((list, count)) => {
            unsafe {
                *processor_list = list.as_ptr();
                *countp = count;
            }
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// `processor_start()` of kern/processor.c.
///
/// # Safety
///
/// `pr` must be null or point at a live `struct processor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_start(pr: *mut Processor) -> c_int {
    let Some(pr) = NonNull::new(pr) else {
        return c_int::from(KernError::InvalidArgument);
    };

    match unsafe { (*pr.as_ptr()).start() } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `processor_exit()` of kern/processor.c.
///
/// # Safety
///
/// `pr` must be null or point at a live `struct processor`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_exit(pr: *mut Processor) -> c_int {
    let Some(pr) = NonNull::new(pr) else {
        return c_int::from(KernError::InvalidArgument);
    };

    match unsafe { (*pr.as_ptr()).exit() } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `processor_set_default()` of `kern/ipc_host.c`.
///
/// # Safety
///
/// `host` must be null or point at a live `struct host`, and `pset` must be a
/// valid out-parameter; MIG's `_Xprocessor_set_default` passes both.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_set_default(
    host: *mut c_void,
    pset: *mut *mut ProcessorSet,
) -> c_int {
    match unsafe { ipc_host::set_default(host) } {
        Ok(default) => {
            unsafe { *pset = default };
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// `processor_set_create()` of kern/processor.c.
///
/// # Safety
///
/// `host` must be null or the live host privilege object; `new_set` and
/// `new_name` must be valid out-parameters, and the caller owns one reference
/// through each.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_set_create(
    host: *mut c_void,
    new_set: *mut *mut ProcessorSet,
    new_name: *mut *mut ProcessorSet,
) -> c_int {
    match unsafe { processor::create(host) } {
        Ok(pset) => {
            unsafe {
                *new_set = pset;
                *new_name = pset;
            }
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// `processor_set_destroy()` of kern/processor.c.
///
/// # Safety
///
/// `pset` must be null or point at a live `struct processor_set` that the
/// caller holds a reference to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_set_destroy(
    pset: *mut ProcessorSet,
) -> c_int {
    let Some(pset) = NonNull::new(pset) else {
        return c_int::from(KernError::InvalidArgument);
    };

    match unsafe { (*pset.as_ptr()).destroy() } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `processor_assign()` of kern/machine.c.
///
/// # Safety
///
/// `processor` must be null or a live processor and `new_pset` null or a live
/// set; the caller must hold no lock, because the routine waits and may block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_assign(
    processor: *mut Processor,
    new_pset: *mut ProcessorSet,
    wait: c_int,
) -> c_int {
    match unsafe { machine::assign(processor, new_pset, wait != 0) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `processor_get_assignment()` of kern/processor.c.
///
/// # Safety
///
/// `pr` must be null or point at a live `struct processor`, and `pset` must be
/// a valid out-parameter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_get_assignment(
    pr: *mut Processor,
    pset: *mut *mut ProcessorSet,
) -> c_int {
    let Some(pr) = NonNull::new(pr) else {
        return c_int::from(KernError::InvalidArgument);
    };

    match unsafe { (*pr.as_ptr()).get_assignment() } {
        Ok(assignment) => {
            unsafe { *pset = assignment };
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// `thread_assign()` of kern/thread.c, the `MACH_HOST` arm both configured
/// builds take.
///
/// # Safety
///
/// `thread` must be null or a live thread the caller holds an extra reference
/// to, `new_pset` must be null or a live processor set, and the caller must
/// hold no locks: the routine waits and may block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_assign(
    thread: *mut Thread,
    new_pset: *mut ProcessorSet,
) -> c_int {
    match unsafe { Thread::assign(thread, new_pset) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `thread_assign_default()` of kern/thread.c.
///
/// # Safety
///
/// `thread` must be null or a live thread the caller holds an extra reference
/// to, and the caller must hold no locks: `thread_assign()` may block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_assign_default(thread: *mut Thread) -> c_int {
    match unsafe { Thread::assign(thread, default_pset()) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `thread_get_assignment()` of kern/thread.c.
///
/// # Safety
///
/// `thread` must be null or point at a live thread, and `pset` must be valid
/// for a write; the MIG server passes the address of its own
/// `processor_set_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_get_assignment(
    thread: *mut Thread,
    pset: *mut *mut ProcessorSet,
) -> c_int {
    match unsafe { Thread::assignment(thread) } {
        Ok(assignment) => {
            unsafe { *pset = assignment };
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// `task_assign()` of kern/task.c.
///
/// # Safety
///
/// `task` must be a live task, `new_pset` must be a live processor set, and
/// the caller must hold no locks: the routine waits and may block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_assign(
    task: *mut c_void,
    new_pset: *mut ProcessorSet,
    assign_threads: c_int,
) -> c_int {
    match unsafe { task::assign(task.cast(), new_pset, assign_threads != 0) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `task_assign_default()` of kern/task.c.
///
/// # Safety
///
/// `task` must be a live task, and the caller must hold no locks: `assign()`
/// waits and may block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_assign_default(
    task: *mut c_void,
    assign_threads: c_int,
) -> c_int {
    let default_pset = processor::default_pset();
    match unsafe {
        task::assign(task.cast(), default_pset, assign_threads != 0)
    } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `task_get_assignment()` of kern/task.c.
///
/// # Safety
///
/// `task` must be a live task, and `pset` must be writable for one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_get_assignment(
    task: *mut c_void,
    pset: *mut *mut ProcessorSet,
) -> c_int {
    match unsafe { task::get_assignment(task.cast()) } {
        Ok(assigned) => {
            unsafe { pset.write(assigned) };
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// The deprecated spelling of [`host_get_kernel_version`].
#[unsafe(no_mangle)]
pub extern "C" fn host_kernel_version(
    host: Option<NonNull<Host>>,
    out_version: Option<&mut [u8; KERNEL_VERSION_MAX]>,
) -> c_int {
    host_get_kernel_version(host, out_version)
}

/// `thread_priority()` of kern/thread.c.
///
/// # Safety
///
/// `thread` must be null or point at a live thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_priority(
    thread: *mut Thread,
    priority: c_int,
    set_max: c_int,
) -> c_int {
    match unsafe { Thread::priority(thread, priority, set_max != 0) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `thread_max_priority()` of kern/thread.c.
///
/// # Safety
///
/// `thread` and `pset` must be null or point at live objects.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_max_priority(
    thread: *mut Thread,
    pset: *mut ProcessorSet,
    max_priority: c_int,
) -> c_int {
    match unsafe { Thread::max_priority(thread, pset, max_priority) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `task_priority()` of kern/task.c.
///
/// # Safety
///
/// `task` must be a live task, and the caller must hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_priority(
    task: *mut c_void,
    priority: c_int,
    change_threads: c_int,
) -> c_int {
    match unsafe { task::priority(task.cast(), priority, change_threads != 0) }
    {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `processor_set_max_priority()` of kern/processor.c.
///
/// # Safety
///
/// `pset` must be null or point at a live `struct processor_set`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_set_max_priority(
    pset: *mut ProcessorSet,
    max_priority: c_int,
    change_threads: c_int,
) -> c_int {
    let Some(pset) = NonNull::new(pset) else {
        return c_int::from(KernError::InvalidArgument);
    };

    match unsafe {
        (*pset.as_ptr()).max_priority(max_priority, change_threads)
    } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `thread_policy()` of kern/thread.c.
///
/// # Safety
///
/// `thread` must be null or point at a live thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_policy(
    thread: *mut Thread,
    policy: c_int,
    data: c_int,
) -> c_int {
    match unsafe { Thread::policy(thread, policy, data) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `processor_set_policy_enable()` of kern/processor.c.
///
/// # Safety
///
/// `pset` must be null or point at a live `struct processor_set`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_set_policy_enable(
    pset: *mut ProcessorSet,
    policy: c_int,
) -> c_int {
    let Some(pset) = NonNull::new(pset) else {
        return c_int::from(KernError::InvalidArgument);
    };

    match unsafe { (*pset.as_ptr()).policy_enable(policy) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `processor_set_policy_disable()` of kern/processor.c.
///
/// # Safety
///
/// `pset` must be null or point at a live `struct processor_set`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_set_policy_disable(
    pset: *mut ProcessorSet,
    policy: c_int,
    change_threads: c_int,
) -> c_int {
    let Some(pset) = NonNull::new(pset) else {
        return c_int::from(KernError::InvalidArgument);
    };

    match unsafe { (*pset.as_ptr()).policy_disable(policy, change_threads) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `processor_set_tasks()` of kern/processor.c.
///
/// # Safety
///
/// `pset` must be null or point at a live `struct processor_set`; `task_list`
/// must be a valid out-parameter for the port array, and `count` for its
/// length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_set_tasks(
    pset: *mut ProcessorSet,
    task_list: *mut *mut Task,
    count: *mut c_uint,
) -> c_int {
    match unsafe { processor::tasks(pset) } {
        Ok((list, length)) => {
            unsafe {
                *task_list = list.cast::<Task>();
                *count = length;
            }
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// `processor_set_threads()` of kern/processor.c.
///
/// # Safety
///
/// `pset` must be null or point at a live `struct processor_set`;
/// `thread_list` must be a valid out-parameter for the port array, and
/// `count` for its length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_set_threads(
    pset: *mut ProcessorSet,
    thread_list: *mut *mut Thread,
    count: *mut c_uint,
) -> c_int {
    match unsafe { processor::threads(pset) } {
        Ok((list, length)) => {
            unsafe {
                *thread_list = list.cast::<Thread>();
                *count = length;
            }
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// `host_processor_sets()` of kern/host.c, the routine <`mach/mach_host.defs`>
/// declares.
///
/// # Safety
///
/// `host` must be `HOST_NULL` or the live host pointer the generated server
/// converted the request port into; `pset_list` and `count` must be valid
/// out-parameters.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_processor_sets(
    host: *mut Host,
    pset_list: *mut *mut c_void,
    count: *mut c_uint,
) -> c_int {
    let Some(host) = NonNull::new(host) else {
        return c_int::from(KernError::InvalidArgument);
    };

    match unsafe { host::processor_sets(Some(host.as_ref())) } {
        Ok((list, actual)) => {
            unsafe {
                *pset_list = list.cast();
                *count = actual;
            }
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// `host_processor_set_priv()` of kern/host.c.
#[unsafe(no_mangle)]
pub extern "C" fn host_processor_set_priv(
    host: Option<NonNull<Host>>,
    pset_name: Option<&mut ProcessorSet>,
    pset: Option<&mut Option<NonNull<ProcessorSet>>>,
) -> c_int {
    let Some(out) = pset else {
        return c_int::from(KernError::InvalidArgument);
    };

    match processor_set_priv(host, pset_name) {
        Ok(set) => {
            *out = Some(set);
            0
        }
        Err(error) => {
            *out = None;
            c_int::from(error)
        }
    }
}

/// `thread_depress_abort()` of `kern/syscall_subr.c`.
///
/// # Safety
///
/// `thread` must be null or a live thread; the routine takes splsched and the
/// thread lock itself.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_depress_abort(thread: *mut Thread) -> c_int {
    unsafe { syscall_subr::depress_abort(thread) }
}

/// `host_set_time()` of `kern/mach_clock.c`, the deprecated 32-bit entry.
///
/// # Safety
///
/// `host` must be null or point at a live `struct host`; MIG's
/// `_Xhost_set_time` passes the host private port's host.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_set_time(
    host: *mut c_void,
    new_time: TimeValue,
) -> c_int {
    match clock::set_time64(host, TimeValue64::from(new_time)) {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `host_adjust_time()` of `kern/mach_clock.c`, the deprecated 32-bit entry.
///
/// # Safety
///
/// `host` must be null or point at a live `struct host`, and `old_adjustment`
/// must be valid for a write on success; MIG's `_Xhost_adjust_time` passes its
/// reply field, which is.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_adjust_time(
    host: *mut c_void,
    new_adjustment: TimeValue,
    old_adjustment: *mut TimeValue,
) -> c_int {
    match clock::adjust_time(host, TimeValue64::from(new_adjustment)) {
        Ok(old) => {
            unsafe { old_adjustment.write(TimeValue::from(old)) };
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// `host_get_time()` of `kern/mach_clock.c`.
///
/// # Safety
///
/// `host` must be null or a live host, and `current_time` must be valid for
/// a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_get_time(
    host: *mut c_void,
    current_time: *mut TimeValue,
) -> c_int {
    match clock::get_time(host) {
        Ok(value) => {
            unsafe { current_time.write(value) };
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// `host_reboot()` of kern/machine.c, the routine <`mach/mach_host.defs`>
/// declares.
///
/// # Safety
///
/// `host_priv` must be `HOST_NULL` or the live host privilege pointer the MIG
/// stub converted the request port into.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_reboot(
    host_priv: *mut c_void,
    options: c_int,
) -> c_int {
    match unsafe { machine::host_reboot(host_priv, options) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `vm_wire()` of `vm/vm_user.c`.
///
/// # Safety
///
/// `port` must be `IP_NULL`, `IP_DEAD` or a live port; `map` must be null or
/// a live, unlocked map.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_wire(
    port: *mut c_void,
    map: *mut VmMap,
    start: VmOffset,
    size: VmSize,
    access: VmProt,
) -> c_int {
    kern_return(unsafe { vm_user::wire(port, map, start, size, access) })
}

/// `thread_wire()` of kern/thread.c.
///
/// # Safety
///
/// `host` must be null or a live `struct host`; `thread` must be null or point
/// at a live thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_wire(
    host: *mut c_void,
    thread: *mut Thread,
    wired: c_int,
) -> c_int {
    if host.is_null() {
        return c_int::from(KernError::InvalidArgument);
    }

    match unsafe { Thread::wire(thread, wired != 0) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// The `flavor` argument of `host_info()`.
///
/// A transparent `c_int`: the generated stub forwards the caller's int
/// unchecked, so unlike an enum every value must be valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct HostFlavor(c_int);

impl HostFlavor {
    /// `HOST_BASIC_INFO`.
    const BASIC_INFO: Self = Self(1);
    /// `HOST_PROCESSOR_SLOTS`.
    const PROCESSOR_SLOTS: Self = Self(2);
    /// `HOST_SCHED_INFO`.
    const SCHED_INFO: Self = Self(3);
    /// `HOST_LOAD_INFO`.
    const LOAD_INFO: Self = Self(4);
}

/// `host_info()` of kern/host.c.
///
/// # Safety
///
/// `host` must be `HOST_NULL` or the live host pointer the generated server
/// converted the request port into; `info` must be readable and writable for
/// `*count` integers, and `count` must be valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_info(
    host: *mut Host,
    flavor: HostFlavor,
    info: *mut c_int,
    count: *mut c_uint,
) -> c_int {
    let (Some(host), Some(count)) = (NonNull::new(host), NonNull::new(count))
    else {
        return c_int::from(KernError::InvalidArgument);
    };
    let Some(info) = NonNull::new(info) else {
        return c_int::from(KernError::InvalidArgument);
    };

    let capacity = unsafe { count.as_ptr().read() as usize };
    let capacity = capacity.min(HOST_INFO_MAX);
    let host = unsafe { host.as_ref() };

    let written = match flavor {
        HostFlavor::BASIC_INFO => {
            if capacity < HostBasicInfo::WORDS as usize {
                return c_int::from(KernError::Failure);
            }
            // SAFETY: the capacity check above covers the record, and the
            // MIG buffer is only `integer_t`-aligned.
            unsafe {
                info.as_ptr()
                    .cast::<HostBasicInfo>()
                    .write_unaligned(HostBasicInfo::from(host));
            }
            HostBasicInfo::WORDS
        }
        HostFlavor::PROCESSOR_SLOTS => {
            if capacity < MAX_NCPUS {
                return c_int::from(KernError::InvalidArgument);
            }
            // SAFETY: the capacity check above holds `MAX_NCPUS` slots.
            unsafe { host_info::processor_slots(host, info.as_ptr()) }
        }
        HostFlavor::SCHED_INFO => {
            if capacity < HostSchedInfo::WORDS as usize {
                return c_int::from(KernError::Failure);
            }
            // SAFETY: the capacity check above covers the record, and the
            // MIG buffer is only `integer_t`-aligned.
            unsafe {
                info.as_ptr()
                    .cast::<HostSchedInfo>()
                    .write_unaligned(HostSchedInfo::from(host));
            }
            HostSchedInfo::WORDS
        }
        HostFlavor::LOAD_INFO => {
            if capacity < HostLoadInfo::WORDS as usize {
                return c_int::from(KernError::Failure);
            }
            // SAFETY: the capacity check above covers the record, and the
            // MIG buffer is only `integer_t`-aligned.
            unsafe {
                info.as_ptr()
                    .cast::<HostLoadInfo>()
                    .write_unaligned(HostLoadInfo::from(host));
            }
            HostLoadInfo::WORDS
        }
        _ => return c_int::from(KernError::InvalidArgument),
    };

    unsafe { count.as_ptr().write(written) };
    0
}

/// The `flavor` argument of `processor_info()`.
///
/// A transparent `c_int`: the generated stub forwards the caller's int
/// unchecked, so unlike an enum every value must be valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ProcessorFlavor(c_int);

impl ProcessorFlavor {
    /// `PROCESSOR_BASIC_INFO`.
    const BASIC_INFO: Self = Self(1);
}

/// `processor_info()` of kern/processor.c.
///
/// # Safety
///
/// `processor` must be null or point at a live `struct processor`; `host` and
/// `count` must be valid out-parameters, and `info` must be writable for the
/// `processor_basic_info` that `*count` reports.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_info(
    processor: *mut Processor,
    flavor: ProcessorFlavor,
    host: *mut *mut c_void,
    info: *mut c_int,
    count: *mut c_uint,
) -> c_int {
    let Some(processor) = NonNull::new(processor) else {
        return c_int::from(KernError::InvalidArgument);
    };

    let capacity = unsafe { *count };
    if flavor != ProcessorFlavor::BASIC_INFO
        || capacity < ProcessorBasicInfo::WORDS
    {
        return c_int::from(KernError::Failure);
    }

    // SAFETY: the port holds a live processor, as the generated stub's port
    // conversion guarantees.
    let basic = ProcessorBasicInfo::from(unsafe { processor.as_ref() });
    // SAFETY: the count check above guarantees the caller's buffer is at
    // least a `processor_basic_info` (and the MIG buffer is only
    // `integer_t`-aligned), and the caller promises the other two
    // out-parameters.
    unsafe {
        info.cast::<ProcessorBasicInfo>().write_unaligned(basic);
        *count = ProcessorBasicInfo::WORDS;
        *host = host::realhost().cast::<c_void>();
    }
    0
}

/// The `flavor` argument of `processor_set_info()`.
///
/// A transparent `c_int`: the generated stub forwards the caller's int
/// unchecked, so unlike an enum every value must be valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ProcessorSetFlavor(c_int);

impl ProcessorSetFlavor {
    /// `PROCESSOR_SET_BASIC_INFO`.
    const BASIC_INFO: Self = Self(1);
    /// `PROCESSOR_SET_SCHED_INFO`.
    const SCHED_INFO: Self = Self(2);
}

/// `processor_set_info()` of kern/processor.c.
///
/// # Safety
///
/// `pset` must be null or point at a live `struct processor_set`; `host` and
/// `count` must be valid out-parameters, and `info` must be writable for the
/// record the flavor and `*count` call for.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_set_info(
    pset: *mut ProcessorSet,
    flavor: ProcessorSetFlavor,
    host: *mut *mut c_void,
    info: *mut c_int,
    count: *mut c_uint,
) -> c_int {
    let Some(pset) = NonNull::new(pset) else {
        return c_int::from(KernError::InvalidArgument);
    };

    let capacity = unsafe { *count };
    match flavor {
        ProcessorSetFlavor::BASIC_INFO => {
            if capacity < ProcessorSetBasicInfo::WORDS {
                return c_int::from(KernError::Failure);
            }

            // SAFETY: the port holds a live set, as the generated stub's
            // port conversion guarantees.
            let basic = ProcessorSetBasicInfo::from(unsafe { pset.as_ref() });
            // SAFETY: the count check above guarantees the caller's buffer
            // is at least a `processor_set_basic_info` (and the MIG buffer
            // is only `integer_t`-aligned), and the caller promises the
            // other two out-parameters.
            unsafe {
                info.cast::<ProcessorSetBasicInfo>().write_unaligned(basic);
                *count = ProcessorSetBasicInfo::WORDS;
                *host = host::realhost().cast::<c_void>();
            }
            0
        }
        ProcessorSetFlavor::SCHED_INFO => {
            if capacity < ProcessorSetSchedInfo::WORDS {
                return c_int::from(KernError::Failure);
            }

            // SAFETY: the port holds a live set, as the generated stub's
            // port conversion guarantees.
            let sched = ProcessorSetSchedInfo::from(unsafe { pset.as_ref() });
            // SAFETY: the count check above guarantees the caller's buffer
            // is at least a `processor_set_sched_info` (and the MIG buffer
            // is only `integer_t`-aligned), and the caller promises the
            // other two out-parameters.
            unsafe {
                info.cast::<ProcessorSetSchedInfo>().write_unaligned(sched);
                *count = ProcessorSetSchedInfo::WORDS;
                *host = host::realhost().cast::<c_void>();
            }
            0
        }
        _ => {
            // The C cleared the host out-parameter it leaves untouched on
            // the other failures.
            unsafe {
                *host = ptr::null_mut();
            }
            c_int::from(KernError::InvalidArgument)
        }
    }
}

/// `processor_control()` of kern/processor.c.
///
/// # Safety
///
/// `pr` must be null or point at a live `struct processor`, and `info` must be
/// readable for `count` integers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn processor_control(
    pr: *mut Processor,
    info: *mut c_int,
    count: c_uint,
) -> c_int {
    let Some(pr) = NonNull::new(pr) else {
        return c_int::from(KernError::InvalidArgument);
    };

    let info: &[c_int] = if count == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(info, count as usize) }
    };

    match unsafe { (*pr.as_ptr()).control(info) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `host_get_time64()` of `kern/mach_clock.c`.
///
/// # Safety
///
/// `host` must be null or a live host, and `current_time` must be valid for
/// a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_get_time64(
    host: *mut c_void,
    current_time: *mut TimeValue64,
) -> c_int {
    match clock::get_time64(host) {
        Ok(value) => {
            unsafe { current_time.write(value) };
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// `host_set_time64()` of `kern/mach_clock.c`.
#[unsafe(no_mangle)]
pub extern "C" fn host_set_time64(
    host: *mut c_void,
    new_time: TimeValue64,
) -> c_int {
    match clock::set_time64(host, new_time) {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `host_adjust_time64()` of `kern/mach_clock.c`.
///
/// # Safety
///
/// `host` must be null or point at a live `struct host`, and `old_adjustment`
/// must be valid for a write on success; MIG's `_Xhost_adjust_time64` passes
/// its reply field, which is.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_adjust_time64(
    host: *mut c_void,
    new_adjustment: TimeValue64,
    old_adjustment: *mut TimeValue64,
) -> c_int {
    match clock::adjust_time(host, new_adjustment) {
        Ok(old) => {
            unsafe { old_adjustment.write(old) };
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// Both the name and the 512 come from <`mach/mach_host.defs`>, whose reply is a
/// `c_string[512]`.
#[unsafe(no_mangle)]
pub extern "C" fn host_get_kernel_version(
    host: Option<NonNull<Host>>,
    out_version: Option<&mut [u8; KERNEL_VERSION_MAX]>,
) -> c_int {
    let (Some(_), Some(out)) = (host, out_version) else {
        return c_int::from(KernError::InvalidArgument);
    };

    let (version, pad) = out.split_at_mut(KERNEL_VERSION.len());
    version.copy_from_slice(KERNEL_VERSION.as_bytes());
    pad.fill(0);

    0
}

/// `host_get_uptime64()` of `kern/mach_clock.c`.
///
/// # Safety
///
/// `host` must be null or a live host, and `uptime` must be valid for a
/// write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn host_get_uptime64(
    host: *mut c_void,
    uptime: *mut TimeValue64,
) -> c_int {
    match clock::get_uptime64(host) {
        Ok(value) => {
            unsafe { uptime.write(value) };
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// `processor_set_processors()` of kern/host.c.
#[unsafe(no_mangle)]
pub extern "C" fn processor_set_processors(
    pset: Option<&mut ProcessorSet>,
    processor_list: Option<&mut Option<NonNull<VmOffset>>>,
    countp: Option<&mut c_uint>,
) -> c_int {
    let (Some(pset), Some(out_list), Some(out_count)) =
        (pset, processor_list, countp)
    else {
        return c_int::from(KernError::InvalidArgument);
    };

    match processor_ports(pset) {
        Ok((list, count)) => {
            *out_list = Some(list);
            *out_count = count;
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// `task_max_priority()` of kern/task.c.
///
/// # Safety
///
/// `host` must be the port MIG converted from the request, `task` must be a
/// live task, and the caller must hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_max_priority(
    host: *mut c_void,
    task: *mut c_void,
    max_priority: c_int,
    set_priority: c_int,
    change_threads: c_int,
) -> c_int {
    match unsafe {
        task::max_priority(
            host,
            task.cast(),
            max_priority,
            set_priority != 0,
            change_threads != 0,
        )
    } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}
