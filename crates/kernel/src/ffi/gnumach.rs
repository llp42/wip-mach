// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from include/mach/gnumach.defs:
//   Copyright (C) 2012 Free Software Foundation.
// Derived from kern/gsync.c:
//   Copyright (C) 2016 Free Software Foundation, Inc.
//   Contributed by Agustina Arzille <avarzille@riseup.net>, 2016.
// Derived from kern/task.c and kern/thread.c:
//   Copyright (c) 1993-1988 Carnegie Mellon University.
//   Copyright (c) 1994-1987 Carnegie Mellon University.
// Derived from vm/vm_user.c:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The <mach/gnumach.defs> server entries, all 17 routines, which
//! `kern/gnumach.srv` presents.
//!
//! The cores stay in the `crate::kern` and `crate::vm` modules.

use crate::arch::types::{RpcPhysAddr, VmOffset, VmSize};
use crate::kern::gsync::{self, Flags};
use crate::kern::host::Host;
use crate::kern::task::{self, Task};
use crate::kern::thread::Thread;
use crate::kern::types::KernError;
use crate::vm::error::{
    KERN_INVALID_ARGUMENT, KERN_INVALID_TASK, KERN_SUCCESS, kern_return,
};
use crate::vm::types::VmObject;
use crate::vm::vm_map::VmMap;
use crate::vm::vm_user::{self, VmCacheStatistics};
use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr::NonNull;

/// `vm_cache_statistics()` of `vm/vm_user.c`.
///
/// # Safety
///
/// `map` must be null or a live map, and `stats` must be writable storage
/// for one cache-statistics record.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_cache_statistics(
    map: *mut VmMap,
    stats: *mut VmCacheStatistics,
) -> c_int {
    if map.is_null() {
        return KERN_INVALID_ARGUMENT;
    }
    unsafe { stats.write_unaligned(vm_user::cache_statistics()) };
    KERN_SUCCESS
}

/// `thread_terminate_release()` of kern/thread.c.
///
/// # Safety
///
/// `thread` and `task` must be null or point at live objects, and the caller
/// must hold no locks: the routine deallocates and may block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_terminate_release(
    thread: *mut Thread,
    task: *mut Task,
    thread_name: c_uint,
    reply_port: c_uint,
    address: VmOffset,
    size: VmSize,
) -> c_int {
    match unsafe {
        Thread::terminate_release(
            thread,
            task,
            thread_name,
            reply_port,
            address,
            size,
        )
    } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `task_set_name()` of kern/task.c.
///
/// # Safety
///
/// `task` must be a live task, and `name` must be a NUL-terminated string,
/// as the C dereferenced it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_set_name(
    task: *mut c_void,
    name: *const c_char,
) -> c_int {
    let name = unsafe { CStr::from_ptr(name) };

    match unsafe { task::set_name(task.cast(), name.to_bytes()) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `register_new_task_notification()` of kern/task.c.
///
/// # Safety
///
/// `host` must be null or the live host privilege pointer the MIG stub
/// converted, and `notification` the port the request carried; the caller
/// holds no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn register_new_task_notification(
    host: *mut c_void,
    notification: *mut c_void,
) -> c_int {
    if host.is_null() {
        return c_int::from(KernError::InvalidHost);
    }

    // SAFETY: the global is the C `ipc_port_t`, never borrowed as a Rust
    // reference; this read is the C body's own unlocked access.
    if !unsafe { task::NEW_TASK_NOTIFICATION }.is_null() {
        return c_int::from(KernError::NoAccess);
    }

    unsafe { task::NEW_TASK_NOTIFICATION = notification };
    0
}

/// `gsync_wait()` of kern/gsync.c.
///
/// # Safety
///
/// `task` must be null or a live task, as MIG's server entry passes it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gsync_wait(
    task: *mut Task,
    addr: VmOffset,
    lo: c_uint,
    hi: c_uint,
    msec: c_uint,
    flags: c_int,
) -> c_int {
    let Some(task) = NonNull::new(task) else {
        return c_int::from(KernError::InvalidTask);
    };
    match gsync::wait(task, addr, lo, hi, msec, Flags::from_bits(flags)) {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `gsync_wake()` of kern/gsync.c.
///
/// # Safety
///
/// `task` must be null or a live task, as MIG's server entry passes it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gsync_wake(
    task: *mut Task,
    addr: VmOffset,
    val: c_uint,
    flags: c_int,
) -> c_int {
    let Some(task) = NonNull::new(task) else {
        return c_int::from(KernError::InvalidTask);
    };
    match gsync::wake(task, addr, val, Flags::from_bits(flags)) {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `gsync_requeue()` of kern/gsync.c.
///
/// # Safety
///
/// `task` must be null or a live task, as MIG's server entry passes it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gsync_requeue(
    task: *mut Task,
    src_addr: VmOffset,
    dst_addr: VmOffset,
    wake_one: c_int,
    flags: c_int,
) -> c_int {
    let Some(task) = NonNull::new(task) else {
        return c_int::from(KernError::InvalidTask);
    };
    match gsync::requeue(
        task,
        src_addr,
        dst_addr,
        wake_one != 0,
        Flags::from_bits(flags),
    ) {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `vm_wire_all()` of `vm/vm_user.c`.
///
/// # Safety
///
/// `port` must be `IP_NULL`, `IP_DEAD` or a live port; `map` must be null or
/// a live, unlocked map.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_wire_all(
    port: *mut c_void,
    map: *mut VmMap,
    flags: c_int,
) -> c_int {
    kern_return(unsafe { vm_user::wire_all(port, map, flags) })
}

/// `vm_object_sync()` in C.
///
/// # Safety
///
/// `object` must be null or the live object the caller holds a reference to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_object_sync(
    object: *mut VmObject,
    offset: VmOffset,
    size: VmSize,
    should_flush: c_int,
    should_return: c_int,
    _should_iosync: c_int,
) -> c_int {
    let Some(object) = NonNull::new(object) else {
        return KERN_INVALID_ARGUMENT;
    };
    kern_return(vm_user::object_sync(
        object,
        offset,
        size,
        should_flush != 0,
        should_return != 0,
    ))
}

/// `vm_msync()` in C.
///
/// # Safety
///
/// `map` must be null or point at a valid, unlocked map.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_msync(
    map: *mut VmMap,
    address: VmOffset,
    size: VmSize,
    sync_flags: c_int,
) -> c_int {
    let Some(map) = NonNull::new(map) else {
        return KERN_INVALID_ARGUMENT;
    };
    kern_return(unsafe {
        vm_user::msync(&mut *map.as_ptr(), address, size, sync_flags)
    })
}

/// `vm_allocate_contiguous()` of `vm/vm_user.c`.
///
/// # Safety
///
/// `host_priv` must be null or the live host pointer the generated server
/// converted the request port into; `map` must be null or a live, unlocked
/// map; `vaddr` and `paddr` must be writable storage, written only on
/// success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_allocate_contiguous(
    host_priv: *mut Host,
    map: *mut VmMap,
    vaddr: *mut VmOffset,
    paddr: *mut RpcPhysAddr,
    size: VmSize,
    pmin: RpcPhysAddr,
    pmax: RpcPhysAddr,
    palign: RpcPhysAddr,
) -> c_int {
    match unsafe {
        vm_user::allocate_contiguous(
            NonNull::new(host_priv),
            map,
            size,
            pmin,
            pmax,
            palign,
        )
    } {
        Ok((address, physical)) => {
            unsafe {
                vaddr.write(address);
                paddr.write(physical);
            }
            KERN_SUCCESS
        }
        Err(error) => error.as_kern_return(),
    }
}

/// `task_set_essential()` of kern/task.c.
///
/// # Safety
///
/// `task` must be a live task.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_set_essential(
    task: *mut c_void,
    essential: c_int,
) -> c_int {
    match unsafe { task::set_essential(task.cast(), essential != 0) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `vm_pages_phys()` of `vm/vm_user.c`.
///
/// # Safety
///
/// `host` must be null or the live host pointer the generated server
/// converted the request port into; `map` must be null or a live, unlocked
/// map; `pagespp` and `countp` must be writable storage, and the caller
/// permits an allocation and a kernel-map copy.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_pages_phys(
    host: *mut Host,
    map: *mut VmMap,
    address: VmOffset,
    size: VmSize,
    pagespp: *mut *mut RpcPhysAddr,
    countp: *mut c_uint,
) -> c_int {
    match unsafe {
        vm_user::pages_phys(
            NonNull::new(host),
            map,
            address,
            size,
            pagespp,
            countp,
        )
    } {
        Ok(()) => KERN_SUCCESS,
        Err(error) => error.as_kern_return(),
    }
}

/// `thread_set_name()` of kern/thread.c.
///
/// # Safety
///
/// `thread` must be null or point at a live thread, and `name` must be
/// readable up to `TASK_NAME_SIZE - 1` bytes or a NUL inside them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_set_name(
    thread: *mut Thread,
    name: *const c_char,
) -> c_int {
    match unsafe { Thread::set_name(thread, name) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `thread_get_name()` of kern/thread.c.
///
/// # Safety
///
/// `thread` must be null or point at a live thread, and `name` must be
/// writable for `TASK_NAME_SIZE` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_get_name(
    thread: *mut Thread,
    name: *mut c_char,
) -> c_int {
    match unsafe { Thread::get_name(thread, name) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `vm_set_size_limit()` of `vm/vm_user.c`.
///
/// # Safety
///
/// `host_port` must be `IP_NULL`, `IP_DEAD` or a live port, and `map` must be
/// null or a live, unlocked map.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_set_size_limit(
    host_port: *mut c_void,
    map: *mut VmMap,
    current_limit: VmSize,
    max_limit: VmSize,
) -> c_int {
    kern_return(unsafe {
        vm_user::set_size_limit(host_port, map, current_limit, max_limit)
    })
}

/// `vm_get_size_limit()` in C.
///
/// # Safety
///
/// `map` must be null or point at a valid map, and both out-pointers writable
/// storage for one size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_get_size_limit(
    map: *mut VmMap,
    current_limit: *mut VmSize,
    max_limit: *mut VmSize,
) -> c_int {
    let Some(map) = NonNull::new(map) else {
        return KERN_INVALID_TASK;
    };
    let (current, max) = vm_user::get_size_limit(unsafe { &*map.as_ptr() });
    unsafe {
        current_limit.write(current);
        max_limit.write(max);
    }
    KERN_SUCCESS
}
