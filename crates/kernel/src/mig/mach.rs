// SPDX-License-Identifier: CMU-Mach
// Derived from include/mach/mach.defs:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// Derived from kern/ipc_tt.c, kern/syscall_emulation.c, kern/task.c,
// kern/thread.c, vm/memory_object.c, vm/vm_map.c, vm/vm_object.c and
// vm/vm_user.c:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The <mach/mach.defs> server entries, 44 of its 45 routines, which
//! `kern/mach.srv` presents; `htg_vm_map` is not compiled.
//!
//! The cores stay in the `crate::kern` and `crate::vm` modules.

use crate::arch::types::{VmOffset, VmSize};
use crate::ipc::IpcPort;
use crate::kern::error::Error;
use crate::kern::host::Host;
use crate::kern::ipc_tt::{self, TaskSpecialPort, ThreadSpecialPort};
use crate::kern::slab::kfree;
use crate::kern::syscall_emulation;
use crate::kern::task::{self, MapSource, TASK_PORT_REGISTER_MAX, Task};
use crate::kern::thread::Thread;
use crate::mig::code::{KERN_INVALID_ARGUMENT, KERN_SUCCESS, kern_return};
use crate::mig::task_info::{
    TaskBasicInfo, TaskEventsInfo, TaskThreadTimesInfo,
};
use crate::mig::thread_info::{ThreadBasicInfo, ThreadSchedInfo};
use crate::vm::memory_object::{self, Return};
use crate::vm::types::{VmInherit, VmObject, VmProt, VmStatistics};
use crate::vm::vm_map::{VmMap, VmMapCopy};
use crate::vm::vm_object;
use crate::vm::vm_user;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull, with_exposed_provenance_mut};
use core::slice;

/// Creates a child of `parent_task`, whose address space inherits from the
/// parent's when `inherit_memory` is set and starts empty otherwise.
///
/// # Safety
///
/// `parent_task` must be a live task, and `child_task` must be writable for
/// one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_create(
    parent_task: *mut c_void,
    inherit_memory: c_int,
    child_task: *mut *mut c_void,
) -> c_int {
    let Some(parent_task) = NonNull::new(parent_task) else {
        return c_int::from(Error::InvalidTask);
    };

    let source = if inherit_memory != 0 {
        MapSource::Inherit
    } else {
        MapSource::Fresh
    };

    match unsafe { task::create_kernel_task(Some(parent_task.cast()), source) }
    {
        Ok(child) => {
            unsafe { *child_task = child.cast() };
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// Terminates `task` and its threads.
///
/// # Safety
///
/// `task` must be null or a live task, and the caller must hold no locks:
/// the routine blocks and deallocates.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_terminate(task: *mut c_void) -> c_int {
    match unsafe { task::terminate(task.cast()) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// Reports `task`'s emulation vector: the user entry points of its emulated
/// system calls.
///
/// # Safety
///
/// `task` must be null or a live task, and the three out-pointers writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_get_emulation_vector(
    task: *mut Task,
    vector_start: *mut c_int,
    emulation_vector: *mut *mut VmOffset,
    emulation_vector_count: *mut c_uint,
) -> c_int {
    match unsafe { syscall_emulation::get_vector(task) } {
        Ok(vector) => {
            unsafe {
                vector_start.write(vector.start);
                emulation_vector.write(vector.vector);
                emulation_vector_count.write(vector.count);
            }
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// Sets the entries of `task`'s emulation vector from `vector_start` on.
///
/// # Safety
///
/// `task` must be null or a live task, and `emulation_vector` a live map copy
/// of `emulation_vector_count` entries or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_set_emulation_vector(
    task: *mut Task,
    vector_start: c_int,
    emulation_vector: *mut VmOffset,
    emulation_vector_count: c_uint,
) -> c_int {
    kern_return(unsafe {
        syscall_emulation::set_vector(
            task,
            vector_start,
            emulation_vector,
            emulation_vector_count,
        )
    })
}

/// Reports `task`'s threads as send rights.
///
/// # Safety
///
/// `task` must be null or a live task, and both output pointers must be
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_threads(
    task: *mut c_void,
    thread_list: *mut *mut VmOffset,
    count: *mut c_uint,
) -> c_int {
    match unsafe { task::threads(task.cast()) } {
        Ok((list, actual)) => {
            unsafe {
                thread_list
                    .write(list.map_or(ptr::null_mut(), NonNull::as_ptr));
                count.write(actual);
            }
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// The `flavor` argument of `task_info()`.
///
/// A transparent `c_int`: the generated stub forwards the caller's int
/// unchecked, so unlike an enum every value must be valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct TaskFlavor(c_int);

impl TaskFlavor {
    /// `TASK_BASIC_INFO`.
    const BASIC_INFO: Self = Self(1);
    /// `TASK_EVENTS_INFO`.
    const EVENTS_INFO: Self = Self(2);
    /// `TASK_THREAD_TIMES_INFO`.
    const THREAD_TIMES_INFO: Self = Self(3);
}

/// Reports `task`'s information of `flavor`.
///
/// # Safety
///
/// `task` must be a live task, `task_info_out` must be writable for
/// `*task_info_count` `integer_t`s, and `task_info_count` must be readable
/// and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_info(
    task: *mut c_void,
    flavor: TaskFlavor,
    task_info_out: *mut c_int,
    task_info_count: *mut c_uint,
) -> c_int {
    let Some(task) = NonNull::new(task.cast::<Task>()) else {
        return c_int::from(Error::InvalidArgument);
    };
    let Some(count) = NonNull::new(task_info_count) else {
        return c_int::from(Error::InvalidArgument);
    };
    let Some(out) = NonNull::new(task_info_out) else {
        return c_int::from(Error::InvalidArgument);
    };

    let capacity = unsafe { count.as_ptr().read() };
    let written = match flavor {
        TaskFlavor::BASIC_INFO => {
            if (capacity as usize) < TaskBasicInfo::LEGACY_WORDS {
                return c_int::from(Error::InvalidArgument);
            }

            // SAFETY: `task` is live and non-null, as the caller promises.
            let basic = TaskBasicInfo::from(unsafe { task.as_ref() });
            // SAFETY: the legacy words fit the capacity, and the MIG buffer
            // is only `integer_t`-aligned.
            unsafe {
                ptr::copy_nonoverlapping(
                    ptr::addr_of!(basic).cast::<c_int>(),
                    out.as_ptr(),
                    TaskBasicInfo::LEGACY_WORDS,
                );
            }
            if capacity == TaskBasicInfo::WORDS {
                // SAFETY: the capacity covers the whole record; the MIG
                // buffer is only `integer_t`-aligned.
                unsafe {
                    out.as_ptr()
                        .cast::<TaskBasicInfo>()
                        .write_unaligned(basic);
                }
            }
            if capacity > TaskBasicInfo::WORDS {
                TaskBasicInfo::WORDS
            } else {
                capacity
            }
        }
        TaskFlavor::EVENTS_INFO => {
            if capacity < TaskEventsInfo::WORDS {
                return c_int::from(Error::InvalidArgument);
            }

            // SAFETY: `task` is live and non-null, as the caller promises.
            let events = TaskEventsInfo::from(unsafe { task.as_ref() });
            // SAFETY: the capacity check above covers the record; the MIG
            // buffer is only `integer_t`-aligned.
            unsafe {
                out.as_ptr()
                    .cast::<TaskEventsInfo>()
                    .write_unaligned(events);
            }
            TaskEventsInfo::WORDS
        }
        TaskFlavor::THREAD_TIMES_INFO => {
            // The count is a `natural_t`, which widens to `usize`.
            if (capacity as usize) < TaskThreadTimesInfo::LEGACY_WORDS {
                return c_int::from(Error::InvalidArgument);
            }

            // SAFETY: `task` is live and non-null, as the caller promises.
            let times = TaskThreadTimesInfo::from(unsafe { task.as_ref() });
            // SAFETY: the legacy words fit the capacity, and the MIG buffer
            // is only `integer_t`-aligned.
            unsafe {
                ptr::copy_nonoverlapping(
                    ptr::addr_of!(times).cast::<c_int>(),
                    out.as_ptr(),
                    TaskThreadTimesInfo::LEGACY_WORDS,
                );
            }
            if capacity >= TaskThreadTimesInfo::WORDS {
                // SAFETY: the capacity covers the whole record; the MIG
                // buffer is only `integer_t`-aligned.
                unsafe {
                    out.as_ptr()
                        .cast::<TaskThreadTimesInfo>()
                        .write_unaligned(times);
                }
            }
            if capacity > TaskThreadTimesInfo::WORDS {
                TaskThreadTimesInfo::WORDS
            } else {
                capacity
            }
        }
        _ => return c_int::from(Error::InvalidArgument),
    };

    unsafe { count.as_ptr().write(written) };
    0
}

/// Terminates `thread`.
///
/// # Safety
///
/// `thread` must be null or a live thread, and the caller must hold no locks:
/// the routine waits and may block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_terminate(thread: *mut Thread) -> c_int {
    match unsafe { Thread::terminate(thread) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// Reports `thread`'s machine state of `flavor`.
///
/// # Safety
///
/// `thread` must be null or point at a live thread; `old_state` must be
/// writable for the words `*old_state_count` names, and `old_state_count` must
/// be valid for a read and a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_get_state(
    thread: *mut Thread,
    flavor: c_int,
    old_state: *mut c_uint,
    old_state_count: *mut c_uint,
) -> c_int {
    match unsafe {
        Thread::get_status(thread, flavor, old_state, old_state_count)
    } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// Sets `thread`'s machine state of `flavor`.
///
/// # Safety
///
/// `thread` must be null or point at a live thread, and `new_state` must be
/// readable for `new_state_count` words.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_set_state(
    thread: *mut Thread,
    flavor: c_int,
    new_state: *mut c_uint,
    new_state_count: c_uint,
) -> c_int {
    match unsafe {
        Thread::set_status(thread, flavor, new_state, new_state_count)
    } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// The `flavor` argument of `thread_info()`.
///
/// A transparent `c_int`: the generated stub forwards the caller's int
/// unchecked, so unlike an enum every value must be valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ThreadFlavor(c_int);

impl ThreadFlavor {
    /// `THREAD_BASIC_INFO`.
    const BASIC_INFO: Self = Self(1);
    /// `THREAD_SCHED_INFO`.
    const SCHED_INFO: Self = Self(2);
}

/// Reports `thread`'s information of `flavor`.
///
/// # Safety
///
/// `thread` must be null or a live thread; `thread_info` must be writable for
/// `*thread_info_count` `integer_t`s, and `thread_info_count` must be readable
/// and writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_info(
    thread: *mut Thread,
    flavor: ThreadFlavor,
    thread_info: *mut c_int,
    thread_info_count: *mut c_uint,
) -> c_int {
    if thread.is_null() {
        return c_int::from(Error::InvalidArgument);
    }
    let Some(count) = NonNull::new(thread_info_count) else {
        return c_int::from(Error::InvalidArgument);
    };
    let Some(info) = NonNull::new(thread_info) else {
        return c_int::from(Error::InvalidArgument);
    };

    let capacity = unsafe { count.as_ptr().read() };
    let written = match flavor {
        ThreadFlavor::BASIC_INFO => {
            if (capacity as usize) < ThreadBasicInfo::LEGACY_WORDS {
                return c_int::from(Error::InvalidArgument);
            }

            // SAFETY: `thread` is live and non-null, as the caller promises.
            let basic = unsafe { ThreadBasicInfo::capture(thread) };
            // SAFETY: the legacy words fit the capacity, and the MIG buffer
            // is only `integer_t`-aligned.
            unsafe {
                ptr::copy_nonoverlapping(
                    ptr::addr_of!(basic).cast::<c_int>(),
                    info.as_ptr(),
                    ThreadBasicInfo::LEGACY_WORDS,
                );
            }
            if capacity == ThreadBasicInfo::WORDS {
                // SAFETY: the capacity covers the whole record; the MIG
                // buffer is only `integer_t`-aligned.
                unsafe {
                    info.as_ptr()
                        .cast::<ThreadBasicInfo>()
                        .write_unaligned(basic);
                }
            }
            if capacity > ThreadBasicInfo::WORDS {
                ThreadBasicInfo::WORDS
            } else {
                capacity
            }
        }
        ThreadFlavor::SCHED_INFO => {
            if capacity < ThreadSchedInfo::WORDS - 1 {
                return c_int::from(Error::InvalidArgument);
            }

            // SAFETY: `thread` is live and non-null.
            let sched = ThreadSchedInfo::from(unsafe { &*thread });
            // SAFETY: the capacity check above covers the record, and the
            // MIG buffer is only `integer_t`-aligned.
            unsafe {
                info.as_ptr()
                    .cast::<ThreadSchedInfo>()
                    .write_unaligned(sched);
            }
            ThreadSchedInfo::WORDS
        }
        _ => return c_int::from(Error::InvalidArgument),
    };

    unsafe { count.as_ptr().write(written) };
    0
}

/// Allocates `size` bytes of zero-filled memory in `map`, at `*addr` or
/// anywhere when `anywhere` is set.
///
/// # Safety
///
/// `map` must be null or point at a valid map, and `addr` at writable storage
/// for one address.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_allocate(
    map: *mut VmMap,
    addr: *mut VmOffset,
    size: VmSize,
    anywhere: c_int,
) -> c_int {
    let Some(map) = NonNull::new(map) else {
        return KERN_INVALID_ARGUMENT;
    };
    kern_return(unsafe {
        vm_user::allocate(&mut *map.as_ptr(), &mut *addr, size, anywhere != 0)
    })
}

/// Deallocates the range of `map` at `start`.
///
/// # Safety
///
/// `map` must be null or point at a valid, unlocked map.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_deallocate(
    map: *mut VmMap,
    start: VmOffset,
    size: VmSize,
) -> c_int {
    let Some(map) = NonNull::new(map) else {
        return KERN_INVALID_ARGUMENT;
    };
    kern_return(unsafe {
        vm_user::deallocate(&mut *map.as_ptr(), start, size)
    })
}

/// Sets the current protection, or the maximum when `set_maximum` is set, of
/// the range of `map` at `start`.
///
/// # Safety
///
/// `map` must be null or point at a valid, unlocked map.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_protect(
    map: *mut VmMap,
    start: VmOffset,
    size: VmSize,
    set_maximum: c_int,
    new_protection: VmProt,
) -> c_int {
    let Some(map) = NonNull::new(map) else {
        return KERN_INVALID_ARGUMENT;
    };
    kern_return(unsafe {
        vm_user::protect(
            &mut *map.as_ptr(),
            start,
            size,
            set_maximum != 0,
            new_protection,
        )
    })
}

/// Sets the inheritance of the range of `map` at `start`.
///
/// # Safety
///
/// `map` must be null or point at a valid, unlocked map.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_inherit(
    map: *mut VmMap,
    start: VmOffset,
    size: VmSize,
    new_inheritance: VmInherit,
) -> c_int {
    let Some(map) = NonNull::new(map) else {
        return KERN_INVALID_ARGUMENT;
    };
    kern_return(unsafe {
        vm_user::inherit(&mut *map.as_ptr(), start, size, new_inheritance)
    })
}

/// Copies `size` bytes of `map` at `address` out of line.
///
/// # Safety
///
/// `map` must be null or point at a valid, unlocked map, and both out-pointers
/// writable storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_read(
    map: *mut VmMap,
    address: VmOffset,
    size: VmSize,
    data: *mut VmOffset,
    data_size: *mut c_uint,
) -> c_int {
    let Some(map) = NonNull::new(map) else {
        return KERN_INVALID_ARGUMENT;
    };
    match unsafe { vm_user::read(&mut *map.as_ptr(), address, size) } {
        Ok(copy) => {
            unsafe {
                data.write(
                    copy.map_or(0, |copy| copy.as_ptr().expose_provenance()),
                );
                data_size.write(size as c_uint);
            }
            KERN_SUCCESS
        }
        Err(error) => c_int::from(error),
    }
}

/// Writes the out-of-line `data` into `map` at `address`.
///
/// # Safety
///
/// `map` must be null or point at a valid, unlocked map, and `data` must be
/// null or the live copy `vm_read()` returned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_write(
    map: *mut VmMap,
    address: VmOffset,
    data: VmOffset,
    _size: c_uint,
) -> c_int {
    let Some(map) = NonNull::new(map) else {
        return KERN_INVALID_ARGUMENT;
    };
    let copy = NonNull::new(with_exposed_provenance_mut::<VmMapCopy>(data));
    kern_return(unsafe { vm_user::write(&mut *map.as_ptr(), address, copy) })
}

/// Copies `size` bytes of `map` from `source_address` to `dest_address`.
///
/// # Safety
///
/// `map` must be null or point at a valid, unlocked map.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_copy(
    map: *mut VmMap,
    source_address: VmOffset,
    size: VmSize,
    dest_address: VmOffset,
) -> c_int {
    let Some(map) = NonNull::new(map) else {
        return KERN_INVALID_ARGUMENT;
    };
    kern_return(unsafe {
        vm_user::copy(&mut *map.as_ptr(), source_address, size, dest_address)
    })
}

/// Reports the region of `map` at or after `*address`: its bounds,
/// protections, inheritance, sharing and memory object.
///
/// # Safety
///
/// `map` must be a valid map or null, every out-pointer must be writable, and
/// `address` must point at readable storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_region(
    map: *mut VmMap,
    address: *mut VmOffset,
    size: *mut VmSize,
    protection: *mut VmProt,
    max_protection: *mut VmProt,
    inheritance: *mut VmInherit,
    is_shared: *mut c_int,
    object_name: *mut *mut c_void,
    offset_in_object: *mut VmOffset,
) -> c_int {
    let Some(map) = NonNull::new(map) else {
        return KERN_INVALID_ARGUMENT;
    };

    let start = unsafe { *address };
    match unsafe { map.as_ref() }.region(start) {
        Ok(region) => {
            unsafe {
                address.write(region.address);
                size.write(region.size);
                protection.write(region.protection);
                max_protection.write(region.max_protection);
                inheritance.write(region.inheritance);
                is_shared.write(c_int::from(region.is_shared));
                object_name.write(
                    region
                        .object_name
                        .map_or(ptr::null_mut(), IpcPort::as_ptr),
                );
                offset_in_object.write(region.offset);
            }
            KERN_SUCCESS
        }
        Err(error) => c_int::from(error),
    }
}

/// Reports the virtual-memory statistics.
///
/// # Safety
///
/// `map` must be null or a live map, and `stat` must be writable storage for
/// one statistics record.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_statistics(
    map: *mut VmMap,
    stat: *mut VmStatistics,
) -> c_int {
    if map.is_null() {
        return KERN_INVALID_ARGUMENT;
    }
    unsafe { stat.write_unaligned(vm_user::statistics()) };
    KERN_SUCCESS
}

/// Registers the `ports_cnt` send rights at `memory` as `task`'s registered
/// ports.
///
/// # Safety
///
/// `task` must be null or a live task, `memory` must be a `kalloc`'d array of
/// `ports_cnt` `mach_port_t`s the caller gives up on success, and the caller
/// must hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_ports_register(
    task: *mut Task,
    memory: *mut VmOffset,
    ports_cnt: c_uint,
) -> c_int {
    // `mach_msg_type_number_t` is a `u32`, and `usize` holds it on both
    // targets.
    if ports_cnt as usize > TASK_PORT_REGISTER_MAX {
        return c_int::from(Error::InvalidArgument);
    }
    let count = ports_cnt as usize;

    let ports: &[VmOffset] = if count == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(memory, count) }
    };

    match unsafe { ipc_tt::ports_register(task, ports) } {
        Ok(()) => {
            if ports_cnt != 0 {
                unsafe {
                    kfree(
                        NonNull::new_unchecked(memory.cast::<u8>()),
                        count * size_of::<VmOffset>(),
                    );
                }
            }
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// Reports `task`'s registered ports.
///
/// # Safety
///
/// `task` must be null or a live task, both out-pointers must be writable,
/// and the caller must hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_ports_lookup(
    task: *mut Task,
    portsp: *mut *mut VmOffset,
    ports_cnt: *mut c_uint,
) -> c_int {
    match unsafe { ipc_tt::ports_lookup(task) } {
        Ok((ports, count)) => {
            unsafe {
                portsp.write(ports.as_ptr());
                ports_cnt.write(count);
            }
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// Tells the kernel the pager has no data for the range of `object`, which
/// then reads as zeros.
///
/// # Safety
///
/// A non-null `object` must be a live object the call may deallocate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_object_data_unavailable(
    object: *mut VmObject,
    offset: VmOffset,
    size: VmSize,
) -> c_int {
    kern_return(unsafe {
        memory_object::data_unavailable(object, offset, size)
    })
}

/// Reports `object`'s readiness, caching and copy strategy.
///
/// # Safety
///
/// A non-null `object` must be a live object the call may deallocate, and the
/// three out-pointers must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_object_get_attributes(
    object: *mut VmObject,
    object_ready: *mut c_int,
    may_cache: *mut c_int,
    copy_strategy: *mut c_int,
) -> c_int {
    match unsafe { memory_object::get_attributes(object) } {
        Ok(attributes) => {
            unsafe {
                object_ready.write(c_int::from(attributes.ready));
                may_cache.write(c_int::from(attributes.may_cache));
                copy_strategy.write(attributes.copy_strategy);
            }
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// Sets the default memory manager from `*default_manager` unless it is null,
/// and reports the previous one there.
///
/// # Safety
///
/// A non-null `host` must be a live host, and `default_manager` must be
/// writable for one port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_set_default_memory_manager(
    host: *mut Host,
    default_manager: *mut *mut c_void,
) -> c_int {
    match unsafe { memory_object::default_manager::set(host, default_manager) }
    {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// Cleans, flushes or locks the pages of `object` in the range, replying to
/// `reply_to` when done.
///
/// # Safety
///
/// A non-null `object` must be a live object the call may deallocate;
/// `reply_to` must be `IP_NULL` or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_object_lock_request(
    object: *mut VmObject,
    offset: VmOffset,
    size: VmSize,
    should_return: c_int,
    should_flush: c_int,
    lock_value: c_int,
    reply_to: *mut c_void,
    reply_to_type: c_uint,
) -> c_int {
    kern_return(unsafe {
        memory_object::lock_request(
            object,
            &memory_object::LockRequest {
                offset,
                size,
                should_return: Return::from_c(should_return),
                should_flush: should_flush != 0,
                prot: VmProt::from_bits(lock_value),
                reply_to,
                reply_to_type,
            },
        )
    })
}

/// Suspends `task`, counting one more suspension.
///
/// # Safety
///
/// `task` must be a live task, and the caller must hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_suspend(task: *mut c_void) -> c_int {
    match unsafe { task::suspend(task.cast()) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// Drops one suspension of `task`, resuming its threads at zero.
///
/// # Safety
///
/// `task` must be a live task, and the caller must hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_resume(task: *mut c_void) -> c_int {
    match unsafe { task::resume(task.cast()) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// Reports `task`'s special port `which`.
///
/// # Safety
///
/// `task` must be null or a live task, `portp` must be writable, and the
/// caller must hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_get_special_port(
    task: *mut Task,
    which: c_int,
    portp: *mut *mut c_void,
) -> c_int {
    let Some(which) = TaskSpecialPort::from_int(which) else {
        return c_int::from(Error::InvalidArgument);
    };

    match unsafe { ipc_tt::task_get_special_port(task, which) } {
        Ok(port) => {
            unsafe {
                portp.write(port.map_or(ptr::null_mut(), IpcPort::as_ptr));
            };
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// Sets `task`'s special port `which` to `port`.
///
/// # Safety
///
/// `task` must be null or a live task, `port` must be a naked send right or
/// `IP_NULL`, and the caller must hold no locks; on success the right is
/// consumed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_set_special_port(
    task: *mut Task,
    which: c_int,
    port: *mut c_void,
) -> c_int {
    let Some(which) = TaskSpecialPort::from_int(which) else {
        return c_int::from(Error::InvalidArgument);
    };

    match unsafe { ipc_tt::task_set_special_port(task, which, port) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// Creates a suspended thread in `parent_task`.
///
/// # Safety
///
/// `parent_task` must be null or a live task, and `child_thread` must be
/// writable for one pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_create(
    parent_task: *mut Task,
    child_thread: *mut *mut Thread,
) -> c_int {
    match unsafe { Thread::create(parent_task) } {
        Ok(thread) => {
            unsafe { child_thread.write(thread) };
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// Suspends `thread`, counting one more suspension.
///
/// # Safety
///
/// `thread` must be null or a live thread, and the caller must hold no locks:
/// the routine waits and may block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_suspend(thread: *mut Thread) -> c_int {
    match unsafe { Thread::suspend(thread) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// Drops one suspension of `thread`, resuming it at zero.
///
/// # Safety
///
/// `thread` must be null or point at a live thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_resume(thread: *mut Thread) -> c_int {
    match unsafe { Thread::resume(thread) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// Aborts `thread`'s system call or wait, so its state can be read or changed.
///
/// # Safety
///
/// `thread` must be null or point at a live thread; the routine takes the
/// thread's locks itself and may block.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_abort(thread: *mut Thread) -> c_int {
    match unsafe { Thread::abort(thread) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// Reports `thread`'s special port `which`.
///
/// # Safety
///
/// `thread` must be null or a live thread, `portp` must be writable, and the
/// caller must hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_get_special_port(
    thread: *mut Thread,
    which: c_int,
    portp: *mut *mut c_void,
) -> c_int {
    let Some(which) = ThreadSpecialPort::from_int(which) else {
        return c_int::from(Error::InvalidArgument);
    };

    match unsafe { ipc_tt::thread_get_special_port(thread, which) } {
        Ok(port) => {
            unsafe {
                portp.write(port.map_or(ptr::null_mut(), IpcPort::as_ptr));
            };
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// Sets `thread`'s special port `which` to `port`.
///
/// # Safety
///
/// `thread` must be null or a live thread, `port` must be a naked send right
/// or `IP_NULL`, and the caller must hold no locks; on success the right is
/// consumed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn thread_set_special_port(
    thread: *mut Thread,
    which: c_int,
    port: *mut c_void,
) -> c_int {
    let Some(which) = ThreadSpecialPort::from_int(which) else {
        return c_int::from(Error::InvalidArgument);
    };

    match unsafe { ipc_tt::thread_set_special_port(thread, which, port) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// Sets one entry of `task`'s emulation vector: system call `routine_number`
/// goes to `routine_entry_pt`.
///
/// # Safety
///
/// `task` must be null or a live task; `routine_entry_pt` is the entry
/// address the task will dispatch to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_set_emulation(
    task: *mut Task,
    routine_entry_pt: VmOffset,
    routine_number: c_int,
) -> c_int {
    let mut routine = routine_entry_pt;
    kern_return(unsafe {
        syscall_emulation::set_vector_internal(
            task,
            routine_number,
            &raw mut routine,
            1,
        )
    })
}

/// Fails: the kernel has no restartable atomic sequences.
///
/// # Safety
///
/// The MIG server calls this with the task it converted from the request
/// port; nothing here reads or writes any argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn task_ras_control(
    _task: *mut c_void,
    _pc: VmOffset,
    _endpc: VmOffset,
    _flavor: c_int,
) -> c_int {
    c_int::from(Error::Failure)
}

/// Maps `memory_object` at `offset` into `target_map`, at `*address` or
/// anywhere when `anywhere` is set, copying it when `copy` is set.
///
/// # Safety
///
/// `target_map` must be null or a live, unlocked map, `address` must point
/// at writable storage for one address, and `memory_object` must be
/// `IP_NULL`, `IP_DEAD` or a live port the caller holds a reference to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_map(
    target_map: *mut VmMap,
    address: *mut VmOffset,
    size: VmSize,
    mask: VmOffset,
    anywhere: c_int,
    memory_object: *mut c_void,
    offset: VmOffset,
    copy: c_int,
    cur_protection: VmProt,
    max_protection: VmProt,
    inheritance: VmInherit,
) -> c_int {
    let Some(target_map) = NonNull::new(target_map) else {
        return KERN_INVALID_ARGUMENT;
    };
    kern_return(unsafe {
        vm_user::map(
            &mut *target_map.as_ptr(),
            &mut vm_user::MapRequest {
                address: &mut *address,
                size,
                mask,
                anywhere: anywhere != 0,
                memory_object,
                offset,
                copy: copy != 0,
                cur_protection,
                max_protection,
                inheritance,
            },
        )
    })
}

/// Tells the kernel the pager cannot supply the range of `object`; the error
/// value is not kept.
///
/// # Safety
///
/// A non-null `object` must be a live object the call may deallocate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_object_data_error(
    object: *mut VmObject,
    offset: VmOffset,
    size: VmSize,
    _error_value: c_int,
) -> c_int {
    kern_return(unsafe { memory_object::data_error(object, offset, size) })
}

/// Destroys `object`, as its pager asked.
///
/// # Safety
///
/// `object` must be null or a live object the caller holds a reference to;
/// `_reason` is unused, as in the C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_object_destroy(
    object: *mut VmObject,
    _reason: c_int,
) -> c_int {
    unsafe { vm_object::memory_object_destroy(object) };
    KERN_SUCCESS
}

/// Supplies the pager's `data` for the range of `object` at `offset`, locked
/// against `lock_value`, replying to `reply_to` when asked.
///
/// # Safety
///
/// A non-null `object` must be a live object the call may deallocate;
/// `data` must name a live page-list copy of `data_cnt` bytes; `reply_to`
/// must be `IP_NULL` or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_object_data_supply(
    object: *mut VmObject,
    offset: VmOffset,
    data: VmOffset,
    data_cnt: c_uint,
    lock_value: c_int,
    precious: c_int,
    reply_to: *mut c_void,
    reply_to_type: c_uint,
) -> c_int {
    kern_return(unsafe {
        memory_object::data_supply(
            object,
            &memory_object::SupplyRequest {
                offset,
                data,
                data_cnt,
                lock_value: VmProt::from_bits(lock_value),
                precious: precious != 0,
                reply_to,
                reply_to_type,
            },
        )
    })
}

/// Marks `object` ready, with its caching and copy strategy.
///
/// # Safety
///
/// A non-null `object` must be a live object the call may deallocate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_object_ready(
    object: *mut VmObject,
    may_cache: c_int,
    copy_strategy: c_int,
) -> c_int {
    kern_return(unsafe {
        memory_object::ready(object, may_cache != 0, copy_strategy)
    })
}

/// Changes `object`'s caching and copy strategy, replying to `reply_to` when
/// asked.
///
/// # Safety
///
/// A non-null `object` must be a live object the call may deallocate;
/// `reply_to` must be `IP_NULL` or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_object_change_attributes(
    object: *mut VmObject,
    may_cache: c_int,
    copy_strategy: c_int,
    reply_to: *mut c_void,
    reply_to_type: c_uint,
) -> c_int {
    kern_return(unsafe {
        memory_object::change_attributes(
            object,
            may_cache != 0,
            copy_strategy,
            reply_to,
            reply_to_type,
        )
    })
}

/// Hands a machine attribute for the range of `map` at `address` to the
/// physical map; the attribute and its value are not used.
///
/// # Safety
///
/// `map` must be null or point at a valid, unlocked map.  `value` is not read
/// while the pmap attribute walk is a stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_machine_attribute(
    map: *mut VmMap,
    address: VmOffset,
    size: VmSize,
    _attribute: c_uint,
    _value: *mut c_int,
) -> c_int {
    let Some(map) = NonNull::new(map) else {
        return KERN_INVALID_ARGUMENT;
    };
    kern_return(unsafe {
        vm_user::machine_attribute(&*map.as_ptr(), address, size)
    })
}
