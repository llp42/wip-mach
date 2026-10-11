// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The trap entries, `mach_msg_trap` and its continuations, and the
//! kernel's own message send.
//!
//! The symbols the generated code calls are in [`crate::mig::runtime`]; this
//! module holds the routines themselves.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::x86_64::locore::thread_syscall_return;
use crate::arch::x86_64::platform::MachPlatform;
use crate::kern::debug::kpanic;
use crate::mig::code::{
    io_return, kern_return, msg_return, receive_return, task_return,
    trap_return,
};
use crate::vm::VmMap;
use core::ffi::{c_int, c_uint, c_ulong, c_void};
use mach_ipc::error::SendError;
use mach_ipc::ipc_kmsg;
use mach_ipc::ipc_mqueue;
use mach_ipc::mach_msg;
use mach_ipc::{IpcSpace, MachMsgHeader, MsgOption};
use mach_thread::syscall_subr;
use mach_thread::task;
use mach_trap::types::VmMapRequest;
use mach_trap::{rpc, self_state};

/// No timeout.
const MACH_MSG_TIMEOUT_NONE: c_uint = 0;

/// Returns the running task's IPC space.
///
/// The space is live for as long as the thread runs: its task holds a
/// reference to it. After the task's death the space is dead as well.
///
/// # Panics
///
/// If the CPU runs no thread, as [`task::current_task()`] does.
pub(crate) fn current_space() -> IpcSpace {
    // SAFETY: the running thread's task is live. Task creation sets its
    // `itk_space` to a fresh, non-null space before the task has a thread,
    // and nothing writes the field again.
    unsafe {
        IpcSpace::from_raw(
            (*task::current_task::<MachPlatform>().as_ptr()).itk_space,
        )
    }
}

/// Returns the running task's address space.
///
/// The map is live for as long as the thread runs: its task holds a
/// reference to it.
///
/// # Panics
///
/// If the CPU runs no thread, as [`task::current_task()`] does.
pub(crate) fn current_map() -> *mut VmMap {
    // SAFETY: the running thread's task is live. Task creation sets its
    // `map` before the task has a thread, and nothing writes the field
    // again.
    unsafe { (*task::current_task::<MachPlatform>().as_ptr()).map.cast() }
}

/// The `mach_msg` trap entry the trap table holds.
///
/// # Safety
///
/// `msg` must name a readable and writable user message of the sizes
/// `option` selects; the caller is the trap dispatcher and holds no locks.
pub(crate) unsafe extern "C" fn mach_msg_trap(
    msg: *mut c_void,
    option: c_int,
    send_size: c_uint,
    rcv_size: c_uint,
    rcv_name: c_uint,
    time_out: c_uint,
    notify: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            mach_msg::trap::<MachPlatform>(
                msg,
                // The C option word is an `int` whose bits the set names;
                // reading its pattern as unsigned keeps them all.
                MsgOption::from_bits_retain(option as c_uint),
                send_size,
                rcv_size,
                rcv_name,
                time_out,
                notify,
            )
        }
        .map_err(msg_return),
    )
}

/// The continuation a receive resumes through after its wait.
///
/// The scheduler and the exception path recognise a thread blocked in a
/// receive by this function's address.
///
/// # Safety
///
/// Called as the continuation a blocked receive stored in the current
/// thread; the thread's stack is the one the wakeup supplied.
pub(crate) unsafe extern "C" fn mach_msg_receive_continue() {
    let completed = unsafe { mach_msg::receive_continue::<MachPlatform>() };
    // SAFETY: `thread_syscall_return` returns to user space and never
    // returns to this continuation.
    unsafe {
        thread_syscall_return(kern_return(completed.map_err(receive_return)))
    }
}

/// The continuation the send-and-receive trap resumes through after its wait.
///
/// The scheduler and the exception path recognise a thread blocked in a
/// receive by this function's address.
///
/// # Safety
///
/// Called as the continuation a blocked send-and-receive stored in the
/// current thread; the thread's stack is the one the wakeup supplied.
pub(crate) unsafe extern "C" fn mach_msg_continue() {
    let completed = unsafe { mach_msg::msg_continue::<MachPlatform>() };
    // SAFETY: `thread_syscall_return` returns to user space and never
    // returns to this continuation.
    unsafe {
        thread_syscall_return(kern_return(completed.map_err(receive_return)))
    }
}

/// The `thread_set_self_state` trap entry, trap -77.
///
/// # Safety
///
/// Reached as trap -77: a non-null `new_state` must be readable for
/// `new_state_count` `natural_t` words, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn thread_set_self_state(
    flavor: c_int,
    new_state: *mut c_uint,
    new_state_count: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            self_state::set_self_state::<MachPlatform>(
                flavor,
                new_state,
                new_state_count,
            )
        }
        .map_err(task_return),
    )
}

/// Sends a message the kernel built, of `send_size` bytes at `msg`.
///
/// # Safety
///
/// `msg` must point at a readable kernel message of `send_size` bytes, and
/// the caller must hold no locks.
pub(crate) unsafe fn mach_msg_send_from_kernel(
    msg: *mut c_void,
    send_size: c_uint,
) -> Result<(), SendError> {
    let remote = unsafe { (*msg.cast::<MachMsgHeader>()).remote() };
    // `MACH_PORT_VALID()` over the kernel header's pointer-wide field.
    if remote == 0 || remote == usize::MAX {
        return Err(SendError::InvalidDest);
    }

    let Ok(kmsg) =
        (unsafe { ipc_kmsg::get_from_kernel::<MachPlatform>(msg, send_size) })
    else {
        kpanic!("mach_msg_send_from_kernel", "mach_msg_send_from_kernel")
    };

    // SAFETY: the message is live and this call owns it.
    unsafe { ipc_kmsg::copyin_from_kernel(kmsg) };
    // SAFETY: the message is live and holds the send right the send consumes;
    // the result is discarded.
    let _ = unsafe {
        ipc_mqueue::send::<MachPlatform>(
            kmsg.as_ptr(),
            MsgOption::SEND_ALWAYS,
            MACH_MSG_TIMEOUT_NONE,
        )
    };
    Ok(())
}

/// The `syscall_vm_map` trap entry, trap 64.
///
/// # Safety
///
/// Reached as trap 64 with user arguments: `address` must name user storage
/// of one address in the current map, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_vm_map_entry(
    target_map: c_uint,
    address: *mut VmOffset,
    size: VmSize,
    mask: VmOffset,
    anywhere: c_int,
    memory_object: c_uint,
    offset: VmOffset,
    copy: c_int,
    cur_protection: c_int,
    max_protection: c_int,
    inheritance: c_int,
) -> c_int {
    let request = VmMapRequest {
        target_map,
        address,
        size,
        mask,
        anywhere,
        memory_object,
        offset,
        copy,
        cur_protection,
        max_protection,
        inheritance,
    };

    kern_return(
        unsafe { rpc::syscall_vm_map::<MachPlatform>(&request) }
            .map_err(trap_return),
    )
}

/// The `syscall_vm_allocate` trap entry, trap 65.
///
/// # Safety
///
/// Reached as trap 65 with user arguments: `address` must name user storage
/// of one address in the current map, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_vm_allocate_entry(
    target_map: c_uint,
    address: *mut VmOffset,
    size: VmSize,
    anywhere: c_int,
) -> c_int {
    kern_return(
        unsafe {
            rpc::syscall_vm_allocate::<MachPlatform>(
                target_map, address, size, anywhere,
            )
        }
        .map_err(trap_return),
    )
}

/// The `syscall_vm_deallocate` trap entry, trap 66.
///
/// # Safety
///
/// Reached as trap 66 with user arguments, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_vm_deallocate_entry(
    target_map: c_uint,
    start: VmOffset,
    size: VmSize,
) -> c_int {
    kern_return(
        unsafe {
            rpc::syscall_vm_deallocate::<MachPlatform>(target_map, start, size)
        }
        .map_err(trap_return),
    )
}

/// The `syscall_task_create` trap entry, trap 68.
///
/// # Safety
///
/// Reached as trap 68 with user arguments: `child_task` must name user
/// storage of one name in the current map, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_task_create_entry(
    parent_task: c_uint,
    inherit_memory: c_int,
    child_task: *mut c_uint,
) -> c_int {
    kern_return(
        unsafe {
            rpc::syscall_task_create::<MachPlatform>(
                parent_task,
                inherit_memory,
                child_task,
            )
        }
        .map_err(trap_return),
    )
}

/// The `syscall_task_terminate` trap entry, trap 69.
///
/// # Safety
///
/// Reached as trap 69 with a user argument, and the caller must hold no
/// locks.
pub(crate) unsafe extern "C" fn syscall_task_terminate_entry(
    task: c_uint,
) -> c_int {
    kern_return(
        unsafe { rpc::syscall_task_terminate::<MachPlatform>(task) }
            .map_err(trap_return),
    )
}

/// The `syscall_task_suspend` trap entry, trap 70.
///
/// # Safety
///
/// Reached as trap 70 with a user argument, and the caller must hold no
/// locks.
pub(crate) unsafe extern "C" fn syscall_task_suspend_entry(
    task: c_uint,
) -> c_int {
    kern_return(
        unsafe { rpc::syscall_task_suspend::<MachPlatform>(task) }
            .map_err(trap_return),
    )
}

/// The `syscall_task_set_special_port` trap entry, trap 71.
///
/// # Safety
///
/// Reached as trap 71 with user arguments, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_task_set_special_port_entry(
    task: c_uint,
    which_port: c_int,
    port_name: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            rpc::syscall_task_set_special_port::<MachPlatform>(
                task, which_port, port_name,
            )
        }
        .map_err(trap_return),
    )
}

/// The `syscall_mach_port_allocate` trap entry, trap 72.
///
/// # Safety
///
/// Reached as trap 72 with user arguments: `namep` must name user storage of
/// one name in the current map, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_mach_port_allocate_entry(
    task: c_uint,
    right: c_uint,
    namep: *mut c_uint,
) -> c_int {
    kern_return(
        unsafe {
            rpc::syscall_mach_port_allocate::<MachPlatform>(task, right, namep)
        }
        .map_err(trap_return),
    )
}

/// The `syscall_mach_port_allocate_name` trap entry, trap 75.
///
/// # Safety
///
/// Reached as trap 75 with user arguments, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_mach_port_allocate_name_entry(
    task: c_uint,
    right: c_uint,
    name: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            rpc::syscall_mach_port_allocate_name::<MachPlatform>(
                task, right, name,
            )
        }
        .map_err(trap_return),
    )
}

/// The `syscall_mach_port_deallocate` trap entry, trap 73.
///
/// # Safety
///
/// Reached as trap 73 with user arguments, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_mach_port_deallocate_entry(
    task: c_uint,
    name: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            rpc::syscall_mach_port_deallocate::<MachPlatform>(task, name)
        }
        .map_err(trap_return),
    )
}

/// The `syscall_mach_port_insert_right` trap entry, trap 74.
///
/// # Safety
///
/// Reached as trap 74 with user arguments, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_mach_port_insert_right_entry(
    task: c_uint,
    name: c_uint,
    right: c_uint,
    right_type: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            rpc::syscall_mach_port_insert_right::<MachPlatform>(
                task, name, right, right_type,
            )
        }
        .map_err(trap_return),
    )
}

/// The `syscall_thread_depress_abort` trap entry, trap 76.
///
/// # Safety
///
/// Reached as trap 76 with a user argument, and the caller must hold no
/// locks.
pub(crate) unsafe extern "C" fn syscall_thread_depress_abort_entry(
    thread: c_uint,
) -> c_int {
    kern_return(
        unsafe { rpc::syscall_thread_depress_abort::<MachPlatform>(thread) }
            .map_err(trap_return),
    )
}

/// The `syscall_device_write_request` trap entry, trap 40.
///
/// # Safety
///
/// Reached as trap 40 with user arguments, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_device_write_request_entry(
    device_name: c_uint,
    reply_name: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    data: VmOffset,
    data_count: VmSize,
) -> c_int {
    match unsafe {
        rpc::syscall_device_write_request::<MachPlatform>(
            device_name,
            reply_name,
            mode,
            recnum,
            data,
            data_count,
        )
    } {
        Ok(reply) => io_return(Ok(reply)),
        Err(error) => trap_return(error),
    }
}

/// The `syscall_device_writev_request` trap entry, trap 39.
///
/// # Safety
///
/// Reached as trap 39 with user arguments, and the caller must hold no locks.
pub(crate) unsafe extern "C" fn syscall_device_writev_request_entry(
    device_name: c_uint,
    reply_name: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    iovec: *mut c_void,
    iocount: VmSize,
) -> c_int {
    match unsafe {
        rpc::syscall_device_writev_request::<MachPlatform>(
            device_name,
            reply_name,
            mode,
            recnum,
            iovec,
            iocount,
        )
    } {
        Ok(reply) => io_return(Ok(reply)),
        Err(error) => trap_return(error),
    }
}

/// The `thread_switch` trap entry.
///
/// # Safety
///
/// Must run on the current thread with no lock held and no wait state set.
pub(crate) unsafe extern "C" fn thread_switch_entry(
    thread_name: c_uint,
    option: c_int,
    option_time: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            syscall_subr::thread_switch::<MachPlatform>(
                thread_name,
                option,
                option_time,
            )
        }
        .map_err(task_return),
    )
}
