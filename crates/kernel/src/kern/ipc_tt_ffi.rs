// SPDX-License-Identifier: CMU-Mach
// Derived from kern/ipc_tt.c:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `extern "C"` edge of the task and thread IPC module, one adapter per
//! symbol `kern/ipc_tt.c` used to define and `kern/ipc_tt.h` declares; the
//! MIG server entries are in [`crate::ffi::mach`].

use crate::ipc::{IpcPort, IpcSpace};
use crate::kern::ipc_tt;
use crate::kern::task::Task;
use crate::kern::thread::Thread;
use crate::vm::vm_map::VmMap;
use core::ffi::c_void;
use core::ptr::{self, NonNull};

/// `convert_port_to_task()` of `kern/ipc_tt.c`.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port, and the caller must
/// hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_task(port: *mut c_void) -> *mut Task {
    unsafe { ipc_tt::convert_port_to_task(port) }
        .map_or(ptr::null_mut(), NonNull::as_ptr)
}

/// `convert_port_to_space()` of `kern/ipc_tt.c`.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port, and the caller must
/// hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_space(
    port: *mut c_void,
) -> *mut c_void {
    unsafe { ipc_tt::convert_port_to_space(port) }
        .map_or(ptr::null_mut(), IpcSpace::as_ptr)
}

/// `convert_port_to_map()` of `kern/ipc_tt.c`.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port, and the caller must
/// hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_map(port: *mut c_void) -> *mut VmMap {
    unsafe { ipc_tt::convert_port_to_map(port) }
        .map_or(ptr::null_mut(), NonNull::as_ptr)
}

/// `convert_port_to_thread()` of `kern/ipc_tt.c`.
///
/// # Safety
///
/// A non-null, non-dead `port` must point at a live port, and the caller must
/// hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_thread(
    port: *mut c_void,
) -> *mut Thread {
    unsafe { ipc_tt::convert_port_to_thread(port) }
        .map_or(ptr::null_mut(), NonNull::as_ptr)
}

/// `convert_task_to_port()` of `kern/ipc_tt.c`.
///
/// # Safety
///
/// `task` must be a live task the caller holds a reference to; the routine
/// consumes the reference and may deallocate the task.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_task_to_port(task: *mut Task) -> *mut c_void {
    unsafe { ipc_tt::convert_task_to_port(task) }
        .map_or(ptr::null_mut(), IpcPort::as_ptr)
}

/// `convert_thread_to_port()` of `kern/ipc_tt.c`.
///
/// # Safety
///
/// `thread` must be a live thread the caller holds a reference to; the
/// routine consumes the reference and may deallocate the thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_thread_to_port(
    thread: *mut Thread,
) -> *mut c_void {
    unsafe { ipc_tt::convert_thread_to_port(thread) }
        .map_or(ptr::null_mut(), IpcPort::as_ptr)
}

/// `space_deallocate()` of `kern/ipc_tt.c`: the `is_release()` of a space ref
/// `convert_port_to_space()` produced.
///
/// # Safety
///
/// A non-null `space` must be a live space the caller holds a reference to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn space_deallocate(space: *mut c_void) {
    unsafe { ipc_tt::space_deallocate(space) };
}
