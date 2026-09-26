// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_target.c and ipc/ipc_target.h:
//   Copyright (c) 1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The common part of IPC ports and port sets, which `ipc/ipc_target.c`
//! defines and `ipc/ipc_target.h` declares.

use crate::ipc::IpcTarget;
use crate::ipc::ipc_mqueue;
use core::ffi::{c_uint, c_void};

/// `ipc_target_init()` in C.
///
/// # Safety
///
/// `target` must be a fresh `struct ipc_target` this call initializes.
pub(crate) unsafe fn init(target: *mut IpcTarget, name: c_uint) {
    unsafe {
        (*target).name = name;
        ipc_mqueue::init((*target).messages());
    }
}

/// `ipc_target_terminate()` in C.
///
/// # Safety
///
/// `target` must be a live target that is being destroyed.
pub(crate) const unsafe fn terminate(_target: *mut IpcTarget) {}

/// `ipc_target_terminate()` of `ipc/ipc_target.c`.
///
/// # Safety
///
/// `target` must be a live target that is being destroyed.
pub(crate) const unsafe fn ipc_target_terminate(target: *mut c_void) {
    unsafe { terminate(target.cast::<IpcTarget>()) };
}
