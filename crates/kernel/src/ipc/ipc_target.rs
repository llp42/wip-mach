// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_target.c and ipc/ipc_target.h:
//   Copyright (c) 1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The common part of IPC ports and port sets.

use crate::ipc::IpcTarget;
use crate::ipc::ipc_mqueue;
use core::ffi::{c_uint, c_void};

/// Initializes `target` under `name`.
///
/// # Safety
///
/// `target` must be a fresh [`IpcTarget`] this call initializes.
pub(crate) unsafe fn init(target: *mut IpcTarget, name: c_uint) {
    unsafe {
        (*target).name = name;
        ipc_mqueue::init((*target).messages());
    }
}

/// Tears `target` down; there is nothing to release.
///
/// # Safety
///
/// `target` must be a live target that is being destroyed.
pub(crate) const unsafe fn terminate(_target: *mut IpcTarget) {}

/// [`terminate`] over an untyped pointer.
///
/// # Safety
///
/// `target` must be a live target that is being destroyed.
pub(crate) const unsafe fn ipc_target_terminate(target: *mut c_void) {
    unsafe { terminate(target.cast::<IpcTarget>()) };
}
