// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The common part of IPC ports and port sets.

use crate::IpcTarget;
use crate::ipc_mqueue;
use core::ffi::c_uint;

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
