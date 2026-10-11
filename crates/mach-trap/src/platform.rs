// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! What the traps ask of the kernel.

use mach_ipc::error::ReceiveError;

/// The kernel services the traps need beyond the device and task
/// platforms'.
///
/// The kernel implements it on the same zero-sized type as the other
/// platforms. Tasks, threads, IPC, VM, devices and user copy come from those
/// seams; this one adds the return to user mode with a receive result, whose
/// `mach_msg_return_t` the kernel computes at its boundary.
///
/// # Safety
///
/// Each item must keep the contract its documentation states.
pub unsafe trait Platform: mach_device::platform::Platform {
    /// Returns from the current `mach_msg` receive to user mode with
    /// `result`'s code.
    ///
    /// # Safety
    ///
    /// The current thread must be in a `mach_msg` receive whose user
    /// buffer the result describes.
    unsafe fn return_from_receive(result: Result<(), ReceiveError>) -> !;
}
