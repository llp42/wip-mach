// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The device service's creation.

use crate::arch::x86_64::platform::MachPlatform;
use core::ptr;
use mach_device::ds_routines::{self, io_done_thread};

/// Sets up the device service and the tty layer, and starts the I/O-done
/// thread.
///
/// # Safety
///
/// Called once, by the boot sequence after the kernel's IPC space exists, and
/// never concurrently with a device open.
pub(crate) unsafe fn device_service_create() {
    // SAFETY: the initializer takes no arguments and builds the device
    // server's state, before the threads below start.
    unsafe { ds_routines::init::<MachPlatform>() };

    // SAFETY: `kernel_task` is the kernel's own task, live since startup, and
    // the start routine takes no argument.
    unsafe {
        mach_thread::thread::kernel_thread(
            mach_thread::task::kernel_task::<MachPlatform>(),
            c"io_done".as_ptr(),
            Some(io_done_thread::<MachPlatform>),
            ptr::null_mut(),
        );
    }
}
