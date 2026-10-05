// SPDX-License-Identifier: CMU-Mach
// Derived from device/device_init.c:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The device service's creation.

use crate::device::chario;
use crate::device::ds_routines::{io_done_thread, mach_device_init};
use crate::ipc::{IpcPort, ipc_port, ipc_space};
use crate::kern::debug::kpanic;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

/// The port the device service answers on, published by the boot before any
/// device open can race it.
static MASTER_DEVICE_PORT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// The master device port, or null before [`device_service_create`] runs.
///
/// The load is `Acquire` to see the port the `Release` store published.
pub(crate) fn master_device_port() -> *mut c_void {
    MASTER_DEVICE_PORT.load(Ordering::Acquire)
}

/// Creates the master device port, initializes the device packages, and starts
/// the I/O-done and network threads.
///
/// # Safety
///
/// Called once, by the boot sequence after the kernel's IPC space exists, and
/// never concurrently with a device open.
///
/// # Panics
///
/// Halts through [`kpanic!`] when the master device port cannot be
/// allocated, as the C `panic()` did.
pub(crate) unsafe fn device_service_create() {
    // SAFETY: the kernel space is the global `ipc_init()` built earlier in
    // the boot; the allocator only reads it and takes its own locks.
    let master = unsafe { ipc_port::alloc_special(ipc_space::kernel()) };
    let port = master.map_or(ptr::null_mut(), IpcPort::as_ptr);
    // The `Release` store publishes the initialized port to the CPUs that
    // compare an incoming open port against it.
    MASTER_DEVICE_PORT.store(port, Ordering::Release);
    if master.is_none() {
        kpanic!("device_service_create", "can't allocate master device port")
    }

    // SAFETY: the five initializers take no arguments and build separate
    // module state; the C ran them in this order, before starting the threads
    // below.
    unsafe {
        mach_device_init();
        crate::device::dev_lookup::init();
        crate::device::net_io::init();
        crate::device::dev_pager::init();
        chario::chario_init();
    }

    // SAFETY: `kernel_task` is the kernel's own task, live since startup, and
    // both start routines take no argument.
    unsafe {
        crate::kern::thread::kernel_thread(
            crate::kern::task::kernel_task(),
            c"io_done".as_ptr(),
            Some(io_done_thread),
            ptr::null_mut(),
        );
        crate::kern::thread::kernel_thread(
            crate::kern::task::kernel_task(),
            c"net".as_ptr(),
            Some(crate::device::net_io::net_thread),
            ptr::null_mut(),
        );
    }
}
