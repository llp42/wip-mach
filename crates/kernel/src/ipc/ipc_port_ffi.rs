// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_port.c:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `extern "C"` edge of the port module, one adapter per symbol
//! `ipc/ipc_port.c` used to define and `ipc/ipc_port.h` declares.

use crate::ipc::IpcPort;
use crate::ipc::ipc_port;
use core::ffi::{c_int, c_void};

/// `ipc_port_release_send()` of `ipc/ipc_port.c`.
///
/// # Safety
///
/// `port` must be a live port holding one send right, and nothing may be
/// locked.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ipc_port_release_send(port: *mut c_void) {
    let port = unsafe { IpcPort::from_raw(port) };

    unsafe { ipc_port::release_send(port) };
}

/// `ipc_port_check_circularity()` of `ipc/ipc_port.c`.
///
/// # Safety
///
/// `port` and `dest` must be live ports and no port locks may be held.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ipc_port_check_circularity(
    port: *mut c_void,
    dest: *mut c_void,
) -> c_int {
    let port = unsafe { IpcPort::from_raw(port) };

    c_int::from(unsafe { ipc_port::check_circularity(port, dest) })
}
