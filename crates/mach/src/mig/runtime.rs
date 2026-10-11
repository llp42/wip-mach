// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The kernel services the generated stubs call besides the handlers: the
//! port operations the server stubs apply to rights they move, and the
//! sends the user stubs make from the kernel.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::platform::MachPlatform;
use crate::kern::debug::kpanic;
use crate::kern::ipc_mig;
use crate::mig::code::{kern_return, send_return};
use core::ffi::{c_int, c_uint, c_void};
use mach_ipc::IpcPort;
use mach_ipc::ipc_port;

/// `ipc_port_release_send()`: drop a send right the stub consumed.
///
/// # Safety
///
/// `port` must be a live port holding one send right, and nothing may be
/// locked.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ipc_port_release_send(port: *mut c_void) {
    let port = unsafe { IpcPort::from_raw(port) };

    unsafe { ipc_port::release_send::<MachPlatform>(port) };
}

/// `ipc_port_check_circularity()`: whether moving the receive right for
/// `port` into a message bound for `dest` would make a cycle of ports; when
/// it would not, `port` is now in transit to `dest`.
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

/// `mach_msg_send_from_kernel()`: send a message the kernel built.
///
/// # Safety
///
/// `msg` must point at a readable kernel message of `send_size` bytes, and
/// the caller must hold no locks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_msg_send_from_kernel(
    msg: *mut c_void,
    send_size: c_uint,
) -> c_int {
    kern_return(
        unsafe { ipc_mig::mach_msg_send_from_kernel(msg, send_size) }
            .map_err(send_return),
    )
}

/// `mach_msg_rpc_from_kernel()`: send a message the kernel built and wait
/// for its reply.
///
/// # Panics
///
/// Always halts through [`kpanic!`]: the kernel has never implemented the
/// call.
#[unsafe(no_mangle)]
pub extern "C" fn mach_msg_rpc_from_kernel(
    _msg: *const c_void,
    _send_size: c_uint,
    _reply_size: c_uint,
) -> c_int {
    kpanic!("mach_msg_rpc_from_kernel", "mach_msg_rpc_from_kernel")
}

/// `mig_dealloc_reply_port()`: give back the reply port of a failed kernel
/// RPC.
///
/// # Panics
///
/// Always halts through [`kpanic!`], as [`mach_msg_rpc_from_kernel`] does.
#[unsafe(no_mangle)]
pub extern "C" fn mig_dealloc_reply_port(_reply_port: VmOffset) {
    kpanic!("mig_dealloc_reply_port", "mig_dealloc_reply_port")
}
