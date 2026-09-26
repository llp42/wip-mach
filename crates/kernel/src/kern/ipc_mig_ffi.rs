// SPDX-License-Identifier: CMU-Mach
// Derived from kern/ipc_mig.c:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `kern/ipc_mig.c` MIG runtime symbols C still calls, over the cores in
//! [`crate::kern::ipc_mig`].

use crate::arch::types::VmOffset;
use crate::kern::debug::kpanic;
use crate::kern::ipc_mig;
use core::ffi::{c_int, c_uint, c_void};

/// `mig_dealloc_reply_port()` of `kern/ipc_mig.c`.
///
/// # Panics
///
/// Always halts through [`kpanic!`].
#[unsafe(no_mangle)]
pub extern "C" fn mig_dealloc_reply_port(_reply_port: VmOffset) {
    kpanic!("mig_dealloc_reply_port", "mig_dealloc_reply_port")
}

/// `mach_msg_rpc_from_kernel()` of `kern/ipc_mig.c`.
///
/// # Panics
///
/// Always halts through [`kpanic!`]: this kernel has never implemented
/// the call, and the C body was the same one `panic()`.
#[unsafe(no_mangle)]
pub extern "C" fn mach_msg_rpc_from_kernel(
    _msg: *const c_void,
    _send_size: c_uint,
    _reply_size: c_uint,
) -> c_int {
    kpanic!("mach_msg_rpc_from_kernel", "mach_msg_rpc_from_kernel")
}

/// `mach_msg_send_from_kernel()` of `kern/ipc_mig.c`.
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
    unsafe { ipc_mig::mach_msg_send_from_kernel(msg, send_size) }.raw()
}
