// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from i386/i386/io_perm.c and i386/i386/io_perm.h:
//   Copyright (C) 2002, 2007 Free Software Foundation, Inc.
//   Copyright (c) 1993,1992,1991,1990 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `extern "C"` edge of `i386/i386/io_perm.c` that the MIG
//! <`mach/i386/mach_i386.defs`> type conversions and the device emulation call.

use crate::arch::x86_64::io_perm::{self, IoPerm};
use core::ffi::c_void;
use core::ptr::NonNull;

/// `convert_io_perm_to_port()` of `i386/i386/io_perm.h`.
///
/// # Safety
///
/// `io_perm` must be null or point at a live [`IoPerm`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_io_perm_to_port(
    io_perm: *mut IoPerm,
) -> *mut c_void {
    unsafe { io_perm::convert_io_perm_to_port(NonNull::new(io_perm)) }
}

/// `convert_port_to_io_perm()` of `i386/i386/io_perm.h`.
///
/// # Safety
///
/// `port` must be null or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_io_perm(
    port: *mut c_void,
) -> *mut IoPerm {
    unsafe { io_perm::convert_port_to_io_perm(port) }
}

/// `io_perm_deallocate()` of `i386/i386/io_perm.h`, the MIG destructor.
///
/// # Safety
///
/// `io_perm` must point at a live [`IoPerm`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_perm_deallocate(io_perm: *mut IoPerm) {
    unsafe { io_perm::deallocate(io_perm) };
}
