// SPDX-License-Identifier: CMU-Mach
// Derived from vm/vm_object.c and vm/vm_object.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `vm_object_deallocate` destructor and the `vm_object_lookup` and
//! `vm_object_lookup_name` translations of `vm/vm_object.c`, which the
//! <`mach/mach_types.defs`> generated code names.
//!
//! The rest of the file lives in [`crate::vm::vm_object`].

use crate::vm::types::VmObject;
use crate::vm::vm_object;
use core::ffi::c_void;
use core::ptr::{NonNull, null_mut};

/// `vm_object_deallocate()` in C.
///
/// # Safety
///
/// `object` must be null or a live object the caller holds a reference to,
/// and no lock of the caller's may be held.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_object_deallocate(object: *mut VmObject) {
    unsafe { vm_object::deallocate(object) };
}

/// `vm_object_lookup()` in C.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_object_lookup(port: *mut c_void) -> *mut VmObject {
    unsafe { vm_object::lookup(port) }.map_or(null_mut(), NonNull::as_ptr)
}

/// `vm_object_lookup_name()` in C.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_object_lookup_name(
    port: *mut c_void,
) -> *mut VmObject {
    unsafe { vm_object::lookup_name(port) }.map_or(null_mut(), NonNull::as_ptr)
}
