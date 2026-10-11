// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The <mach/mach4.defs> server entries, both routines, which
//! `kern/mach4.srv` presents.
//!
//! The cores are [`mach_vm::memory_object_proxy::create_proxy`] and
//! [`crate::vm::VmMap::region_create_proxy`].

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::x86_64::platform::MachPlatform;
use crate::mig::code::{KERN_INVALID_ARGUMENT, KERN_SUCCESS, vm_return};
use crate::vm::VmMap;
use core::ffi::{c_int, c_uint, c_void};
use core::ptr::{self, NonNull};
use mach_thread::task::Task;
use mach_vm::memory_object_proxy;
use mach_vm::platform::Port;
use mach_vm::types::VmProt;

/// A MIG array as a slice; an absent array is an empty one.
///
/// # Safety
///
/// `ptr` must be readable for `count` records when `count` is nonzero.
const unsafe fn slice<'a, T>(ptr: *mut T, count: c_uint) -> &'a [T] {
    if count == 0 {
        return &[];
    }
    unsafe { core::slice::from_raw_parts(ptr, count as usize) }
}

/// Makes a proxy memory object over the ranges of the `object` ports, limited
/// to `max_protection`.
///
/// # Safety
///
/// `object`, `offset`, `start` and `len` must be readable for their own
/// counts, and `proxy` must be writable storage for one port, written only on
/// success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memory_object_create_proxy(
    task: *mut c_void,
    max_protection: VmProt,
    object: *mut *mut c_void,
    object_count: c_uint,
    offset: *mut VmOffset,
    offset_count: c_uint,
    start: *mut VmOffset,
    start_count: c_uint,
    len: *mut VmSize,
    len_count: c_uint,
    proxy: *mut *mut c_void,
) -> c_int {
    let result = unsafe {
        memory_object_proxy::create_proxy::<MachPlatform>(
            NonNull::new(task),
            max_protection,
            slice(object, object_count),
            slice(offset, offset_count),
            slice(start, start_count),
            slice(len, len_count),
        )
    };

    match result {
        Ok(port) => {
            unsafe { proxy.write(port.as_ptr()) };
            KERN_SUCCESS
        }
        Err(error) => vm_return(error),
    }
}

/// Makes a proxy memory object over the region of `task`'s map at `address`,
/// limited to `max_protection`.
///
/// # Safety
///
/// `task` must be a valid task or null, the task's map must be valid, and
/// `port` must be writable storage for one port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vm_region_create_proxy(
    task: *mut c_void,
    address: VmOffset,
    max_protection: VmProt,
    len: VmSize,
    port: *mut *mut c_void,
) -> c_int {
    if task.is_null() {
        return KERN_INVALID_ARGUMENT;
    }

    let (map, space) = unsafe {
        let task = task.cast::<Task<MachPlatform>>();
        (
            NonNull::new((*task).map.cast::<VmMap>()),
            NonNull::new((*task).itk_space),
        )
    };
    let Some(map) = map else {
        return KERN_INVALID_ARGUMENT;
    };

    match unsafe { map.as_ref() }.region_create_proxy(
        space,
        address,
        max_protection,
        len,
    ) {
        Ok(proxy) => {
            unsafe {
                port.write(proxy.map_or(ptr::null_mut(), Port::as_ptr));
            };
            KERN_SUCCESS
        }
        Err(error) => vm_return(error),
    }
}
