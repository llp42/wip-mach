// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from i386/i386/fpu.c, i386/i386/fpu.h, i386/i386/io_perm.c,
// i386/i386/io_perm.h, i386/i386/user_ldt.c and i386/i386/user_ldt.h:
//   Copyright (c) 1992-1990 Carnegie Mellon University
//   Copyright (C) 1994 Linus Torvalds
//   Copyright (C) 2002, 2007 Free Software Foundation, Inc.
//   Copyright (c) 1994,1993,1992,1991 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The <`mach/i386/mach_i386.defs`> server entries, all 7 routines, which
//! `i386/i386/mach_i386.srv` presents.
//!
//! The cores are in [`crate::arch::x86_64::fpu`],
//! [`crate::arch::x86_64::io_perm`] and [`crate::arch::x86_64::user_ldt`].
//! The translations and the destructor the interface names for its
//! `io_perm_t` are here too.

use crate::arch::types::VmSize;
use crate::arch::x86_64::fpu;
use crate::arch::x86_64::io_perm::{self, Access, IoPerm};
use crate::arch::x86_64::pcb::RealDescriptor;
use crate::arch::x86_64::user_ldt::{self, Descriptor};
use crate::kern::error::Error;
use crate::kern::task::Task;
use crate::kern::thread::Thread;
use core::ffi::{c_int, c_uint, c_void};
use core::ptr::NonNull;
use core::slice;

/// `i386_set_ldt()` of the MIG `mach_i386` interface.
///
/// # Safety
///
/// `thread` must be null or a live thread; `descriptor_list` must point at
/// `count` writable descriptors when `desc_list_inline` is true, and at a
/// live `vm_map_copy` the caller owns when it is false.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i386_set_ldt(
    thread: *mut Thread,
    first_selector: c_int,
    descriptor_list: *const Descriptor,
    count: c_uint,
    desc_list_inline: c_int,
) -> c_int {
    let Some(thread) = NonNull::new(thread) else {
        return c_int::from(
            crate::arch::x86_64::error::Error::InvalidArgument,
        );
    };
    let descriptors = descriptor_list.cast::<RealDescriptor>().cast_mut();
    match unsafe {
        user_ldt::set_ldt(
            thread,
            first_selector,
            descriptors,
            count,
            desc_list_inline != 0,
        )
    } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `i386_get_ldt()` of the MIG `mach_i386` interface.
///
/// # Safety
///
/// `thread` must be null or a live thread, and `descriptor_list`/`count` must
/// be valid for a read and a write; `*descriptor_list` must be writable for
/// `*count` descriptors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i386_get_ldt(
    thread: *mut Thread,
    first_selector: c_int,
    selector_count: c_int,
    descriptor_list: *mut *mut Descriptor,
    count: *mut c_uint,
) -> c_int {
    let Some(thread) = NonNull::new(thread) else {
        return c_int::from(
            crate::arch::x86_64::error::Error::InvalidArgument,
        );
    };
    let capacity = unsafe { *count };
    let out = if capacity == 0 {
        None
    } else {
        Some(unsafe {
            slice::from_raw_parts_mut(
                (*descriptor_list).cast::<RealDescriptor>(),
                capacity as usize,
            )
        })
    };

    match unsafe {
        user_ldt::get_ldt(thread, first_selector, selector_count, out)
    } {
        Ok((new_count, copy)) => {
            unsafe {
                *count = new_count;
                if let Some(copy) = copy {
                    *descriptor_list = copy.as_ptr().cast::<Descriptor>();
                }
            }
            0
        }
        Err(error) => c_int::from(error),
    }
}

/// `i386_io_perm_create()` of the MIG `mach_i386` server.
///
/// # Safety
///
/// `master_port` must be null or a live port, and `new` writable storage for
/// one pointer, written only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i386_io_perm_create(
    master_port: *mut c_void,
    from: u16,
    to: u16,
    new: *mut *mut IoPerm,
) -> c_int {
    match unsafe { io_perm::create(master_port, from, to, new) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `i386_io_perm_modify()` of the MIG `mach_i386` server.
///
/// # Safety
///
/// `target_task` must be null or a live task, and `io_perm` null or a live
/// [`IoPerm`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i386_io_perm_modify(
    target_task: *mut Task,
    io_perm: *mut IoPerm,
    enable: c_int,
) -> c_int {
    let (Some(target_task), Some(io_perm)) =
        (NonNull::new(target_task), NonNull::new(io_perm))
    else {
        return c_int::from(Error::InvalidArgument);
    };
    let access = match enable {
        0 => Access::Withdraw,
        _ => Access::Grant,
    };

    match unsafe { io_perm::modify(target_task, io_perm, access) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `i386_set_gdt()` of the MIG `mach_i386` interface.
///
/// # Safety
///
/// `thread` must be null or a live thread; `selector` must be valid for a
/// read and a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i386_set_gdt(
    thread: *mut Thread,
    selector: *mut c_int,
    descriptor: Descriptor,
) -> c_int {
    let Some(thread) = NonNull::new(thread) else {
        return c_int::from(
            crate::arch::x86_64::error::Error::InvalidArgument,
        );
    };
    match unsafe { user_ldt::set_gdt(thread, selector, descriptor) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `i386_get_gdt()` of the MIG `mach_i386` interface.
///
/// # Safety
///
/// `thread` must be null or a live thread, and `descriptor` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i386_get_gdt(
    thread: *mut Thread,
    selector: c_int,
    descriptor: *mut Descriptor,
) -> c_int {
    let Some(thread) = NonNull::new(thread) else {
        return c_int::from(
            crate::arch::x86_64::error::Error::InvalidArgument,
        );
    };
    match unsafe { user_ldt::get_gdt(thread, selector, descriptor) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// `i386_get_xstate_size()` of i386/i386/fpu.h, the routine
/// <`mach/i386/mach_i386.defs`> declares.
///
/// # Safety
///
/// `size` must be valid for a write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn i386_get_xstate_size(
    host: *mut c_void,
    size: *mut VmSize,
) -> c_int {
    if host.is_null() {
        return c_int::from(Error::InvalidArgument);
    }

    unsafe { fpu::i386_get_xstate_size(size) };
    0
}

/// `convert_io_perm_to_port()`: a send right for `io_perm`'s port, or null.
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

/// `convert_port_to_io_perm()`: the I/O permission `port` names, or null.
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

/// `io_perm_deallocate()`: the destructor of an `io_perm_t` argument.
///
/// # Safety
///
/// `io_perm` must point at a live [`IoPerm`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn io_perm_deallocate(io_perm: *mut IoPerm) {
    unsafe { io_perm::deallocate(io_perm) };
}
