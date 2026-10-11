// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The <`mach/i386/mach_i386.defs`> server entries, all 7 routines, which
//! `i386/i386/mach_i386.srv` presents.
//!
//! The cores are in [`crate::arch::x86_64::fpu`],
//! [`crate::arch::x86_64::io_perm`] and [`crate::arch::x86_64::user_gdt`].
//! The translations and the destructor the interface names for its
//! `io_perm_t` are here too.

use crate::arch::types::VmSize;
use crate::arch::x86_64::fpu;
use crate::arch::x86_64::io_perm::{self, Access, IoPerm};
use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::user_gdt::{Descriptor, get_gdt, set_gdt};
use crate::kern::error::Error;
use crate::mig::code::WIPMACH_DEPRECATED;
use core::ffi::{c_int, c_uint, c_void};
use core::ptr::NonNull;
use mach_thread::task::Task;
use mach_thread::thread::Thread;

/// `i386_set_ldt()` of the MIG `mach_i386` interface.
///
/// The kernel keeps no thread-programmable LDT, so the call answers
/// [`WIPMACH_DEPRECATED`] without reading an argument.
///
/// # Safety
///
/// The MIG stub passes the caller's arguments here; none is read.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn i386_set_ldt(
    _thread: *mut Thread<MachPlatform>,
    _first_selector: c_int,
    _descriptor_list: *const Descriptor,
    _count: c_uint,
    _desc_list_inline: c_int,
) -> c_int {
    WIPMACH_DEPRECATED
}

/// `i386_get_ldt()` of the MIG `mach_i386` interface.
///
/// The kernel keeps no thread-programmable LDT, so the call answers
/// [`WIPMACH_DEPRECATED`] without reading an argument.
///
/// # Safety
///
/// The MIG stub passes the caller's arguments here; none is read.
#[unsafe(no_mangle)]
pub const unsafe extern "C" fn i386_get_ldt(
    _thread: *mut Thread<MachPlatform>,
    _first_selector: c_int,
    _selector_count: c_int,
    _descriptor_list: *mut *mut Descriptor,
    _count: *mut c_uint,
) -> c_int {
    WIPMACH_DEPRECATED
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
    target_task: *mut Task<MachPlatform>,
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
    thread: *mut Thread<MachPlatform>,
    selector: *mut c_int,
    descriptor: Descriptor,
) -> c_int {
    let Some(thread) = NonNull::new(thread) else {
        return c_int::from(
            crate::arch::x86_64::error::Error::InvalidArgument,
        );
    };
    match unsafe { set_gdt(thread, selector, descriptor) } {
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
    thread: *mut Thread<MachPlatform>,
    selector: c_int,
    descriptor: *mut Descriptor,
) -> c_int {
    let Some(thread) = NonNull::new(thread) else {
        return c_int::from(
            crate::arch::x86_64::error::Error::InvalidArgument,
        );
    };
    match unsafe { get_gdt(thread, selector, descriptor) } {
        Ok(()) => 0,
        Err(error) => c_int::from(error),
    }
}

/// Reports the size of a thread's extended FPU state.
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

    unsafe { *size = fpu::xstate_size() };
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
