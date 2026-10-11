// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The <`mach/mach_port.defs`> server entries, all 21 routines, which
//! `ipc/mach_port.srv` presents.
//!
//! The cores are in [`mach_ipc::mach_port`].

use crate::arch::x86_64::platform::MachPlatform;
use crate::mig::code::{ipc_return, kern_return};
use crate::mig::copy_out;
use core::ffi::{c_int, c_uint, c_void};
use core::ptr::{self, NonNull};
use mach_ipc::error::Error;
use mach_ipc::mach_port::{self, MachPortStatus};
use mach_ipc::{IpcPort, IpcSpace};

/// Reports the names in `task`'s space and the rights each holds.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`; all four out-pointers must be
/// writable storage, and the array pointers are written only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_names(
    task: *mut c_void,
    namesp: *mut *mut c_uint,
    names_cnt: *mut c_uint,
    typesp: *mut *mut c_uint,
    types_cnt: *mut c_uint,
) -> c_int {
    match unsafe { mach_port::names::<MachPlatform>(IpcSpace::new(task)) } {
        Ok(result) => {
            unsafe {
                namesp.write(
                    result
                        .names
                        .map_or(ptr::null_mut(), |copy| copy.as_ptr().cast()),
                );
                names_cnt.write(result.count);
                typesp.write(
                    result
                        .types
                        .map_or(ptr::null_mut(), |copy| copy.as_ptr().cast()),
                );
                types_cnt.write(result.count);
            }
            0
        }
        Err(error) => ipc_return(error),
    }
}

/// Reports the rights `name` holds in `task`'s space.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`, and `typep` must be writable
/// storage for one type mask, written only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_type(
    task: *mut c_void,
    name: c_uint,
    typep: *mut c_uint,
) -> c_int {
    match unsafe {
        mach_port::port_type::<MachPlatform>(IpcSpace::new(task), name)
    } {
        Ok(type_mask) => {
            unsafe { typep.write(type_mask.bits()) };
            0
        }
        Err(error) => ipc_return(error),
    }
}

/// Renames `old_name` in `task`'s space to `new_name`.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_rename(
    task: *mut c_void,
    old_name: c_uint,
    new_name: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            mach_port::rename::<MachPlatform>(
                IpcSpace::new(task),
                old_name,
                new_name,
            )
        }
        .map_err(ipc_return),
    )
}

/// Allocates a `right` in `task`'s space under the chosen `name`.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`; may allocate memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_allocate_name(
    task: *mut c_void,
    right: c_uint,
    name: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            mach_port::allocate_name::<MachPlatform>(
                IpcSpace::new(task),
                right,
                name,
            )
        }
        .map_err(ipc_return),
    )
}

/// Allocates a `right` in `task`'s space, reporting its name.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`, and `namep` must be writable
/// storage for one name, written only on success; may allocate memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_allocate(
    task: *mut c_void,
    right: c_uint,
    namep: *mut c_uint,
) -> c_int {
    match unsafe {
        mach_port::allocate::<MachPlatform>(IpcSpace::new(task), right)
    } {
        Ok(name) => {
            unsafe { namep.write(name) };
            0
        }
        Err(error) => ipc_return(error),
    }
}

/// Inserts the right `poly` into `task`'s space under `name`.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`, and `poly` must be `IO_NULL`,
/// `IO_DEAD` or a live `ipc_object` the caller holds one reference to, which
/// the call consumes on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_insert_right(
    task: *mut c_void,
    name: c_uint,
    poly: *mut c_void,
    poly_poly: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            mach_port::insert_right::<MachPlatform>(
                IpcSpace::new(task),
                name,
                poly,
                poly_poly,
            )
        }
        .map_err(ipc_return),
    )
}

/// Extracts the right `name` holds from `task`'s space, as `msgt_name`
/// transforms it.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`; `poly` must be writable storage
/// for one object pointer and `poly_poly` for one type name, both written
/// only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_extract_right(
    task: *mut c_void,
    name: c_uint,
    msgt_name: c_uint,
    poly: *mut *mut c_void,
    poly_poly: *mut c_uint,
) -> c_int {
    match unsafe {
        mach_port::extract_right::<MachPlatform>(
            IpcSpace::new(task),
            name,
            msgt_name,
        )
    } {
        Ok((object, received)) => {
            unsafe {
                poly.write(object);
                poly_poly.write(received);
            }
            0
        }
        Err(error) => ipc_return(error),
    }
}

/// Destroys every right `name` holds in `task`'s space.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_destroy(
    task: *mut c_void,
    name: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            mach_port::destroy::<MachPlatform>(IpcSpace::new(task), name)
        }
        .map_err(ipc_return),
    )
}

/// Drops one user reference on `name` in `task`'s space.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_deallocate(
    task: *mut c_void,
    name: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            mach_port::deallocate::<MachPlatform>(IpcSpace::new(task), name)
        }
        .map_err(ipc_return),
    )
}

/// Reports the user references on the `right` of `name` in `task`'s space.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`, and `refs` must be writable
/// storage for one count, written only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_get_refs(
    task: *mut c_void,
    name: c_uint,
    right: c_uint,
    refs: *mut c_uint,
) -> c_int {
    match unsafe {
        mach_port::get_refs::<MachPlatform>(IpcSpace::new(task), name, right)
    } {
        Ok(urefs) => {
            unsafe { refs.write(urefs) };
            0
        }
        Err(error) => ipc_return(error),
    }
}

/// Adds `delta` user references to the `right` of `name` in `task`'s space.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_mod_refs(
    task: *mut c_void,
    name: c_uint,
    right: c_uint,
    delta: c_int,
) -> c_int {
    kern_return(
        unsafe {
            mach_port::mod_refs::<MachPlatform>(
                IpcSpace::new(task),
                name,
                right,
                delta,
            )
        }
        .map_err(ipc_return),
    )
}

/// Sets the queue limit of the receive right `name`.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_set_qlimit(
    task: *mut c_void,
    name: c_uint,
    qlimit: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            mach_port::set_qlimit::<MachPlatform>(
                IpcSpace::new(task),
                name,
                qlimit,
            )
        }
        .map_err(ipc_return),
    )
}

/// Sets the make-send count of the receive right `name`.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_set_mscount(
    task: *mut c_void,
    name: c_uint,
    mscount: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            mach_port::set_mscount::<MachPlatform>(
                IpcSpace::new(task),
                name,
                mscount,
            )
        }
        .map_err(ipc_return),
    )
}

/// Reports the members of the port set `name`.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`; `members` must be writable
/// storage for one array pointer and `members_cnt` for one count, both
/// written only on success; may allocate memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_get_set_status(
    task: *mut c_void,
    name: c_uint,
    members: *mut *mut c_uint,
    members_cnt: *mut c_uint,
) -> c_int {
    match unsafe {
        mach_port::get_set_status::<MachPlatform>(IpcSpace::new(task), name)
    } {
        Ok(status) => {
            unsafe {
                members.write(
                    status
                        .members
                        .map_or(ptr::null_mut(), |copy| copy.as_ptr().cast()),
                );
                members_cnt.write(status.count);
            }
            0
        }
        Err(error) => ipc_return(error),
    }
}

/// Moves the receive right `member` into the port set `after`, or out of any
/// set when `after` is null.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_move_member(
    task: *mut c_void,
    member: c_uint,
    after: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            mach_port::move_member::<MachPlatform>(
                IpcSpace::new(task),
                member,
                after,
            )
        }
        .map_err(ipc_return),
    )
}

/// Requests the notification `id` for `name`, sent to `notify`, reporting the
/// previous request.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`; `notify` must be `IP_NULL`,
/// `IP_DEAD` or a live `ipc_port`; and `previous` must be writable storage
/// for one port pointer, written only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_request_notification(
    task: *mut c_void,
    name: c_uint,
    id: c_int,
    sync: c_uint,
    notify: *mut c_void,
    previous: *mut *mut c_void,
) -> c_int {
    match unsafe {
        mach_port::request_notification::<MachPlatform>(
            IpcSpace::new(task),
            name,
            id,
            sync,
            NonNull::new(notify),
        )
    } {
        Ok(previous_port) => {
            let previous_port =
                previous_port.map_or(ptr::null_mut(), IpcPort::as_ptr);

            unsafe { previous.write(previous_port) };

            0
        }
        Err(error) => ipc_return(error),
    }
}

/// Reports the status of the receive right `name`.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`, and `status` must be writable
/// storage for one `mach_port_status_t`, written only on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_get_receive_status(
    task: *mut c_void,
    name: c_uint,
    status: *mut c_void,
) -> c_int {
    match unsafe {
        mach_port::get_receive_status::<MachPlatform>(
            IpcSpace::new(task),
            name,
        )
    } {
        Ok(status_value) => {
            unsafe {
                copy_out(status.cast::<MachPortStatus>(), &status_value);
            }
            0
        }
        Err(error) => ipc_return(error),
    }
}

/// Sets the sequence number of the receive right `name`.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_set_seqno(
    task: *mut c_void,
    name: c_uint,
    seqno: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            mach_port::set_seqno::<MachPlatform>(
                IpcSpace::new(task),
                name,
                seqno,
            )
        }
        .map_err(ipc_return),
    )
}

/// Sets the protected payload of the receive right `name`.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_set_protected_payload(
    task: *mut c_void,
    name: c_uint,
    payload: usize,
) -> c_int {
    kern_return(
        unsafe {
            mach_port::set_protected_payload::<MachPlatform>(
                IpcSpace::new(task),
                name,
                payload,
            )
        }
        .map_err(ipc_return),
    )
}

/// Clears the protected payload of the receive right `name`.
///
/// # Safety
///
/// `task` must be null or a live `ipc_space`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_clear_protected_payload(
    task: *mut c_void,
    name: c_uint,
) -> c_int {
    kern_return(
        unsafe {
            mach_port::clear_protected_payload::<MachPlatform>(
                IpcSpace::new(task),
                name,
            )
        }
        .map_err(ipc_return),
    )
}

/// Marks the receive right `name` as a kernel object of type `ktype`, for the
/// privileged `host`.
///
/// # Safety
///
/// `host` must be null or a live host, and `task` must be null or a live IPC
/// space.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mach_port_set_ktype(
    host: *mut c_void,
    task: *mut c_void,
    name: c_uint,
    right: c_uint,
    ktype: c_uint,
) -> c_int {
    if host.is_null() {
        return ipc_return(Error::InvalidHost);
    }

    kern_return(
        unsafe {
            mach_port::set_ktype::<MachPlatform>(
                IpcSpace::new(task),
                name,
                right,
                ktype,
            )
        }
        .map_err(ipc_return),
    )
}
