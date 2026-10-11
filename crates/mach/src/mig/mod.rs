// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The MIG seam: the one place the kernel speaks C.
//!
//! The generated server stubs call the handlers here, one module per
//! interface definition file, together with the type translations and the
//! message transport they need. The kernel calls the generated user stubs
//! through the typed wrappers below, and every typed result becomes its C
//! code in [`code`]. The generated half itself lives in [`mach_mig_sys`].
//!
//! The image bounds the linker defines live here too: they are the only
//! other symbols the kernel takes from outside Rust.

pub mod code;
pub mod device;
pub mod device_pager;
pub mod gnumach;
pub mod mach;
pub mod mach4;
pub mod mach_debug;
pub mod mach_host;
pub mod mach_i386;
pub mod mach_port;
pub mod mach_types;
pub mod runtime;
pub mod time_value;

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::x86_64::trap::Recovery;
use code::send_result;
use code::vm_return;
use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;
use mach_device::types::Message;
use mach_ipc::error::SendError;
use mach_vm::error::Error as VmError;
use mach_vm::types::VmProt;
use zerocopy::{Immutable, IntoBytes};

pub(crate) use mach_mig_sys::{
    MigRoutine, device_pager_server_routines, device_server_routines,
    gnumach_server_routines, mach_debug_server_routines,
    mach_host_server_routines, mach_i386_server_routines,
    mach_port_server_routines, mach_server_routines, mach4_server_routines,
};

unsafe extern "C" {

    /// The bounds the linker derives from the `mach_recover` section, the
    /// fault fixups `src/arch/x86_64/user_access.rs` emits.
    pub static __start_mach_recover: Recovery;
    /// The end of the `mach_recover` section; see
    /// [`__start_mach_recover`].
    pub static __stop_mach_recover: Recovery;

    /// The bounds the linker derives from the `mach_retry` section, the
    /// `inst_fetch()` page-fault retries of `src/arch/x86_64/user_access.rs`.
    pub static __start_mach_retry: Recovery;
    /// The end of the `mach_retry` section; see [`__start_mach_retry`].
    pub static __stop_mach_retry: Recovery;

    /// The load image bounds `pmap_bootstrap()` maps read-only.
    pub static _start: c_char;
    /// The end of the load image's text; see [`_start`].
    pub static etext: c_char;
    /// The end of the load image; see [`_start`].
    pub static _end: c_char;

}

/// Copies `record` to `out`, the reply buffer a MIG stub hands its server,
/// which may be aligned to `integer_t` only.
///
/// `IntoBytes` keeps out a record with a padding hole, whose bytes would
/// carry stale kernel memory to the task.
///
/// # Safety
///
/// `out` must be writable for `size_of::<T>()` bytes.
pub(crate) unsafe fn copy_out<T: IntoBytes + Immutable>(
    out: *mut T,
    record: &T,
) {
    let bytes = record.as_bytes();
    // SAFETY: the caller promises `out` is writable for the record's bytes,
    // and a byte copy needs no alignment.
    unsafe {
        ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            out.cast::<u8>(),
            bytes.len(),
        );
    }
}

/// Sends `message` through its MIG user stub: one of the `device_reply`
/// stubs, or `memory_object_data_error()` or `memory_object_ready()` of the
/// `mach` stubs.
///
/// # Errors
///
/// Returns the [`SendError`] the kernel send reported.
///
/// # Safety
///
/// The ports and data of `message` must be what its variant documents: live
/// rights the send consumes, and data readable for its count.
pub(crate) unsafe fn send(message: Message) -> Result<(), SendError> {
    send_result(match message {
        Message::OpenReply {
            reply_port,
            reply_port_type,
            result,
            device_port,
        } => unsafe {
            mach_mig_sys::ds_device_open_reply(
                reply_port,
                reply_port_type,
                code::device_result(result),
                device_port,
            )
        },
        Message::WriteReply {
            reply_port,
            reply_port_type,
            inband: false,
            result,
            bytes_written,
        } => unsafe {
            mach_mig_sys::ds_device_write_reply(
                reply_port,
                reply_port_type,
                code::device_result(result),
                bytes_written,
            )
        },
        Message::WriteReply {
            reply_port,
            reply_port_type,
            inband: true,
            result,
            bytes_written,
        } => unsafe {
            mach_mig_sys::ds_device_write_reply_inband(
                reply_port,
                reply_port_type,
                code::device_result(result),
                bytes_written,
            )
        },
        Message::ReadReply {
            reply_port,
            reply_port_type,
            inband: false,
            result,
            data,
            data_count,
        } => unsafe {
            mach_mig_sys::ds_device_read_reply(
                reply_port,
                reply_port_type,
                code::device_result(result),
                data,
                data_count,
            )
        },
        Message::ReadReply {
            reply_port,
            reply_port_type,
            inband: true,
            result,
            data,
            data_count,
        } => unsafe {
            mach_mig_sys::ds_device_read_reply_inband(
                reply_port,
                reply_port_type,
                code::device_result(result),
                data,
                data_count,
            )
        },
        Message::DataError {
            memory_control,
            offset,
            size,
            error,
        } => unsafe {
            mach_mig_sys::r_memory_object_data_error(
                memory_control,
                offset,
                size,
                vm_return(error),
            )
        },
        Message::Ready {
            memory_control,
            may_cache,
            copy_strategy,
        } => unsafe {
            mach_mig_sys::r_memory_object_ready(
                memory_control,
                c_int::from(may_cache),
                copy_strategy,
            )
        },
    })
}

/// `mach_notify_new_task()` of the MIG `task_notify` stubs.
///
/// # Errors
///
/// Returns the [`SendError`] the kernel send reported.
///
/// # Safety
///
/// `notify` must be a live send right the message consumes, and `task` and
/// `parent` send rights for the message to carry, or null.
pub(crate) unsafe fn mach_notify_new_task(
    notify: *mut c_void,
    task: *mut c_void,
    parent: *mut c_void,
) -> Result<(), SendError> {
    send_result(unsafe {
        mach_mig_sys::mach_notify_new_task(notify, task, parent)
    })
}

/// `memory_object_data_request()` of the MIG `memory_object` stubs, with the
/// protection bits unwrapped for the stub.
///
/// # Errors
///
/// Returns the [`SendError`] the kernel send reported.
///
/// # Safety
///
/// The memory object and control ports must be live, and `offset`/`length`
/// must describe a valid range of the object.
pub(crate) unsafe fn memory_object_data_request(
    memory_object: *mut c_void,
    memory_control: *mut c_void,
    offset: VmOffset,
    length: VmSize,
    desired_access: VmProt,
) -> Result<(), SendError> {
    send_result(unsafe {
        mach_mig_sys::memory_object_data_request(
            memory_object,
            memory_control,
            offset,
            length,
            desired_access.bits(),
        )
    })
}

/// `memory_object_data_unlock()` of the MIG `memory_object` stubs, with the
/// protection bits unwrapped for the stub.
///
/// # Errors
///
/// Returns the [`SendError`] the kernel send reported.
///
/// # Safety
///
/// The memory object and control ports must be live, and `offset`/`length`
/// must describe a valid range of the object.
pub(crate) unsafe fn memory_object_data_unlock(
    memory_object: *mut c_void,
    memory_control: *mut c_void,
    offset: VmOffset,
    length: VmSize,
    desired_access: VmProt,
) -> Result<(), SendError> {
    send_result(unsafe {
        mach_mig_sys::memory_object_data_unlock(
            memory_object,
            memory_control,
            offset,
            length,
            desired_access.bits(),
        )
    })
}

/// `memory_object_data_return()` of the MIG `memory_object` stubs.
///
/// # Errors
///
/// Returns the [`SendError`] the kernel send reported.
///
/// # Safety
///
/// The memory object and control ports must be live, and `data` a page-list
/// copy of `data_cnt` bytes the message consumes.
pub(crate) unsafe fn memory_object_data_return(
    memory_object: *mut c_void,
    memory_control: *mut c_void,
    offset: VmOffset,
    data: VmOffset,
    data_cnt: c_uint,
    dirty: c_int,
    kernel_copy: c_int,
) -> Result<(), SendError> {
    send_result(unsafe {
        mach_mig_sys::memory_object_data_return(
            memory_object,
            memory_control,
            offset,
            data,
            data_cnt,
            dirty,
            kernel_copy,
        )
    })
}

/// `memory_object_data_initialize()` of the MIG `memory_object_default`
/// stubs.
///
/// # Errors
///
/// Returns the [`SendError`] the kernel send reported.
///
/// # Safety
///
/// The memory object and control ports must be live, and `data` a page-list
/// copy of `data_cnt` bytes the message consumes.
pub(crate) unsafe fn memory_object_data_initialize(
    memory_object: *mut c_void,
    memory_control: *mut c_void,
    offset: VmOffset,
    data: VmOffset,
    data_cnt: c_uint,
) -> Result<(), SendError> {
    send_result(unsafe {
        mach_mig_sys::memory_object_data_initialize(
            memory_object,
            memory_control,
            offset,
            data,
            data_cnt,
        )
    })
}

/// `memory_object_lock_completed()` of the MIG `memory_object` stubs.
///
/// # Errors
///
/// Returns the [`SendError`] the kernel send reported.
///
/// # Safety
///
/// `memory_object` must be a live reply right of type `memory_object_poly`
/// the message consumes, and `memory_control` the object's request port.
pub(crate) unsafe fn memory_object_lock_completed(
    memory_object: *mut c_void,
    memory_object_poly: c_uint,
    memory_control: *mut c_void,
    offset: VmOffset,
    length: VmSize,
) -> Result<(), SendError> {
    send_result(unsafe {
        mach_mig_sys::memory_object_lock_completed(
            memory_object,
            memory_object_poly,
            memory_control,
            offset,
            length,
        )
    })
}

/// `memory_object_supply_completed()` of the MIG `memory_object` stubs, with
/// the outcome of the supply.
///
/// # Errors
///
/// Returns the [`SendError`] the kernel send reported.
///
/// # Safety
///
/// `memory_object` must be a live reply right of type `memory_object_poly`
/// the message consumes, and `memory_control` the object's request port.
pub(crate) unsafe fn memory_object_supply_completed(
    memory_object: *mut c_void,
    memory_object_poly: c_uint,
    memory_control: *mut c_void,
    offset: VmOffset,
    length: VmSize,
    result: Result<(), VmError>,
    error_offset: VmOffset,
) -> Result<(), SendError> {
    send_result(unsafe {
        mach_mig_sys::memory_object_supply_completed(
            memory_object,
            memory_object_poly,
            memory_control,
            offset,
            length,
            code::kern_return(result.map_err(vm_return)),
            error_offset,
        )
    })
}

/// `memory_object_change_completed()` of the MIG `memory_object` stubs.
///
/// # Errors
///
/// Returns the [`SendError`] the kernel send reported.
///
/// # Safety
///
/// `memory_object` must be a live reply right of type `memory_object_poly`
/// the message consumes.
pub(crate) unsafe fn memory_object_change_completed(
    memory_object: *mut c_void,
    memory_object_poly: c_uint,
    may_cache: c_int,
    copy_strategy: c_int,
) -> Result<(), SendError> {
    send_result(unsafe {
        mach_mig_sys::memory_object_change_completed(
            memory_object,
            memory_object_poly,
            may_cache,
            copy_strategy,
        )
    })
}

/// `memory_object_init()` of the MIG `memory_object` stubs.
///
/// # Errors
///
/// Returns the [`SendError`] the kernel send reported.
///
/// # Safety
///
/// The three ports must be live; the message carries send rights to the
/// request and name ports.
pub(crate) unsafe fn memory_object_init(
    pager: *mut c_void,
    pager_request: *mut c_void,
    pager_name: *mut c_void,
    page_size: VmSize,
) -> Result<(), SendError> {
    send_result(unsafe {
        mach_mig_sys::memory_object_init(
            pager,
            pager_request,
            pager_name,
            page_size,
        )
    })
}

/// `memory_object_create()` of the MIG `memory_object_default` stubs.
///
/// # Errors
///
/// Returns the [`SendError`] the kernel send reported.
///
/// # Safety
///
/// The ports must be live; the message carries the new pager and send
/// rights to the request and name ports.
pub(crate) unsafe fn memory_object_create(
    memory_object: *mut c_void,
    pager: *mut c_void,
    size: VmSize,
    pager_request: *mut c_void,
    pager_name: *mut c_void,
    page_size: VmSize,
) -> Result<(), SendError> {
    send_result(unsafe {
        mach_mig_sys::memory_object_create(
            memory_object,
            pager,
            size,
            pager_request,
            pager_name,
            page_size,
        )
    })
}

/// `memory_object_copy()` of the MIG `memory_object` stubs.
///
/// # Errors
///
/// Returns the [`SendError`] the kernel send reported.
///
/// # Safety
///
/// The ports must be live; the message carries a send right to
/// `new_memory_object`.
pub(crate) unsafe fn memory_object_copy(
    memory_object: *mut c_void,
    pager_request: *mut c_void,
    offset: VmOffset,
    size: VmSize,
    new_memory_object: *mut c_void,
) -> Result<(), SendError> {
    send_result(unsafe {
        mach_mig_sys::memory_object_copy(
            memory_object,
            pager_request,
            offset,
            size,
            new_memory_object,
        )
    })
}

/// `memory_object_terminate()` of the MIG `memory_object` stubs.
///
/// # Errors
///
/// Returns the [`SendError`] the kernel send reported.
///
/// # Safety
///
/// The three ports must be live; the message consumes the request and name
/// rights.
pub(crate) unsafe fn memory_object_terminate(
    pager: *mut c_void,
    pager_request: *mut c_void,
    pager_name: *mut c_void,
) -> Result<(), SendError> {
    send_result(unsafe {
        mach_mig_sys::memory_object_terminate(pager, pager_request, pager_name)
    })
}
