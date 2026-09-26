// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The C functions Rust calls, and the interface records both halves share.
//!
//! The MIG half lives in [`mach_mig_sys`]; this module re-exports it under
//! the paths the kernel already uses and keeps the kernel-image symbols and
//! the typed wrappers over the few stubs whose MIG signatures carry kernel
//! types.

pub mod mig;
pub mod time_value;

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::x86_64::trap::Recovery;
use crate::vm::types::VmProt;
use core::ffi::{c_char, c_int, c_void};

pub(crate) use mach_mig_sys::{
    MigRoutine, device_pager_server_routines, device_server_routines,
    ds_device_open_reply, ds_device_read_reply, ds_device_read_reply_inband,
    ds_device_write_reply, ds_device_write_reply_inband,
    experimental_server_routines, gnumach_server_routines,
    mach_debug_server_routines, mach_host_server_routines,
    mach_i386_server_routines, mach_notify_new_task,
    mach_port_server_routines, mach_server_routines, mach4_server_routines,
    memory_object_change_completed, memory_object_copy, memory_object_create,
    memory_object_data_initialize, memory_object_data_return,
    memory_object_init, memory_object_lock_completed,
    memory_object_supply_completed, memory_object_terminate,
    r_memory_object_data_error, r_memory_object_ready,
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

    /// `version[]` of the generated version object: the kernel's release
    /// string, printed by `c_boot_entry()`.
    pub static version: c_char;

}

/// `memory_object_data_request()` of the MIG `memory_object_user` stubs,
/// with the protection bits unwrapped for the C.
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
) -> c_int {
    unsafe {
        mach_mig_sys::memory_object_data_request(
            memory_object,
            memory_control,
            offset,
            length,
            desired_access.bits(),
        )
    }
}

/// `memory_object_data_unlock()` of the MIG `memory_object_user` stubs,
/// with the protection bits unwrapped for the C.
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
) -> c_int {
    unsafe {
        mach_mig_sys::memory_object_data_unlock(
            memory_object,
            memory_control,
            offset,
            length,
            desired_access.bits(),
        )
    }
}
