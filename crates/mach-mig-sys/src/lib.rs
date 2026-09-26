// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The MIG-generated C symbols Rust calls: the user stubs, the server
//! routine tables the kernel dispatches through, and the raw record types
//! they exchange.
//!
//! The `build.rs` generates and compiles the C glue from `mig/` and links it
//! into every dependent image; this half declares what that glue exports.

#![no_std]

use core::ffi::{c_char, c_int, c_uint, c_void};

/// `vm_offset_t`: a type-neutral pointer, `uintptr_t` in the C.
pub type VmOffset = usize;

/// `vm_size_t`: the difference between two `vm_offset_t`s, likewise a
/// `uintptr_t` in the C.
pub type VmSize = usize;

/// `mig_routine_t` of <mach/mig.h>: one generated MIG server entry point.
pub type MigRoutine = Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>;

unsafe extern "C" {

    /// `mach_notify_new_task()` of the MIG `task_notify` user stubs.
    pub fn mach_notify_new_task(
        notify: *mut c_void,
        task: *mut c_void,
        parent: *mut c_void,
    ) -> c_int;

    /// `r_memory_object_data_error()` of the MIG `memory_object_reply`
    /// user stubs.
    pub fn r_memory_object_data_error(
        memory_control: *mut c_void,
        offset: VmOffset,
        size: VmSize,
        error_value: c_int,
    ) -> c_int;

    /// `r_memory_object_ready()` of the MIG `memory_object_reply` user
    /// stubs.
    pub fn r_memory_object_ready(
        memory_control: *mut c_void,
        may_cache: c_int,
        copy_strategy: c_int,
    ) -> c_int;

    /// `ds_device_open_reply()` of the MIG `device_reply` user stubs.
    pub fn ds_device_open_reply(
        reply_port: *mut c_void,
        reply_port_type: c_uint,
        return_code: c_int,
        device_port: *mut c_void,
    ) -> c_int;

    /// `ds_device_write_reply()` of the MIG `device_reply` user stubs.
    pub fn ds_device_write_reply(
        reply_port: *mut c_void,
        reply_port_type: c_uint,
        return_code: c_int,
        bytes_written: c_int,
    ) -> c_int;

    /// `ds_device_write_reply_inband()` of the MIG `device_reply` user
    /// stubs.
    pub fn ds_device_write_reply_inband(
        reply_port: *mut c_void,
        reply_port_type: c_uint,
        return_code: c_int,
        bytes_written: c_int,
    ) -> c_int;

    /// `ds_device_read_reply()` of the MIG `device_reply` user stubs.
    pub fn ds_device_read_reply(
        reply_port: *mut c_void,
        reply_port_type: c_uint,
        return_code: c_int,
        data: *mut c_char,
        data_count: c_uint,
    ) -> c_int;

    /// `ds_device_read_reply_inband()` of the MIG `device_reply` user stubs.
    pub fn ds_device_read_reply_inband(
        reply_port: *mut c_void,
        reply_port_type: c_uint,
        return_code: c_int,
        data: *mut c_char,
        data_count: c_uint,
    ) -> c_int;

    /// The `*_server_routines[]` tables the generated `*.server.h` headers
    /// declare, one per MIG subsystem.  Each is declared as its first
    /// element, as the C header declares the array.
    pub static mut mach_server_routines: MigRoutine;
    pub static mut mach_port_server_routines: MigRoutine;
    pub static mut mach_host_server_routines: MigRoutine;
    pub static mut device_server_routines: MigRoutine;
    pub static mut device_pager_server_routines: MigRoutine;
    pub static mut mach_debug_server_routines: MigRoutine;
    pub static mut mach4_server_routines: MigRoutine;
    pub static mut gnumach_server_routines: MigRoutine;
    pub static mut experimental_server_routines: MigRoutine;
    pub static mut mach_i386_server_routines: MigRoutine;

    /// `memory_object_data_request()` of the MIG `memory_object_user`
    /// stubs.
    pub fn memory_object_data_request(
        memory_object: *mut c_void,
        memory_control: *mut c_void,
        offset: VmOffset,
        length: VmSize,
        desired_access: c_int,
    ) -> c_int;

    /// `memory_object_data_unlock()` of the MIG `memory_object_user`
    /// stubs.
    pub fn memory_object_data_unlock(
        memory_object: *mut c_void,
        memory_control: *mut c_void,
        offset: VmOffset,
        length: VmSize,
        desired_access: c_int,
    ) -> c_int;

    /// `memory_object_data_return()` of the MIG `memory_object_user`
    /// stubs.
    pub fn memory_object_data_return(
        memory_object: *mut c_void,
        memory_control: *mut c_void,
        offset: VmOffset,
        data: VmOffset,
        data_cnt: c_uint,
        dirty: c_int,
        kernel_copy: c_int,
    ) -> c_int;

    /// `memory_object_lock_completed()` of the MIG `memory_object_user`
    /// stubs.
    pub fn memory_object_lock_completed(
        memory_object: *mut c_void,
        memory_object_poly: c_uint,
        memory_control: *mut c_void,
        offset: VmOffset,
        length: VmSize,
    ) -> c_int;

    /// `memory_object_supply_completed()` of the MIG `memory_object_user`
    /// stubs.
    pub fn memory_object_supply_completed(
        memory_object: *mut c_void,
        memory_object_poly: c_uint,
        memory_control: *mut c_void,
        offset: VmOffset,
        length: VmSize,
        result: c_int,
        error_offset: VmOffset,
    ) -> c_int;

    /// `memory_object_change_completed()` of the MIG `memory_object_user`
    /// stubs.
    pub fn memory_object_change_completed(
        memory_object: *mut c_void,
        memory_object_poly: c_uint,
        may_cache: c_int,
        copy_strategy: c_int,
    ) -> c_int;

    /// `memory_object_init()` of the MIG `memory_object` user stubs.
    pub fn memory_object_init(
        pager: *mut c_void,
        pager_request: *mut c_void,
        pager_name: *mut c_void,
        page_size: VmSize,
    ) -> c_int;
    /// `memory_object_create()` of the MIG `memory_object` user stubs.
    pub fn memory_object_create(
        memory_object: *mut c_void,
        pager: *mut c_void,
        size: VmSize,
        pager_request: *mut c_void,
        pager_name: *mut c_void,
        page_size: VmSize,
    ) -> c_int;
    /// `memory_object_copy()` of the MIG `memory_object` user stubs.
    pub fn memory_object_copy(
        memory_object: *mut c_void,
        pager_request: *mut c_void,
        offset: VmOffset,
        size: VmSize,
        new_memory_object: *mut c_void,
    ) -> c_int;
    /// `memory_object_terminate()` of the MIG `memory_object` user stubs.
    pub fn memory_object_terminate(
        pager: *mut c_void,
        pager_request: *mut c_void,
        pager_name: *mut c_void,
    ) -> c_int;

    /// `memory_object_data_initialize()` of the MIG
    /// `memory_object_default` stubs.
    pub fn memory_object_data_initialize(
        memory_object: *mut c_void,
        memory_control: *mut c_void,
        offset: VmOffset,
        data: VmOffset,
        data_cnt: c_uint,
    ) -> c_int;

}
