// SPDX-License-Identifier: CMU-Mach
// Derived from device/dev_pager.c:
//   Copyright (c) 1993-1989 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The <`mach/memory_object.defs`> server entries, all 9 routines, which
//! `device/device_pager.srv` presents renamed to `device_pager_*`.
//!
//! Every adapter hands its raw arguments to the matching core in
//! [`crate::device::dev_pager`] without adding an obligation of its own.

use crate::arch::types::{VmOffset, VmSize};
use crate::device::dev_pager;
use crate::ipc::IpcPort;
use crate::kern::debug::kpanic;
use crate::vm::types::VmProt;
use core::ffi::{c_int, c_uint};

/// `KERN_SUCCESS` of <`mach/kern_return.h`>.
const KERN_SUCCESS: c_int = 0;

/// `device_pager_data_request()` of `device/dev_pager.c`, the MIG
/// `memory_object_data_request` server entry.
///
/// # Safety
///
/// `pager` must be the live port of a set-up pager record and
/// `pager_request` the live control port the kernel bound to it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn device_pager_data_request(
    pager: Option<IpcPort>,
    pager_request: Option<IpcPort>,
    offset: VmOffset,
    length: VmSize,
    _protection_required: VmProt,
) -> c_int {
    unsafe { dev_pager::data_request(pager, pager_request, offset, length) };
    KERN_SUCCESS
}

/// `device_pager_init_pager()` of `device/dev_pager.c`, the MIG
/// `memory_object_init` server entry.
///
/// # Safety
///
/// The MIG server calls this once for the pager `pager` denotes, before any
/// data request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn device_pager_init_pager(
    pager: Option<IpcPort>,
    pager_request: Option<IpcPort>,
    pager_name: Option<IpcPort>,
) -> c_int {
    unsafe { dev_pager::init_pager(pager, pager_request, pager_name) };
    KERN_SUCCESS
}

/// `device_pager_terminate()` of `device/dev_pager.c`, the MIG
/// `memory_object_terminate` server entry.
///
/// # Safety
///
/// The MIG server calls this once after a completed init, with the ports of
/// that init.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn device_pager_terminate(
    pager: Option<IpcPort>,
    pager_request: Option<IpcPort>,
    pager_name: Option<IpcPort>,
) -> c_int {
    unsafe { dev_pager::terminate(pager, pager_request, pager_name) };
    KERN_SUCCESS
}

/// `device_pager_copy()` of `device/dev_pager.c`.
///
/// # Safety
///
/// Never returns; the caller must accept the halt.
///
/// # Panics
///
/// Always, through [`kpanic!`], as the C did.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn device_pager_copy(
    _old_memory_object: Option<IpcPort>,
    _old_memory_control: Option<IpcPort>,
    _offset: VmOffset,
    _length: VmSize,
    _new_memory_object: Option<IpcPort>,
) -> c_int {
    kpanic!("device_pager_copy", "(device_pager)copy: called")
}

/// `device_pager_supply_completed()` of `device/dev_pager.c`.
///
/// # Safety
///
/// Never returns; the caller must accept the halt.
///
/// # Panics
///
/// Always, through [`kpanic!`], as the C did.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn device_pager_supply_completed(
    _device_pager: Option<IpcPort>,
    _memory_control: Option<IpcPort>,
    _offset: VmOffset,
    _length: VmSize,
    _result: c_int,
    _error_offset: VmOffset,
) -> c_int {
    kpanic!(
        "device_pager_supply_completed",
        "(device_pager)supply_completed: called"
    )
}

/// `device_pager_data_return()` of `device/dev_pager.c`.
///
/// # Safety
///
/// Never returns; the caller must accept the halt.
///
/// # Panics
///
/// Always, through [`kpanic!`], as the C did.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn device_pager_data_return(
    _device_pager: Option<IpcPort>,
    _memory_control: Option<IpcPort>,
    _offset: VmOffset,
    _data: VmOffset,
    _data_cnt: c_uint,
    _dirty: c_int,
    _kernel_copy: c_int,
) -> c_int {
    kpanic!(
        "device_pager_data_return",
        "(device_pager)data_return: called"
    )
}

/// `device_pager_change_completed()` of `device/dev_pager.c`.
///
/// # Safety
///
/// Never returns; the caller must accept the halt.
///
/// # Panics
///
/// Always, through [`kpanic!`], as the C did.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn device_pager_change_completed(
    _device_pager: Option<IpcPort>,
    _may_cache: c_int,
    _copy_strategy: c_int,
) -> c_int {
    kpanic!(
        "device_pager_change_completed",
        "(device_pager)change_completed: called"
    )
}

/// `device_pager_data_unlock()` of `device/dev_pager.c`.
///
/// # Safety
///
/// Never returns; the caller must accept the halt.
///
/// # Panics
///
/// Always, through [`kpanic!`], as the C did.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn device_pager_data_unlock(
    _device_pager: Option<IpcPort>,
    _memory_control: Option<IpcPort>,
    _offset: VmOffset,
    _length: VmSize,
    _desired_access: VmProt,
) -> c_int {
    kpanic!(
        "device_pager_data_unlock",
        "(device_pager)data_unlock: called"
    )
}

/// `device_pager_lock_completed()` of `device/dev_pager.c`.
///
/// # Safety
///
/// Never returns; the caller must accept the halt.
///
/// # Panics
///
/// Always, through [`kpanic!`], as the C did.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn device_pager_lock_completed(
    _device_pager: Option<IpcPort>,
    _memory_control: Option<IpcPort>,
    _offset: VmOffset,
    _length: VmSize,
) -> c_int {
    kpanic!(
        "device_pager_lock_completed",
        "(device_pager)lock_completed: called"
    )
}
