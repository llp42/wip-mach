// SPDX-License-Identifier: CMU-Mach
// Derived from kern/ipc_host.c:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `kern/ipc_host.c` symbols C still calls, over the cores in
//! [`crate::kern::ipc_host`].

use crate::kern::host::Host;
use crate::kern::ipc_host;
use crate::kern::processor::{Processor, ProcessorSet};
use core::ffi::c_void;

/// `convert_port_to_host()` of `kern/ipc_host.c`.
///
/// # Safety
///
/// `port` must be null or a live port pointer `IP_VALID()` accepts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_host(port: *mut c_void) -> *mut Host {
    unsafe { ipc_host::port_to_host(port) }
}

/// `convert_port_to_host_priv()` of `kern/ipc_host.c`.
///
/// # Safety
///
/// `port` must be null or a live port pointer `IP_VALID()` accepts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_host_priv(
    port: *mut c_void,
) -> *mut Host {
    unsafe { ipc_host::port_to_host_priv(port) }
}

/// `convert_host_to_port()` of `kern/ipc_host.c`.
///
/// # Safety
///
/// `host` must point at a live `struct host`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_host_to_port(host: *mut Host) -> *mut c_void {
    unsafe { ipc_host::host_to_port(host) }
}

/// `convert_port_to_processor()` of `kern/ipc_host.c`.
///
/// # Safety
///
/// `port` must be null or a live port pointer `IP_VALID()` accepts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_processor(
    port: *mut c_void,
) -> *mut Processor {
    unsafe { ipc_host::port_to_processor(port) }
}

/// `convert_port_to_processor_name()` of `kern/ipc_host.c`.
///
/// # Safety
///
/// `port` must be null or a live port pointer `IP_VALID()` accepts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_processor_name(
    port: *mut c_void,
) -> *mut Processor {
    unsafe { ipc_host::port_to_processor_name(port) }
}

/// `convert_port_to_pset()` of `kern/ipc_host.c`.
///
/// # Safety
///
/// `port` must be null or a live port pointer `IP_VALID()` accepts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_pset(
    port: *mut c_void,
) -> *mut ProcessorSet {
    unsafe { ipc_host::port_to_pset(port) }
}

/// `convert_port_to_pset_name()` of `kern/ipc_host.c`.
///
/// # Safety
///
/// `port` must be null or a live port pointer `IP_VALID()` accepts.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_port_to_pset_name(
    port: *mut c_void,
) -> *mut ProcessorSet {
    unsafe { ipc_host::port_to_pset_name(port) }
}

/// `convert_pset_to_port()` of `kern/ipc_host.c`.
///
/// # Safety
///
/// `pset` must point at a live, referenced `struct processor_set`; the call
/// consumes the reference.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_pset_to_port(
    pset: *mut ProcessorSet,
) -> *mut c_void {
    unsafe { ipc_host::pset_to_port(pset) }
}

/// `convert_pset_name_to_port()` of `kern/ipc_host.c`.
///
/// # Safety
///
/// `pset` must point at a live, referenced `struct processor_set`; the call
/// consumes the reference.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_pset_name_to_port(
    pset: *mut ProcessorSet,
) -> *mut c_void {
    unsafe { ipc_host::pset_name_to_port(pset) }
}
