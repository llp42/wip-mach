// SPDX-License-Identifier: CMU-Mach
// Derived from device/dev_lookup.c and device/dev_hdr.h:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `extern "C"` exports of `device/dev_lookup.c`, which
//! <`device/dev_hdr.h`>, the MIG `device_types.defs` translations and
//! <`device/ds_routines.h`> call.
//!
//! Every adapter hands its raw arguments to the matching core in
//! [`dev_lookup`] without adding an obligation of its own.

use crate::device::dev_lookup;
use crate::device::ds_routines::Device;
use core::ffi::c_void;
use core::ptr::NonNull;

/// `dev_port_lookup()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// `port` must be null, dead, or a live port. The returned `struct device`,
/// when non-null, carries the reference the emulation made.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dev_port_lookup(port: *mut c_void) -> *mut c_void {
    unsafe { dev_lookup::port_lookup(port) }.cast::<c_void>()
}

/// `convert_device_to_port()` of `device/dev_lookup.c`.
///
/// # Safety
///
/// `device` must be null or a live `struct device`, and its emulation must
/// be one whose `dev_to_port` takes the reference the caller consumed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn convert_device_to_port(
    device: *mut c_void,
) -> *mut c_void {
    unsafe {
        dev_lookup::convert_to_port(NonNull::new(device.cast::<Device>()))
    }
}
