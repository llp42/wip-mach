// SPDX-License-Identifier: CMU-Mach
// Derived from device/ds_routines.c:
//   Copyright (c) 1993,1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1996 The University of Utah and the Computer Systems
//   Laboratory at the University of Utah (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The `device_deallocate` export of `device/ds_routines.c`: the destructor
//! the generated `device.server.c` names.  The rest of the file lives in
//! [`ds_routines`].

use crate::device::ds_routines;
use core::ffi::c_void;
use core::ptr::NonNull;

/// `device_deallocate()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` is null or a live `struct device`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn device_deallocate(dev: *mut c_void) {
    let Some(dev) = NonNull::new(dev) else {
        return;
    };
    unsafe { ds_routines::device_deallocate(dev) }
}
