// SPDX-License-Identifier: CMU-Mach
// Derived from device/ds_routines.c:
//   Copyright (c) 1993,1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1996 The University of Utah and the Computer Systems
//   Laboratory at the University of Utah (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The <device/device.defs> server entries, all 13 routines, which
//! `device/device.srv` presents under the MIG `serverprefix ds_`.
//!
//! Every adapter hands its raw arguments to the matching core in
//! [`crate::device::ds_routines`] without adding an obligation of its own.

use crate::arch::types::{VmOffset, VmSize};
use crate::device::ds_routines;
use crate::device::r#return::{DeviceError, IoResultExt};
use core::ffi::{c_char, c_int, c_uint, c_ulong, c_ushort, c_void};
use core::ptr::NonNull;

/// `ds_device_open()` of `device/ds_routines.c`, which the MIG server and
/// `ds_device_open_new()` call.
///
/// # Safety
///
/// `open_port` is the master device port, `reply_port` a valid port or
/// `IP_NULL`, `name` a NUL-terminated device name, and `devp` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_device_open(
    open_port: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    name: *const c_char,
    devp: *mut *mut c_void,
) -> c_int {
    unsafe {
        ds_routines::ds_device_open(
            open_port,
            reply_port,
            reply_port_type,
            mode,
            name,
            devp,
        )
    }
}

/// `ds_device_open_new()` of the MIG <device/device.server.h>.
///
/// # Safety
///
/// Same contract as [`ds_device_open()`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_device_open_new(
    open_port: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    name: *const c_char,
    devp: *mut *mut c_void,
) -> c_int {
    unsafe {
        ds_routines::ds_device_open(
            open_port,
            reply_port,
            reply_port_type,
            mode,
            name,
            devp,
        )
    }
}

/// `ds_device_close()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` is `DEVICE_NULL` or a live `struct device`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_device_close(dev: *mut c_void) -> c_int {
    let Some(dev) = NonNull::new(dev) else {
        return Err(DeviceError::NoSuchDevice).as_io_return();
    };
    unsafe { ds_routines::ds_device_close(dev) }
}

/// `ds_device_write()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` is a live `struct device`, `data` readable for `count` bytes when
/// non-null, and `bytes_written` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_device_write(
    dev: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    data: *mut c_char,
    count: c_uint,
    bytes_written: *mut c_int,
) -> c_int {
    let Some(dev) = NonNull::new(dev) else {
        return Err(DeviceError::NoSuchDevice).as_io_return();
    };
    let Some(data) = NonNull::new(data) else {
        return Err(DeviceError::InvalidSize).as_io_return();
    };
    unsafe {
        ds_routines::ds_device_write(
            dev,
            reply_port,
            reply_port_type,
            mode,
            recnum,
            data,
            count,
            bytes_written,
        )
    }
}

/// `ds_device_write_inband()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` is a live `struct device`, `data` readable for `count` bytes when
/// non-null, and `bytes_written` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_device_write_inband(
    dev: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    data: *const c_char,
    count: c_uint,
    bytes_written: *mut c_int,
) -> c_int {
    let Some(dev) = NonNull::new(dev) else {
        return Err(DeviceError::NoSuchDevice).as_io_return();
    };
    let Some(data) = NonNull::new(data.cast_mut()) else {
        return Err(DeviceError::InvalidSize).as_io_return();
    };
    unsafe {
        ds_routines::ds_device_write_inband(
            dev,
            reply_port,
            reply_port_type,
            mode,
            recnum,
            data,
            count,
            bytes_written,
        )
    }
}

/// `ds_device_read()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` is a live `struct device`, and `data` and `bytes_read` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_device_read(
    dev: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    count: c_int,
    data: *mut *mut c_char,
    bytes_read: *mut c_uint,
) -> c_int {
    let Some(dev) = NonNull::new(dev) else {
        return Err(DeviceError::NoSuchDevice).as_io_return();
    };
    unsafe {
        ds_routines::ds_device_read(
            dev,
            reply_port,
            reply_port_type,
            mode,
            recnum,
            count,
            data,
            bytes_read,
        )
    }
}

/// `ds_device_read_inband()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` is a live `struct device`, `data` writable for the reply, and
/// `bytes_read` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_device_read_inband(
    dev: *mut c_void,
    reply_port: *mut c_void,
    reply_port_type: c_uint,
    mode: c_uint,
    recnum: c_ulong,
    count: c_int,
    data: *mut c_char,
    bytes_read: *mut c_uint,
) -> c_int {
    let Some(dev) = NonNull::new(dev) else {
        return Err(DeviceError::NoSuchDevice).as_io_return();
    };
    unsafe {
        ds_routines::ds_device_read_inband(
            dev,
            reply_port,
            reply_port_type,
            mode,
            recnum,
            count,
            data,
            bytes_read,
        )
    }
}

/// `ds_device_set_status()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` is a live `struct device`, and `status` readable for `status_count`
/// integers when the emulation reads it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_device_set_status(
    dev: *mut c_void,
    flavor: c_uint,
    status: *mut c_int,
    status_count: c_uint,
) -> c_int {
    let Some(dev) = NonNull::new(dev) else {
        return Err(DeviceError::NoSuchDevice).as_io_return();
    };
    unsafe {
        ds_routines::ds_device_set_status(dev, flavor, status, status_count)
    }
}

/// `ds_device_get_status()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` is a live `struct device`, `status` writable for `*status_count`
/// integers, and `status_count` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_device_get_status(
    dev: *mut c_void,
    flavor: c_uint,
    status: *mut c_int,
    status_count: *mut c_uint,
) -> c_int {
    let Some(dev) = NonNull::new(dev) else {
        return Err(DeviceError::NoSuchDevice).as_io_return();
    };
    unsafe {
        ds_routines::ds_device_get_status(dev, flavor, status, status_count)
    }
}

/// `ds_device_set_filter()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` is a live `struct device`, `receive_port` a valid port, and `filter`
/// readable for `filter_count` entries.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_device_set_filter(
    dev: *mut c_void,
    receive_port: *mut c_void,
    priority: c_int,
    filter: *mut c_ushort,
    filter_count: c_uint,
) -> c_int {
    let Some(dev) = NonNull::new(dev) else {
        return Err(DeviceError::NoSuchDevice).as_io_return();
    };
    unsafe {
        ds_routines::ds_device_set_filter(
            dev,
            receive_port,
            priority,
            filter,
            filter_count,
        )
    }
}

/// `ds_device_map()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` is a live `struct device`, and `pager` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_device_map(
    dev: *mut c_void,
    protection: c_int,
    offset: VmOffset,
    size: VmSize,
    pager: *mut *mut c_void,
    unmap: c_int,
) -> c_int {
    let Some(dev) = NonNull::new(dev) else {
        return Err(DeviceError::NoSuchDevice).as_io_return();
    };
    unsafe {
        ds_routines::ds_device_map(dev, protection, offset, size, pager, unmap)
    }
}

/// `ds_device_intr_register()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` is a live `struct device` for a mach device, and `receive_port` a
/// valid port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_device_intr_register(
    dev: *mut c_void,
    id: c_int,
    flags: c_int,
    receive_port: *mut c_void,
) -> c_int {
    let Some(dev) = NonNull::new(dev) else {
        return Err(DeviceError::NoSuchDevice).as_io_return();
    };
    unsafe {
        ds_routines::ds_device_intr_register(dev, id, flags, receive_port)
    }
}

/// `ds_device_intr_ack()` of `device/ds_routines.c`.
///
/// # Safety
///
/// `dev` is a live `struct device` for a mach device, and `receive_port` a
/// valid port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_device_intr_ack(
    dev: *mut c_void,
    receive_port: *mut c_void,
) -> c_int {
    let Some(dev) = NonNull::new(dev) else {
        return Err(DeviceError::NoSuchDevice).as_io_return();
    };
    unsafe { ds_routines::ds_device_intr_ack(dev, receive_port) }
}
