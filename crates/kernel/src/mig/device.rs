// SPDX-License-Identifier: CMU-Mach
// Derived from device/ds_routines.c:
//   Copyright (c) 1993,1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1996 The University of Utah and the Computer Systems
//   Laboratory at the University of Utah (CSL).
// Derived from device/dev_lookup.c and device/dev_hdr.h:
//   Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The <device/device.defs> server entries, all 13 routines, which
//! `device/device.srv` presents under the MIG `serverprefix ds_`.
//!
//! Every adapter hands its raw arguments to the matching core in
//! [`crate::device::ds_routines`] without adding an obligation of its own.
//! The translations and the destructor <`device/device_types.defs`> names
//! for `device_t` are here too, over [`crate::device::dev_lookup`].

use crate::arch::types::{VmOffset, VmSize};
use crate::device::dev_lookup;
use crate::device::ds_routines::{self, Device};
use crate::device::r#return::DeviceError;
use crate::mig::code::{io_return, kern_return};
use core::ffi::{c_char, c_int, c_uint, c_ulong, c_ushort, c_void};
use core::ptr::NonNull;

/// Opens the device `name` with `mode`, serving `device_open` and
/// [`ds_device_open_new`].
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
    io_return(unsafe {
        ds_routines::ds_device_open(
            open_port,
            reply_port,
            reply_port_type,
            mode,
            name,
            devp,
        )
    })
}

/// Opens the device `name` with `mode`, serving `device_open_new`.
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
    io_return(unsafe {
        ds_routines::ds_device_open(
            open_port,
            reply_port,
            reply_port_type,
            mode,
            name,
            devp,
        )
    })
}

/// Closes `dev`.
///
/// # Safety
///
/// `dev` is null or a live device.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ds_device_close(dev: *mut c_void) -> c_int {
    let Some(dev) = NonNull::new(dev) else {
        return c_int::from(DeviceError::NoSuchDevice);
    };
    kern_return(unsafe { ds_routines::ds_device_close(dev) })
}

/// Writes the out-of-line `data` to `dev` at `recnum`.
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
        return c_int::from(DeviceError::NoSuchDevice);
    };
    let Some(data) = NonNull::new(data) else {
        return c_int::from(DeviceError::InvalidSize);
    };
    io_return(unsafe {
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
    })
}

/// Writes the in-band `data` to `dev` at `recnum`.
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
        return c_int::from(DeviceError::NoSuchDevice);
    };
    let Some(data) = NonNull::new(data.cast_mut()) else {
        return c_int::from(DeviceError::InvalidSize);
    };
    io_return(unsafe {
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
    })
}

/// Reads `count` bytes from `dev` at `recnum`, out of line.
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
        return c_int::from(DeviceError::NoSuchDevice);
    };
    io_return(unsafe {
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
    })
}

/// Reads `count` bytes from `dev` at `recnum`, in band.
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
        return c_int::from(DeviceError::NoSuchDevice);
    };
    io_return(unsafe {
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
    })
}

/// Applies the status flavor `flavor` to `dev`.
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
        return c_int::from(DeviceError::NoSuchDevice);
    };
    kern_return(unsafe {
        ds_routines::ds_device_set_status(dev, flavor, status, status_count)
    })
}

/// Reports the status flavor `flavor` of `dev`.
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
        return c_int::from(DeviceError::NoSuchDevice);
    };
    kern_return(unsafe {
        ds_routines::ds_device_get_status(dev, flavor, status, status_count)
    })
}

/// Installs the packet `filter` on `dev` for `receive_port`, at `priority`.
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
        return c_int::from(DeviceError::NoSuchDevice);
    };
    kern_return(unsafe {
        ds_routines::ds_device_set_filter(
            dev,
            receive_port,
            priority,
            filter,
            filter_count,
        )
    })
}

/// Makes a pager that maps `size` bytes of `dev` at `offset` with
/// `protection`.
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
        return c_int::from(DeviceError::NoSuchDevice);
    };
    kern_return(unsafe {
        ds_routines::ds_device_map(dev, protection, offset, size, pager, unmap)
    })
}

/// Registers `receive_port` to receive the interrupt `id` of `dev`.
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
        return c_int::from(DeviceError::NoSuchDevice);
    };
    kern_return(unsafe {
        ds_routines::ds_device_intr_register(dev, id, flags, receive_port)
    })
}

/// Acknowledges the interrupt `receive_port` was notified of, enabling its
/// line again.
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
        return c_int::from(DeviceError::NoSuchDevice);
    };
    kern_return(unsafe { ds_routines::ds_device_intr_ack(dev, receive_port) })
}

/// `dev_port_lookup()`: the device `port` names, with the reference its
/// emulation takes, or null.
///
/// # Safety
///
/// `port` must be null, dead, or a live port.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dev_port_lookup(port: *mut c_void) -> *mut c_void {
    unsafe { dev_lookup::port_lookup(port) }.cast::<c_void>()
}

/// `convert_device_to_port()`: a send right for `device`'s port, or null.
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

/// `device_deallocate()`: drop a device reference.
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
