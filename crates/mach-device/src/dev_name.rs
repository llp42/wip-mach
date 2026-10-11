// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The device-name lookup over the machine's device tables, and the stub
//! operations drivers fill those tables with.

use crate::ds_routines::DevOps;
use crate::io_req::{DevT, IoReq};
use crate::platform::Platform;
use crate::r#return::{DeviceError, DeviceSuccess, IoResult};
use core::ffi::{CStr, c_char, c_int, c_uint, c_ushort, c_void};
use core::mem::size_of;
use core::ptr::NonNull;
use core::slice;
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};
use mach_vm::param::VmOffset;

/// The operation vector and unit one indirect name stands for.  The vector
/// and the unit change when the console init points the name elsewhere.
#[repr(C)]
#[allow(missing_docs)]
pub struct DevIndirect<P: Platform> {
    pub d_name: *const c_char,
    pub d_ops: AtomicPtr<DevOps<P>>,
    pub d_unit: AtomicI32,
}

// SAFETY: the name is a static string nothing writes, and the vector and the
// unit are atomics.
unsafe impl<P: Platform> Sync for DevIndirect<P> {}

impl<P: Platform> DevIndirect<P> {
    /// The record keeps its established size, alignment and field offsets.
    pub(crate) const LAYOUT: () = {
        assert!(size_of::<Self>() == 24);
        assert!(align_of::<Self>() == 8);
        assert!(core::mem::offset_of!(Self, d_name) == 0);
        assert!(core::mem::offset_of!(Self, d_ops) == 8);
        assert!(core::mem::offset_of!(Self, d_unit) == 16);
    };
}

/// The open of a device that needs none: succeeds.
pub const fn nulldev_open<P: Platform>(
    _dev: DevT,
    _flags: c_int,
    _ior: *mut IoReq<P>,
) -> IoResult {
    Ok(DeviceSuccess::Success)
}

/// The close of a device that needs none.
pub const fn nulldev_close(_dev: DevT, _flags: c_int) {}

/// The read of a device with no data: succeeds.
pub const fn nulldev_read<P: Platform>(
    _dev: DevT,
    _ior: *mut IoReq<P>,
) -> IoResult {
    Ok(DeviceSuccess::Success)
}

/// The write of a device that drops data: succeeds.
pub const fn nulldev_write<P: Platform>(
    _dev: DevT,
    _ior: *mut IoReq<P>,
) -> IoResult {
    Ok(DeviceSuccess::Success)
}

/// The status read of a device with no status: succeeds.
pub const fn nulldev_getstat(
    _dev: DevT,
    _flavor: c_uint,
    _data: *mut c_int,
    _count: *mut c_uint,
) -> Result<(), DeviceError> {
    Err(DeviceError::InvalidOperation)
}

/// The status write of a device with no status: succeeds.
pub const fn nulldev_setstat(
    _dev: DevT,
    _flavor: c_uint,
    _data: *mut c_int,
    _count: c_uint,
) -> Result<(), DeviceError> {
    Err(DeviceError::InvalidOperation)
}

/// The asynchronous input of a device without it: fails.
pub const fn nodev_async_in(
    _dev: DevT,
    _port: *mut c_void,
    _x: c_int,
    _filter: *mut c_ushort,
    _j: c_uint,
) -> Result<(), DeviceError> {
    Err(DeviceError::InvalidOperation)
}

/// The information call of a device without it: fails.
pub const fn nodev_info(
    _dev: DevT,
    _a: c_int,
    _b: *mut c_int,
) -> Result<(), DeviceError> {
    Err(DeviceError::InvalidOperation)
}

/// The mapping of a device that cannot be mapped: fails.
#[must_use]
pub const fn nomap(_dev: DevT, _off: VmOffset, _prot: c_int) -> VmOffset {
    VmOffset::MAX
}

/// The C `c >= '0' && c <= '9'`.
const fn is_digit(c: c_char) -> bool {
    b'0' as c_char <= c && c <= b'9' as c_char
}

/// Whether `target` begins with the `len` bytes at `src` and ends there.
///
/// # Safety
///
/// `src` must be readable for `len` bytes when `len` is positive (nothing is
/// read when it is not), and `target` must be readable through the first byte
/// that differs from `src`, or through `target[len]` when the first `len`
/// bytes all match.
#[must_use]
pub unsafe fn name_equal(
    src: *const c_char,
    len: c_int,
    target: *const c_char,
) -> bool {
    // The C's pre-decrement skips its loop for any len <= 0 and then asks only
    // whether target is empty; the clamp keeps that answer.
    let len = len.max(0) as usize;
    let src: &[u8] = if len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(src.cast::<u8>(), len) }
    };
    let target = target.cast::<u8>();
    for (i, &want) in src.iter().enumerate() {
        if unsafe { *target.add(i) } != want {
            return false;
        }
    }
    // SAFETY: every byte of the prefix matched, and the caller promises
    // `target[len]` readable for that case; it is the terminator the C tests.
    (unsafe { *target.add(len) }) == 0
}

/// The unit number of a matched name, with its sub-device letter folded in.
///
/// # Safety
///
/// `cp` must point into the NUL-terminated name, at the first byte after the
/// unit digits, and `c` must be the byte at `cp`; `subdev` is the matched
/// entry's `d_subdev`.
unsafe fn subdev_unit(
    mut unit: c_int,
    subdev: c_int,
    mut c: c_char,
    mut cp: *const c_char,
) -> c_int {
    if subdev <= 0 {
        return unit;
    }

    unit = unit.wrapping_mul(subdev);
    let mut slice_num: c_int = 0;
    if c == b's' as c_char {
        cp = unsafe { cp.add(1) };
        loop {
            c = unsafe { *cp };
            if c == 0 || !is_digit(c) {
                break;
            }
            slice_num = slice_num
                .wrapping_mul(10)
                .wrapping_add(c_int::from(c as u8 - b'0'));
            cp = unsafe { cp.add(1) };
        }
    }

    unit = unit.wrapping_add(slice_num << 4);
    let offset = c_int::from(c) - c_int::from(b'a' as c_char);
    if 0 <= offset && offset < subdev {
        unit = unit.wrapping_add(offset + 1);
    }
    unit
}

/// The operations and device number `name` names, or `None`.
///
/// # Safety
///
/// `name` must be a NUL-terminated string readable by the caller.
#[must_use]
pub unsafe fn lookup<P: Platform>(
    name: *const c_char,
) -> Option<(NonNull<DevOps<P>>, c_int)> {
    let mut cp = name;
    let mut len: c_int = 0;
    loop {
        let c = unsafe { *cp };
        if c == 0 || is_digit(c) {
            break;
        }
        len += 1;
        // SAFETY: the walk stops at the terminator.
        cp = unsafe { cp.add(1) };
    }

    let mut unit: c_int = 0;
    // SAFETY: the walk stopped at the terminator or the first digit.
    let mut c = unsafe { *cp };
    if c != 0 {
        while is_digit(c) {
            // The C multiplied an `int` and offset by the digit.
            unit = unit
                .wrapping_mul(10)
                .wrapping_add(c_int::from(c as u8 - b'0'));
            // SAFETY: the walk stops at the terminator.
            cp = unsafe { cp.add(1) };
            // SAFETY: the walk stopped at a digit or the terminator, both
            // inside the NUL-terminated name.
            c = unsafe { *cp };
        }
    }

    let state = P::device_state();
    for dev in state.devices {
        // SAFETY: the entry's name is a NUL-terminated string.
        if unsafe { name_equal(name, len, dev.d_name) } {
            // SAFETY: the name is live.
            let unit = unsafe { subdev_unit(unit, dev.d_subdev, c, cp) };
            return Some((NonNull::from(dev), unit));
        }
    }

    for di in state.indirect {
        // SAFETY: the entry's name is a NUL-terminated string.
        if unsafe { name_equal(name, len, di.d_name) } {
            let ops = NonNull::new(di.d_ops.load(Ordering::Relaxed))?;
            return Some((ops, di.d_unit.load(Ordering::Relaxed)));
        }
    }

    None
}

/// Points the indirect device `name` at `ops` and `unit`.
///
/// # Safety
///
/// `name` must be a NUL-terminated string, and `ops` must be a live entry
/// point table.
pub unsafe fn set_indirection<P: Platform>(
    name: *const c_char,
    ops: *mut DevOps<P>,
    unit: c_int,
) {
    for di in P::device_state().indirect {
        // SAFETY: both names are NUL-terminated strings.
        if unsafe { CStr::from_ptr(di.d_name) == CStr::from_ptr(name) } {
            di.d_ops.store(ops, Ordering::Relaxed);
            di.d_unit.store(unit, Ordering::Relaxed);
            break;
        }
    }
}
