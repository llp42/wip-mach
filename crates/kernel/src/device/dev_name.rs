// SPDX-License-Identifier: CMU-Mach
// Derived from device/dev_name.c and i386/i386at/conf.c:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The device-name lookup and the machine's device tables.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::com::{
    comclose, comgetstat, comopen, comportdeath, comread, comsetstat, comwrite,
};
use crate::arch::x86_64::io_req::{DevT, IoReq};
use crate::arch::x86_64::kd::tty::{
    kdclose, kdgetstat, kdmmap, kdopen, kdportdeath, kdread, kdsetstat,
    kdwrite,
};
use crate::arch::x86_64::kd_event::{
    kbdclose, kbdgetstat, kbdopen, kbdread, kbdsetstat,
};
use crate::arch::x86_64::kd_mouse::{
    mouseclose, mousegetstat, mouseopen, mouseread,
};
use crate::arch::x86_64::mbinfo::mbinforead;
use crate::arch::x86_64::mem::memmmap;
use crate::arch::x86_64::model_dep::timemmap;
use crate::device::ds_routines::DevOps;
use crate::device::intr::irqgetstat;
use crate::device::kmsg::{kmsgclose, kmsggetstat, kmsgopen, kmsgread};
use crate::device::r#return::{DeviceError, DeviceSuccess, IoResult};

/// `/dev/time` open stub.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the device switch entry has this signature"
)]
const fn timeopen(_dev: DevT, _flag: c_int, _ior: *mut IoReq) -> IoResult {
    Ok(DeviceSuccess::Success)
}

/// `/dev/time` close stub.
const fn timeclose(_dev: DevT, _flag: c_int) {}

use crate::utils::cell::SyncCell;
use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_uint, c_ushort, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull};
use core::slice;

/// The operation vector and unit one indirect name stands for.
#[repr(C)]
#[allow(missing_docs)]
pub struct DevIndirect {
    pub d_name: *mut c_char,
    pub d_ops: *mut DevOps,
    pub d_unit: c_int,
}

const _: () = {
    assert!(size_of::<DevIndirect>() == 24);
    assert!(align_of::<DevIndirect>() == 8);
    assert!(core::mem::offset_of!(DevIndirect, d_name) == 0);
    assert!(core::mem::offset_of!(DevIndirect, d_ops) == 8);
    assert!(core::mem::offset_of!(DevIndirect, d_unit) == 16);
};

/// The number of entries in [`DEV_NAME_LIST`].
const DEV_NAME_COUNT: usize = 10;

/// The number of entries in [`DEV_INDIRECT_LIST`].
const DEV_INDIRECT_COUNT: usize = 1;

/// The reset of a device that needs none: succeeds.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the device switch entry has this signature"
)]
pub(crate) const fn nulldev_reset(_dev: DevT) -> Result<(), DeviceError> {
    Ok(())
}

/// The open of a device that needs none: succeeds.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the device switch entry has this signature"
)]
pub(crate) const fn nulldev_open(
    _dev: DevT,
    _flags: c_int,
    _ior: *mut IoReq,
) -> IoResult {
    Ok(DeviceSuccess::Success)
}

/// The close of a device that needs none.
pub(crate) const fn nulldev_close(_dev: DevT, _flags: c_int) {}

/// The read of a device with no data: succeeds.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the device switch entry has this signature"
)]
pub(crate) const fn nulldev_read(_dev: DevT, _ior: *mut IoReq) -> IoResult {
    Ok(DeviceSuccess::Success)
}

/// The write of a device that drops data: succeeds.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the device switch entry has this signature"
)]
pub(crate) const fn nulldev_write(_dev: DevT, _ior: *mut IoReq) -> IoResult {
    Ok(DeviceSuccess::Success)
}

/// The status read of a device with no status: succeeds.
pub(crate) const fn nulldev_getstat(
    _dev: DevT,
    _flavor: c_uint,
    _data: *mut c_int,
    _count: *mut c_uint,
) -> Result<(), DeviceError> {
    Err(DeviceError::InvalidOperation)
}

/// The status write of a device with no status: succeeds.
pub(crate) const fn nulldev_setstat(
    _dev: DevT,
    _flavor: c_uint,
    _data: *mut c_int,
    _count: c_uint,
) -> Result<(), DeviceError> {
    Err(DeviceError::InvalidOperation)
}

/// The port-death hook of a device that keeps no ports: claims nothing.
pub(crate) const fn nulldev_portdeath(_dev: DevT, _port: VmOffset) -> bool {
    false
}

/// The asynchronous input of a device without it: fails.
pub(crate) const fn nodev_async_in(
    _dev: DevT,
    _port: *mut c_void,
    _x: c_int,
    _filter: *mut c_ushort,
    _j: c_uint,
) -> Result<(), DeviceError> {
    Err(DeviceError::InvalidOperation)
}

/// The information call of a device without it: fails.
pub(crate) const fn nodev_info(
    _dev: DevT,
    _a: c_int,
    _b: *mut c_int,
) -> Result<(), DeviceError> {
    Err(DeviceError::InvalidOperation)
}

/// The mapping of a device that cannot be mapped: fails.
pub(crate) const fn nomap(
    _dev: DevT,
    _off: VmOffset,
    _prot: c_int,
) -> VmOffset {
    VmOffset::MAX
}

/// The major-device table [`lookup`] searches.  Slot 0 is the console
/// placeholder the console init fills through [`set_indirection`].
static DEV_NAME_LIST: SyncCell<[DevOps; DEV_NAME_COUNT]> =
    SyncCell(UnsafeCell::new([
        DevOps {
            d_name: c"cn".as_ptr().cast_mut(),
            d_open: Some(nulldev_open),
            d_close: Some(nulldev_close),
            d_read: Some(nulldev_read),
            d_write: Some(nulldev_write),
            d_getstat: Some(nulldev_getstat),
            d_setstat: Some(nulldev_setstat),
            d_mmap: Some(nomap),
            d_async_in: Some(nodev_async_in),
            d_reset: Some(nulldev_reset),
            d_port_death: Some(nulldev_portdeath),
            d_subdev: 0,
            d_dev_info: Some(nodev_info),
        },
        DevOps {
            d_name: c"kd".as_ptr().cast_mut(),
            d_open: Some(kdopen),
            d_close: Some(kdclose),
            d_read: Some(kdread),
            d_write: Some(kdwrite),
            d_getstat: Some(kdgetstat),
            d_setstat: Some(kdsetstat),
            d_mmap: Some(kdmmap),
            d_async_in: Some(nodev_async_in),
            d_reset: Some(nulldev_reset),
            d_port_death: Some(kdportdeath),
            d_subdev: 0,
            d_dev_info: Some(nodev_info),
        },
        DevOps {
            d_name: c"time".as_ptr().cast_mut(),
            d_open: Some(timeopen),
            d_close: Some(timeclose),
            d_read: Some(nulldev_read),
            d_write: Some(nulldev_write),
            d_getstat: Some(nulldev_getstat),
            d_setstat: Some(nulldev_setstat),
            d_mmap: Some(timemmap),
            d_async_in: Some(nodev_async_in),
            d_reset: Some(nulldev_reset),
            d_port_death: Some(nulldev_portdeath),
            d_subdev: 0,
            d_dev_info: Some(nodev_info),
        },
        DevOps {
            d_name: c"com".as_ptr().cast_mut(),
            d_open: Some(comopen),
            d_close: Some(comclose),
            d_read: Some(comread),
            d_write: Some(comwrite),
            d_getstat: Some(comgetstat),
            d_setstat: Some(comsetstat),
            d_mmap: Some(nomap),
            d_async_in: Some(nodev_async_in),
            d_reset: Some(nulldev_reset),
            d_port_death: Some(comportdeath),
            d_subdev: 0,
            d_dev_info: Some(nodev_info),
        },
        DevOps {
            d_name: c"mouse".as_ptr().cast_mut(),
            d_open: Some(mouseopen),
            d_close: Some(mouseclose),
            d_read: Some(mouseread),
            d_write: Some(nulldev_write),
            d_getstat: Some(mousegetstat),
            d_setstat: Some(nulldev_setstat),
            d_mmap: Some(nomap),
            d_async_in: Some(nodev_async_in),
            d_reset: Some(nulldev_reset),
            d_port_death: Some(nulldev_portdeath),
            d_subdev: 0,
            d_dev_info: Some(nodev_info),
        },
        DevOps {
            d_name: c"kbd".as_ptr().cast_mut(),
            d_open: Some(kbdopen),
            d_close: Some(kbdclose),
            d_read: Some(kbdread),
            d_write: Some(nulldev_write),
            d_getstat: Some(kbdgetstat),
            d_setstat: Some(kbdsetstat),
            d_mmap: Some(nomap),
            d_async_in: Some(nodev_async_in),
            d_reset: Some(nulldev_reset),
            d_port_death: Some(nulldev_portdeath),
            d_subdev: 0,
            d_dev_info: Some(nodev_info),
        },
        DevOps {
            d_name: c"mem".as_ptr().cast_mut(),
            d_open: Some(nulldev_open),
            d_close: Some(nulldev_close),
            d_read: Some(nulldev_read),
            d_write: Some(nulldev_write),
            d_getstat: Some(nulldev_getstat),
            d_setstat: Some(nulldev_setstat),
            d_mmap: Some(memmmap),
            d_async_in: Some(nodev_async_in),
            d_reset: Some(nulldev_reset),
            d_port_death: Some(nulldev_portdeath),
            d_subdev: 0,
            d_dev_info: Some(nodev_info),
        },
        DevOps {
            d_name: c"kmsg".as_ptr().cast_mut(),
            d_open: Some(kmsgopen),
            d_close: Some(kmsgclose),
            d_read: Some(kmsgread),
            d_write: Some(nulldev_write),
            d_getstat: Some(kmsggetstat),
            d_setstat: Some(nulldev_setstat),
            d_mmap: Some(nomap),
            d_async_in: Some(nodev_async_in),
            d_reset: Some(nulldev_reset),
            d_port_death: Some(nulldev_portdeath),
            d_subdev: 0,
            d_dev_info: Some(nodev_info),
        },
        DevOps {
            d_name: c"irq".as_ptr().cast_mut(),
            d_open: Some(nulldev_open),
            d_close: Some(nulldev_close),
            d_read: Some(nulldev_read),
            d_write: Some(nulldev_write),
            d_getstat: Some(irqgetstat),
            d_setstat: Some(nulldev_setstat),
            d_mmap: Some(nomap),
            d_async_in: Some(nodev_async_in),
            d_reset: Some(nulldev_reset),
            d_port_death: Some(nulldev_portdeath),
            d_subdev: 0,
            d_dev_info: Some(nodev_info),
        },
        DevOps {
            d_name: c"mbinfo".as_ptr().cast_mut(),
            d_open: Some(nulldev_open),
            d_close: Some(nulldev_close),
            d_read: Some(mbinforead),
            d_write: Some(nulldev_write),
            d_getstat: Some(nulldev_getstat),
            d_setstat: Some(nulldev_setstat),
            d_mmap: Some(nomap),
            d_async_in: Some(nodev_async_in),
            d_reset: Some(nulldev_reset),
            d_port_death: Some(nulldev_portdeath),
            d_subdev: 0,
            d_dev_info: Some(nodev_info),
        },
    ]));

/// The indirect-device table [`lookup`] falls back to.  The console init
/// rewrites the console entry's operations through [`set_indirection`].
static DEV_INDIRECT_LIST: SyncCell<[DevIndirect; DEV_INDIRECT_COUNT]> =
    SyncCell(UnsafeCell::new([DevIndirect {
        d_name: c"console".as_ptr().cast_mut(),
        d_ops: ptr::addr_of!(DEV_NAME_LIST.0).cast_mut().cast::<DevOps>(),
        d_unit: 0,
    }]));

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
pub(crate) unsafe fn name_equal(
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
pub(crate) unsafe fn lookup(
    name: *const c_char,
) -> Option<(NonNull<DevOps>, c_int)> {
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

    // SAFETY: the table is boot-initialized and only read from here.
    let first = DEV_NAME_LIST.0.get().cast::<DevOps>();
    for i in 0..DEV_NAME_COUNT {
        // SAFETY: `i` is inside the table.
        let dev = unsafe { first.add(i) };
        // SAFETY: the entry's name is a NUL-terminated string.
        if unsafe { name_equal(name, len, (*dev).d_name) } {
            // SAFETY: `dev` is a live table entry, never null.
            let dev = unsafe { NonNull::new_unchecked(dev) };
            // SAFETY: the name and the entry's fields are live.
            let unit =
                unsafe { subdev_unit(unit, (*dev.as_ptr()).d_subdev, c, cp) };
            return Some((dev, unit));
        }
    }

    // SAFETY: the table is boot-initialized and only read from here.
    let indirect = DEV_INDIRECT_LIST.0.get().cast::<DevIndirect>();
    for i in 0..DEV_INDIRECT_COUNT {
        // SAFETY: `i` is inside the table.
        let di = unsafe { indirect.add(i) };
        // SAFETY: the entry's name is a NUL-terminated string.
        if unsafe { name_equal(name, len, (*di).d_name) } {
            // SAFETY: the entry's operation vector is live.
            let ops = unsafe { NonNull::new((*di).d_ops)? };
            // SAFETY: `di` is a live table entry.
            return Some((ops, unsafe { (*di).d_unit }));
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
pub(crate) unsafe fn set_indirection(
    name: *const c_char,
    ops: *mut DevOps,
    unit: c_int,
) {
    // SAFETY: the table is boot-initialized and only written here.
    let list = DEV_INDIRECT_LIST.0.get().cast::<DevIndirect>();
    for i in 0..DEV_INDIRECT_COUNT {
        // SAFETY: `i` is inside the table.
        let di = unsafe { list.add(i) };
        // SAFETY: both names are NUL-terminated strings.
        if unsafe { CStr::from_ptr((*di).d_name) == CStr::from_ptr(name) } {
            // SAFETY: the lock-free update is the C's own; the table is
            // initialized at boot.
            unsafe {
                (*di).d_ops = ops;
                (*di).d_unit = unit;
            }
            break;
        }
    }
}
