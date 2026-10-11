// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The machine's device tables: the drivers each device name opens.

use crate::arch::x86_64::com::{
    comclose, comgetstat, comopen, comread, comsetstat, comwrite,
};
use crate::arch::x86_64::kd::tty::{
    kdclose, kdgetstat, kdmmap, kdopen, kdread, kdsetstat, kdwrite,
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
use crate::device::intr::irqgetstat;
use crate::device::kmsg::{kmsgclose, kmsggetstat, kmsgopen, kmsgread};
use crate::device::{DevIndirect, DevOps, IoReq};
use core::ffi::c_int;
use core::ptr;
use core::sync::atomic::{AtomicI32, AtomicPtr};
use mach_device::dev_name::{
    nodev_async_in, nodev_info, nomap, nulldev_close, nulldev_getstat,
    nulldev_open, nulldev_read, nulldev_setstat, nulldev_write,
};
use mach_device::io_req::DevT;
use mach_device::r#return::{DeviceSuccess, IoResult};

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

/// The number of entries in [`DEV_NAME_LIST`].
pub(crate) const DEV_NAME_COUNT: usize = 10;

/// The number of entries in [`DEV_INDIRECT_LIST`].
pub(crate) const DEV_INDIRECT_COUNT: usize = 1;

/// The major-device table [`lookup`] searches.  Slot 0 is the console
/// placeholder the console init fills through [`set_indirection`].
///
/// [`lookup`]: mach_device::dev_name::lookup
/// [`set_indirection`]: mach_device::dev_name::set_indirection
pub(crate) static DEV_NAME_LIST: [DevOps; DEV_NAME_COUNT] = [
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
        d_subdev: 0,
        d_dev_info: Some(nodev_info),
    },
];

/// The indirect-device table [`lookup`] falls back to.  The console init
/// rewrites the console entry's operations through [`set_indirection`].
///
/// [`lookup`]: mach_device::dev_name::lookup
/// [`set_indirection`]: mach_device::dev_name::set_indirection
pub(crate) static DEV_INDIRECT_LIST: [DevIndirect; DEV_INDIRECT_COUNT] =
    [DevIndirect {
        d_name: c"console".as_ptr(),
        d_ops: AtomicPtr::new(ptr::addr_of!(DEV_NAME_LIST[0]).cast_mut()),
        d_unit: AtomicI32::new(0),
    }];
