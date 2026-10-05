// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from i386/i386at/mbinfo.c:
//   Copyright (c) 2024 Free Software Foundation, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! `/dev/mbinfo`: `mbinfo.c`'s raw multiboot information device.

use crate::arch::x86_64::io_req::{DevT, IoReq};
use crate::arch::x86_64::multiboot::MultibootRawInfo;
use crate::device::ds_routines::device_read_alloc;
use crate::device::r#return::{DeviceError, DeviceSuccess, IoResult};
use crate::utils::cell::SyncCell;
use core::cell::UnsafeCell;
use core::ffi::c_long;
use core::mem::size_of;
use core::ptr;

/// The block the boot loader passed and the one `/dev/mbinfo` serves.
static MB_INFO: SyncCell<MultibootRawInfo> =
    // SAFETY: `MultibootRawInfo` is plain old data, so all-zeroes is valid.
    SyncCell(UnsafeCell::new(unsafe { core::mem::zeroed() }));

/// Keep the boot loader's multiboot information block.
///
/// # Safety
///
/// Called once by `src/arch/x86_64/model_dep.rs` with the block the loader left.
pub(crate) unsafe fn mbinfo_register_boot_data(mbi: *const MultibootRawInfo) {
    let info = unsafe { *mbi };
    // SAFETY: the boot path is single-threaded and runs before any read.
    unsafe { *MB_INFO.0.get() = info };
}

/// `mbinforead()` in C.
///
/// # Safety
///
/// Called from the `/dev/mbinfo` device switch in `conf.c`; `ior` must be the
/// request the device layer passed.
pub(crate) unsafe fn mbinforead(_dev: DevT, ior: *mut IoReq) -> IoResult {
    // SAFETY: the device layer owns the request for this call.
    let ior = unsafe { &mut *ior };
    let count = ior.count();
    if count > size_of::<MultibootRawInfo>() as c_long {
        return Err(DeviceError::InvalidSize);
    }
    // SAFETY: `count` bytes fit the info block, checked above.
    unsafe { device_read_alloc(ptr::from_mut::<IoReq>(ior), count as usize) }?;
    // SAFETY: the request now has a buffer of `count` bytes, and the info
    // block is at least that large.
    unsafe {
        ptr::copy_nonoverlapping(
            MB_INFO.0.get().cast::<u8>(),
            ior.data().cast::<u8>(),
            count as usize,
        );
    };
    ior.set_residual(0);
    Ok(DeviceSuccess::Success)
}
