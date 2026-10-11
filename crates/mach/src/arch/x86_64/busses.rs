// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The generic bus autoconfiguration, which `probeio()` runs at boot.
//!
//! The table it walks, `BUS_DEVICE_INIT`, lives in
//! [`autoconf`](crate::arch::x86_64::autoconf); [`BusDevice`] and
//! [`BusDriver`] are the records [`crate::arch::x86_64::com`] owns.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::com::{BusCtlr, BusDevice, BusDriver};
use crate::kern::console::{CStrArg, kprint};
use core::ffi::{CStr, c_char, c_int};
use core::ptr::{self, NonNull};

/// The `?` the tables use for an adaptor or controller any number matches.
const WILDCARD: c_char = b'?' as c_char;

/// The walk of `BUS_DEVICE_INIT`, which stops at its driver-less sentinel.
struct BusDevices {
    next: *mut BusDevice,
}

impl Iterator for BusDevices {
    type Item = (NonNull<BusDevice>, NonNull<BusDriver>);

    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: `next` starts at `BUS_DEVICE_INIT` and only steps inside it,
        // so every entry read, sentinel included, is initialized.
        let driver = unsafe { ptr::addr_of!((*self.next).driver).read() };
        let driver = NonNull::new(driver)?;
        let entry = NonNull::new(self.next)?;
        // SAFETY: the sentinel ends the array, so the step stays inside it.
        self.next = unsafe { self.next.add(1) };
        Some((entry, driver))
    }
}

fn devices() -> BusDevices {
    BusDevices {
        next: ptr::addr_of_mut!(
            crate::arch::x86_64::autoconf::BUS_DEVICE_INIT
        )
        .cast::<BusDevice>(),
    }
}

/// Finds and attaches the device `name` of the adaptor `adpt_no` on
/// `bus_name`, returning whether it was found.
pub(crate) fn configure_device(
    name: &CStr,
    virt: VmOffset,
    phys: VmOffset,
    adpt_no: c_int,
    bus_name: &CStr,
) -> bool {
    let Some((device, driver)) = devices().find(|(entry, _)| {
        // SAFETY: the walk only yields initialized `BUS_DEVICE_INIT` entries.
        let entry = unsafe { entry.as_ref() };
        if entry.alive != 0 {
            return false;
        }
        if entry.adaptor != WILDCARD && c_int::from(entry.adaptor) != adpt_no {
            return false;
        }
        if entry.slave != -1 {
            return false;
        }
        if entry.phys_address != 0
            && (entry.phys_address != phys || entry.address != virt)
        {
            return false;
        }
        // SAFETY: an initialized entry's `name` is NUL-terminated, and the
        // adapter promises the argument is.
        unsafe { CStr::from_ptr(entry.name) == name }
    }) else {
        return false;
    };
    let driver = driver.as_ptr();

    // SAFETY: `driver` is the non-null driver record the entry names.
    let probe = unsafe { (*driver).probe };
    let Some(probe) = probe else {
        // The C would call a null probe; a driver without one is a broken
        // table, not a found device.
        return false;
    };
    // SAFETY: `probe` is the driver's probe routine, which takes the device
    // entry as a controller: `BusCtlr` and `BusDevice` place `unit` and
    // `address` at the same offsets, which is all the AT-bus probe reads.
    if !unsafe { probe(virt, device.as_ptr().cast::<BusCtlr>()) } {
        return false;
    }

    // SAFETY: `device` is a live table entry.
    let (device_unit, device_name) = unsafe {
        let entry = device.as_ref();
        (entry.unit, entry.name)
    };
    let Ok(device_index) = usize::try_from(device_unit) else {
        return false;
    };

    // SAFETY: `device` is a live table entry.
    unsafe {
        let entry = device.as_ptr();
        (*entry).alive = 1;
        // The C stored the adaptor number in a `char`, truncating.
        (*entry).adaptor = adpt_no as c_char;
    }

    // SAFETY: the table's device name is NUL-terminated.
    kprint!(
        "{}{}: at {}{}",
        // SAFETY: the table's device name is NUL-terminated.
        unsafe { CStrArg::from_ptr(device_name.cast_const()) },
        device_unit,
        CStrArg::from(bus_name),
        adpt_no,
    );

    // SAFETY: `dinfo` is the driver's array of device slots.
    unsafe { (*driver).dinfo.add(device_index).write(device.as_ptr()) };

    // The C called `attach` unconditionally; a table without one leaves the
    // device unconfigured rather than calling a null pointer.
    // SAFETY: `driver` is the live driver record the entry names.
    if let Some(attach) = unsafe { (*driver).attach } {
        // SAFETY: `attach` is the driver's routine and `device` is the live
        // table entry the C passed it.
        unsafe { attach(device.as_ptr()) };
    }
    kprint!("\n");

    true
}
