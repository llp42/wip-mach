// SPDX-License-Identifier: CMU-Mach
// Derived from chips/busses.c:
//   Copyright (c) 1993-1989 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The generic bus autoconfiguration, which `probeio()` runs at boot.
//!
//! The tables it walks, `BUS_MASTER_INIT` and `BUS_DEVICE_INIT`, live in
//! [`autoconf`](crate::arch::x86_64::autoconf); [`BusCtlr`], [`BusDevice`] and
//! [`BusDriver`] are the records [`crate::arch::x86_64::com`] owns.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::com::{BusCtlr, BusDevice, BusDriver};
use crate::kern::console::{CStrArg, kprint};
use core::ffi::{CStr, c_char, c_int};
use core::ptr::{self, NonNull};

/// The `?` the tables use for an adaptor or controller any number matches.
const WILDCARD: c_char = b'?' as c_char;

/// The walk of `BUS_MASTER_INIT`, which stops at its driver-less sentinel.
struct BusMasters {
    next: *mut BusCtlr,
}

impl Iterator for BusMasters {
    type Item = (NonNull<BusCtlr>, NonNull<BusDriver>);

    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: `next` starts at `BUS_MASTER_INIT` and only steps inside it,
        // so every entry read, sentinel included, is initialized.
        let driver = unsafe { ptr::addr_of!((*self.next).driver).read() };
        let driver = NonNull::new(driver)?;
        let entry = NonNull::new(self.next)?;
        // SAFETY: the sentinel ends the array, so the step stays inside it.
        self.next = unsafe { self.next.add(1) };
        Some((entry, driver))
    }
}

fn masters() -> BusMasters {
    BusMasters {
        next: ptr::addr_of_mut!(
            crate::arch::x86_64::autoconf::BUS_MASTER_INIT
        )
        .cast::<BusCtlr>(),
    }
}

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

/// Probes and attaches the devices of one found controller.
fn configure_master_devices(
    driver: *mut BusDriver,
    master: NonNull<BusCtlr>,
    virt: VmOffset,
    adpt_no: c_int,
    master_unit: c_int,
) {
    // SAFETY: `driver` is the live driver record the caller's master names.
    let (slave, mname, dinfo) =
        unsafe { ((*driver).slave, (*driver).mname, (*driver).dinfo) };

    for (device, device_driver) in devices() {
        // SAFETY: the walk only yields initialized `BUS_DEVICE_INIT` entries.
        let (alive, adaptor, ctlr, device_unit, device_name, device_slave) = unsafe {
            let entry = device.as_ref();
            (
                entry.alive,
                entry.adaptor,
                entry.ctlr,
                entry.unit,
                entry.name,
                entry.slave,
            )
        };
        if alive != 0
            || device_driver.as_ptr() != driver
            || (adaptor != WILDCARD && c_int::from(adaptor) != adpt_no)
        {
            continue;
        }
        let Ok(device_index) = usize::try_from(device_unit) else {
            continue;
        };

        if ctlr == WILDCARD {
            // The C stored the controller number in a `char`, truncating.
            // SAFETY: `device` is a live table entry.
            unsafe { (*device.as_ptr()).ctlr = master_unit as c_char };
        }
        // The C would call a null slave; a missing routine cannot report a
        // slave.
        // SAFETY: `device` is a live table entry.
        let probed = c_int::from(unsafe { (*device.as_ptr()).ctlr })
            == master_unit
            && slave.is_some_and(|slave| {
                // SAFETY: `slave` is the driver's routine and `device` is a
                // live table entry.
                unsafe { slave(device.as_ptr(), virt) }
            });
        if !probed {
            // SAFETY: `device` is a live table entry.
            unsafe { (*device.as_ptr()).ctlr = ctlr };
            continue;
        }

        // SAFETY: `device` is a live table entry, `master` its live
        // controller, and `dinfo` the driver's array of device slots.
        unsafe {
            let entry = device.as_ptr();
            (*entry).alive = 1;
            // The C stored the adaptor number in a `char`, truncating.
            (*entry).adaptor = adpt_no as c_char;
            // The C stored the controller number in a `char`, truncating.
            (*entry).ctlr = master_unit as c_char;
            (*entry).mi = master.as_ptr();
            dinfo.add(device_index).write(entry);
        }

        if c_int::from(device_slave) >= 0 {
            // SAFETY: the table's device name is NUL-terminated.
            kprint!(
                " {}{}: at {}{} slave {}",
                // SAFETY: the table's device name is NUL-terminated.
                unsafe { CStrArg::from_ptr(device_name.cast_const()) },
                device_unit,
                // SAFETY: the driver's name is NUL-terminated.
                unsafe { CStrArg::from_ptr(mname.cast_const()) },
                master_unit,
                c_int::from(device_slave),
            );
        } else {
            // SAFETY: the table's device name is NUL-terminated.
            kprint!(
                " {}{}: at {}{}",
                // SAFETY: the table's device name is NUL-terminated.
                unsafe { CStrArg::from_ptr(device_name.cast_const()) },
                device_unit,
                // SAFETY: the driver's name is NUL-terminated.
                unsafe { CStrArg::from_ptr(mname.cast_const()) },
                master_unit,
            );
        }

        // The C called `attach` unconditionally; a table without one leaves
        // the device unconfigured rather than calling a null pointer.
        // SAFETY: `driver` is the live driver record the entry names.
        if let Some(attach) = unsafe { (*driver).attach } {
            // SAFETY: `attach` is the driver's routine and `device` is the
            // live table entry the C passed it.
            unsafe { attach(device.as_ptr()) };
        }
        kprint!("\n");
    }
}

/// Finds and attaches the controller `name` of the adaptor `adpt_no` on
/// `bus_name`, then its devices, returning whether it was found.
fn configure_master(
    name: &CStr,
    virt: VmOffset,
    adpt_no: c_int,
    bus_name: &CStr,
) -> bool {
    let Some((master, driver)) = masters().find(|(entry, _)| {
        // SAFETY: the walk only yields initialized `BUS_MASTER_INIT` entries.
        let entry = unsafe { entry.as_ref() };
        if entry.alive != 0 {
            return false;
        }
        if entry.adaptor != WILDCARD && c_int::from(entry.adaptor) != adpt_no {
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
        // table, not a found controller.
        return false;
    };
    // SAFETY: `probe` is the driver's probe routine, and `master` is the
    // live table entry the C passed it.
    if !unsafe { probe(virt, master.as_ptr()) } {
        return false;
    }

    // SAFETY: `master` is a live table entry.
    let (master_name, master_unit) = unsafe {
        let entry = master.as_ref();
        (entry.name, entry.unit)
    };
    let Ok(master_index) = usize::try_from(master_unit) else {
        return false;
    };

    // SAFETY: `master` is a live table entry, `driver` its live driver, and
    // `master_index` the slot the driver's `minfo` has for it.
    unsafe {
        let entry = master.as_ptr();
        (*entry).alive = 1;
        // The C stored the adaptor number in a `char`, truncating.
        (*entry).adaptor = adpt_no as c_char;
        (*driver).minfo.add(master_index).write(entry);
    }

    // SAFETY: the table's controller name is NUL-terminated.
    kprint!(
        "{}{}: at {}{}\n",
        // SAFETY: the table's controller name is NUL-terminated.
        unsafe { CStrArg::from_ptr(master_name.cast_const()) },
        master_unit,
        CStrArg::from(bus_name),
        adpt_no,
    );

    configure_master_devices(driver, master, virt, adpt_no, master_unit);

    true
}

/// Finds and attaches the device `name` of the adaptor `adpt_no` on
/// `bus_name`, returning whether it was found.
fn configure_device(
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

/// [`configure_master`] over NUL-terminated names.
///
/// # Safety
///
/// `name` and `bus_name` must point at NUL-terminated strings.
pub(crate) unsafe fn configure_bus_master(
    name: *const c_char,
    virt: VmOffset,
    _phys: VmOffset,
    adpt_no: c_int,
    bus_name: *const c_char,
) -> bool {
    let (name, bus_name) =
        unsafe { (CStr::from_ptr(name), CStr::from_ptr(bus_name)) };
    configure_master(name, virt, adpt_no, bus_name)
}

/// [`configure_device`] over NUL-terminated names.
///
/// # Safety
///
/// `name` and `bus_name` must point at NUL-terminated strings.
pub(crate) unsafe fn configure_bus_device(
    name: *const c_char,
    virt: VmOffset,
    phys: VmOffset,
    adpt_no: c_int,
    bus_name: *const c_char,
) -> bool {
    let (name, bus_name) =
        unsafe { (CStr::from_ptr(name), CStr::from_ptr(bus_name)) };
    configure_device(name, virt, phys, adpt_no, bus_name)
}
