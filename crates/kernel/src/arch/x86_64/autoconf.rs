// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386at/autoconf.c and i386/i386at/autoconf.h:
//   Copyright (c) 1993,1992,1991,1990,1989 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The AT-bus device tables and probe.

use crate::arch::types::VmOffset;
use crate::arch::x86_64::busses::configure_bus_device;
use crate::arch::x86_64::com::{BusCtlr, BusDevice, comintr};
use crate::arch::x86_64::{com, ioapic, irq};
use crate::kern::console::{CStrArg, kprint};
use core::ffi::{c_char, c_int, c_void};
use core::ptr;

/// The interrupt level the serial table records in `sysdep`.
const SPL_TTY: VmOffset = 6;

/// The `{0}` sentinel that ends each bus table.
const SENTINEL_DEVICE: BusDevice =
    // SAFETY: a zeroed `BusDevice` is a null driver and nothing else set.
    unsafe { core::mem::zeroed() };
const SENTINEL_CTLR: BusCtlr =
    // SAFETY: a zeroed `BusCtlr` is a null driver and nothing else set.
    unsafe { core::mem::zeroed() };

/// The AT-bus controller table, ended by a driver-less sentinel.
pub(crate) static mut BUS_MASTER_INIT: [BusCtlr; 1] = [SENTINEL_CTLR];

/// The AT-bus device table, ended by a driver-less sentinel.
pub(crate) static mut BUS_DEVICE_INIT: [BusDevice; 4] = [
    BusDevice {
        driver: ptr::addr_of_mut!(com::COMDRIVER),
        name: c"com".as_ptr().cast_mut(),
        unit: 0,
        intr: Some(comintr),
        address: 0x3f8,
        am: 8,
        phys_address: 0x3f8,
        adaptor: b'?' as c_char,
        alive: 0,
        ctlr: -1,
        slave: -1,
        flags: 0,
        mi: ptr::null_mut(),
        next: ptr::null_mut(),
        sysdep: SPL_TTY,
        sysdep1: 4,
    },
    BusDevice {
        driver: ptr::addr_of_mut!(com::COMDRIVER),
        name: c"com".as_ptr().cast_mut(),
        unit: 1,
        intr: Some(comintr),
        address: 0x2f8,
        am: 8,
        phys_address: 0x2f8,
        adaptor: b'?' as c_char,
        alive: 0,
        ctlr: -1,
        slave: -1,
        flags: 0,
        mi: ptr::null_mut(),
        next: ptr::null_mut(),
        sysdep: SPL_TTY,
        sysdep1: 3,
    },
    BusDevice {
        driver: ptr::addr_of_mut!(com::COMDRIVER),
        name: c"com".as_ptr().cast_mut(),
        unit: 2,
        intr: Some(comintr),
        address: 0x3e8,
        am: 8,
        phys_address: 0x3e8,
        adaptor: b'?' as c_char,
        alive: 0,
        ctlr: -1,
        slave: -1,
        flags: 0,
        mi: ptr::null_mut(),
        next: ptr::null_mut(),
        sysdep: SPL_TTY,
        sysdep1: 5,
    },
    SENTINEL_DEVICE,
];

/// The walk of [`BUS_MASTER_INIT`], until the driver-less sentinel.
struct BusMasters {
    next: *mut BusCtlr,
}

impl Iterator for BusMasters {
    type Item = *mut BusCtlr;

    fn next(&mut self) -> Option<*mut BusCtlr> {
        // SAFETY: every entry up to the sentinel is an initialized table
        // entry, and the sentinel's `driver` is null.
        let driver = unsafe { ptr::addr_of!((*self.next).driver).read() };
        if driver.is_null() {
            return None;
        }
        let current = self.next;
        // SAFETY: the sentinel terminates the array, so the step stays inside
        // the table.
        self.next = unsafe { self.next.add(1) };
        Some(current)
    }
}

fn bus_masters() -> BusMasters {
    BusMasters {
        next: ptr::addr_of_mut!(BUS_MASTER_INIT).cast::<BusCtlr>(),
    }
}

/// The walk of [`BUS_DEVICE_INIT`], until the driver-less sentinel.
pub(crate) struct BusDevices {
    next: *mut BusDevice,
}

impl Iterator for BusDevices {
    type Item = *mut BusDevice;

    fn next(&mut self) -> Option<*mut BusDevice> {
        // SAFETY: every entry up to the sentinel is an initialized table
        // entry, and the sentinel's `driver` is null.
        let driver = unsafe { ptr::addr_of!((*self.next).driver).read() };
        if driver.is_null() {
            return None;
        }
        let current = self.next;
        // SAFETY: the sentinel terminates the array, so the step stays inside
        // the table.
        self.next = unsafe { self.next.add(1) };
        Some(current)
    }
}

pub(crate) fn bus_devices() -> BusDevices {
    BusDevices {
        next: ptr::addr_of_mut!(BUS_DEVICE_INIT).cast::<BusDevice>(),
    }
}

/// Probes and attaches the AT-bus devices.
pub(crate) fn probeio() {
    let mut adapter = 0;
    for master in bus_masters() {
        // SAFETY: every entry up to the sentinel is an initialized `BusCtlr`,
        // and the sentinel ends the walk.
        let (name, address, phys) = unsafe {
            ((*master).name, (*master).address, (*master).phys_address)
        };
        // SAFETY: the C routine takes the entry's NUL-terminated name and the
        // literal bus name.
        if unsafe {
            crate::arch::x86_64::busses::configure_bus_master(
                name,
                address,
                phys,
                adapter,
                c"atbus".as_ptr(),
            )
        } {
            adapter += 1;
        }
    }

    for device in bus_devices() {
        // SAFETY: every entry up to the sentinel is an initialized
        // `BusDevice`, and the sentinel ends the walk.
        let (name, address, phys, alive, ctlr) = unsafe {
            (
                (*device).name,
                (*device).address,
                (*device).phys_address,
                (*device).alive,
                (*device).ctlr,
            )
        };
        if alive != 0 || ctlr >= 0 {
            continue;
        }
        // SAFETY: the C routine takes the entry's NUL-terminated name and
        // the literal bus name.
        if unsafe {
            configure_bus_device(
                name,
                address,
                phys,
                adapter,
                c"atbus".as_ptr(),
            )
        } {
            adapter += 1;
        }
    }
}

/// Binds `dev`'s interrupt to its line, or halts when another device already
/// holds it.
pub(crate) fn take_dev_irq(dev: &BusDevice) {
    // The table's `sysdep1` is an IRQ number below `NINTR`, so the narrowing
    // from `natural_t` cannot lose a bit.
    let pic = dev.sysdep1 as c_int;

    let handler = irq::handler(pic);
    let null_handler: unsafe extern "C" fn(c_int) = ioapic::intnull;
    let line_is_free =
        matches!(handler, Some(h) if ptr::fn_addr_eq(h, null_handler));

    if line_is_free {
        irq::set_unit(pic, dev.unit);
        irq::set_handler(pic, dev.intr);
    } else {
        let holder =
            handler.map_or_else(ptr::null, |handler| handler as *const c_void);
        kprint!(
            "The device below will clobber IRQ {} ({:x}).\n",
            pic,
            holder.expose_provenance(),
        );
        kprint!("You have two devices at the same IRQ.\n");
        kprint!(
            "This won't work.  Reconfigure your hardware and try again.\n"
        );
        // SAFETY: the device's name is NUL-terminated.
        kprint!(
            "{}{}: port = {:x}, spl = {}, pic = {}.\n",
            // SAFETY: the device's name is NUL-terminated.
            unsafe { CStrArg::from_ptr(dev.name.cast_const()) },
            dev.unit,
            dev.address,
            dev.sysdep,
            dev.sysdep1,
        );
        loop {
            core::hint::spin_loop();
        }
    }

    ioapic::unmask(pic);
}
