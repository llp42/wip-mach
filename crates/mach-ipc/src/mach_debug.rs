// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The mach-debug kernel calls.

use crate::error::Error;
use crate::ipc_marequest;
use crate::ipc_object;
use crate::ipc_right;
use crate::platform::Platform;
use crate::types::PortType;
use crate::{IpcPort, IpcSpace};
use core::ffi::c_uint;
use core::mem::size_of;
use core::ptr::with_exposed_provenance_mut;
use mach_vm::param::VmOffset;
use mach_vm::types::HashInfoBucket;
use mach_vm::vm_kern::{kmem_alloc_pageable, kmem_free};
use mach_vm::vm_map::round_page;

/// The receive-right type a debug call asks for.
const MACH_PORT_RIGHT_RECEIVE: c_uint = 1;
/// The null port name.
const MACH_PORT_NULL: c_uint = 0;

/// A table count as an index; `usize` is at least 32 bits on both targets,
/// so the widening is lossless.
const fn as_index(count: c_uint) -> usize {
    count as usize
}

/// The send-right count of the receive right `name` names.
///
/// # Safety
///
/// `space` must be null or live and unlocked; nothing may be locked.
pub unsafe fn get_srights<P: Platform>(
    space: Option<IpcSpace>,
    name: c_uint,
) -> Result<c_uint, Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    let port = unsafe {
        ipc_object::translate::<P>(space, name, MACH_PORT_RIGHT_RECEIVE)
    }?;
    // SAFETY: the translation returned a live port.
    let port = unsafe { IpcPort::from_raw(port) };

    // SAFETY: the port is live and locked.
    let srights = unsafe { port.srights() };
    unsafe { port.unlock() };

    Ok(srights)
}

/// The bucket occupancy of the message-accepted request table, as
/// `host_ipc_marequest_info()` reports it.
///
/// # Safety
///
/// `maxp` and `countp` must be writable storage for one count, and `infop`
/// for one bucket-array pointer.  The caller permits an allocation and a
/// kernel-map copy.
pub unsafe fn marequest_info<P: Platform>(
    maxp: *mut c_uint,
    infop: *mut *mut HashInfoBucket,
    countp: *mut c_uint,
) -> Result<(), Error> {
    let initial = unsafe { *infop };
    let mut info = initial;
    let mut potential = unsafe { *countp };
    let mut addr: VmOffset = 0;
    let mut size: VmOffset = 0;

    let kernel_map = P::state().ipc_kernel_map();

    let actual = loop {
        let actual = unsafe { ipc_marequest::info(maxp, info, potential) };
        if actual <= potential {
            break actual;
        }

        if info != initial {
            // SAFETY: `info` came from the kernel-map allocation below.
            let _ = unsafe { kmem_free(&mut *kernel_map, addr, size) };
        }

        size = round_page(as_index(actual) * size_of::<HashInfoBucket>());
        // SAFETY: the kernel map is live, nothing is locked, and the caller
        // permits an allocation.
        match unsafe { kmem_alloc_pageable(&mut *kernel_map, size) } {
            Ok(allocated) => addr = allocated,
            Err(_) => return Err(Error::ResourceShortage),
        }
        info = with_exposed_provenance_mut(addr);
        // The C divided the same `vm_size_t` and assigned to an
        // `unsigned int`; the size is a small multiple of the bucket record.
        potential = (size / size_of::<HashInfoBucket>()) as c_uint;
    };

    if info == initial {
        // The data fit in-line; nothing to deallocate.
        unsafe { *countp = actual };
        return Ok(());
    }

    if actual == 0 {
        // SAFETY: the region came from the kernel-map allocation above.
        let _ = unsafe { kmem_free(&mut *kernel_map, addr, size) };
        unsafe { *countp = 0 };
        return Ok(());
    }

    let used = round_page(as_index(actual) * size_of::<HashInfoBucket>());
    if used != size {
        // SAFETY: the tail of the region came from the same allocation.
        let _ =
            unsafe { kmem_free(&mut *kernel_map, addr + used, size - used) };
    }

    // SAFETY: the region is live in the kernel map, the map is unlocked, and
    // the caller permits the copy.
    if let Ok(copy) = unsafe { (*kernel_map).copyin(addr, used, true) } {
        unsafe { *infop = copy.as_ptr().cast() };
    }
    // The C stored a copy the failed call left uninitialized; the region
    // was just mapped, so the failure is unreachable and the out-pointer
    // stays as the caller left it rather than taking a garbage value.
    unsafe { *countp = actual };

    Ok(())
}

/// The size and use of the dead-name request table of the receive right `name`
/// names.
///
/// # Safety
///
/// `space` must be null or live and unlocked; nothing may be locked.
pub unsafe fn dnrequest_info<P: Platform>(
    space: Option<IpcSpace>,
    name: c_uint,
) -> Result<(c_uint, c_uint), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    let port = unsafe {
        ipc_object::translate::<P>(space, name, MACH_PORT_RIGHT_RECEIVE)
    }?;
    // SAFETY: the translation returned a live port.
    let port = unsafe { IpcPort::from_raw(port) };

    // SAFETY: the port is live and locked.
    let dnrequests = unsafe { port.dnrequests() };
    let (total, used) = if dnrequests.is_null() {
        (0, 0)
    } else {
        // SAFETY: a non-null table's element zero holds the size record.
        let total = unsafe { (*(*dnrequests).size()).its_size };
        let mut used: c_uint = 0;

        for index in 1..total {
            // SAFETY: `total` is the table's size, so `index` is in bounds.
            let request = unsafe { dnrequests.add(as_index(index)) };
            // SAFETY: the slot is inside the live table.
            if unsafe { (*request).name() } != MACH_PORT_NULL {
                used = used.wrapping_add(1);
            }
        }

        (total, used)
    };

    // SAFETY: the port is live and locked.
    unsafe { port.unlock() };

    Ok((total, used))
}

/// The kernel-object type and object address of the port `name` names.
///
/// # Safety
///
/// `space` must be null or live and unlocked; nothing may be locked.
pub unsafe fn mach_port_kernel_object<P: Platform>(
    space: Option<IpcSpace>,
    name: c_uint,
) -> Result<(c_uint, VmOffset), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    let entry = unsafe { ipc_right::lookup_write::<P>(space, name) }?;

    // SAFETY: the entry is live and the space is write-locked.
    if !unsafe { (*entry).bits() }
        .type_
        .intersects(PortType::SEND_RECEIVE)
    {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write::<P>() };
        return Err(Error::InvalidRight);
    }

    // SAFETY: a typed entry names a live port.
    let port = unsafe { IpcPort::from_raw((*entry).object()) };
    // SAFETY: the port is live and unlocked.
    unsafe { port.lock() };
    // SAFETY: the space lock is held.
    unsafe { space.unlock_write::<P>() };

    // SAFETY: the port is live and locked.
    if !unsafe { port.is_active() } {
        // SAFETY: the port is live and locked.
        unsafe { port.unlock() };
        return Err(Error::InvalidRight);
    }

    // SAFETY: the port is live and locked.
    let object_type = unsafe { port.kotype() };
    let object_addr = unsafe { port.kobject() }.addr();
    unsafe { port.unlock() };

    Ok((object_type, object_addr))
}
