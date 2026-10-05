// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_pset.c and ipc/ipc_pset.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The port-set routines, which `ipc/ipc_pset.c` used to define and
//! `ipc/ipc_pset.h` declares.

use crate::ipc::error::Error;
use crate::ipc::ipc_mqueue;
use crate::ipc::ipc_object;
use crate::ipc::ipc_target;
use crate::ipc::ipc_thread::IpcWait;
use crate::ipc::{
    IOT_PORT_SET, IpcPort, IpcSpace, IpcTarget, MACH_PORT_TYPE_PORT_SET,
};
use core::ffi::c_uint;
use core::ptr::{self, NonNull};

/// `IOT_PORT_SET` of <`ipc/ipc_object.h`> as `ipc_object_alloc()` takes it.
const IOT_PORT_SET_OBJECT: c_uint = IOT_PORT_SET as c_uint;

/// `ipc_pset_alloc()` in C.
///
/// # Safety
///
/// `space` must be live and nothing may be locked; may allocate memory.  On
/// success the returned set is locked and the caller does not hold a
/// reference.
pub(crate) unsafe fn alloc(
    space: IpcSpace,
) -> Result<(c_uint, *mut IpcTarget), Error> {
    let (name, object) = unsafe {
        ipc_object::alloc(
            space,
            IOT_PORT_SET_OBJECT,
            MACH_PORT_TYPE_PORT_SET,
            0,
        )
    }?;
    let pset = object.cast::<IpcTarget>();

    // SAFETY: the fresh, locked object is a port set; this initializes it as
    // the C did.
    unsafe { ipc_target::init(pset, name) };
    Ok((name, pset))
}

/// `ipc_pset_alloc_name()` in C.
///
/// # Safety
///
/// `space` must be live and nothing may be locked; may allocate memory.  On
/// success the returned set is locked and the caller does not hold a
/// reference.
pub(crate) unsafe fn alloc_name(
    space: IpcSpace,
    name: c_uint,
) -> Result<*mut IpcTarget, Error> {
    let object = unsafe {
        ipc_object::alloc_name(
            space,
            IOT_PORT_SET_OBJECT,
            MACH_PORT_TYPE_PORT_SET,
            0,
            name,
        )
    }?;
    let pset = object.cast::<IpcTarget>();

    // SAFETY: the fresh, locked object is a port set; this initializes it as
    // the C did.
    unsafe { ipc_target::init(pset, name) };
    Ok(pset)
}

/// `ipc_pset_add()` in C.
///
/// # Safety
///
/// `pset` and `port` must be live and locked, the port must not be in a set,
/// and the set's owner must be the port's receiver.
pub(crate) unsafe fn add(pset: *mut IpcTarget, port: IpcPort) {
    unsafe {
        port.set_pset(pset.cast());
        port.set_cur_target(pset);
        IpcTarget::increment_references(pset);

        let port_queue = port.messages();
        let pset_queue = (*pset).messages();

        (*port_queue).lock();
        (*pset_queue).lock();

        ipc_mqueue::move_messages(pset_queue, port_queue, port);

        (*pset_queue).unlock();
        ipc_mqueue::changed(port_queue, IpcWait::PortChanged);
        (*port_queue).unlock();
    }
}

/// `ipc_pset_remove()` in C.
///
/// # Safety
///
/// `pset` and `port` must be live and locked, and the port must be active and
/// a member of the set.
pub(crate) unsafe fn remove(pset: *mut IpcTarget, port: IpcPort) {
    unsafe {
        port.set_pset(ptr::null_mut());
        port.set_cur_target(port.record().cast::<IpcTarget>());
        IpcTarget::decrement_references(pset);

        let port_queue = port.messages();
        let pset_queue = (*pset).messages();

        (*port_queue).lock();
        (*pset_queue).lock();

        ipc_mqueue::move_messages(port_queue, pset_queue, port);

        (*pset_queue).unlock();
        (*port_queue).unlock();
    }
}

/// `ipc_pset_move()` in C.
///
/// # Safety
///
/// `space` must be live and read-locked, and `port` live with `nset` either
/// `None` or a live port set.
pub(crate) unsafe fn move_between(
    space: IpcSpace,
    port: IpcPort,
    nset: Option<NonNull<IpcTarget>>,
) -> Result<(), Error> {
    unsafe { port.lock() };

    // SAFETY: the port is live and locked.
    let mut oset = NonNull::new(unsafe { port.pset() }.cast::<IpcTarget>());

    match (oset, nset) {
        (None, None) => {
            unsafe { space.lock_done() };
        }
        (Some(old), Some(new)) if old == new => {
            unsafe { space.lock_done() };
        }
        (None, Some(nset)) => {
            // SAFETY: a non-null `nset` names a live port set.
            unsafe { (*nset.as_ptr()).lock() };
            unsafe { space.lock_done() };

            // SAFETY: both are live, active, and locked.
            unsafe { add(nset.as_ptr(), port) };

            // SAFETY: the set is live and locked.
            unsafe { (*nset.as_ptr()).unlock() };
        }
        (Some(old), None) => {
            unsafe { space.lock_done() };
            // SAFETY: the old set holds a reference for the port.
            unsafe { (*old.as_ptr()).lock() };

            // SAFETY: both are live and locked.
            unsafe { remove(old.as_ptr(), port) };

            // SAFETY: the set is live and locked after the removal.
            if unsafe { (*old.as_ptr()).is_active() } {
                // SAFETY: the set is live and locked.
                unsafe { (*old.as_ptr()).unlock() };
            } else {
                // SAFETY: the set is live and locked, and `remove` consumed
                // the port's reference to it.
                unsafe { IpcTarget::check_unlock(old.as_ptr()) };
                oset = None;
            }
        }
        (Some(old), Some(new)) => {
            // The C locks the two sets in address order so concurrent moves
            // cannot deadlock.
            if old.addr() < new.addr() {
                // SAFETY: both are live port sets with a reference held
                // through the space or the port.
                unsafe {
                    (*old.as_ptr()).lock();
                    (*new.as_ptr()).lock();
                }
            } else {
                unsafe {
                    (*new.as_ptr()).lock();
                    (*old.as_ptr()).lock();
                }
            }

            unsafe { space.lock_done() };

            // SAFETY: both sets and the port are live and locked; the port
            // cannot be inactive, so the old set stays live through the
            // reference the port holds.
            unsafe {
                remove(old.as_ptr(), port);
                add(new.as_ptr(), port);
                (*new.as_ptr()).unlock();
                IpcTarget::check_unlock(old.as_ptr());
            }
        }
    }

    // SAFETY: the port is live and locked.
    unsafe { port.unlock() };

    if nset.is_none() && oset.is_none() {
        Err(Error::NotInSet)
    } else {
        Ok(())
    }
}

/// `ipc_pset_destroy()` in C.
///
/// # Safety
///
/// `pset` must be a live, locked, active port set, and the caller's reference
/// is consumed; on return the set is unlocked and dead.
pub(crate) unsafe fn destroy(pset: *mut IpcTarget) {
    unsafe {
        IpcTarget::clear_active(pset);

        let mqueue = (*pset).messages();
        (*mqueue).lock();
        ipc_mqueue::changed(mqueue, IpcWait::PortDied);
        (*mqueue).unlock();

        ipc_target::terminate(pset);

        IpcTarget::decrement_references(pset);
        IpcTarget::check_unlock(pset);
    }
}
