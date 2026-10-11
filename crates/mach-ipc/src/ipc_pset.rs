// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The port-set routines.

use crate::error::Error;
use crate::ipc_mqueue;
use crate::ipc_object;
use crate::ipc_target;
use crate::ipc_thread::IpcWait;
use crate::platform::Platform;
use crate::types::PortType;
use crate::{IOT_PORT_SET, IpcPort, IpcSpace, IpcTarget};
use core::ffi::c_uint;
use core::ptr::{self, NonNull};

/// The port-set object type, as `ipc_object::alloc` takes it.
const IOT_PORT_SET_OBJECT: c_uint = IOT_PORT_SET as c_uint;

/// Allocates a port set in `space` under a fresh name.
///
/// # Safety
///
/// `space` must be live and nothing may be locked; may allocate memory.  On
/// success the returned set is locked and the caller does not hold a
/// reference.
pub(crate) unsafe fn alloc<P: Platform>(
    space: IpcSpace,
) -> Result<(c_uint, *mut IpcTarget), Error> {
    let (name, object) = unsafe {
        ipc_object::alloc::<P>(
            space,
            IOT_PORT_SET_OBJECT,
            PortType::PORT_SET,
            0,
        )
    }?;
    let pset = object.cast::<IpcTarget>();

    // SAFETY: the fresh, locked object is a port set; this initializes it as
    // the C did.
    unsafe { ipc_target::init(pset, name) };
    Ok((name, pset))
}

/// Allocates a port set in `space` under `name`.
///
/// # Safety
///
/// `space` must be live and nothing may be locked; may allocate memory.  On
/// success the returned set is locked and the caller does not hold a
/// reference.
pub(crate) unsafe fn alloc_name<P: Platform>(
    space: IpcSpace,
    name: c_uint,
) -> Result<*mut IpcTarget, Error> {
    let object = unsafe {
        ipc_object::alloc_name::<P>(
            space,
            IOT_PORT_SET_OBJECT,
            PortType::PORT_SET,
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

/// Adds `port` to `pset`.
///
/// # Safety
///
/// `pset` and `port` must be live and locked, the port must not be in a set,
/// and the set's owner must be the port's receiver.
pub(crate) unsafe fn add<P: Platform>(pset: *mut IpcTarget, port: IpcPort) {
    unsafe {
        port.set_pset(pset.cast());
        port.set_cur_target(pset);
        IpcTarget::increment_references(pset);

        let port_queue = port.messages();
        let pset_queue = (*pset).messages();

        (*port_queue).lock();
        (*pset_queue).lock();

        ipc_mqueue::move_messages::<P>(pset_queue, port_queue, port);

        (*pset_queue).unlock();
        ipc_mqueue::changed::<P>(port_queue, IpcWait::PortChanged);
        (*port_queue).unlock();
    }
}

/// Removes `port` from `pset`.
///
/// # Safety
///
/// `pset` and `port` must be live and locked, and the port must be active and
/// a member of the set.
pub(crate) unsafe fn remove<P: Platform>(pset: *mut IpcTarget, port: IpcPort) {
    unsafe {
        port.set_pset(ptr::null_mut());
        port.set_cur_target(port.record().cast::<IpcTarget>());
        IpcTarget::decrement_references(pset);

        let port_queue = port.messages();
        let pset_queue = (*pset).messages();

        (*port_queue).lock();
        (*pset_queue).lock();

        ipc_mqueue::move_messages::<P>(port_queue, pset_queue, port);

        (*pset_queue).unlock();
        (*port_queue).unlock();
    }
}

/// Moves `port` into `nset`, or out of its set when `nset` is `None`.
///
/// # Safety
///
/// `space` must be live and write-locked, and `port` live with `nset` either
/// `None` or a live port set.
pub(crate) unsafe fn move_between<P: Platform>(
    space: IpcSpace,
    port: IpcPort,
    nset: Option<NonNull<IpcTarget>>,
) -> Result<(), Error> {
    unsafe { port.lock() };

    // SAFETY: the port is live and locked.
    let mut oset = NonNull::new(unsafe { port.pset() }.cast::<IpcTarget>());

    match (oset, nset) {
        (None, None) => {
            unsafe { space.unlock_write::<P>() };
        }
        (Some(old), Some(new)) if old == new => {
            unsafe { space.unlock_write::<P>() };
        }
        (None, Some(nset)) => {
            // SAFETY: a non-null `nset` names a live port set.
            unsafe { (*nset.as_ptr()).lock() };
            unsafe { space.unlock_write::<P>() };

            // SAFETY: both are live, active, and locked.
            unsafe { add::<P>(nset.as_ptr(), port) };

            // SAFETY: the set is live and locked.
            unsafe { (*nset.as_ptr()).unlock() };
        }
        (Some(old), None) => {
            unsafe { space.unlock_write::<P>() };
            // SAFETY: the old set holds a reference for the port.
            unsafe { (*old.as_ptr()).lock() };

            // SAFETY: both are live and locked.
            unsafe { remove::<P>(old.as_ptr(), port) };

            // SAFETY: the set is live and locked after the removal.
            if unsafe { (*old.as_ptr()).is_active() } {
                // SAFETY: the set is live and locked.
                unsafe { (*old.as_ptr()).unlock() };
            } else {
                // SAFETY: the set is live and locked, and `remove` consumed
                // the port's reference to it.
                unsafe { IpcTarget::check_unlock::<P>(old.as_ptr()) };
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

            unsafe { space.unlock_write::<P>() };

            // SAFETY: both sets and the port are live and locked; the port
            // cannot be inactive, so the old set stays live through the
            // reference the port holds.
            unsafe {
                remove::<P>(old.as_ptr(), port);
                add::<P>(new.as_ptr(), port);
                (*new.as_ptr()).unlock();
                IpcTarget::check_unlock::<P>(old.as_ptr());
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

/// Destroys `pset`, removing its member ports.
///
/// # Safety
///
/// `pset` must be a live, locked, active port set, and the caller's reference
/// is consumed; on return the set is unlocked and dead.
pub(crate) unsafe fn destroy<P: Platform>(pset: *mut IpcTarget) {
    unsafe {
        IpcTarget::clear_active(pset);

        let mqueue = (*pset).messages();
        (*mqueue).lock();
        ipc_mqueue::changed::<P>(mqueue, IpcWait::PortDied);
        (*mqueue).unlock();

        IpcTarget::decrement_references(pset);
        IpcTarget::check_unlock::<P>(pset);
    }
}
