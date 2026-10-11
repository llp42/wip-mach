// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The capability-manipulation routines.

use crate::error::Error;
use crate::ipc_entry;
use crate::ipc_marequest;
use crate::ipc_notify;
use crate::ipc_object;
use crate::ipc_port;
use crate::ipc_pset;
use crate::platform::Platform;
use crate::types::{EntryBits, PortType};
use crate::{IO_DEAD, IpcEntry, IpcPort, IpcSpace, IpcTarget};
use core::ffi::{c_int, c_uint, c_void};
use core::ptr::{self, NonNull};

/// The null port name.
const MACH_PORT_NULL: c_uint = 0;
/// The most user references an entry may hold.
const MACH_PORT_UREFS_MAX: u32 = (1 << 16) - 1;

/// The right number of a send right.
const MACH_PORT_RIGHT_SEND: c_uint = 0;
/// The right number of a receive right.
const MACH_PORT_RIGHT_RECEIVE: c_uint = 1;
/// The right number of a send-once right.
const MACH_PORT_RIGHT_SEND_ONCE: c_uint = 2;
/// The right number of a port set.
const MACH_PORT_RIGHT_PORT_SET: c_uint = 3;
/// The right number of a dead name.
const MACH_PORT_RIGHT_DEAD_NAME: c_uint = 4;

/// The disposition that moves a receive right.
const MACH_MSG_TYPE_MOVE_RECEIVE: c_uint = 16;
/// The disposition that moves a send right.
const MACH_MSG_TYPE_MOVE_SEND: c_uint = 17;
/// The disposition that moves a send-once right.
const MACH_MSG_TYPE_MOVE_SEND_ONCE: c_uint = 18;
/// The disposition that copies a send right.
const MACH_MSG_TYPE_COPY_SEND: c_uint = 19;
/// The disposition that makes a send right from a receive right.
const MACH_MSG_TYPE_MAKE_SEND: c_uint = 20;
/// The disposition that makes a send-once right from a receive right.
const MACH_MSG_TYPE_MAKE_SEND_ONCE: c_uint = 21;

/// The C `default: panic()` arm of a rights switch.
fn strange_rights(fun: &'static str, message: &'static str) -> ! {
    panic!("{fun}: {message}")
}

/// Whether adding the signed `delta` to `urefs` overflows the count, decided
/// on the wrapping sum.
const fn urefs_overflow(urefs: u16, delta: c_int) -> bool {
    if delta <= 0 {
        return false;
    }

    // The positive delta converts exactly.
    let urefs = urefs as u32;
    let sum = urefs.wrapping_add(delta as u32);
    sum <= urefs || sum > MACH_PORT_UREFS_MAX
}

/// Whether adding the negative `delta` to `urefs` underflows the count.
const fn urefs_underflow(urefs: u16, delta: c_int) -> bool {
    // The negated delta is positive except at `c_int::MIN`, whose bit pattern
    // still compares greater than any 16-bit count.
    delta < 0 && delta.wrapping_neg() as u32 > urefs as u32
}

/// Finds the entry `name` names in `space`, leaving the space write-locked.
///
/// # Safety
///
/// `space` must be live and unlocked.  On success the space is write-locked
/// and the returned entry is live.
pub(crate) unsafe fn lookup_write<P: Platform>(
    space: IpcSpace,
    name: c_uint,
) -> Result<*mut IpcEntry, Error> {
    unsafe { space.lock_write::<P>() };

    if !unsafe { space.is_active::<P>() } {
        unsafe { space.unlock_write::<P>() };
        return Err(Error::DeadSpace);
    }

    // SAFETY: the space is live and write-locked.
    let Some(entry) = (unsafe { space.entry_lookup::<P>(name) }) else {
        unsafe { space.unlock_write::<P>() };
        return Err(Error::InvalidName);
    };

    Ok(entry)
}

/// Finds the name and entry under which `space` holds a receive or send right
/// to the port `object`, leaving the port locked.
///
/// # Safety
///
/// The space must be live and locked for reading or writing, and `object`
/// must be a live port.
pub(crate) unsafe fn reverse<P: Platform>(
    space: IpcSpace,
    object: *mut c_void,
) -> Option<(c_uint, *mut IpcEntry)> {
    let port = unsafe { IpcPort::from_raw(object) };

    unsafe { port.lock() };
    // SAFETY: the port lock is held.
    if !unsafe { port.is_active() } {
        // SAFETY: the port lock is held.
        unsafe { port.unlock() };
        return None;
    }

    // SAFETY: the port lock is held.
    if unsafe { port.receiver() } == space.as_ptr() {
        // SAFETY: the port lock is held.
        let name = unsafe { port.receiver_name() };

        let entry = unsafe { space.entry_lookup::<P>(name) }
            .unwrap_or(ptr::null_mut());

        return Some((name, entry));
    }

    let Some(entry) = (unsafe { space.reverse_lookup::<P>(port.as_ptr()) })
    else {
        // SAFETY: the port lock is held; nothing was found for it.
        unsafe { port.unlock() };
        return None;
    };
    // SAFETY: a reverse-map result is a live entry.
    let name = unsafe { (*entry).name() };

    Some((name, entry))
}

/// Registers a dead-name request for `name` in `space`, returning the
/// previously registered send-once right.
///
/// # Safety
///
/// `space` must be live and unlocked; `notify` must be `IP_NULL` or a live
/// send-once right the call consumes on success.
pub(crate) unsafe fn dnrequest<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    immediate: bool,
    notify: Option<NonNull<c_void>>,
) -> Result<*mut c_void, Error> {
    loop {
        let entry = unsafe { lookup_write::<P>(space, name) }?;
        // SAFETY: the lookup returned a live entry.
        let mut bits = unsafe { (*entry).bits() };

        if bits.type_.intersects(PortType::PORT_RIGHTS) {
            // SAFETY: a port-rights entry names a live port.
            let port = unsafe { IpcPort::from_raw((*entry).object()) };

            // SAFETY: the space is write-locked and the entry is live; the
            // port is unlocked.
            if !unsafe { check::<P>(space, port, name, entry) } {
                // The port is locked and active.

                let Some(notify) = notify else {
                    // SAFETY: the port is live and locked.
                    let previous =
                        unsafe { dncancel_if_requested(port, entry) };
                    // SAFETY: the port lock is held.
                    unsafe { port.unlock() };
                    // SAFETY: the space lock is held.
                    unsafe { space.unlock_write::<P>() };
                    return Ok(previous);
                };

                // SAFETY: the port is live and locked.
                let previous = unsafe { dncancel_if_requested(port, entry) };

                // SAFETY: the port is live, locked, and active.
                if let Ok(request) =
                    // SAFETY: the port is live, locked, and active.
                    unsafe { ipc_port::dnrequest(port, name, notify) }
                {
                    // SAFETY: the port lock is held.
                    unsafe { port.unlock() };
                    // SAFETY: the entry is live.
                    unsafe { (*entry).set_request(request) };
                    // SAFETY: the space lock is held.
                    unsafe { space.unlock_write::<P>() };
                    return Ok(previous);
                }
                // SAFETY: the space lock is held.
                unsafe { space.unlock_write::<P>() };

                // SAFETY: the port is live and locked; `dngrow`
                // unlocks it and reports why it could not grow.
                unsafe { ipc_port::dngrow::<P>(port) }?;
                continue;
            }

            // SAFETY: the entry is live.
            bits = unsafe { (*entry).bits() };
        }

        if bits.type_.intersects(PortType::DEAD_NAME)
            && immediate
            && let Some(notify) = notify
        {
            if urefs_overflow(bits.urefs, 1) {
                // SAFETY: the space lock is held.
                unsafe { space.unlock_write::<P>() };
                return Err(Error::UrefsOverflow);
            }

            // SAFETY: the entry is live and the space lock is held.
            unsafe {
                (*entry).set_bits(EntryBits {
                    urefs: bits.urefs.wrapping_add(1),
                    ..bits
                });
            }
            // SAFETY: the space lock is held.
            unsafe { space.unlock_write::<P>() };

            unsafe { ipc_notify::dead_name::<P>(notify.as_ptr(), name) };
            return Ok(ptr::null_mut());
        }

        // SAFETY: the space lock is held.
        unsafe { space.unlock_write::<P>() };

        return if bits.type_.intersects(PortType::PORT_OR_DEAD) {
            Err(Error::InvalidArgument)
        } else {
            Err(Error::InvalidRight)
        };
    }
}

/// Cancels the entry's dead-name request and returns the registered send-once
/// right.
///
/// # Safety
///
/// `port` must be live and locked, and `entry`'s request index must name a
/// live request in the port's table.
pub(crate) unsafe fn dncancel(
    port: IpcPort,
    entry: *mut IpcEntry,
) -> *mut c_void {
    let request = unsafe { (*entry).request() };
    unsafe { (*entry).set_request(0) };

    unsafe { ipc_port::dncancel(port, request) }
}

/// Cancels the entry's dead-name request when it holds one, returning its
/// send-once right, or null.
///
/// # Safety
///
/// `port` must be live and locked, and `entry` must be a live entry of the
/// write-locked space.
unsafe fn dncancel_if_requested(
    port: IpcPort,
    entry: *mut IpcEntry,
) -> *mut c_void {
    if unsafe { (*entry).request() } == 0 {
        return ptr::null_mut();
    }

    unsafe { dncancel(port, entry) }
}

/// Whether `entry` is in use; when it is, the space is unlocked.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `entry` a live entry
/// of it.
pub(crate) unsafe fn inuse<P: Platform>(
    space: IpcSpace,
    entry: *mut IpcEntry,
) -> bool {
    let bits = unsafe { (*entry).bits() };

    if bits.type_ != PortType::NONE {
        unsafe { space.unlock_write::<P>() };
        return true;
    }

    false
}

/// Whether the port behind `entry` died; when it did, the entry becomes a dead
/// name.
///
/// # Safety
///
/// The space must be write-locked.  On success the port is dead and converted
/// to a dead name; otherwise the port is live and locked.
pub(crate) unsafe fn check<P: Platform>(
    space: IpcSpace,
    port: IpcPort,
    name: c_uint,
    entry: *mut IpcEntry,
) -> bool {
    unsafe { port.lock() };
    if unsafe { port.is_active() } {
        return false;
    }
    unsafe { port.unlock() };

    // SAFETY: the entry is live.
    let mut bits = unsafe { (*entry).bits() };

    if bits.type_.intersects(PortType::SEND) {
        if bits.marequest {
            bits.marequest = false;

            unsafe { ipc_marequest::cancel(space, name) };
        }

        let _ = unsafe { space.reverse_remove::<P>(port.as_ptr()) };
    }

    // SAFETY: the port is dead, so its lock is free; this drops its reference.
    unsafe { port.release::<P>() };

    bits.type_ = PortType::DEAD_NAME;

    // SAFETY: the entry is live.
    if unsafe { (*entry).request() } != 0 {
        // SAFETY: the entry is live.
        unsafe {
            (*entry).set_request(0);
            (*entry).set_bits(EntryBits {
                urefs: bits.urefs.wrapping_add(1),
                ..bits
            });
            (*entry).set_object(ptr::null_mut());
        }
    } else {
        // SAFETY: the entry is live.
        unsafe { (*entry).set_bits(bits) };
        // SAFETY: the entry is live.
        unsafe { (*entry).set_object(ptr::null_mut()) };
    }

    true
}

/// Releases a dead space's entry.
///
/// # Safety
///
/// `entry` must be a live entry of a dead, unlocked space.
pub(crate) unsafe fn clean<P: Platform>(name: c_uint, entry: *mut IpcEntry) {
    let bits = unsafe { (*entry).bits() };
    let type_ = bits.type_;

    match type_ {
        PortType::DEAD_NAME => (),

        PortType::PORT_SET => {
            // SAFETY: a typed port-set entry names a live port set.
            let pset = unsafe { (*entry).object() };
            // SAFETY: the pset is live.
            let target = pset.cast::<IpcTarget>();
            // SAFETY: the pset is live and unlocked.
            unsafe { (*target).lock() };

            // SAFETY: the port set is live and locked; the destroy consumes
            // the entry's reference and unlocks.
            unsafe { ipc_pset::destroy::<P>(pset.cast::<IpcTarget>()) };
        }

        PortType::SEND
        | PortType::RECEIVE
        | PortType::SEND_RECEIVE
        | PortType::SEND_ONCE => {
            // SAFETY: a port-rights entry names a live port.
            let port = unsafe { IpcPort::from_raw((*entry).object()) };

            // SAFETY: the port is live and unlocked.
            unsafe { port.lock() };

            // SAFETY: the port lock is held.
            if !unsafe { port.is_active() } {
                // SAFETY: the port is dead and its lock is held; dropping the
                // reference and `check_unlock` release it.
                unsafe {
                    port.decrement_references();
                    port.check_unlock::<P>();
                }
                return;
            }

            // SAFETY: the port is live and locked.
            let dnrequest = unsafe { dncancel_if_requested(port, entry) };

            let mut nsrequest = None;
            let mut mscount = 0;

            if type_.intersects(PortType::SEND) {
                // SAFETY: the port is live and locked.
                unsafe { port.decrement_srights() };
                // SAFETY: the port lock is held.
                if unsafe { port.srights() } == 0 {
                    // SAFETY: the port lock is held.
                    nsrequest = unsafe { port.nsrequest() };
                    if nsrequest.is_some() {
                        // SAFETY: the port is live and locked.
                        unsafe { port.set_nsrequest(None) };
                        // SAFETY: the port lock is held.
                        mscount = unsafe { port.mscount() };
                    }
                }
            }

            if type_.intersects(PortType::RECEIVE) {
                // SAFETY: the port is live and locked.
                unsafe { ipc_port::clear_receiver::<P>(port) };
                // SAFETY: the port is live and locked; the destroy consumes
                // the entry's reference and unlocks.
                unsafe { ipc_port::destroy::<P>(port) };
            } else if type_.intersects(PortType::SEND_ONCE) {
                // SAFETY: the port lock is held.
                unsafe { port.unlock() };

                // SAFETY: the notifications consume the send-once right.
                unsafe { ipc_notify::send_once::<P>(port.as_non_null()) };
            } else {
                // SAFETY: the port is live and its lock is held; the release
                // consumes the entry's reference.
                unsafe {
                    port.decrement_references();
                    port.unlock();
                }
            }

            if let Some(nsrequest) = nsrequest {
                // SAFETY: a nonzero no-senders request is a live send-once
                // right.
                unsafe { ipc_notify::no_senders::<P>(nsrequest, mscount) };
            }

            if !dnrequest.is_null() {
                // SAFETY: a nonzero dead-name request is a live send-once
                // right.
                unsafe { ipc_notify::port_deleted::<P>(dnrequest, name) };
            }
        }

        _ => {
            strange_rights("ipc_right_clean", "ipc_right_clean: strange type")
        }
    }
}

/// Destroys the right `entry` holds under `name` in `space`.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `entry` a live entry
/// of it.  The space is unlocked on return.
pub(crate) unsafe fn destroy<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
) {
    let bits = unsafe { (*entry).bits() };
    let type_ = bits.type_;

    match type_ {
        PortType::DEAD_NAME => {
            unsafe { ipc_entry::dealloc::<P>(space, name, entry) };
            // SAFETY: the space lock is held.
            unsafe { space.unlock_write::<P>() };
        }

        PortType::PORT_SET => {
            // SAFETY: a typed port-set entry names a live port set.
            let pset = unsafe { (*entry).object() };

            // SAFETY: the entry is live and the space lock is held.
            unsafe {
                (*entry).set_object(ptr::null_mut());
                ipc_entry::dealloc::<P>(space, name, entry);
            }

            // SAFETY: the pset is live.
            let target = pset.cast::<IpcTarget>();
            // SAFETY: the pset is live and unlocked.
            unsafe { (*target).lock() };
            // SAFETY: the space lock is held.
            unsafe { space.unlock_write::<P>() };

            // SAFETY: the port set is live and locked; the destroy consumes
            // the entry's reference and unlocks.
            unsafe { ipc_pset::destroy::<P>(pset.cast::<IpcTarget>()) };
        }

        PortType::SEND
        | PortType::RECEIVE
        | PortType::SEND_RECEIVE
        | PortType::SEND_ONCE => {
            // SAFETY: a port-rights entry names a live port.
            let port = unsafe { IpcPort::from_raw((*entry).object()) };

            if bits.marequest {
                unsafe { ipc_marequest::cancel(space, name) };
            }

            if type_ == PortType::SEND {
                let _ = unsafe { space.reverse_remove::<P>(port.as_ptr()) };
            }

            // SAFETY: the port is live and unlocked.
            unsafe { port.lock() };

            // SAFETY: the port lock is held.
            if !unsafe { port.is_active() } {
                // SAFETY: the port is dead and its lock is held; dropping the
                // reference and `check_unlock` release it, and the entry is
                // freed under the space lock.
                unsafe {
                    port.decrement_references();
                    port.check_unlock::<P>();
                    (*entry).set_request(0);
                    (*entry).set_object(ptr::null_mut());
                    ipc_entry::dealloc::<P>(space, name, entry);
                    space.unlock_write::<P>();
                }
                return;
            }

            // SAFETY: the port is live and locked.
            let dnrequest = unsafe { dncancel_if_requested(port, entry) };

            // SAFETY: the entry is live and the space lock is held.
            unsafe {
                (*entry).set_object(ptr::null_mut());
                ipc_entry::dealloc::<P>(space, name, entry);
                space.unlock_write::<P>();
            }

            let mut nsrequest = None;
            let mut mscount = 0;

            if type_.intersects(PortType::SEND) {
                // SAFETY: the port is live and locked.
                unsafe { port.decrement_srights() };
                // SAFETY: the port lock is held.
                if unsafe { port.srights() } == 0 {
                    // SAFETY: the port lock is held.
                    nsrequest = unsafe { port.nsrequest() };
                    if nsrequest.is_some() {
                        // SAFETY: the port is live and locked.
                        unsafe { port.set_nsrequest(None) };
                        // SAFETY: the port lock is held.
                        mscount = unsafe { port.mscount() };
                    }
                }
            }

            if type_.intersects(PortType::RECEIVE) {
                // SAFETY: the port is live and locked.
                unsafe { ipc_port::clear_receiver::<P>(port) };
                // SAFETY: the port is live and locked; the destroy consumes
                // the entry's reference and unlocks.
                unsafe { ipc_port::destroy::<P>(port) };
            } else if type_.intersects(PortType::SEND_ONCE) {
                // SAFETY: the port lock is held.
                unsafe { port.unlock() };

                // SAFETY: the notifications consume the send-once right.
                unsafe { ipc_notify::send_once::<P>(port.as_non_null()) };
            } else {
                // SAFETY: the port is live and its lock is held; the release
                // consumes the entry's reference.
                unsafe {
                    port.decrement_references();
                    port.unlock();
                }
            }

            if let Some(nsrequest) = nsrequest {
                // SAFETY: a nonzero no-senders request is a live send-once
                // right.
                unsafe { ipc_notify::no_senders::<P>(nsrequest, mscount) };
            }

            if !dnrequest.is_null() {
                // SAFETY: a nonzero dead-name request is a live send-once
                // right.
                unsafe { ipc_notify::port_deleted::<P>(dnrequest, name) };
            }
        }

        _ => strange_rights(
            "ipc_right_destroy",
            "ipc_right_destroy: strange type",
        ),
    }
}

/// Releases one user reference to the dead name `entry` holds.
///
/// # Safety
///
/// The space must be write-locked, active, and live, and `entry` a live entry
/// of it whose type is `MACH_PORT_TYPE_DEAD_NAME`.
unsafe fn dealloc_dead_name<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
    bits: EntryBits,
) {
    if bits.urefs == 1 {
        unsafe { ipc_entry::dealloc::<P>(space, name, entry) };
    } else {
        unsafe {
            (*entry).set_bits(EntryBits {
                urefs: bits.urefs.wrapping_sub(1),
                ..bits
            });
        }
    }

    unsafe { space.unlock_write::<P>() };
}

/// Releases one user reference to the send, send-once or dead-name right
/// `entry` holds.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `entry` a live entry
/// of it.  The space is unlocked on return.
pub(crate) unsafe fn dealloc<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
) -> Result<(), Error> {
    let mut bits = unsafe { (*entry).bits() };
    let type_ = bits.type_;

    match type_ {
        PortType::DEAD_NAME => {
            unsafe { dealloc_dead_name::<P>(space, name, entry, bits) };
            Ok(())
        }

        PortType::SEND_ONCE => {
            unsafe { dealloc_send_once::<P>(space, name, entry) };
            Ok(())
        }

        PortType::SEND => {
            // SAFETY: a send entry names a live port.
            let port = unsafe { IpcPort::from_raw((*entry).object()) };

            // SAFETY: the space is write-locked and the entry is live.
            if unsafe { check::<P>(space, port, name, entry) } {
                // SAFETY: the check converted the entry to a dead name.
                bits = unsafe { (*entry).bits() };
                // SAFETY: the entry is a live dead name.
                unsafe { dealloc_dead_name::<P>(space, name, entry, bits) };
                return Ok(());
            }

            // The port is locked and active.

            let mut dnrequest = ptr::null_mut();
            let mut nsrequest = None;
            let mut mscount = 0;

            if bits.urefs == 1 {
                // SAFETY: the port is live and locked.
                unsafe { port.decrement_srights() };
                // SAFETY: the port lock is held.
                if unsafe { port.srights() } == 0 {
                    // SAFETY: the port lock is held.
                    nsrequest = unsafe { port.nsrequest() };
                    if nsrequest.is_some() {
                        // SAFETY: the port is live and locked.
                        unsafe { port.set_nsrequest(None) };
                        // SAFETY: the port lock is held.
                        mscount = unsafe { port.mscount() };
                    }
                }

                // SAFETY: the port is live and locked.
                dnrequest = unsafe { dncancel_if_requested(port, entry) };

                let _ = unsafe { space.reverse_remove::<P>(port.as_ptr()) };

                if bits.marequest {
                    unsafe { ipc_marequest::cancel(space, name) };
                }

                // SAFETY: the port is live and its lock is held; the release
                // consumes the entry's reference.
                unsafe { port.decrement_references() };
                // SAFETY: the entry is live and the space lock is held.
                unsafe {
                    (*entry).set_object(ptr::null_mut());
                    ipc_entry::dealloc::<P>(space, name, entry);
                }
            } else {
                unsafe {
                    (*entry).set_bits(EntryBits {
                        urefs: bits.urefs.wrapping_sub(1),
                        ..bits
                    });
                }
            }

            // SAFETY: the port is live and its lock is held.
            unsafe { port.unlock() };
            // SAFETY: the space lock is held.
            unsafe { space.unlock_write::<P>() };

            if let Some(nsrequest) = nsrequest {
                // SAFETY: a nonzero no-senders request is a live send-once
                // right.
                unsafe { ipc_notify::no_senders::<P>(nsrequest, mscount) };
            }

            if !dnrequest.is_null() {
                // SAFETY: a nonzero dead-name request is a live send-once
                // right.
                unsafe { ipc_notify::port_deleted::<P>(dnrequest, name) };
            }

            Ok(())
        }

        PortType::SEND_RECEIVE => {
            // SAFETY: a send-receive entry names a live port.
            let port = unsafe { IpcPort::from_raw((*entry).object()) };

            // SAFETY: the port is live and unlocked.
            unsafe { port.lock() };

            let mut nsrequest = None;
            let mut mscount = 0;

            if bits.urefs == 1 {
                // SAFETY: the port is live and locked.
                unsafe { port.decrement_srights() };
                // SAFETY: the port lock is held.
                if unsafe { port.srights() } == 0 {
                    // SAFETY: the port lock is held.
                    nsrequest = unsafe { port.nsrequest() };
                    if nsrequest.is_some() {
                        // SAFETY: the port is live and locked.
                        unsafe { port.set_nsrequest(None) };
                        // SAFETY: the port lock is held.
                        mscount = unsafe { port.mscount() };
                    }
                }

                unsafe {
                    (*entry).set_bits(EntryBits {
                        type_: bits.type_.difference(PortType::SEND),
                        urefs: 0,
                        ..bits
                    });
                }
            } else {
                unsafe {
                    (*entry).set_bits(EntryBits {
                        urefs: bits.urefs.wrapping_sub(1),
                        ..bits
                    });
                }
            }

            // SAFETY: the port lock is held.
            unsafe { port.unlock() };
            // SAFETY: the space lock is held.
            unsafe { space.unlock_write::<P>() };

            if let Some(nsrequest) = nsrequest {
                // SAFETY: a nonzero no-senders request is a live send-once
                // right.
                unsafe { ipc_notify::no_senders::<P>(nsrequest, mscount) };
            }

            Ok(())
        }

        _ => {
            // SAFETY: the space lock is held.
            unsafe { space.unlock_write::<P>() };
            Err(Error::InvalidRight)
        }
    }
}

/// The `MACH_PORT_TYPE_SEND_ONCE` arm of [`dealloc()`].
///
/// # Safety
///
/// The same contract as [`dealloc()`]: the space must be live, active, and
/// write-locked, and `entry` a live send-once entry of it; the space is
/// unlocked on return.
unsafe fn dealloc_send_once<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
) {
    // SAFETY: a send-once entry names a live port.
    let port = unsafe { IpcPort::from_raw((*entry).object()) };

    // SAFETY: the space is write-locked and the entry is live.
    if unsafe { check::<P>(space, port, name, entry) } {
        // SAFETY: the check converted the entry to a dead name.
        let bits = unsafe { (*entry).bits() };
        // SAFETY: the entry is a live dead name.
        unsafe { dealloc_dead_name::<P>(space, name, entry, bits) };
        return;
    }

    // The port is locked and active.

    // SAFETY: the port is live and locked.
    let dnrequest = unsafe { dncancel_if_requested(port, entry) };
    // SAFETY: the port lock is held.
    unsafe { port.unlock() };

    // SAFETY: the entry is live and the space lock is held.
    unsafe {
        (*entry).set_object(ptr::null_mut());
        ipc_entry::dealloc::<P>(space, name, entry);
        space.unlock_write::<P>();
    }

    // SAFETY: the notification consumes the send-once right (or its
    // reference).
    unsafe { ipc_notify::send_once::<P>(port.as_non_null()) };

    if !dnrequest.is_null() {
        // SAFETY: a nonzero dead-name request is a live send-once right.
        unsafe { ipc_notify::port_deleted::<P>(dnrequest, name) };
    }
}

/// Adds `delta` to the user references of `right` in `entry`, destroying the
/// right when they reach zero.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `entry` a live entry
/// of it.  The space is unlocked on return.
pub(crate) unsafe fn delta<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
    right: c_uint,
    delta: c_int,
) -> Result<(), Error> {
    let mut bits = unsafe { (*entry).bits() };

    match right {
        MACH_PORT_RIGHT_PORT_SET => {
            if !bits.type_.intersects(PortType::PORT_SET) {
                // SAFETY: the space lock is held.
                unsafe { space.unlock_write::<P>() };
                return Err(Error::InvalidRight);
            }

            if delta == 0 {
                // SAFETY: the space lock is held.
                unsafe { space.unlock_write::<P>() };
                return Ok(());
            }

            if delta != -1 {
                // SAFETY: the space lock is held.
                unsafe { space.unlock_write::<P>() };
                return Err(Error::InvalidValue);
            }

            // SAFETY: a typed port-set entry names a live port set.
            let pset = unsafe { (*entry).object() };

            // SAFETY: the entry is live and the space lock is held.
            unsafe {
                (*entry).set_object(ptr::null_mut());
                ipc_entry::dealloc::<P>(space, name, entry);
            }

            // SAFETY: the pset is live.
            let target = pset.cast::<IpcTarget>();
            // SAFETY: the pset is live and unlocked.
            unsafe { (*target).lock() };
            // SAFETY: the space lock is held.
            unsafe { space.unlock_write::<P>() };

            // SAFETY: the port set is live and locked; the destroy consumes
            // the entry's reference and unlocks.
            unsafe { ipc_pset::destroy::<P>(pset.cast::<IpcTarget>()) };

            Ok(())
        }

        MACH_PORT_RIGHT_RECEIVE => {
            if !bits.type_.intersects(PortType::RECEIVE) {
                // SAFETY: the space lock is held.
                unsafe { space.unlock_write::<P>() };
                return Err(Error::InvalidRight);
            }

            if delta == 0 {
                // SAFETY: the space lock is held.
                unsafe { space.unlock_write::<P>() };
                return Ok(());
            }

            if delta != -1 {
                // SAFETY: the space lock is held.
                unsafe { space.unlock_write::<P>() };
                return Err(Error::InvalidValue);
            }

            if bits.marequest {
                bits.marequest = false;

                unsafe { ipc_marequest::cancel(space, name) };
            }

            // SAFETY: a receive entry names a live port.
            let port = unsafe { IpcPort::from_raw((*entry).object()) };

            // SAFETY: the port is live and unlocked.
            unsafe { port.lock() };

            let mut dnrequest = ptr::null_mut();

            if bits.type_.intersects(PortType::SEND) {
                bits.type_ = PortType::DEAD_NAME;

                if unsafe { (*entry).request() } != 0 {
                    unsafe { (*entry).set_request(0) };
                    bits = EntryBits {
                        urefs: bits.urefs.wrapping_add(1),
                        ..bits
                    };
                }

                // SAFETY: the entry is live and the port is locked.
                unsafe {
                    (*entry).set_bits(bits);
                    (*entry).set_object(ptr::null_mut());
                }
            } else {
                // SAFETY: the port is live and locked.
                dnrequest = unsafe { dncancel_if_requested(port, entry) };

                // SAFETY: the entry is live and the space lock is held.
                unsafe {
                    (*entry).set_object(ptr::null_mut());
                    ipc_entry::dealloc::<P>(space, name, entry);
                }
            }

            // SAFETY: the space lock is held.
            unsafe { space.unlock_write::<P>() };

            // SAFETY: the port is live and locked.
            unsafe { ipc_port::clear_receiver::<P>(port) };
            // SAFETY: the port is live and locked; the destroy consumes the
            // entry's reference and unlocks.
            unsafe { ipc_port::destroy::<P>(port) };

            if !dnrequest.is_null() {
                // SAFETY: a nonzero dead-name request is a live send-once
                // right.
                unsafe { ipc_notify::port_deleted::<P>(dnrequest, name) };
            }

            Ok(())
        }

        MACH_PORT_RIGHT_SEND_ONCE => unsafe {
            delta_send_once::<P>(space, name, entry, bits, delta)
        },

        MACH_PORT_RIGHT_DEAD_NAME => unsafe {
            delta_dead_name::<P>(space, name, entry, bits, delta)
        },

        MACH_PORT_RIGHT_SEND => unsafe {
            delta_send::<P>(space, name, entry, bits, delta)
        },

        _ => {
            strange_rights("ipc_right_delta", "ipc_right_delta: strange right")
        }
    }
}

/// The `MACH_PORT_RIGHT_SEND` arm of [`delta()`].
///
/// # Safety
///
/// The same contract as [`delta()`]: the space must be live, active, and
/// write-locked, and `entry` a live send-rights entry of it; the space is
/// unlocked on return.
unsafe fn delta_send<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
    bits: EntryBits,
    delta: c_int,
) -> Result<(), Error> {
    if !bits.type_.intersects(PortType::SEND) {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write::<P>() };
        return Err(Error::InvalidRight);
    }

    // The maximum user-reference count for a send right is one short of
    // `MACH_PORT_UREFS_MAX`.
    let urefs = bits.urefs;
    if urefs_underflow(urefs, delta) {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write::<P>() };
        return Err(Error::InvalidValue);
    }

    if urefs_overflow(urefs.wrapping_add(1), delta) {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write::<P>() };
        return Err(Error::UrefsOverflow);
    }

    // SAFETY: a send entry names a live port.
    let port = unsafe { IpcPort::from_raw((*entry).object()) };

    // SAFETY: the space is write-locked and the entry is live.
    if unsafe { check::<P>(space, port, name, entry) } {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write::<P>() };
        return Err(Error::InvalidRight);
    }

    // The port is locked and active.

    let mut dnrequest = ptr::null_mut();
    let mut nsrequest = None;
    let mut mscount = 0;

    if i32::from(urefs).wrapping_add(delta) == 0 {
        // SAFETY: the port is live and locked.
        unsafe { port.decrement_srights() };
        // SAFETY: the port lock is held.
        if unsafe { port.srights() } == 0 {
            // SAFETY: the port lock is held.
            nsrequest = unsafe { port.nsrequest() };
            if nsrequest.is_some() {
                // SAFETY: the port is live and locked.
                unsafe { port.set_nsrequest(None) };
                // SAFETY: the port lock is held.
                mscount = unsafe { port.mscount() };
            }
        }

        if bits.type_.intersects(PortType::RECEIVE) {
            unsafe {
                (*entry).set_bits(EntryBits {
                    type_: bits.type_.difference(PortType::SEND),
                    urefs: 0,
                    ..bits
                });
            }
        } else {
            // SAFETY: the port is live and locked.
            dnrequest = unsafe { dncancel_if_requested(port, entry) };

            let _ = unsafe { space.reverse_remove::<P>(port.as_ptr()) };

            if bits.marequest {
                unsafe { ipc_marequest::cancel(space, name) };
            }

            // SAFETY: the port is live and its lock is held; the release
            // consumes the entry's reference.
            unsafe { port.decrement_references() };
            // SAFETY: the entry is live and the space lock is held.
            unsafe {
                (*entry).set_object(ptr::null_mut());
                ipc_entry::dealloc::<P>(space, name, entry);
            }
        }
    } else {
        unsafe {
            (*entry).set_bits(EntryBits {
                urefs: i32::from(bits.urefs).wrapping_add(delta) as u16,
                ..bits
            });
        }
    }

    // SAFETY: the port is live and its lock is held.
    unsafe { port.unlock() };
    // SAFETY: the space lock is held.
    unsafe { space.unlock_write::<P>() };

    if let Some(nsrequest) = nsrequest {
        // SAFETY: a nonzero no-senders request is a live send-once right.
        unsafe { ipc_notify::no_senders::<P>(nsrequest, mscount) };
    }

    if !dnrequest.is_null() {
        // SAFETY: a nonzero dead-name request is a live send-once right.
        unsafe { ipc_notify::port_deleted::<P>(dnrequest, name) };
    }

    Ok(())
}

/// The `MACH_PORT_RIGHT_SEND_ONCE` arm of [`delta()`].
///
/// # Safety
///
/// The same contract as [`delta()`]: the space must be live, active, and
/// write-locked, and `entry` a live send-once entry of it; the space is
/// unlocked on return.
unsafe fn delta_send_once<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
    bits: EntryBits,
    delta: c_int,
) -> Result<(), Error> {
    if !bits.type_.intersects(PortType::SEND_ONCE) {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write::<P>() };
        return Err(Error::InvalidRight);
    }

    if !(-1..=0).contains(&delta) {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write::<P>() };
        return Err(Error::InvalidValue);
    }
    // SAFETY: a send-once entry names a live port.
    let port = unsafe { IpcPort::from_raw((*entry).object()) };

    // SAFETY: the space is write-locked and the entry is live.
    if unsafe { check::<P>(space, port, name, entry) } {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write::<P>() };
        return Err(Error::InvalidRight);
    }

    // The port is locked and active.

    if delta == 0 {
        // SAFETY: the port lock is held.
        unsafe { port.unlock() };
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write::<P>() };
        return Ok(());
    }

    // SAFETY: the port is live and locked.
    let dnrequest = unsafe { dncancel_if_requested(port, entry) };
    // SAFETY: the port lock is held.
    unsafe { port.unlock() };

    // SAFETY: the entry is live and the space lock is held.
    unsafe {
        (*entry).set_object(ptr::null_mut());
        ipc_entry::dealloc::<P>(space, name, entry);
        space.unlock_write::<P>();
    }

    // SAFETY: the send-once notification consumes the entry's reference.
    unsafe { ipc_notify::send_once::<P>(port.as_non_null()) };

    if !dnrequest.is_null() {
        // SAFETY: a nonzero dead-name request is a live send-once right.
        unsafe { ipc_notify::port_deleted::<P>(dnrequest, name) };
    }

    Ok(())
}

/// The `MACH_PORT_RIGHT_DEAD_NAME` arm of [`delta()`].
///
/// # Safety
///
/// The same contract as [`delta()`]: the space must be live, active, and
/// write-locked, and `entry` a live entry of it; the space is unlocked on
/// return.
unsafe fn delta_dead_name<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
    mut bits: EntryBits,
    delta: c_int,
) -> Result<(), Error> {
    if bits.type_.intersects(PortType::SEND_RIGHTS) {
        // SAFETY: a send-rights entry names a live port.
        let port = unsafe { IpcPort::from_raw((*entry).object()) };

        // SAFETY: the space is write-locked and the entry is live.
        if !unsafe { check::<P>(space, port, name, entry) } {
            // SAFETY: the port is live and locked.
            unsafe { port.unlock() };
            // SAFETY: the space lock is held.
            unsafe { space.unlock_write::<P>() };
            return Err(Error::InvalidRight);
        }

        // SAFETY: the check converted the entry to a dead name.
        bits = unsafe { (*entry).bits() };
    } else if !bits.type_.intersects(PortType::DEAD_NAME) {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write::<P>() };
        return Err(Error::InvalidRight);
    }

    let urefs = bits.urefs;

    if urefs_underflow(urefs, delta) {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write::<P>() };
        return Err(Error::InvalidValue);
    }

    if urefs_overflow(urefs, delta) {
        // SAFETY: the space lock is held.
        unsafe { space.unlock_write::<P>() };
        return Err(Error::UrefsOverflow);
    }

    if i32::from(urefs).wrapping_add(delta) == 0 {
        unsafe { ipc_entry::dealloc::<P>(space, name, entry) };
    } else {
        unsafe {
            (*entry).set_bits(EntryBits {
                urefs: i32::from(bits.urefs).wrapping_add(delta) as u16,
                ..bits
            });
        }
    }

    // SAFETY: the space lock is held.
    unsafe { space.unlock_write::<P>() };
    Ok(())
}

/// The entry's type bits and user-reference count.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `entry` a live entry
/// of it.  The space stays locked.
pub(crate) unsafe fn info<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
) -> (PortType, c_uint) {
    let mut bits = unsafe { (*entry).bits() };

    if bits.type_.intersects(PortType::SEND_RIGHTS) {
        // SAFETY: a send-rights entry names a live port.
        let port = unsafe { IpcPort::from_raw((*entry).object()) };

        // SAFETY: the space is write-locked and the entry is live.
        if unsafe { check::<P>(space, port, name, entry) } {
            // SAFETY: the check converted the entry to a dead name.
            bits = unsafe { (*entry).bits() };
        } else {
            // SAFETY: the port is live and locked.
            unsafe { port.unlock() };
        }
    }

    let mut type_ = bits.type_;

    if unsafe { (*entry).request() } != 0 {
        type_ |= PortType::DNREQUEST;
    }

    if bits.marequest {
        type_ |= PortType::MAREQUEST;
    }

    (type_, c_uint::from(bits.urefs))
}

/// Whether a copyin of `entry` with `msgt_name` would succeed.
///
/// # Safety
///
/// The space must be live, active, and locked for reading or writing, and
/// `entry` a live entry of it.
pub(crate) unsafe fn copyin_check(
    entry: *mut IpcEntry,
    msgt_name: c_uint,
) -> bool {
    let bits = unsafe { (*entry).bits() };

    match msgt_name {
        MACH_MSG_TYPE_MAKE_SEND
        | MACH_MSG_TYPE_MAKE_SEND_ONCE
        | MACH_MSG_TYPE_MOVE_RECEIVE => {
            bits.type_.intersects(PortType::RECEIVE)
        }

        MACH_MSG_TYPE_COPY_SEND
        | MACH_MSG_TYPE_MOVE_SEND
        | MACH_MSG_TYPE_MOVE_SEND_ONCE => {
            if bits.type_.intersects(PortType::DEAD_NAME) {
                return true;
            }

            if !bits.type_.intersects(PortType::SEND_RIGHTS) {
                return false;
            }

            // SAFETY: a send-rights entry names a live port.
            let port = unsafe { IpcPort::from_raw((*entry).object()) };

            // SAFETY: the port is live and unlocked.
            unsafe { port.lock() };
            // SAFETY: the port lock is held.
            let active = unsafe { port.is_active() };
            // SAFETY: the port lock is held.
            unsafe { port.unlock() };

            if !active {
                return true;
            }

            if msgt_name == MACH_MSG_TYPE_MOVE_SEND_ONCE {
                bits.type_.intersects(PortType::SEND_ONCE)
            } else {
                bits.type_.intersects(PortType::SEND)
            }
        }

        _ => strange_rights(
            "ipc_right_copyin_check",
            "ipc_right_copyin_check: strange rights",
        ),
    }
}

/// The copyin of a dead name with a copy disposition: the dead value, when
/// dead names are accepted.
const fn copy_dead(deadok: bool) -> Result<(*mut c_void, *mut c_void), Error> {
    if !deadok {
        return Err(Error::InvalidRight);
    }

    Ok((IO_DEAD, ptr::null_mut()))
}

/// The copyin of a dead name with a move disposition: drops a user reference
/// and yields the dead value, when dead names are accepted.
///
/// # Safety
///
/// The space must be write-locked and `entry` a live entry of it whose type is
/// `MACH_PORT_TYPE_DEAD_NAME`.
unsafe fn move_dead(
    entry: *mut IpcEntry,
    bits: EntryBits,
    deadok: bool,
) -> Result<(*mut c_void, *mut c_void), Error> {
    if !deadok {
        return Err(Error::InvalidRight);
    }

    let bits = if bits.urefs == 1 {
        EntryBits {
            type_: bits.type_.difference(PortType::DEAD_NAME),
            ..bits
        }
    } else {
        EntryBits {
            urefs: bits.urefs.wrapping_sub(1),
            ..bits
        }
    };

    unsafe { (*entry).set_bits(bits) };

    Ok((IO_DEAD, ptr::null_mut()))
}

/// Takes the right `entry` holds out of `space` for a message, as `msgt_name`
/// disposes it.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `entry` a live entry
/// of it.  On success the caller gets a reference for the object, unless it is
/// `IO_DEAD`.
pub(crate) unsafe fn copyin<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
    msgt_name: c_uint,
    deadok: bool,
) -> Result<(*mut c_void, *mut c_void), Error> {
    let bits = unsafe { (*entry).bits() };

    match msgt_name {
        MACH_MSG_TYPE_MAKE_SEND => {
            if !bits.type_.intersects(PortType::RECEIVE) {
                return Err(Error::InvalidRight);
            }

            // SAFETY: a receive entry names a live port.
            let port = unsafe { IpcPort::from_raw((*entry).object()) };

            // SAFETY: the port is live and unlocked.
            unsafe {
                port.lock();
                port.increment_mscount();
                port.increment_srights();
                port.increment_references();
                port.unlock();
            }

            Ok((port.as_ptr(), ptr::null_mut()))
        }

        MACH_MSG_TYPE_MAKE_SEND_ONCE => {
            if !bits.type_.intersects(PortType::RECEIVE) {
                return Err(Error::InvalidRight);
            }

            // SAFETY: a receive entry names a live port.
            let port = unsafe { IpcPort::from_raw((*entry).object()) };

            // SAFETY: the port is live and unlocked.
            unsafe {
                port.lock();
                port.increment_sorights();
                port.increment_references();
                port.unlock();
            }

            Ok((port.as_ptr(), ptr::null_mut()))
        }

        MACH_MSG_TYPE_MOVE_RECEIVE => {
            if !bits.type_.intersects(PortType::RECEIVE) {
                return Err(Error::InvalidRight);
            }

            // SAFETY: a receive entry names a live port.
            let port = unsafe { IpcPort::from_raw((*entry).object()) };

            // SAFETY: the port is live and unlocked.
            unsafe { port.lock() };

            let dnrequest;

            if bits.type_.intersects(PortType::SEND) {
                unsafe { (*entry).set_name(name) };
                let _ =
                    unsafe { space.reverse_insert::<P>(port.as_ptr(), entry) };
                // SAFETY: the port is live and locked.
                unsafe { port.increment_references() };
                dnrequest = ptr::null_mut();
            } else {
                // SAFETY: the port is live and locked.
                dnrequest = unsafe { dncancel_if_requested(port, entry) };

                if bits.marequest {
                    unsafe { ipc_marequest::cancel(space, name) };
                }

                unsafe { (*entry).set_object(ptr::null_mut()) };
            }

            // SAFETY: the entry is live and the port is locked; the C clears
            // the receiver before unlocking.
            unsafe {
                (*entry).set_bits(EntryBits {
                    type_: bits.type_.difference(PortType::RECEIVE),
                    ..bits
                });
                ipc_port::clear_receiver::<P>(port);
                port.set_receiver_name(MACH_PORT_NULL);
                port.set_destination(ptr::null_mut());
                port.clear_protected_flag();
                port.unlock();
            }

            Ok((port.as_ptr(), dnrequest))
        }

        MACH_MSG_TYPE_COPY_SEND
        | MACH_MSG_TYPE_MOVE_SEND
        | MACH_MSG_TYPE_MOVE_SEND_ONCE => unsafe {
            copyin_send_rights::<P>(
                space, name, entry, bits, msgt_name, deadok,
            )
        },

        _ => strange_rights(
            "ipc_right_copyin",
            "ipc_right_copyin: strange rights",
        ),
    }
}

/// The `MACH_MSG_TYPE_COPY_SEND`, `MOVE_SEND` and `MOVE_SEND_ONCE` arm of
/// [`copyin()`].
///
/// # Safety
///
/// The same contract as [`copyin()`]: the space must be live, active, and
/// write-locked, and `entry` a live send-rights entry of it.
unsafe fn copyin_send_rights<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
    mut bits: EntryBits,
    msgt_name: c_uint,
    deadok: bool,
) -> Result<(*mut c_void, *mut c_void), Error> {
    let copy = msgt_name == MACH_MSG_TYPE_COPY_SEND;

    if bits.type_.intersects(PortType::DEAD_NAME) {
        return if copy {
            copy_dead(deadok)
        } else {
            unsafe { move_dead(entry, bits, deadok) }
        };
    }

    // Allow for dead send-once rights.
    if !bits.type_.intersects(PortType::SEND_RIGHTS) {
        return Err(Error::InvalidRight);
    }

    // SAFETY: a send-rights entry names a live port.
    let port = unsafe { IpcPort::from_raw((*entry).object()) };

    // SAFETY: the space is write-locked and the entry is live.
    if unsafe { check::<P>(space, port, name, entry) } {
        // SAFETY: the check converted the entry to a dead name.
        bits = unsafe { (*entry).bits() };

        return if copy {
            copy_dead(deadok)
        } else {
            // SAFETY: the entry is a live dead name.
            unsafe { move_dead(entry, bits, deadok) }
        };
    }

    // The port is locked and active.

    if copy {
        if !bits.type_.intersects(PortType::SEND) {
            // SAFETY: the port lock is held.
            unsafe { port.unlock() };
            return Err(Error::InvalidRight);
        }

        // SAFETY: the port is live and locked.
        unsafe {
            port.increment_srights();
            port.increment_references();
            port.unlock();
        }

        return Ok((port.as_ptr(), ptr::null_mut()));
    }

    if msgt_name == MACH_MSG_TYPE_MOVE_SEND {
        if !bits.type_.intersects(PortType::SEND) {
            // SAFETY: the port lock is held.
            unsafe { port.unlock() };
            return Err(Error::InvalidRight);
        }

        let dnrequest;

        if bits.urefs == 1 {
            if bits.type_.intersects(PortType::RECEIVE) {
                // SAFETY: the port is live and locked.
                unsafe { port.increment_references() };
                dnrequest = ptr::null_mut();
            } else {
                // SAFETY: the port is live and locked.
                dnrequest = unsafe { dncancel_if_requested(port, entry) };

                let _ = unsafe { space.reverse_remove::<P>(port.as_ptr()) };

                if bits.marequest {
                    unsafe { ipc_marequest::cancel(space, name) };
                }

                unsafe { (*entry).set_object(ptr::null_mut()) };
            }

            unsafe {
                (*entry).set_bits(EntryBits {
                    type_: bits.type_.difference(PortType::SEND),
                    urefs: 0,
                    ..bits
                });
            }
        } else {
            // SAFETY: the port is live and locked.
            unsafe {
                port.increment_srights();
                port.increment_references();
                (*entry).set_bits(EntryBits {
                    urefs: bits.urefs.wrapping_sub(1),
                    ..bits
                });
            }
            dnrequest = ptr::null_mut();
        }

        // SAFETY: the port lock is held.
        unsafe { port.unlock() };

        return Ok((port.as_ptr(), dnrequest));
    }

    if !bits.type_.intersects(PortType::SEND_ONCE) {
        // SAFETY: the port lock is held.
        unsafe { port.unlock() };
        return Err(Error::InvalidRight);
    }

    // SAFETY: the port is live and locked.
    let dnrequest = unsafe { dncancel_if_requested(port, entry) };
    // SAFETY: the port lock is held.
    unsafe { port.unlock() };

    unsafe {
        (*entry).set_object(ptr::null_mut());
        (*entry).set_bits(EntryBits {
            type_: bits.type_.difference(PortType::SEND_ONCE),
            ..bits
        });
    }

    Ok((port.as_ptr(), dnrequest))
}

/// Undoes the copyin of a send or send-once right that turned out dead.
///
/// # Safety
///
/// The space must be live, active, and write-locked; `entry` a live entry of
/// it; and `object` either `IO_DEAD` or a dead port the entry refers to.
pub(crate) unsafe fn copyin_undo<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
    msgt_name: c_uint,
    object: *mut c_void,
    soright: Option<NonNull<c_void>>,
) {
    let bits = unsafe { (*entry).bits() };

    if soright.is_some() {
        unsafe {
            (*entry).set_bits(EntryBits {
                type_: PortType::DEAD_NAME,
                urefs: 2,
                marequest: false,
            });
        }
    } else if bits.type_ == PortType::NONE {
        unsafe {
            (*entry).set_bits(EntryBits {
                type_: PortType::DEAD_NAME,
                urefs: 1,
                marequest: false,
            });
        }
    } else if bits.type_ == PortType::DEAD_NAME {
        if msgt_name != MACH_MSG_TYPE_COPY_SEND {
            unsafe {
                (*entry).set_bits(EntryBits {
                    urefs: bits.urefs.wrapping_add(1),
                    ..bits
                });
            }
        }
    } else {
        if msgt_name != MACH_MSG_TYPE_COPY_SEND {
            unsafe {
                (*entry).set_bits(EntryBits {
                    urefs: bits.urefs.wrapping_add(1),
                    ..bits
                });
            }
        }

        // The object is dead, so the check leaves the entry a dead name and
        // returns without keeping a lock.
        let port = unsafe { IpcPort::from_raw(object) };
        // SAFETY: the space is write-locked and the entry is live.
        let _ = unsafe { check::<P>(space, port, name, entry) };
    }

    // The reference copyin acquired does not exist for `IO_DEAD`.
    if object != IO_DEAD {
        unsafe { ipc_object::release::<P>(object) };
    }
}

/// Moves two send rights out of `entry` at once, for a message whose
/// destination and reply are the same name.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `entry` a live entry
/// of it.  On success the object is returned with two references.
pub(crate) unsafe fn copyin_two<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
) -> Result<(*mut c_void, *mut c_void), Error> {
    let bits = unsafe { (*entry).bits() };

    if !bits.type_.intersects(PortType::SEND) {
        return Err(Error::InvalidRight);
    }

    let urefs = bits.urefs;
    if urefs < 2 {
        return Err(Error::InvalidRight);
    }

    // SAFETY: a send entry names a live port.
    let port = unsafe { IpcPort::from_raw((*entry).object()) };

    // SAFETY: the space is write-locked and the entry is live.
    if unsafe { check::<P>(space, port, name, entry) } {
        return Err(Error::InvalidRight);
    }

    // The port is locked and active.

    let dnrequest;

    if urefs == 2 {
        if bits.type_.intersects(PortType::RECEIVE) {
            // SAFETY: the port is live and locked.
            unsafe {
                port.increment_srights();
                port.increment_references();
                port.increment_references();
            }
            dnrequest = ptr::null_mut();
        } else {
            // SAFETY: the port is live and locked.
            dnrequest = unsafe { dncancel_if_requested(port, entry) };

            let _ = unsafe { space.reverse_remove::<P>(port.as_ptr()) };

            if bits.marequest {
                unsafe { ipc_marequest::cancel(space, name) };
            }

            // SAFETY: the port is live and locked.
            unsafe {
                port.increment_srights();
                port.increment_references();
                (*entry).set_object(ptr::null_mut());
            }
        }

        unsafe {
            (*entry).set_bits(EntryBits {
                type_: bits.type_.difference(PortType::SEND),
                urefs: 0,
                ..bits
            });
        }
    } else {
        // SAFETY: the port is live and locked.
        unsafe {
            port.increment_srights();
            port.increment_srights();
            port.increment_references();
            port.increment_references();
            (*entry).set_bits(EntryBits {
                urefs: bits.urefs.wrapping_sub(2),
                ..bits
            });
        }
        dnrequest = ptr::null_mut();
    }

    // SAFETY: the port lock is held.
    unsafe { port.unlock() };

    Ok((port.as_ptr(), dnrequest))
}

/// Puts a right to `object` from a message into `entry` of `space`.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `entry` a live entry
/// of it.  The object must be live, active, and locked; it is unlocked on
/// return, and the call consumes a reference on success.
pub(crate) unsafe fn copyout<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
    msgt_name: c_uint,
    overflow: bool,
    object: *mut c_void,
) -> Result<(), Error> {
    let bits = unsafe { (*entry).bits() };
    let port = unsafe { IpcPort::from_raw(object) };

    match msgt_name {
        MACH_MSG_TYPE_MOVE_SEND_ONCE => {
            // SAFETY: the port lock is held; the send-once right and its
            // reference transfer to the entry.
            unsafe { port.unlock() };
            unsafe {
                (*entry).set_bits(EntryBits {
                    type_: bits.type_ | PortType::SEND_ONCE,
                    urefs: bits.urefs | 1,
                    ..bits
                });
            }
            Ok(())
        }

        MACH_MSG_TYPE_MOVE_SEND => {
            if bits.type_.intersects(PortType::SEND) {
                let urefs = bits.urefs;

                if u32::from(urefs) + 1 == MACH_PORT_UREFS_MAX {
                    if overflow {
                        // Leave the user references pegged to the maximum.
                        // SAFETY: the port is live and locked.
                        unsafe {
                            port.decrement_srights();
                            port.decrement_references();
                            port.unlock();
                        }
                        return Ok(());
                    }

                    // SAFETY: the port lock is held.
                    unsafe { port.unlock() };
                    return Err(Error::UrefsOverflow);
                }

                // SAFETY: the port is live and locked.
                unsafe {
                    port.decrement_srights();
                    port.decrement_references();
                    port.unlock();
                }
            } else if bits.type_.intersects(PortType::RECEIVE) {
                // The send right transfers to the entry.
                // SAFETY: the port is live and locked.
                unsafe {
                    port.decrement_references();
                    port.unlock();
                }
            } else {
                // The send right and its reference transfer to the entry.
                // SAFETY: the port lock is held.
                unsafe { port.unlock() };
                // SAFETY: the entry is live and the space is write-locked.
                unsafe {
                    (*entry).set_name(name);
                    let _ = space.reverse_insert::<P>(port.as_ptr(), entry);
                }
            }

            unsafe {
                (*entry).set_bits(EntryBits {
                    type_: bits.type_ | PortType::SEND,
                    urefs: bits.urefs.wrapping_add(1),
                    ..bits
                });
            }
            Ok(())
        }

        MACH_MSG_TYPE_MOVE_RECEIVE => {
            // SAFETY: the port is live and locked.
            let dest = unsafe { port.destination() };

            // SAFETY: the port is live and locked.
            unsafe {
                port.set_receiver_name(name);
                port.set_receiver(space.as_ptr());
                port.clear_protected_flag();
            }

            if bits.type_.intersects(PortType::SEND) {
                // SAFETY: the port is live and locked.
                unsafe {
                    port.decrement_references();
                    port.unlock();
                }

                // SAFETY: the entry holds a reference, so the port is alive.
                let _ = unsafe { space.reverse_remove::<P>(port.as_ptr()) };
            } else {
                // The reference transfers to the entry.
                // SAFETY: the port lock is held.
                unsafe { port.unlock() };
            }

            unsafe {
                (*entry).set_bits(EntryBits {
                    type_: bits.type_ | PortType::RECEIVE,
                    ..bits
                });
            }

            if !dest.is_null() {
                // SAFETY: a nonzero destination is a live port holding a
                // reference.
                unsafe { ipc_object::release::<P>(dest) };
            }

            Ok(())
        }

        _ => strange_rights(
            "ipc_right_copyout",
            "ipc_right_copyout: strange rights",
        ),
    }
}

/// Moves the right of `oentry` under `oname` to `nentry` under `nname`.
///
/// # Safety
///
/// The space must be live, active, and write-locked; `oentry` and `nentry`
/// live entries of it, with `nentry` unused.  The space is unlocked on return.
pub(crate) unsafe fn rename<P: Platform>(
    space: IpcSpace,
    oname: c_uint,
    oentry: *mut IpcEntry,
    nname: c_uint,
    nentry: *mut IpcEntry,
) {
    let mut bits = unsafe { (*oentry).bits() };
    let mut request = unsafe { (*oentry).request() };
    let mut object = unsafe { (*oentry).object() };

    if request != 0 {
        // SAFETY: a request entry names a live port.
        let port = unsafe { IpcPort::from_raw(object) };

        // SAFETY: the space is write-locked and the entry is live.
        if unsafe { check::<P>(space, port, oname, oentry) } {
            // SAFETY: the check converted the entry to a dead name.
            bits = unsafe { (*oentry).bits() };
            request = 0;
            object = ptr::null_mut();
        } else {
            // The port is locked and active.
            // SAFETY: the port is live and locked, and the request names a
            // live slot.
            unsafe { ipc_port::dnrename(port, request, nname) };
            // SAFETY: the port lock is held.
            unsafe { port.unlock() };
            // SAFETY: the entry is live.
            unsafe { (*oentry).set_request(0) };
        }
    }

    if bits.marequest {
        unsafe { ipc_marequest::rename(space, oname, nname) };
    }

    // SAFETY: the new entry is live and unused.
    unsafe {
        (*nentry).set_bits(bits);
        (*nentry).set_request(request);
        (*nentry).set_object(object);
    }

    match bits.type_ {
        PortType::SEND => {
            // SAFETY: a send entry names a live port.
            let port = unsafe { IpcPort::from_raw(object) };

            let _ = unsafe { space.reverse_remove::<P>(port.as_ptr()) };
            // SAFETY: the new entry is live.
            unsafe { (*nentry).set_name(nname) };
            let _ =
                unsafe { space.reverse_insert::<P>(port.as_ptr(), nentry) };
        }

        PortType::RECEIVE | PortType::SEND_RECEIVE => {
            // SAFETY: a receive entry names a live port.
            let port = unsafe { IpcPort::from_raw(object) };

            // SAFETY: the port is live and unlocked.
            unsafe {
                port.lock();
                port.set_receiver_name(nname);
                port.unlock();
            }
        }

        PortType::PORT_SET => {
            // SAFETY: a port-set entry names a live port set.
            let target = object.cast::<IpcTarget>();

            // SAFETY: the port set is live and unlocked.
            unsafe {
                (*target).lock();
                (*target).set_local_name(nname);
                (*target).unlock();
            }
        }

        PortType::SEND_ONCE | PortType::DEAD_NAME => (),

        _ => strange_rights(
            "ipc_right_rename",
            "ipc_right_rename: strange rights",
        ),
    }

    // SAFETY: the old entry is live and the space lock is held.
    unsafe {
        (*oentry).set_object(ptr::null_mut());
        ipc_entry::dealloc::<P>(space, oname, oentry);
        space.unlock_write::<P>();
    }
}
