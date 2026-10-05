// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_object.c:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The IPC object routines.

use crate::ipc::error::Error;
use crate::ipc::ipc_entry;
use crate::ipc::ipc_notify;
use crate::ipc::ipc_right;
use crate::ipc::{
    IE_BITS_TYPE_MASK, IO_BITS_ACTIVE, IOT_PORT, IOT_PORT_SET, IpcObject,
    IpcPort, IpcSpace, IpcTarget,
};
use crate::kern::debug::kpanic;
use crate::kern::slab::{KmemCache, kmem_cache_init};
use core::ffi::{c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull};

/// The send-once right disposition, an alias of
/// `MACH_MSG_TYPE_MOVE_SEND_ONCE`.
const MACH_MSG_TYPE_PORT_SEND_ONCE: c_uint = 18;
/// The type bit of a dead name: `1 << (right + 16)` for the dead-name right.
const MACH_PORT_TYPE_DEAD_NAME: c_uint = 1 << (4 + 16);
/// The null port name.
const MACH_PORT_NAME_NULL: c_uint = 0;
/// The port object type, as callers pass it.
const IOT_PORT_OBJECT: c_uint = IOT_PORT as c_uint;
/// The port-set object type, as callers pass it.
const IOT_PORT_SET_OBJECT: c_uint = IOT_PORT_SET as c_uint;

/// The port and port-set caches [`io_alloc`] and [`io_free`] select.
pub(crate) static mut IPC_OBJECT_CACHES: [KmemCache; crate::ipc::IOT_NUMBER] =
    [const { KmemCache::zeroed() }; crate::ipc::IOT_NUMBER];

/// A `mach_msg_type_name_t` the C `switch` accepted: the type names a message
/// can carry for a port right, plus the bare zero.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MsgTypeName {
    /// The bare `0` case: no right is named.
    Null = 0,
    /// `MACH_MSG_TYPE_MOVE_RECEIVE`: the sender held receive rights.
    MoveReceive = 16,
    /// `MACH_MSG_TYPE_MOVE_SEND`: the sender held send rights.
    MoveSend = 17,
    /// `MACH_MSG_TYPE_MOVE_SEND_ONCE`: the sender held send-once rights.
    MoveSendOnce = 18,
    /// `MACH_MSG_TYPE_COPY_SEND`: a copy of a send right.
    CopySend = 19,
    /// `MACH_MSG_TYPE_MAKE_SEND`: a new send right made from receive rights.
    MakeSend = 20,
    /// `MACH_MSG_TYPE_MAKE_SEND_ONCE`: a new send-once right made from
    /// receive rights.
    MakeSendOnce = 21,
}

impl MsgTypeName {
    /// The name a wire `mach_msg_type_name_t` spells, or `None` for a name
    /// the C `switch` would not have accepted.
    const fn from_u32(name: c_uint) -> Option<Self> {
        match name {
            0 => Some(Self::Null),
            16 => Some(Self::MoveReceive),
            17 => Some(Self::MoveSend),
            18 => Some(Self::MoveSendOnce),
            19 => Some(Self::CopySend),
            20 => Some(Self::MakeSend),
            21 => Some(Self::MakeSendOnce),
            _ => None,
        }
    }

    /// The form the receiver ends up holding.
    const fn received(self) -> Self {
        match self {
            Self::Null => Self::Null,
            Self::MoveReceive => Self::MoveReceive,
            Self::MoveSendOnce | Self::MakeSendOnce => Self::MoveSendOnce,
            Self::MoveSend | Self::MakeSend | Self::CopySend => Self::MoveSend,
        }
    }
}

/// The C `default: panic()` arm of a rights switch.
fn strange_rights(fun: &'static str, message: &'static str) -> ! {
    kpanic!(fun, "{}", message)
}

/// The type bit of `right`: `1 << (right + 16)`.
const fn mach_port_type(right: c_uint) -> c_uint {
    // The C shifts by `right + 16`; the target masks the shift count the
    // same way.
    1u32.wrapping_shl(right.wrapping_add(16))
}

/// The object bits of an active or inactive object of type `otype` and
/// kernel-object type `kotype`.
const fn io_makebits(active: bool, otype: c_uint, kotype: c_uint) -> c_uint {
    let active = if active { IO_BITS_ACTIVE } else { 0 };
    active | otype.wrapping_shl(16) | kotype
}

/// Allocates an object of type `otype` from its cache.
fn io_alloc(otype: c_uint) -> Option<*mut c_void> {
    // SAFETY: `ipc_bootstrap()` initialized both caches before any object
    // could exist, and the C callers pass one of the two types.
    let caches = unsafe { &mut *ptr::addr_of_mut!(IPC_OBJECT_CACHES) };
    // `usize` is at least as wide as the two-value object type on both
    // targets, so the widening cannot lose anything.
    let cache = caches.get_mut(otype as usize)?;
    cache.alloc().map(|buf| buf.as_ptr().cast())
}

/// Returns `object` of type `otype` to its cache.
///
/// # Safety
///
/// `object` must be a live allocation from the cache `otype` selects, and
/// nothing may reference it.
unsafe fn io_free(otype: c_uint, object: *mut c_void) {
    let caches = unsafe { &mut *ptr::addr_of_mut!(IPC_OBJECT_CACHES) };
    // As in `io_alloc()`, the widening cannot lose the object type.
    let Some(cache) = caches.get_mut(otype as usize) else {
        return;
    };
    let Some(object) = NonNull::new(object.cast::<u8>()) else {
        return;
    };

    unsafe { cache.free(object) };
}

/// The C's `memset(object, 0, sizeof(*object))` for the cached object types.
///
/// # Safety
///
/// `object` must be a fresh allocation of the size `otype` selects.
const unsafe fn zero_object(otype: c_uint, object: *mut c_void) {
    let size = match otype {
        IOT_PORT_OBJECT => size_of::<crate::ipc::IpcPortRecord>(),
        IOT_PORT_SET_OBJECT => size_of::<IpcTarget>(),
        _ => 0,
    };

    if size != 0 {
        unsafe { ptr::write_bytes(object.cast::<u8>(), 0, size) };
    }
}

/// Initializes and takes the lock of a fresh object.
///
/// # Safety
///
/// `object` must be a fresh allocation this call owns.
unsafe fn lock_object(object: *mut c_void) {
    unsafe {
        let header = object.cast::<IpcObject>();
        (*header).lock.init();
        (*header).lock.lock();
    }
}

/// Gives a fresh object its first reference and its active type bits.
///
/// # Safety
///
/// `object` must be a live object this call owns, locked by [`lock_object()`].
unsafe fn activate_object(object: *mut c_void, otype: c_uint) {
    unsafe {
        let header = object.cast::<IpcObject>();
        (*header).references = 1;
        (*header).bits = io_makebits(true, otype, 0);
    }
}

/// Takes a reference on `object`.
///
/// # Safety
///
/// `object` must be a live IPC object.
pub(crate) unsafe fn reference(object: *mut c_void) {
    unsafe {
        let header = object.cast::<IpcObject>();
        (*header).lock.lock();
        (*header).references = (*header).references.wrapping_add(1);
        (*header).lock.unlock();
    }
}

/// Drops a reference on `object`, destroying it on the last one.
///
/// # Safety
///
/// `object` must be a live IPC object holding a reference.
pub(crate) unsafe fn release(object: *mut c_void) {
    unsafe {
        let header = object.cast::<IpcObject>();
        (*header).lock.lock();
        (*header).references = (*header).references.wrapping_sub(1);
        IpcObject::check_unlock(header);
    }
}

/// Looks `name` up and returns its object, locked.
///
/// # Safety
///
/// `space` must be live and nothing may be locked.
pub(crate) unsafe fn translate(
    space: IpcSpace,
    name: c_uint,
    right: c_uint,
) -> Result<*mut c_void, Error> {
    let entry = unsafe { ipc_right::lookup_write(space, name) }?;

    // SAFETY: the entry is live and the space is locked.
    if unsafe { (*entry).bits() } & mach_port_type(right) == 0 {
        // SAFETY: the earlier call took the space lock.
        unsafe { space.lock_done() };
        return Err(Error::InvalidRight);
    }

    // SAFETY: a typed entry names a live object.
    let object = unsafe { (*entry).object() };

    // SAFETY: the object is live, and the caller held no lock before.
    unsafe { (*object.cast::<IpcObject>()).lock.lock() };

    // SAFETY: the space lock from the lookup is still held.
    unsafe { space.lock_done() };

    Ok(object)
}

/// Allocates a dead name in `space` under a fresh name.
///
/// # Safety
///
/// `space` must be live and nothing may be locked; may allocate memory.
pub(crate) unsafe fn alloc_dead(space: IpcSpace) -> Result<c_uint, Error> {
    unsafe { space.lock_write() };

    // SAFETY: the space lock is held.
    let (name, entry) = match unsafe { ipc_entry::alloc(space) } {
        Ok(found) => found,
        Err(error) => {
            // SAFETY: the space lock is held.
            unsafe { space.lock_done() };
            return Err(error);
        }
    };

    // SAFETY: the entry is live and the space is locked.
    unsafe {
        (*entry).or_bits(MACH_PORT_TYPE_DEAD_NAME | 1);
        space.lock_done();
    }

    Ok(name)
}

/// Allocates a dead name in `space` under `name`.
///
/// # Safety
///
/// `space` must be live and nothing may be locked; may allocate memory.
pub(crate) unsafe fn alloc_dead_name(
    space: IpcSpace,
    name: c_uint,
) -> Result<(), Error> {
    unsafe { space.lock_write() };

    // SAFETY: the space lock is held.
    let entry = match unsafe { ipc_entry::alloc_name(space, name) } {
        Ok(entry) => entry,
        Err(error) => {
            // SAFETY: the space lock is held.
            unsafe { space.lock_done() };
            return Err(error);
        }
    };

    // SAFETY: `ipc_right::inuse` unlocks the space when the entry is in use.
    if unsafe { ipc_right::inuse(space, entry) } {
        return Err(Error::NameExists);
    }

    // SAFETY: the entry is live and the space is locked.
    unsafe {
        (*entry).or_bits(MACH_PORT_TYPE_DEAD_NAME | 1);
        space.lock_done();
    }

    Ok(())
}

/// Allocates an object of type `otype` in `space` under a fresh name, with a
/// right of `type_` and `urefs` user references.
///
/// # Safety
///
/// `space` must be live and nothing may be locked; may allocate memory.  On
/// success the object is returned locked.
pub(crate) unsafe fn alloc(
    space: IpcSpace,
    otype: c_uint,
    type_: c_uint,
    urefs: c_uint,
) -> Result<(c_uint, *mut c_void), Error> {
    let Some(object) = io_alloc(otype) else {
        return Err(Error::ResourceShortage);
    };

    // SAFETY: `io_alloc` returned a fresh allocation of `otype`'s size.
    unsafe { zero_object(otype, object) };

    unsafe { space.lock_write() };

    // SAFETY: the space lock is held.
    let (name, entry) = match unsafe { ipc_entry::alloc(space) } {
        Ok(found) => found,
        Err(error) => {
            // SAFETY: the space lock is held.
            unsafe { space.lock_done() };
            // SAFETY: the object is the fresh allocation from above.
            unsafe { io_free(otype, object) };
            return Err(error);
        }
    };

    // SAFETY: the entry is live, the object is fresh, and the space lock is
    // held; the C's field writes and unlock follow in this order.
    unsafe {
        (*entry).or_bits(type_ | urefs);
        (*entry).set_object(object);
        lock_object(object);
        space.lock_done();
        activate_object(object, otype);
    }

    Ok((name, object))
}

/// Allocates an object of type `otype` in `space` under `name`, with a right
/// of `type_` and `urefs` user references.
///
/// # Safety
///
/// `space` must be live and nothing may be locked; may allocate memory.  On
/// success the object is returned locked.
pub(crate) unsafe fn alloc_name(
    space: IpcSpace,
    otype: c_uint,
    type_: c_uint,
    urefs: c_uint,
    name: c_uint,
) -> Result<*mut c_void, Error> {
    let Some(object) = io_alloc(otype) else {
        return Err(Error::ResourceShortage);
    };

    // SAFETY: `io_alloc` returned a fresh allocation of `otype`'s size.
    unsafe { zero_object(otype, object) };

    unsafe { space.lock_write() };

    // SAFETY: the space lock is held.
    let entry = match unsafe { ipc_entry::alloc_name(space, name) } {
        Ok(entry) => entry,
        Err(error) => {
            // SAFETY: the space lock is held.
            unsafe { space.lock_done() };
            // SAFETY: the object is the fresh allocation from above.
            unsafe { io_free(otype, object) };
            return Err(error);
        }
    };

    // SAFETY: `ipc_right::inuse` unlocks the space when the entry is in use.
    if unsafe { ipc_right::inuse(space, entry) } {
        // SAFETY: the object is the fresh allocation from above.
        unsafe { io_free(otype, object) };
        return Err(Error::NameExists);
    }

    // SAFETY: the entry is live, the object is fresh, and the space lock is
    // held; the C's field writes and unlock follow in this order.
    unsafe {
        (*entry).or_bits(type_ | urefs);
        (*entry).set_object(object);
        lock_object(object);
        space.lock_done();
        activate_object(object, otype);
    }

    Ok(object)
}

/// Takes the right `name` names in `space` out for a message, as `msgt_name`
/// disposes it.
///
/// # Safety
///
/// `space` must be live and nothing may be locked.  On success the caller
/// gets one reference to the returned object.
pub(crate) unsafe fn copyin(
    space: IpcSpace,
    name: c_uint,
    msgt_name: c_uint,
) -> Result<*mut c_void, Error> {
    let entry = unsafe { ipc_right::lookup_write(space, name) }?;

    // SAFETY: the entry is live and the space is write-locked and active.
    let result =
        unsafe { ipc_right::copyin(space, name, entry, msgt_name, true) };

    // SAFETY: the space lock is held; an entry left with no type goes back to
    // the free list.
    unsafe {
        if (*entry).bits() & IE_BITS_TYPE_MASK == 0 {
            ipc_entry::dealloc(space, name, entry);
        }
        space.lock_done();
    }

    let (object, soright) = result?;

    if !soright.is_null() {
        // SAFETY: a non-null send-once right came from the successful copyin
        // and is consumed by the notification.
        unsafe { ipc_notify::port_deleted(soright, name) };
    }

    Ok(object)
}

/// Takes a right the kernel holds on `object` for a message, as `msgt_name`
/// disposes it.
///
/// # Safety
///
/// `object` must be a live IPC object and the caller must own the right the
/// type name describes.
pub(crate) unsafe fn copyin_from_kernel(
    object: *mut c_void,
    msgt_name: c_uint,
) {
    match MsgTypeName::from_u32(msgt_name) {
        Some(MsgTypeName::MoveReceive) => {
            let port = unsafe { IpcPort::from_raw(object) };

            unsafe {
                port.lock();
                port.set_mscount(0);
                port.set_receiver_name(MACH_PORT_NAME_NULL);
                port.set_destination(ptr::null_mut());
                port.clear_protected_flag();
                port.unlock();
            }
        }
        Some(MsgTypeName::CopySend) => {
            let port = unsafe { IpcPort::from_raw(object) };

            unsafe {
                port.lock();
                if port.is_active() {
                    port.increment_srights();
                }
                port.increment_references();
                port.unlock();
            }
        }
        Some(MsgTypeName::MakeSend) => {
            let port = unsafe { IpcPort::from_raw(object) };

            unsafe {
                port.lock();
                port.increment_references();
                port.increment_mscount();
                port.increment_srights();
                port.unlock();
            }
        }
        Some(MsgTypeName::MoveSend | MsgTypeName::MoveSendOnce) => (),
        Some(MsgTypeName::MakeSendOnce) => {
            let port = unsafe { IpcPort::from_raw(object) };

            unsafe {
                port.lock();
                port.increment_references();
                port.increment_sorights();
                port.unlock();
            }
        }
        Some(MsgTypeName::Null) | None => strange_rights(
            "ipc_object_copyin_from_kernel",
            "ipc_object_copyin_from_kernel: strange rights",
        ),
    }
}

/// Puts a right to `object` from a message into `space`, returning its name.
///
/// # Safety
///
/// `space` must be live and nothing may be locked.  On success the call
/// consumes one reference to `object`.
pub(crate) unsafe fn copyout(
    space: IpcSpace,
    object: *mut c_void,
    msgt_name: c_uint,
    overflow: bool,
) -> Result<c_uint, Error> {
    unsafe { space.lock_write() };

    // SAFETY: the space lock is held.
    if !unsafe { space.is_active() } {
        // SAFETY: the space lock is held.
        unsafe { space.lock_done() };
        return Err(Error::DeadSpace);
    }

    // SAFETY: the space is locked and active.  On success the object is
    // locked and active.
    let reversed = if msgt_name == MACH_MSG_TYPE_PORT_SEND_ONCE {
        None
    } else {
        // SAFETY: the space is write-locked and the object is live.
        unsafe { ipc_right::reverse(space, object) }
    };

    let (name, entry) = if let Some(found) = reversed {
        found
    } else {
        // SAFETY: the space lock is held and no object lock is held.
        let (name, entry) = match unsafe { ipc_entry::alloc(space) } {
            Ok(found) => found,
            Err(error) => {
                // SAFETY: the space lock is held.
                unsafe { space.lock_done() };
                return Err(error);
            }
        };

        // SAFETY: the space is locked, so the object cannot die under us.
        unsafe {
            let header = object.cast::<IpcObject>();
            (*header).lock.lock();
            if (*header).bits & IO_BITS_ACTIVE == 0 {
                (*header).lock.unlock();
                ipc_entry::dealloc(space, name, entry);
                space.lock_done();
                return Err(Error::InvalidCapability);
            }
            (*entry).set_object(object);
        }

        (name, entry)
    };

    // SAFETY: the space is write-locked and active, and the object is locked
    // and active; `ipc_right::copyout` unlocks the object.
    let result = unsafe {
        ipc_right::copyout(space, name, entry, msgt_name, overflow, object)
    };

    // SAFETY: the space lock is still held.
    unsafe { space.lock_done() };

    result.map(|()| name)
}

/// Puts a right to `object` from a message into `space` under `name`.
///
/// # Safety
///
/// `space` must be live and nothing may be locked.  On success the call
/// consumes one reference to `object`.
pub(crate) unsafe fn copyout_name(
    space: IpcSpace,
    object: *mut c_void,
    msgt_name: c_uint,
    overflow: bool,
    name: c_uint,
) -> Result<(), Error> {
    unsafe { space.lock_write() };

    // SAFETY: the space lock is held.
    let entry = match unsafe { ipc_entry::alloc_name(space, name) } {
        Ok(entry) => entry,
        Err(error) => {
            // SAFETY: the space lock is held.
            unsafe { space.lock_done() };
            return Err(error);
        }
    };

    // SAFETY: the space is locked and active.  On success the object is
    // locked and active.
    let reversed = if msgt_name == MACH_MSG_TYPE_PORT_SEND_ONCE {
        None
    } else {
        // SAFETY: the space is write-locked and the object is live.
        unsafe { ipc_right::reverse(space, object) }
    };

    if let Some((oname, _)) = reversed {
        if name != oname {
            // SAFETY: the object is locked and the space is write-locked.
            unsafe {
                (*object.cast::<IpcObject>()).lock.unlock();
                if (*entry).bits() & IE_BITS_TYPE_MASK == 0 {
                    ipc_entry::dealloc(space, name, entry);
                }
                space.lock_done();
            }
            return Err(Error::RightExists);
        }
    } else {
        // SAFETY: `ipc_right::inuse` unlocks the space when the entry is in
        // use.
        if unsafe { ipc_right::inuse(space, entry) } {
            return Err(Error::NameExists);
        }

        // SAFETY: the space is locked, so the object cannot die under us.
        unsafe {
            let header = object.cast::<IpcObject>();
            (*header).lock.lock();
            if (*header).bits & IO_BITS_ACTIVE == 0 {
                (*header).lock.unlock();
                ipc_entry::dealloc(space, name, entry);
                space.lock_done();
                return Err(Error::InvalidCapability);
            }
            (*entry).set_object(object);
        }
    }

    // SAFETY: the space is write-locked and active, and the object is locked
    // and active; `ipc_right::copyout` unlocks the object.
    let result = unsafe {
        ipc_right::copyout(space, name, entry, msgt_name, overflow, object)
    };

    // SAFETY: the space lock is still held.
    unsafe { space.lock_done() };

    result
}

/// Quietly consumes a message's destination right and returns the receiver's
/// name for it, or `MACH_PORT_NAME_NULL`.
///
/// # Safety
///
/// The object must be live, active, and locked; the call unlocks it and
/// consumes a reference.
pub(crate) unsafe fn copyout_dest(
    space: IpcSpace,
    object: *mut c_void,
    msgt_name: c_uint,
) -> c_uint {
    unsafe {
        let header = object.cast::<IpcObject>();
        (*header).references = (*header).references.wrapping_sub(1);
    }

    match MsgTypeName::from_u32(msgt_name) {
        Some(MsgTypeName::MoveSend) => {
            let port = unsafe { IpcPort::from_raw(object) };
            let mut nsrequest: Option<NonNull<c_void>> = None;
            let mut mscount: c_uint = 0;

            // SAFETY: the port is live and locked.
            unsafe {
                port.decrement_srights();
                if port.srights() == 0 {
                    nsrequest = port.nsrequest();
                    if nsrequest.is_some() {
                        port.set_nsrequest(None);
                        mscount = port.mscount();
                    }
                }

                let name = if port.receiver() == space.as_ptr() {
                    port.receiver_name()
                } else {
                    MACH_PORT_NAME_NULL
                };

                port.unlock();

                if let Some(nsrequest) = nsrequest {
                    ipc_notify::no_senders(nsrequest, mscount);
                }

                name
            }
        }
        Some(MsgTypeName::MoveSendOnce) => {
            let port = unsafe { IpcPort::from_raw(object) };

            // SAFETY: the port is live and locked.
            unsafe {
                if port.receiver() == space.as_ptr() {
                    port.decrement_sorights();
                    let name = port.receiver_name();
                    port.unlock();
                    name
                } else {
                    port.increment_references();
                    port.unlock();
                    ipc_notify::send_once(port.as_non_null());
                    MACH_PORT_NAME_NULL
                }
            }
        }
        _ => strange_rights(
            "ipc_object_copyout_dest",
            "ipc_object_copyout_dest: strange rights",
        ),
    }
}

/// Moves the right `oname` names in `space` to `nname`.
///
/// # Safety
///
/// `space` must be live and nothing may be locked.
pub(crate) unsafe fn rename(
    space: IpcSpace,
    oname: c_uint,
    nname: c_uint,
) -> Result<(), Error> {
    unsafe { space.lock_write() };

    // SAFETY: the space lock is held.
    let nentry = match unsafe { ipc_entry::alloc_name(space, nname) } {
        Ok(entry) => entry,
        Err(error) => {
            // SAFETY: the space lock is held.
            unsafe { space.lock_done() };
            return Err(error);
        }
    };

    // SAFETY: `ipc_right::inuse` unlocks the space when the entry is in use.
    if unsafe { ipc_right::inuse(space, nentry) } {
        return Err(Error::NameExists);
    }

    // SAFETY: the space is live, active, and write-locked.
    let oentry = if oname == nname {
        None
    } else {
        // SAFETY: the space is live, active, and write-locked.
        unsafe { space.entry_lookup(oname) }
    };
    let Some(oentry) = oentry else {
        // SAFETY: the space lock is held and `nentry` is live.
        unsafe {
            ipc_entry::dealloc(space, nname, nentry);
            space.lock_done();
        }
        return Err(Error::InvalidName);
    };

    // SAFETY: the space is write-locked and both entries are live;
    // `ipc_right::rename` unlocks the space.
    unsafe { ipc_right::rename(space, oname, oentry, nname, nentry) };
    Ok(())
}

/// The disposition a right carried with `msgt_name` arrives with.
///
/// # Panics
///
/// Halts through [`kpanic!`] when `msgt_name` is not one of the names the
/// C accepted, which the C `panic()`ed on.
pub(crate) fn copyin_type(msgt_name: c_uint) -> c_uint {
    MsgTypeName::from_u32(msgt_name).map_or_else(
        || {
            strange_rights(
                "ipc_object_copyin_type",
                "ipc_object_copyin_type: strange rights",
            )
        },
        |name| name.received() as c_uint,
    )
}

/// Destroys a naked capability, consuming one reference to the port.
///
/// # Safety
///
/// `port` must be a live port of the kind `name` describes, and the caller
/// must own the one right the destruction consumes.
unsafe fn destroy(port: IpcPort, name: MsgTypeName) {
    match name {
        MsgTypeName::MoveReceive => unsafe {
            crate::ipc::ipc_port::release_receive(port);
        },
        MsgTypeName::MoveSend => unsafe {
            crate::ipc::ipc_port::release_send(port);
        },
        MsgTypeName::MoveSendOnce => unsafe {
            ipc_notify::send_once(port.as_non_null());
        },
        MsgTypeName::Null
        | MsgTypeName::CopySend
        | MsgTypeName::MakeSend
        | MsgTypeName::MakeSendOnce => strange_rights(
            "ipc_object_destroy",
            "ipc_object_destroy: strange rights",
        ),
    }
}

/// Releases a right to `object` a message carried with `msgt_name`.
///
/// # Safety
///
/// `object` must be a live `ipc_object` of the port kind, and the caller must
/// own the one reference the destruction consumes.
pub(crate) unsafe fn destroy_object(object: *mut c_void, msgt_name: c_uint) {
    let port = IpcPort(unsafe { NonNull::new_unchecked(object) });

    match MsgTypeName::from_u32(msgt_name) {
        Some(name) => {
            unsafe { destroy(port, name) };
        }
        None => strange_rights(
            "ipc_object_destroy",
            "ipc_object_destroy: strange rights",
        ),
    }
}

/// The `kmem_cache_init()` calls `ipc_bootstrap()` makes for the two object
/// caches.
pub(crate) fn init_caches() {
    // SAFETY: `ipc_bootstrap()` runs once, before any object exists.
    unsafe {
        let caches = ptr::addr_of_mut!(IPC_OBJECT_CACHES).cast::<KmemCache>();
        kmem_cache_init(
            caches.add(IOT_PORT),
            c"ipc_port".as_ptr(),
            size_of::<crate::ipc::IpcPortRecord>(),
            0,
            None,
            0,
        );
        kmem_cache_init(
            caches.add(IOT_PORT_SET),
            c"ipc_pset".as_ptr(),
            size_of::<IpcTarget>(),
            0,
            None,
            0,
        );
    }
}
