// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/mach_port.c:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The port calls.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::PAGE_SIZE;
use crate::ipc::error::Error;
use crate::ipc::ipc_init;
use crate::ipc::ipc_object::{self, copyin_type};
use crate::ipc::ipc_port;
use crate::ipc::ipc_pset;
use crate::ipc::ipc_right;
use crate::ipc::{IE_BITS_TYPE_MASK, IpcEntry, IpcPort, IpcSpace, IpcTarget};
use crate::kern::console::{CStrArg, kprint};
use crate::kern::debug::{kpanic, soft_debugger};
use crate::kern::ipc_kobject::set_locked;
use crate::kern::task::current_task;
use crate::vm::error::Error as VmError;
use crate::vm::types::VmProt;
use crate::vm::vm_kern;
use crate::vm::vm_map::{VmMapCopy, round_page};
use crate::vm::vm_user;
use core::ffi::{CStr, c_char, c_int, c_uint, c_ulong, c_void};
use core::mem::{align_of, offset_of, size_of, size_of_val};
use core::ptr::{self, NonNull};
use core::slice;
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// The name no entry holds.
const MACH_PORT_NAME_NULL: c_uint = 0;
/// The receive right, as [`translate_receive`] asks `ipc_object::translate`
/// for it.
const MACH_PORT_RIGHT_RECEIVE: c_uint = 1;
/// The largest queue limit [`set_qlimit`] accepts.
const MACH_PORT_QLIMIT_MAX: c_uint = 16;
/// No kernel-object type.
const MACH_PORT_KTYPE_NONE: c_uint = 0;
/// The only other kernel-object type [`set_ktype`] accepts.
const MACH_PORT_KTYPE_USER_DEVICE: c_uint = 28;

/// The type bits of the send and send-once rights.
const MACH_PORT_TYPE_SEND_RIGHTS: u32 = (1 << 16) | (1 << 18);
/// The type bit of a receive right.
const MACH_PORT_TYPE_RECEIVE: u32 = 1 << 17;
/// The type bit of a port set.
const MACH_PORT_TYPE_PORT_SET: u32 = 1 << 19;
/// The type bit of a dead name.
const MACH_PORT_TYPE_DEAD_NAME: u32 = 1 << 20;
/// The type bit reported when a dead-name request is outstanding.
const MACH_PORT_TYPE_DNREQUEST: u32 = 0x8000_0000;
/// The type bit reported when a msg-accepted request is outstanding.
const MACH_PORT_TYPE_MAREQUEST: u32 = 0x4000_0000;
/// The msg-accepted bit of an entry.
const IE_BITS_MAREQUEST: u32 = 0x0020_0000;

/// A port bound to no kernel object.
const IKOT_NONE: c_uint = 0;
/// The kernel-object type of a user device port.
const IKOT_USER_DEVICE: c_uint = 28;

/// `MACH_MSG_TYPE_MOVE_RECEIVE`: the first port type name.
const MOVE_RECEIVE: c_uint = 16;
/// `MACH_MSG_TYPE_MOVE_SEND_ONCE`: the last name
/// `MACH_MSG_TYPE_PORT_ANY_RIGHT` accepts.
const MOVE_SEND_ONCE: c_uint = 18;
/// `MACH_MSG_TYPE_MAKE_SEND_ONCE`: the last name `MACH_MSG_TYPE_PORT_ANY`
/// accepts.
const MAKE_SEND_ONCE: c_uint = 21;

/// The message id of a port-destroyed notification: a receive right was
/// deallocated.
const MACH_NOTIFY_PORT_DESTROYED: c_int = 0o100 + 5;
/// The message id of a no-senders notification: a receive right has no extant
/// send rights.
const MACH_NOTIFY_NO_SENDERS: c_int = 0o100 + 6;
/// The message id of a dead-name notification: a send or send-once right died,
/// leaving a dead name.
const MACH_NOTIFY_DEAD_NAME: c_int = 0o100 + 0o10;

/// The dead-object pointer, all bits set.
const IO_DEAD: *mut c_void = usize::MAX as *mut c_void;

/// The debug switch the bogus-name diagnostics check.
pub(crate) static MACH_PORT_DEALLOCATE_DEBUG: AtomicI32 = AtomicI32::new(0);

/// `mach_port_status_t`: the record [`get_receive_status`] fills in.
#[repr(C)]
#[allow(missing_docs)]
pub struct MachPortStatus {
    pub mps_pset: c_uint,
    pub mps_seqno: c_uint,
    pub mps_mscount: c_uint,
    pub mps_qlimit: c_uint,
    pub mps_msgcount: c_uint,
    pub mps_sorights: c_uint,
    pub mps_srights: c_int,
    pub mps_pdrequest: c_int,
    pub mps_nsrequest: c_int,
}

const _: () = {
    assert!(size_of::<MachPortStatus>() == 36);
    assert!(align_of::<MachPortStatus>() == 4);
    assert!(offset_of!(MachPortStatus, mps_pset) == 0);
    assert!(offset_of!(MachPortStatus, mps_seqno) == 4);
    assert!(offset_of!(MachPortStatus, mps_mscount) == 8);
    assert!(offset_of!(MachPortStatus, mps_qlimit) == 12);
    assert!(offset_of!(MachPortStatus, mps_msgcount) == 16);
    assert!(offset_of!(MachPortStatus, mps_sorights) == 20);
    assert!(offset_of!(MachPortStatus, mps_srights) == 24);
    assert!(offset_of!(MachPortStatus, mps_pdrequest) == 28);
    assert!(offset_of!(MachPortStatus, mps_nsrequest) == 32);
};

/// The `MACH_PORT_RIGHT_*` values the port calls accept.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PortRight {
    Send = 0,
    Receive = 1,
    SendOnce = 2,
    PortSet = 3,
    DeadName = 4,
}

impl PortRight {
    /// The right a wire value names, or `None` for the values the C's
    /// `right >= MACH_PORT_RIGHT_NUMBER` checks rejected.
    const fn from_u32(right: c_uint) -> Option<Self> {
        match right {
            0 => Some(Self::Send),
            1 => Some(Self::Receive),
            2 => Some(Self::SendOnce),
            3 => Some(Self::PortSet),
            4 => Some(Self::DeadName),
            _ => None,
        }
    }
}

/// The `mach_port_names()` result: the two map copies and the count both
/// arrays hold.
pub(crate) struct PortNames {
    pub(crate) names: Option<NonNull<VmMapCopy>>,
    pub(crate) types: Option<NonNull<VmMapCopy>>,
    pub(crate) count: c_uint,
}

/// The `mach_port_get_set_status()` result.
pub(crate) struct SetStatus {
    pub(crate) members: Option<NonNull<VmMapCopy>>,
    pub(crate) count: c_uint,
}

/// A name is valid when it is neither null nor dead.
const fn port_name_valid(name: c_uint) -> bool {
    name != 0 && name != c_uint::MAX
}

/// The type bit of `right`: `1 << (right + 16)`.
const fn mach_port_type(right: c_uint) -> c_uint {
    // The C shifts by `right + 16`; the target masks the count the same way.
    1u32.wrapping_shl(right.wrapping_add(16))
}

/// An object is valid when it is neither null nor dead.
fn io_valid(object: *mut c_void) -> bool {
    !object.is_null() && !ptr::eq(object, IO_DEAD)
}

/// A table count as an index.  `usize` is at least as wide as `c_uint` on both
/// targets, so the widening cannot lose anything.
const fn as_index(count: c_uint) -> usize {
    count as usize
}

/// Whether `one` happened before `two` across the counter's 32-bit wrap.
const fn timestamp_order(one: c_uint, two: c_uint) -> bool {
    // The C casts the wrapping difference to a signed int, so only the sign
    // bit matters; this is the same reinterpretation.
    (one.wrapping_sub(two) as c_int) < 0
}

/// The [`Error`] a VM map error stands for.
const fn map_error(error: VmError) -> Error {
    match error {
        VmError::InvalidAddress => Error::InvalidAddress,
        VmError::NoSpace => Error::NoSpace,
        VmError::InvalidArgument => Error::InvalidArgument,
        VmError::ResourceShortage => Error::ResourceShortage,
        _ => Error::Failure,
    }
}

/// The C `printf_once` macro: print one literal once, as the per-site static
/// did.
fn printf_once(printed: &AtomicBool, message: &CStr) {
    if !printed.load(Ordering::Relaxed) {
        printed.store(true, Ordering::Relaxed);

        kprint!("{}", CStrArg::from(message));
    }
}

/// The C's "task ... a bogus port ..." diagnostic, for the two routines that
/// share its wording.
///
/// # Safety
///
/// `space` must be live.
unsafe fn report_bogus_port(space: IpcSpace, name: c_uint, action: &CStr) {
    let task = current_task().as_ptr();
    if !port_name_valid(name) || space.as_ptr() != unsafe { (*task).itk_space }
    {
        return;
    }

    // SAFETY: the task is live and its name array is NUL-terminated within
    // the size the format's precision reads.
    let (name_len, task_name) = unsafe {
        (
            size_of_val(&(*task).name),
            CStrArg::from_ptr(ptr::addr_of!((*task).name).cast::<c_char>()),
        )
    };
    kprint!(
        "task {:.*} {} a bogus port {}, most probably a bug.\n",
        name_len,
        task_name,
        CStrArg::from(action),
        c_ulong::from(name),
    );

    if MACH_PORT_DEALLOCATE_DEBUG.load(Ordering::Relaxed) != 0 {
        // SAFETY: the C string literal is NUL-terminated.
        unsafe { soft_debugger(c"mach_port_deallocate".as_ptr()) };
    }
}

/// The write lookup of the routines that report a bogus name.
///
/// # Safety
///
/// `space` must be live and unlocked, and `name` is a plain value.
unsafe fn lookup_write(
    space: IpcSpace,
    name: c_uint,
) -> Result<*mut IpcEntry, Error> {
    unsafe { ipc_right::lookup_write(space, name) }
}

/// Appends the name and type of `entry` to the arrays [`names`] fills.
///
/// # Safety
///
/// `entry` must be a live entry of the read-locked space, and `names` and
/// `types` must have room for `*actual` plus one.
unsafe fn names_push(
    timestamp: c_uint,
    entry: *mut IpcEntry,
    names: &mut [c_uint],
    types: &mut [c_uint],
    actual: &mut c_uint,
) {
    let mut bits = unsafe { (*entry).bits() };
    let mut request = unsafe { (*entry).request() };

    if bits & MACH_PORT_TYPE_SEND_RIGHTS != 0 {
        // SAFETY: a send-rights entry names a live port.
        let port = IpcPort::valid(unsafe { (*entry).object() });

        if let Some(port) = port {
            // SAFETY: the space is read-locked and the entry's right keeps
            // the port alive, so this is the only lock taken.
            let died = unsafe {
                port.lock();
                let died = !port.is_active()
                    && timestamp_order(port.timestamp(), timestamp);
                port.unlock();
                died
            };

            if died {
                bits &= !(IE_BITS_TYPE_MASK | IE_BITS_MAREQUEST);
                bits |= MACH_PORT_TYPE_DEAD_NAME;
                if request != 0 {
                    bits = bits.wrapping_add(1);
                }
                request = 0;
            }
        }
    }

    let mut kind = bits & IE_BITS_TYPE_MASK;
    if request != 0 {
        kind |= MACH_PORT_TYPE_DNREQUEST;
    }
    if bits & IE_BITS_MAREQUEST != 0 {
        kind |= MACH_PORT_TYPE_MAREQUEST;
    }

    let index = *actual;
    if let (Some(names), Some(types)) = (
        names.get_mut(as_index(index)),
        types.get_mut(as_index(index)),
    ) {
        *names = unsafe { (*entry).name() };
        *types = kind;
    }
    *actual = index.wrapping_add(1);
}

/// The C's allocation loop of `mach_port_names()`: keep two kernel-map
/// regions large enough for the space's bounds.
///
/// # Safety
///
/// `space` must be live and unlocked; may allocate memory.
unsafe fn names_buffers(
    space: IpcSpace,
    map: *mut crate::vm::vm_map::VmMap,
) -> Result<(VmSize, VmOffset, VmOffset, c_uint), Error> {
    static FIRST_NO_ROOM: AtomicBool = AtomicBool::new(false);
    static SECOND_NO_ROOM: AtomicBool = AtomicBool::new(false);

    let mut size: VmSize = 0;
    let mut addr1: VmOffset = 0;
    let mut addr2: VmOffset = 0;
    let bound: c_uint;

    loop {
        unsafe { space.lock_read() };

        // SAFETY: the space is live and read-locked.
        if !unsafe { space.is_active() } {
            // SAFETY: the space is live and read-locked.
            unsafe { space.unlock_read() };
            if size != 0 {
                // SAFETY: the two regions came from the allocations below.
                unsafe {
                    vm_kern::kmem_free(&mut *map, addr1, size)
                        .unwrap_or_else(|_| kpanic!("kmem_free", "kmem_free"));
                    vm_kern::kmem_free(&mut *map, addr2, size)
                        .unwrap_or_else(|_| kpanic!("kmem_free", "kmem_free"));
                }
            }
            return Err(Error::DeadSpace);
        }

        // The table size is 32 bits wide, so the bound truncates the same way.
        // SAFETY: the space is live and read-locked.
        let bound_now = unsafe { (*space.record()).size as c_uint };
        let size_needed =
            round_page(as_index(bound_now) * size_of::<c_uint>());

        if size_needed <= size {
            bound = bound_now;
            break;
        }

        // SAFETY: the space is live and read-locked.
        unsafe { space.unlock_read() };

        if size != 0 {
            // SAFETY: the two regions came from the allocations below.
            unsafe {
                vm_kern::kmem_free(&mut *map, addr1, size)
                    .unwrap_or_else(|_| kpanic!("kmem_free", "kmem_free"));
                vm_kern::kmem_free(&mut *map, addr2, size)
                    .unwrap_or_else(|_| kpanic!("kmem_free", "kmem_free"));
            }
        }
        size = size_needed;

        // SAFETY: `ipc_kernel_map` is the live kernel map, nothing is
        // locked, and `addr1` is this call's live local.
        if unsafe { vm_user::allocate(&mut *map, &mut addr1, size, true) }
            .is_err()
        {
            printf_once(&FIRST_NO_ROOM, c"no more room in ipc_kernel_map\n");
            return Err(Error::ResourceShortage);
        }

        if unsafe { vm_user::allocate(&mut *map, &mut addr2, size, true) }
            .is_err()
        {
            printf_once(&SECOND_NO_ROOM, c"no more room in ipc_kernel_map\n");
            // SAFETY: `addr1` came from the allocation above.
            unsafe {
                vm_kern::kmem_free(&mut *map, addr1, size)
                    .unwrap_or_else(|_| kpanic!("kmem_free", "kmem_free"));
            }
            return Err(Error::ResourceShortage);
        }

        // The C ignored both statuses; the regions were just allocated from
        // the kernel map.
        // SAFETY: the regions are live in the live kernel map.
        unsafe {
            let _ = (*map).pageable(
                addr1,
                addr1.wrapping_add(size),
                VmProt::READ | VmProt::WRITE,
                true,
                true,
            );
            let _ = (*map).pageable(
                addr2,
                addr2.wrapping_add(size),
                VmProt::READ | VmProt::WRITE,
                true,
                true,
            );
        }
    }

    Ok((size, addr1, addr2, bound))
}

/// The names and types of a space's rights, as two map copies.
///
/// # Safety
///
/// `space` must be null or live and unlocked; may allocate memory.  The
/// returned copies hold their own references.
pub(crate) unsafe fn names(
    space: Option<IpcSpace>,
) -> Result<PortNames, Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    let map = ipc_init::ipc_kernel_map();

    let (size, addr1, addr2, bound) = unsafe { names_buffers(space, map) }?;
    // The space is read-locked and active, and `bound` bounds its entries.

    let mut actual: c_uint = 0;
    let timestamp = ipc_port::timestamp();
    // SAFETY: each region holds `bound` names, and the space is read-locked.
    let names = unsafe {
        slice::from_raw_parts_mut(addr1 as *mut c_uint, as_index(bound))
    };
    let types = unsafe {
        slice::from_raw_parts_mut(addr2 as *mut c_uint, as_index(bound))
    };

    // SAFETY: the space is live and read-locked; the map address is formed
    // without reading.
    let map_ptr = unsafe { ptr::addr_of_mut!((*space.record()).map) };
    // SAFETY: the space is read-locked, so its map is stable; each walk
    // returns a live entry once.
    for (_key, found) in unsafe { (*map_ptr).iter() } {
        let entry = found.as_ptr();

        // SAFETY: a walked pointer is a live entry.
        if unsafe { (*entry).bits() } & IE_BITS_TYPE_MASK != 0 {
            // SAFETY: `bound` bounds the entries the walk can yield, so the
            // slices have room, and the entry is live under the space lock.
            unsafe { names_push(timestamp, entry, names, types, &mut actual) };
        }
    }

    // SAFETY: the space is live and read-locked.
    unsafe { space.unlock_read() };

    if actual == 0 {
        if size != 0 {
            // SAFETY: the two regions came from the allocations above.
            unsafe {
                vm_kern::kmem_free(&mut *map, addr1, size)
                    .unwrap_or_else(|_| kpanic!("kmem_free", "kmem_free"));
                vm_kern::kmem_free(&mut *map, addr2, size)
                    .unwrap_or_else(|_| kpanic!("kmem_free", "kmem_free"));
            }
        }
        return Ok(PortNames {
            names: None,
            types: None,
            count: 0,
        });
    }

    let size_used = round_page(as_index(actual) * size_of::<c_uint>());

    // The C ignored both statuses; the copies below consume the regions.
    // SAFETY: the regions are live in the live kernel map.
    unsafe {
        let _ = (*map).pageable(
            addr1,
            addr1.wrapping_add(size_used),
            VmProt::NONE,
            true,
            true,
        );
        let _ = (*map).pageable(
            addr2,
            addr2.wrapping_add(size_used),
            VmProt::NONE,
            true,
            true,
        );
    }

    // SAFETY: each region holds `actual` names; the C left the copies
    // uninitialized when one of these failed, which cannot be expressed.
    let names_copy =
        unsafe { (*map).copyin(addr1, size_used, true) }.map_err(map_error)?;
    let types_copy =
        unsafe { (*map).copyin(addr2, size_used, true) }.map_err(map_error)?;

    if size_used != size {
        // SAFETY: the tails of the allocations are unused.
        unsafe {
            vm_kern::kmem_free(
                &mut *map,
                addr1.wrapping_add(size_used),
                size - size_used,
            )
            .unwrap_or_else(|_| kpanic!("kmem_free", "kmem_free"));
            vm_kern::kmem_free(
                &mut *map,
                addr2.wrapping_add(size_used),
                size - size_used,
            )
            .unwrap_or_else(|_| kpanic!("kmem_free", "kmem_free"));
        }
    }

    Ok(PortNames {
        names: Some(names_copy),
        types: Some(types_copy),
        count: actual,
    })
}

/// The type bits of the named right.
///
/// # Safety
///
/// `space` must be null or live and unlocked.
pub(crate) unsafe fn port_type(
    space: Option<IpcSpace>,
    name: c_uint,
) -> Result<c_uint, Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    let entry = unsafe { lookup_write(space, name) }?;

    // SAFETY: the lookup returned the live entry with the space write-locked;
    // `ipc_right::info` leaves the space locked on success.
    let (type_, _) = unsafe { ipc_right::info(space, name, entry) };

    // SAFETY: the space is live and write-locked.
    unsafe { space.unlock_write() };

    Ok(type_)
}

/// Allocates a right of `right` in `space` under `name`.
///
/// # Safety
///
/// `space` must be null or live and unlocked; may allocate memory.
pub(crate) unsafe fn allocate_name(
    space: Option<IpcSpace>,
    right: c_uint,
    name: c_uint,
) -> Result<(), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    if !port_name_valid(name) {
        return Err(Error::InvalidValue);
    }

    match PortRight::from_u32(right) {
        Some(PortRight::Receive) => {
            let port = ipc_port::alloc_name(space, name)?;

            // SAFETY: the port is locked and the caller holds no reference, so
            // unlocking it is all that is left.
            unsafe { port.unlock() };
            Ok(())
        }
        Some(PortRight::PortSet) => {
            let pset = unsafe { ipc_pset::alloc_name(space, name) }?;

            // SAFETY: a successful allocation returned the port set locked.
            unsafe { (*pset).unlock() };
            Ok(())
        }
        Some(PortRight::DeadName) => unsafe {
            ipc_object::alloc_dead_name(space, name)
        },
        Some(PortRight::Send | PortRight::SendOnce) | None => {
            Err(Error::InvalidValue)
        }
    }
}

/// Allocates a right of `right` in `space` under a fresh name.
///
/// # Safety
///
/// `space` must be null or live and unlocked; may allocate memory.
pub(crate) unsafe fn allocate(
    space: Option<IpcSpace>,
    right: c_uint,
) -> Result<c_uint, Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    match PortRight::from_u32(right) {
        Some(PortRight::Receive) => {
            let (name, port) = ipc_port::alloc(space)?;

            // SAFETY: the port is locked and the caller holds no reference, so
            // unlocking it is all that is left.
            unsafe { port.unlock() };
            Ok(name)
        }
        Some(PortRight::PortSet) => {
            let (name, pset) = unsafe { ipc_pset::alloc(space) }?;

            // SAFETY: a successful allocation returned the port set locked.
            unsafe { (*pset).unlock() };
            Ok(name)
        }
        Some(PortRight::DeadName) => unsafe { ipc_object::alloc_dead(space) },
        Some(PortRight::Send | PortRight::SendOnce) | None => {
            Err(Error::InvalidValue)
        }
    }
}

/// Destroys the right `name` names in `space`.
///
/// # Safety
///
/// `space` must be null or live and unlocked.
pub(crate) unsafe fn destroy(
    space: Option<IpcSpace>,
    name: c_uint,
) -> Result<(), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    let entry = match unsafe { lookup_write(space, name) } {
        Ok(entry) => entry,
        Err(error) => {
            // SAFETY: the space is live and this call runs in a thread
            // context.
            unsafe { report_bogus_port(space, name, c"destroying") };
            return Err(error);
        }
    };

    // SAFETY: the lookup returned the live entry with the space write-locked;
    // `ipc_right::destroy` unlocks the space.
    unsafe { ipc_right::destroy(space, name, entry) };
    Ok(())
}

/// Releases one user reference to the right `name` names in `space`.
///
/// # Safety
///
/// `space` must be null or live and unlocked.
pub(crate) unsafe fn deallocate(
    space: Option<IpcSpace>,
    name: c_uint,
) -> Result<(), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    let entry = match unsafe { lookup_write(space, name) } {
        Ok(entry) => entry,
        Err(error) => {
            // SAFETY: the space is live and this call runs in a thread
            // context.
            unsafe { report_bogus_port(space, name, c"deallocating") };
            return Err(error);
        }
    };

    // SAFETY: the lookup returned the live entry with the space write-locked;
    // `ipc_right::dealloc` unlocks the space.
    unsafe { ipc_right::dealloc(space, name, entry) }
}

/// The user-reference count of `right` in the entry `name` names.
///
/// # Safety
///
/// `space` must be null or live and unlocked.
pub(crate) unsafe fn get_refs(
    space: Option<IpcSpace>,
    name: c_uint,
    right: c_uint,
) -> Result<c_uint, Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };
    let Some(right) = PortRight::from_u32(right) else {
        return Err(Error::InvalidValue);
    };

    let entry = unsafe { lookup_write(space, name) }?;

    // SAFETY: the lookup returned the live entry with the space write-locked;
    // `ipc_right::info` leaves the space locked on success.
    let (type_, urefs) = unsafe { ipc_right::info(space, name, entry) };

    // SAFETY: the space is live and write-locked.
    unsafe { space.unlock_write() };

    if type_ & mach_port_type(right as c_uint) == 0 {
        return Ok(0);
    }

    match right {
        PortRight::SendOnce | PortRight::PortSet | PortRight::Receive => Ok(1),
        PortRight::DeadName | PortRight::Send => Ok(urefs),
    }
}

/// Adds `delta` to the user references of `right` in the entry `name` names.
///
/// # Safety
///
/// `space` must be null or live and unlocked.
pub(crate) unsafe fn mod_refs(
    space: Option<IpcSpace>,
    name: c_uint,
    right: c_uint,
    delta: c_int,
) -> Result<(), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };
    if PortRight::from_u32(right).is_none() {
        return Err(Error::InvalidValue);
    }

    let entry = match unsafe { lookup_write(space, name) } {
        Ok(entry) => entry,
        Err(error) => {
            let task = current_task().as_ptr();
            if port_name_valid(name)
                && space.as_ptr() == unsafe { (*task).itk_space }
            {
                // SAFETY: the task is live and its name array is NUL-terminated
                // within the size the format's precision reads.
                let (name_len, task_name) = unsafe {
                    (
                        size_of_val(&(*task).name),
                        CStrArg::from_ptr(
                            ptr::addr_of!((*task).name).cast::<c_char>(),
                        ),
                    )
                };
                kprint!(
                    "task {:.*} {}creasing a bogus port {} by {}, \
                 most probably a bug.\n",
                    name_len,
                    task_name,
                    CStrArg::from(if delta < 0 { c"de" } else { c"in" }),
                    name,
                    if delta < 0 {
                        delta.wrapping_neg()
                    } else {
                        delta
                    },
                );

                if MACH_PORT_DEALLOCATE_DEBUG.load(Ordering::Relaxed) != 0 {
                    // SAFETY: the C string literal is NUL-terminated.
                    unsafe { soft_debugger(c"mach_port_mod_refs".as_ptr()) };
                }
            }
            return Err(error);
        }
    };

    // SAFETY: the lookup returned the live entry with the space write-locked;
    // `ipc_right::delta` unlocks the space.
    unsafe { ipc_right::delta(space, name, entry, right, delta) }
}

/// Sets the queue limit of the receive right `name` names.
///
/// # Safety
///
/// `space` must be null or live and unlocked.
pub(crate) unsafe fn set_qlimit(
    space: Option<IpcSpace>,
    name: c_uint,
    qlimit: c_uint,
) -> Result<(), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };
    if qlimit > MACH_PORT_QLIMIT_MAX {
        return Err(Error::InvalidValue);
    }

    let port = unsafe { translate_receive(space, name) }?;

    // SAFETY: `translate_receive` returned the live, locked, active port.
    let port = unsafe { IpcPort::from_raw(port) };

    // SAFETY: the port is live, active, and locked; `ipc_port::set_qlimit`
    // leaves it locked for the unlock that follows.
    unsafe {
        ipc_port::set_qlimit(port, qlimit);
        port.unlock();
    }

    Ok(())
}

/// Sets the make-send count of the receive right `name` names.
///
/// # Safety
///
/// `space` must be null or live and unlocked.
pub(crate) unsafe fn set_mscount(
    space: Option<IpcSpace>,
    name: c_uint,
    mscount: c_uint,
) -> Result<(), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    let port = unsafe { translate_receive(space, name) }?;

    // SAFETY: `translate_receive` returned the live, locked, active port.
    let port = unsafe { IpcPort::from_raw(port) };

    // SAFETY: the port is live, active, and locked; the assignment and the
    // unlock follow.
    unsafe {
        port.set_mscount(mscount);
        port.unlock();
    }

    Ok(())
}

/// Sets the sequence number of the receive right `name` names.
///
/// # Safety
///
/// `space` must be null or live and unlocked.
pub(crate) unsafe fn set_seqno(
    space: Option<IpcSpace>,
    name: c_uint,
    seqno: c_uint,
) -> Result<(), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    let port = unsafe { translate_receive(space, name) }?;

    // SAFETY: `translate_receive` returned the live, locked, active port.
    let port = unsafe { IpcPort::from_raw(port) };

    // SAFETY: the port is live, active, and locked; `ipc_port::set_seqno`
    // leaves it locked for the unlock that follows.
    unsafe {
        ipc_port::set_seqno(port, seqno);
        port.unlock();
    }

    Ok(())
}

/// Appends the name of `port` to `names` when it is a member of `pset`.
///
/// # Safety
///
/// `pset` must be a live port set, `port` a live receive port, and `names`
/// must have room for `*actual` plus one.
unsafe fn get_set_status_helper(
    pset: *mut IpcTarget,
    port: *mut c_void,
    maxnames: usize,
    names: &mut [c_uint],
    actual: &mut c_uint,
) {
    let port = unsafe { IpcPort::from_raw(port) };

    let (name, ip_pset) = unsafe {
        port.lock();
        let pair = (port.receiver_name(), port.pset());
        port.unlock();
        pair
    };

    if pset.cast::<c_void>() == ip_pset {
        let index = *actual;
        if as_index(index) < maxnames
            && let Some(slot) = names.get_mut(as_index(index))
        {
            *slot = name;
        }
        *actual = index.wrapping_add(1);
    }
}

/// The members of a port set, as a map copy.
///
/// # Safety
///
/// `space` must be null or live and unlocked; may allocate memory.  The
/// returned copy holds its own reference.
pub(crate) unsafe fn get_set_status(
    space: Option<IpcSpace>,
    name: c_uint,
) -> Result<SetStatus, Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    let map = ipc_init::ipc_kernel_map();
    let mut size: VmSize = PAGE_SIZE;

    let (addr, actual) = loop {
        let mut addr: VmOffset = 0;

        // SAFETY: `ipc_kernel_map` is the live kernel map, nothing is
        // locked, and `addr` is this call's live local.
        if unsafe { vm_user::allocate(&mut *map, &mut addr, size, true) }
            .is_err()
        {
            static NO_ROOM: AtomicBool = AtomicBool::new(false);
            printf_once(&NO_ROOM, c"no more room in ipc_kernel_map\n");
            return Err(Error::ResourceShortage);
        }

        // The C ignored the status; the region was just allocated from the
        // kernel map.
        // SAFETY: the region is live in the live kernel map.
        unsafe {
            let _ = (*map).pageable(
                addr,
                addr.wrapping_add(size),
                VmProt::READ | VmProt::WRITE,
                true,
                true,
            );
        }

        let entry = match unsafe { lookup_write(space, name) } {
            Ok(entry) => entry,
            Err(error) => {
                // SAFETY: the region came from the allocation above.
                unsafe {
                    vm_kern::kmem_free(&mut *map, addr, size)
                        .unwrap_or_else(|_| kpanic!("kmem_free", "kmem_free"));
                }
                return Err(error);
            }
        };

        // SAFETY: the lookup returned the live entry.
        if unsafe { (*entry).bits() } & IE_BITS_TYPE_MASK
            != MACH_PORT_TYPE_PORT_SET
        {
            // SAFETY: the space is live and write-locked.
            unsafe {
                space.unlock_write();
                vm_kern::kmem_free(&mut *map, addr, size)
                    .unwrap_or_else(|_| kpanic!("kmem_free", "kmem_free"));
            }
            return Err(Error::InvalidRight);
        }

        // SAFETY: a port-set entry names a live port set.
        let pset = unsafe { (*entry).object() };
        let maxnames = size / size_of::<c_uint>();
        // SAFETY: the allocation holds `maxnames` names, and the space is
        // write-locked.
        let names = unsafe {
            slice::from_raw_parts_mut(addr as *mut c_uint, maxnames)
        };

        // SAFETY: the space is live and write-locked, and the allocation
        // holds `maxnames` names.
        let actual = unsafe {
            set_members(pset.cast::<IpcTarget>(), maxnames, names, space)
        };

        // SAFETY: the space is live and write-locked.
        unsafe { space.unlock_write() };

        if as_index(actual) <= maxnames {
            break (addr, actual);
        }

        // SAFETY: the region came from the allocation above.
        unsafe {
            vm_kern::kmem_free(&mut *map, addr, size)
                .unwrap_or_else(|_| kpanic!("kmem_free", "kmem_free"));
        }
        size = round_page(as_index(actual) * size_of::<c_uint>()) + PAGE_SIZE;
    };

    if actual == 0 {
        // SAFETY: the region came from the allocation above.
        unsafe {
            vm_kern::kmem_free(&mut *map, addr, size)
                .unwrap_or_else(|_| kpanic!("kmem_free", "kmem_free"));
        }
        return Ok(SetStatus {
            members: None,
            count: 0,
        });
    }

    let size_used = round_page(as_index(actual) * size_of::<c_uint>());

    // The C ignored the status; the copy below consumes the region.
    // SAFETY: the region is live in the live kernel map.
    unsafe {
        let _ = (*map).pageable(
            addr,
            addr.wrapping_add(size_used),
            VmProt::NONE,
            true,
            true,
        );
    }

    // SAFETY: the region holds `actual` names; the C left the copy
    // uninitialized when this failed, which cannot be expressed.
    let memory =
        unsafe { (*map).copyin(addr, size_used, true) }.map_err(map_error)?;

    if size_used != size {
        // SAFETY: the tail of the allocation is unused.
        unsafe {
            vm_kern::kmem_free(
                &mut *map,
                addr.wrapping_add(size_used),
                size - size_used,
            )
            .unwrap_or_else(|_| kpanic!("kmem_free", "kmem_free"));
        }
    }

    Ok(SetStatus {
        members: Some(memory),
        count: actual,
    })
}

/// Collect the names of the ports that are members of `pset`, the C's walk
/// over the write-locked space's map.
///
/// # Safety
///
/// The space must be live and write-locked, `pset` must be a live port set,
/// and `names` must have room for `maxnames` entries.
unsafe fn set_members(
    pset: *mut IpcTarget,
    maxnames: usize,
    names: &mut [c_uint],
    space: IpcSpace,
) -> c_uint {
    let mut actual: c_uint = 0;

    // SAFETY: the space is live and write-locked; the map address is formed
    // without reading.
    let map_ptr = unsafe { ptr::addr_of_mut!((*space.record()).map) };
    // SAFETY: the space is write-locked, so its map is stable; each walk
    // returns a live entry once.
    for (_key, found) in unsafe { (*map_ptr).iter() } {
        let entry = found.as_ptr();

        // SAFETY: a walked pointer is a live entry.
        if unsafe { (*entry).bits() } & MACH_PORT_TYPE_RECEIVE != 0 {
            // SAFETY: a receive entry names a live port.
            let port = unsafe { (*entry).object() };

            // SAFETY: the entry's receive right keeps the port alive for
            // the walk.
            unsafe {
                get_set_status_helper(
                    pset,
                    port,
                    maxnames,
                    names,
                    &mut actual,
                );
            }
        }
    }

    actual
}

/// Moves the receive right `member` names into the port set `after` names, or
/// out of its set.
///
/// # Safety
///
/// `space` must be null or live and unlocked.
pub(crate) unsafe fn move_member(
    space: Option<IpcSpace>,
    member: c_uint,
    after: c_uint,
) -> Result<(), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    let entry = unsafe { lookup_write(space, member) }?;

    // SAFETY: the lookup returned the live entry.
    if unsafe { (*entry).bits() } & MACH_PORT_TYPE_RECEIVE == 0 {
        // SAFETY: the space is live and write-locked.
        unsafe { space.unlock_write() };
        return Err(Error::InvalidRight);
    }

    let port = unsafe { (*entry).object() };

    let nset = if after == MACH_PORT_NAME_NULL {
        ptr::null_mut()
    } else {
        // SAFETY: the space is live and write-locked.
        let Some(entry) = (unsafe { space.entry_lookup(after) }) else {
            // SAFETY: the space is live and write-locked.
            unsafe { space.unlock_write() };
            return Err(Error::InvalidName);
        };

        // SAFETY: a looked-up entry is live.
        if unsafe { (*entry).bits() } & MACH_PORT_TYPE_PORT_SET == 0 {
            // SAFETY: the space is live and write-locked.
            unsafe { space.unlock_write() };
            return Err(Error::InvalidRight);
        }

        // SAFETY: a port-set entry names a live port set.
        unsafe { (*entry).object() }
    };

    // SAFETY: the lookup left the space write-locked and active, the receive
    // entry named a live port, and any port-set entry named a live set;
    // `ipc_pset::move_between` unlocks the space.
    unsafe {
        ipc_pset::move_between(
            space,
            IpcPort::from_raw(port),
            NonNull::new(nset.cast::<IpcTarget>()),
        )
    }
}

/// The status of the receive right `name` names.
///
/// # Safety
///
/// `space` must be null or live and unlocked.
pub(crate) unsafe fn get_receive_status(
    space: Option<IpcSpace>,
    name: c_uint,
) -> Result<MachPortStatus, Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    let port = unsafe { translate_receive(space, name) }?;

    // SAFETY: `translate_receive` returned the live, locked, active port.
    let port = unsafe { IpcPort::from_raw(port) };

    // SAFETY: the port is live, active, and locked; the port-set and message
    // queue locks come and go under it, as the C's do.
    let (mps_pset, mps_seqno) = unsafe {
        let pset = port.pset();
        if pset.is_null() {
            let mqueue = port.messages();
            (*mqueue).lock();
            let seqno = port.seqno();
            (*mqueue).unlock();
            (MACH_PORT_NAME_NULL, seqno)
        } else {
            let target = pset.cast::<IpcTarget>();
            (*target).lock();
            if (*target).is_active() {
                let name = (*target).local_name();
                let mqueue = (*target).messages();
                (*mqueue).lock();
                let seqno = port.seqno();
                (*mqueue).unlock();
                (*target).unlock();
                (name, seqno)
            } else {
                ipc_pset::remove(target, port);
                IpcTarget::check_unlock(target);
                let mqueue = port.messages();
                (*mqueue).lock();
                let seqno = port.seqno();
                (*mqueue).unlock();
                (MACH_PORT_NAME_NULL, seqno)
            }
        }
    };

    let status = MachPortStatus {
        mps_pset,
        mps_seqno,
        // SAFETY: the port is live and locked.
        mps_mscount: unsafe { port.mscount() },
        mps_qlimit: unsafe { port.qlimit() },
        mps_msgcount: unsafe { port.msgcount() },
        mps_sorights: unsafe { port.sorights() },
        mps_srights: c_int::from(unsafe { port.srights() } > 0),
        mps_pdrequest: c_int::from(unsafe { port.pdrequest() }.is_some()),
        mps_nsrequest: c_int::from(unsafe { port.nsrequest() }.is_some()),
    };

    // SAFETY: the port is live, active, and locked; only the unlock is left.
    unsafe { port.unlock() };

    Ok(status)
}

/// Sets the protected payload of the receive right `name` names.
///
/// # Safety
///
/// `space` must be null or live and unlocked.
pub(crate) unsafe fn set_protected_payload(
    space: Option<IpcSpace>,
    name: c_uint,
    payload: usize,
) -> Result<(), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    let port = unsafe { translate_receive(space, name) }?;

    // SAFETY: `translate_receive` returned the live, locked, active port.
    let port = unsafe { IpcPort::from_raw(port) };

    // SAFETY: the port is live, active, and locked;
    // `ipc_port::set_protected_payload` leaves it locked for the unlock that
    // follows.
    unsafe {
        ipc_port::set_protected_payload(port, payload);
        port.unlock();
    }

    Ok(())
}

/// Clears the protected payload of the receive right `name` names.
///
/// # Safety
///
/// `space` must be null or live and unlocked.
pub(crate) unsafe fn clear_protected_payload(
    space: Option<IpcSpace>,
    name: c_uint,
) -> Result<(), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    let port = unsafe { translate_receive(space, name) }?;

    // SAFETY: `translate_receive` returned the live, locked, active port.
    let port = unsafe { IpcPort::from_raw(port) };

    // SAFETY: the port is live, active, and locked;
    // `ipc_port::clear_protected_payload` leaves it locked for the unlock that
    // follows.
    unsafe {
        ipc_port::clear_protected_payload(port);
        port.unlock();
    }

    Ok(())
}

/// Sets the kernel-object type of the receive right `name` names.
///
/// # Safety
///
/// `space` must be null or live and unlocked.
pub(crate) unsafe fn set_ktype(
    space: Option<IpcSpace>,
    name: c_uint,
    right: c_uint,
    ktype: c_uint,
) -> Result<(), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };
    if ktype != MACH_PORT_KTYPE_NONE && ktype != MACH_PORT_KTYPE_USER_DEVICE {
        return Err(Error::InvalidArgument);
    }

    let object = unsafe { ipc_object::translate(space, name, right) }?;

    // SAFETY: the translate returned the live, locked object.
    let port = unsafe { IpcPort::from_raw(object) };

    // SAFETY: the port is live and locked.
    let kind = unsafe { port.kotype() };

    let result = if kind == IKOT_NONE || kind == IKOT_USER_DEVICE {
        // SAFETY: the port is live and locked, and `ktype` is one of the two
        // values the check above accepted.
        unsafe {
            set_locked(
                port.as_ptr(),
                0,
                if ktype == MACH_PORT_KTYPE_USER_DEVICE {
                    IKOT_USER_DEVICE
                } else {
                    IKOT_NONE
                },
            );
        }
        Ok(())
    } else {
        Err(Error::InvalidArgument)
    };

    // SAFETY: the port is live, active, and locked; only the unlock is left.
    unsafe { port.unlock() };

    result
}

/// Moves the right `oname` names in `space` to `nname`.
///
/// # Safety
///
/// `space` must be null or live and unlocked.
pub(crate) unsafe fn rename(
    space: Option<IpcSpace>,
    oname: c_uint,
    nname: c_uint,
) -> Result<(), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    if !port_name_valid(nname) {
        return Err(Error::InvalidValue);
    }

    unsafe { ipc_object::rename(space, oname, nname) }
}

/// Inserts the right `poly`, with the disposition `poly_poly`, into `space`
/// under `name`.
///
/// # Safety
///
/// `space` must be null or live; `poly` must be `IO_NULL`, `IO_DEAD` or a
/// live `ipc_object` the caller holds one reference to, which the call
/// consumes on success.
pub(crate) unsafe fn insert_right(
    space: Option<IpcSpace>,
    name: c_uint,
    poly: *mut c_void,
    poly_poly: c_uint,
) -> Result<(), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    if !port_name_valid(name)
        || !(MOVE_RECEIVE..=MOVE_SEND_ONCE).contains(&poly_poly)
    {
        return Err(Error::InvalidValue);
    }

    if !io_valid(poly) {
        return Err(Error::InvalidCapability);
    }

    unsafe { ipc_object::copyout_name(space, poly, poly_poly, false, name) }
}

/// Extracts the right `name` names from `space`, as `msgt_name` disposes it.
///
/// # Safety
///
/// `space` must be null or live.
pub(crate) unsafe fn extract_right(
    space: Option<IpcSpace>,
    name: c_uint,
    msgt_name: c_uint,
) -> Result<(*mut c_void, c_uint), Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    if !(MOVE_RECEIVE..=MAKE_SEND_ONCE).contains(&msgt_name) {
        return Err(Error::InvalidValue);
    }

    let object = unsafe { ipc_object::copyin(space, name, msgt_name) }?;

    Ok((object, copyin_type(msgt_name)))
}

/// The receive right `name` names in `space`, locked.
///
/// # Safety
///
/// `space` must be live and unlocked.
unsafe fn translate_receive(
    space: IpcSpace,
    name: c_uint,
) -> Result<*mut c_void, Error> {
    unsafe { ipc_object::translate(space, name, MACH_PORT_RIGHT_RECEIVE) }
}

/// Registers `notify` for the notification `id` on the right `name` names,
/// returning the previously registered one.
///
/// # Safety
///
/// `space` must be null or live; `notify` must be `IP_NULL`, `IP_DEAD` or a
/// live `ipc_port`, and on success the call consumes it.
pub(crate) unsafe fn request_notification(
    space: Option<IpcSpace>,
    name: c_uint,
    id: c_int,
    sync: c_uint,
    notify: Option<NonNull<c_void>>,
) -> Result<Option<IpcPort>, Error> {
    let Some(space) = space else {
        return Err(Error::DeadSpace);
    };

    if notify.is_some_and(|notify| ptr::eq(notify.as_ptr(), IO_DEAD)) {
        return Err(Error::InvalidCapability);
    }

    match id {
        MACH_NOTIFY_PORT_DESTROYED => {
            if sync != 0 {
                return Err(Error::InvalidValue);
            }

            let port = unsafe { translate_receive(space, name) }?;

            let previous = unsafe {
                ipc_port::pdrequest(IpcPort::from_raw(port), notify)
            };

            // SAFETY: the previous request owns a reference, so it still
            // names a live send-once port.
            Ok(previous.map(|port| unsafe { IpcPort::from_non_null(port) }))
        }
        MACH_NOTIFY_NO_SENDERS => {
            let port = unsafe { translate_receive(space, name) }?;

            let previous = unsafe {
                ipc_port::nsrequest(IpcPort::from_raw(port), sync, notify)
            };

            // SAFETY: the previous request owns a reference, so it still
            // names a live send-once port.
            Ok(previous.map(|port| unsafe { IpcPort::from_non_null(port) }))
        }
        MACH_NOTIFY_DEAD_NAME => {
            let previous = unsafe {
                ipc_right::dnrequest(space, name, sync != 0, notify)
            }?;

            Ok(IpcPort::new(previous))
        }
        _ => Err(Error::InvalidValue),
    }
}
