// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_space.c and ipc/ipc_space.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The capability-space routines, which `ipc/ipc_space.c` used to define and
//! `ipc/ipc_space.h` declares.

use crate::ipc::ipc_entry;
use crate::ipc::ipc_right;
use crate::ipc::{IE_BITS_TYPE_MASK, IpcEntry, IpcSpace, IpcSpaceRecord};
use crate::kern::lock::LockData;

use crate::kern::slab::{KmemCache, kmem_cache_init};
use crate::kern::types::KernError;
use crate::vm::error::Error;
use crate::vm::vm_kern::VM_MIN_KERNEL_ADDRESS;
use core::ffi::{c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull};

/// `MACH_PORT_NAME_NULL` of <mach/port.h>: the name no entry holds.
const MACH_PORT_NAME_NULL: c_uint = 0;

/// `ipc_space_cache` of `ipc/ipc_space.c`: the `struct ipc_space` slab cache.
static mut IPC_SPACE_CACHE: KmemCache = KmemCache::zeroed();

/// `ipc_space_kernel` of `ipc/ipc_space.c`: the space holding the kernel's
/// naked receive rights.
static mut KERNEL_SPACE: *mut c_void = ptr::null_mut();

/// `ipc_space_reply` of `ipc/ipc_space.c`: the space holding the kernel's reply
/// ports.
static mut REPLY_SPACE: *mut c_void = ptr::null_mut();

/// `zero_entry` of `ipc/ipc_space.c`: the placeholder for the reserved zeroth
/// entry.
static mut ZERO_ENTRY: IpcEntry = IpcEntry {
    name: 0,
    bits: 0,
    object: ptr::null_mut(),
    index: ptr::null_mut(),
};

impl IpcSpace {
    /// `is_write_lock()` of <`ipc/ipc_space.h`>.
    ///
    /// # Safety
    ///
    /// The space must be live, and this call must not already hold its lock.
    pub(crate) unsafe fn lock_write(self) {
        unsafe { (*self.record()).lock.write() };
    }

    /// `is_read_lock()` of <`ipc/ipc_space.h`>.
    ///
    /// # Safety
    ///
    /// The space must be live, and this call must not already hold its lock.
    pub(crate) unsafe fn lock_read(self) {
        unsafe { (*self.record()).lock.read() };
    }

    /// `is_write_unlock()` and `is_read_unlock()` of <`ipc/ipc_space.h`>, both
    /// the C's `lock_done()`.
    ///
    /// # Safety
    ///
    /// The space must be live, and this call must hold its lock.
    pub(crate) unsafe fn lock_done(self) {
        unsafe { (*self.record()).lock.done() };
    }

    /// `is_active` of `struct ipc_space`.
    ///
    /// # Safety
    ///
    /// The space must be live.
    pub(crate) unsafe fn is_active(self) -> bool {
        unsafe { (*self.record()).active != 0 }
    }

    /// `ipc_reverse_lookup()` of <`ipc/ipc_space.h>`: the entry the reverse map
    /// holds for `object`, or `None`.
    ///
    /// # Safety
    ///
    /// The space must be live and read- or write-locked.
    pub(crate) unsafe fn reverse_lookup(
        self,
        object: *mut c_void,
    ) -> Option<*mut IpcEntry> {
        let found =
            unsafe { (*self.record()).reverse_map.get(reverse_key(object)) }?;
        Some(found.as_ptr())
    }

    /// `ipc_reverse_insert()` of <`ipc/ipc_space.h>`: record `entry` as
    /// `object`'s reverse mapping.
    ///
    /// # Safety
    ///
    /// The space must be live and write-locked, and `entry` must be a live,
    /// non-null entry of it.
    pub(crate) unsafe fn reverse_insert(
        self,
        object: *mut c_void,
        entry: *mut IpcEntry,
    ) -> Result<(), Error> {
        let entry = unsafe { NonNull::new_unchecked(entry.cast()) };

        unsafe {
            (*self.record())
                .reverse_map
                .insert(reverse_key(object), entry)
                .map_err(|error| match error {
                    kmem::RadixTreeError::Busy => Error::InvalidArgument,
                    kmem::RadixTreeError::NoMemory => Error::ResourceShortage,
                })
        }
    }

    /// `ipc_reverse_remove()` of <`ipc/ipc_space.h>`: drop `object` from the
    /// reverse map.
    ///
    /// # Safety
    ///
    /// The space must be live and write-locked.
    pub(crate) unsafe fn reverse_remove(
        self,
        object: *mut c_void,
    ) -> Option<*mut IpcEntry> {
        unsafe { (*self.record()).reverse_map.remove(reverse_key(object)) }
            .map(NonNull::as_ptr)
    }
}

/// The C `KEY()` macro of <`ipc/ipc_space.h>`: the reverse map's key for an
/// object.
fn reverse_key(object: *mut c_void) -> u64 {
    (object.addr().wrapping_sub(VM_MIN_KERNEL_ADDRESS) >> 3) as u64
}

/// `is_alloc()` of <`ipc/ipc_space.h`>.
fn alloc() -> Option<IpcSpace> {
    // SAFETY: `ipc_bootstrap()` initialized the cache before any space could
    // exist.
    let buf = unsafe { (*ptr::addr_of_mut!(IPC_SPACE_CACHE)).alloc()? };
    // SAFETY: the cache's buffers are `struct ipc_space` sized, as its init
    // recorded from the C size, and `alloc()` returned a live one.
    Some(unsafe { IpcSpace::from_raw(buf.as_ptr().cast()) })
}

/// `is_free()` of <`ipc/ipc_space.h`>.
///
/// # Safety
///
/// `space` must be an allocation from the space cache that nothing uses.
unsafe fn free(space: IpcSpace) {
    unsafe {
        (*ptr::addr_of_mut!(IPC_SPACE_CACHE))
            .free(NonNull::new_unchecked(space.as_ptr().cast::<u8>()));
    }
}

/// `ipc_space_reference_macro()` of <`ipc/ipc_space.h`> and the function
/// `ipc_space_reference()` was.
///
/// # Safety
///
/// The space must be live.
pub(crate) unsafe fn reference(space: IpcSpace) {
    unsafe {
        let record = space.record();
        (*record).ref_lock.lock();
        (*record).references = (*record).references.wrapping_add(1);
        (*record).ref_lock.unlock();
    }
}

/// `ipc_space_release_macro()` of <`ipc/ipc_space.h`> and the function
/// `ipc_space_release()` was.
///
/// # Safety
///
/// The space must be live and hold a reference.
pub(crate) unsafe fn release(space: IpcSpace) {
    let references;

    unsafe {
        let record = space.record();
        (*record).ref_lock.lock();
        references = (*record).references.wrapping_sub(1);
        (*record).references = references;
        (*record).ref_lock.unlock();
    }

    if references == 0 {
        // SAFETY: the last reference is gone, so nothing can reach the space.
        unsafe { free(space) };
    }
}

/// `ipc_space_create()` in C.
pub(crate) fn create() -> Result<IpcSpace, KernError> {
    let Some(space) = alloc() else {
        return Err(KernError::ResourceShortage);
    };

    // SAFETY: the fresh allocation is unshared, and this call initializes it
    // as the C did.
    unsafe {
        let record = space.record();
        (*record).ref_lock.init();
        (*record).references = 2;
        LockData::init(ptr::addr_of_mut!((*record).lock), true);
        (*record).active = 1;

        let map = ptr::addr_of_mut!((*record).map);
        map.write(crate::ipc::NameMap::new(crate::kern::kheap::Kalloc, true));
        let reverse = ptr::addr_of_mut!((*record).reverse_map);
        reverse.write(crate::ipc::NameMap::new(
            crate::kern::kheap::Kalloc,
            false,
        ));

        // The C ignored the insert result too; the zeroth entry is reserved.
        let zero =
            NonNull::new_unchecked(ptr::addr_of_mut!(ZERO_ENTRY)).cast();
        let _ = (*map).insert(0, zero);

        (*record).size = 1;
        (*record).free_list = ptr::null_mut();
        (*record).free_list_size = 0;
    }

    Ok(space)
}

/// `ipc_space_create_special()` in C.
pub(crate) fn create_special() -> Result<IpcSpace, KernError> {
    let Some(space) = alloc() else {
        return Err(KernError::ResourceShortage);
    };

    // SAFETY: the fresh allocation is unshared, and this call initializes it
    // as the C did.  A special space has no map.
    unsafe {
        let record = space.record();
        (*record).ref_lock.init();
        (*record).references = 1;
        LockData::init(ptr::addr_of_mut!((*record).lock), true);
        (*record).active = 0;
    }

    Ok(space)
}

/// The two `ipc_space_create_special()` calls of `ipc_bootstrap()`, whose
/// results the C ignored.
pub(crate) fn create_specials() {
    if let Ok(space) = create_special() {
        // SAFETY: bootstrap is the only writer, before any reader runs.
        unsafe { KERNEL_SPACE = space.as_ptr() };
    }

    if let Ok(space) = create_special() {
        // SAFETY: bootstrap is the only writer, before any reader runs.
        unsafe { REPLY_SPACE = space.as_ptr() };
    }
}

/// The kernel's space, live from `ipc_bootstrap()` on.
pub(crate) fn kernel() -> IpcSpace {
    // SAFETY: `create_specials()` is the only writer, and it runs in
    // `ipc_bootstrap()` before any caller that needs the space.
    unsafe { IpcSpace::from_raw(KERNEL_SPACE) }
}

/// The reply space, live from `ipc_bootstrap()` on.
pub(crate) fn reply() -> IpcSpace {
    // SAFETY: `create_specials()` is the only writer, and it runs in
    // `ipc_bootstrap()` before any caller that needs the space.
    unsafe { IpcSpace::from_raw(REPLY_SPACE) }
}

/// `ipc_space_destroy()` in C.
///
/// # Safety
///
/// The space must be live, and nothing may be locked.
pub(crate) unsafe fn destroy(space: IpcSpace) {
    let active = unsafe {
        space.lock_write();
        let record = space.record();
        let active = (*record).active != 0;
        (*record).active = 0;
        space.lock_done();
        active
    };

    if !active {
        return;
    }

    let map = unsafe { ptr::addr_of_mut!((*space.record()).map) };

    // SAFETY: the space is live and its map belongs to it; the walk hands
    // back each stored entry once.
    for (_key, found) in unsafe { (*map).iter() } {
        let entry = found.as_ptr();

        // SAFETY: a walked pointer is a live entry in the map.
        unsafe {
            if (*entry).name() == MACH_PORT_NAME_NULL {
                continue;
            }

            // The generation is zero in this configuration, so the C's
            // `MACH_PORT_MAKEB()` is the entry's name.
            if (*entry).bits() & IE_BITS_TYPE_MASK != 0 {
                ipc_right::clean((*entry).name(), entry);
            }

            ipc_entry::free(entry);
        }
    }

    // SAFETY: the space is live and dead, so nothing else walks its maps.
    unsafe {
        (*map).clear();
        let reverse = ptr::addr_of_mut!((*space.record()).reverse_map);
        (*reverse).clear();
    }

    // SAFETY: the space is live and the dead space's active reference is the
    // one this releases.
    unsafe { release(space) };
}

/// The `kmem_cache_init()` call `ipc_bootstrap()` makes for the space cache.
pub(crate) fn init_cache() {
    // SAFETY: `ipc_bootstrap()` runs once, before any space allocation.
    unsafe {
        kmem_cache_init(
            ptr::addr_of_mut!(IPC_SPACE_CACHE),
            c"ipc_space".as_ptr(),
            size_of::<IpcSpaceRecord>(),
            0,
            None,
            0,
        );
    }
}
