// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_space.c and ipc/ipc_space.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The capability-space routines.

use crate::ipc::ipc_entry;
use crate::ipc::ipc_right;
use crate::ipc::{IE_BITS_TYPE_MASK, IpcEntry, IpcSpace, IpcSpaceRecord};
use crate::kern::lock::LockData;

use crate::ipc::error::Error;
use crate::kern::slab::{KmemCache, kmem_cache_init};
use crate::vm::vm_kern::VM_MIN_KERNEL_ADDRESS;
use core::ffi::{c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicPtr, Ordering};

/// The name no entry holds.
const MACH_PORT_NAME_NULL: c_uint = 0;

/// The slab cache of IPC space records.
static mut IPC_SPACE_CACHE: KmemCache = KmemCache::zeroed();

/// The space holding the kernel's naked receive rights.
static KERNEL_SPACE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// The space holding the kernel's reply ports.
static REPLY_SPACE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// The placeholder for the reserved zeroth entry.
static mut ZERO_ENTRY: IpcEntry = IpcEntry {
    name: 0,
    bits: 0,
    object: ptr::null_mut(),
    index: ptr::null_mut(),
};

impl IpcSpace {
    /// Takes the space's write lock.
    ///
    /// # Safety
    ///
    /// The space must be live, and this call must not already hold its lock.
    pub(crate) unsafe fn lock_write(self) {
        unsafe { (*self.record()).lock.write() };
    }

    /// Takes the space's read lock.
    ///
    /// # Safety
    ///
    /// The space must be live, and this call must not already hold its lock.
    pub(crate) unsafe fn lock_read(self) {
        unsafe { (*self.record()).lock.read() };
    }

    /// Releases the space's read or write lock.
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

    /// The entry the reverse map holds for `object`, or `None`.
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

    /// Records `entry` as `object`'s reverse mapping.
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

    /// Drops `object` from the reverse map.
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

/// The reverse map's key for `object`.
fn reverse_key(object: *mut c_void) -> u64 {
    (object.addr().wrapping_sub(VM_MIN_KERNEL_ADDRESS) >> 3) as u64
}

/// Allocates a space record from the cache.
fn alloc() -> Option<IpcSpace> {
    // SAFETY: `ipc_bootstrap()` initialized the cache before any space could
    // exist.
    let buf = unsafe { (*ptr::addr_of_mut!(IPC_SPACE_CACHE)).alloc()? };
    // SAFETY: the cache's buffers are `struct ipc_space` sized, as its init
    // recorded from the C size, and `alloc()` returned a live one.
    Some(unsafe { IpcSpace::from_raw(buf.as_ptr().cast()) })
}

/// Returns `space` to the cache.
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

/// Takes a reference on `space`.
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

/// Drops a reference on `space`, freeing it on the last one.
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

/// Creates an empty space with one reference.
pub(crate) fn create() -> Result<IpcSpace, Error> {
    let Some(space) = alloc() else {
        return Err(Error::ResourceShortage);
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

/// Creates a special space: one that holds the kernel's rights and no entries.
pub(crate) fn create_special() -> Result<IpcSpace, Error> {
    let Some(space) = alloc() else {
        return Err(Error::ResourceShortage);
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

/// Creates the kernel space and the reply space at boot.
pub(crate) fn create_specials() {
    if let Ok(space) = create_special() {
        KERNEL_SPACE.store(space.as_ptr(), Ordering::Relaxed);
    }

    if let Ok(space) = create_special() {
        REPLY_SPACE.store(space.as_ptr(), Ordering::Relaxed);
    }
}

/// The kernel's space, live from `ipc_bootstrap()` on.
pub(crate) fn kernel() -> IpcSpace {
    // SAFETY: `create_specials()` is the only writer, and it runs in
    // `ipc_bootstrap()` before any caller that needs the space.
    unsafe { IpcSpace::from_raw(KERNEL_SPACE.load(Ordering::Relaxed)) }
}

/// The reply space, live from `ipc_bootstrap()` on.
pub(crate) fn reply() -> IpcSpace {
    // SAFETY: `create_specials()` is the only writer, and it runs in
    // `ipc_bootstrap()` before any caller that needs the space.
    unsafe { IpcSpace::from_raw(REPLY_SPACE.load(Ordering::Relaxed)) }
}

/// Destroys every right in `space` and marks it inactive.
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

            // The generation is zero in this configuration, so the name is the
            // entry's own.
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
