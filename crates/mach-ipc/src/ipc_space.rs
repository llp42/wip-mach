// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The capability-space routines.

use crate::ipc_entry;
use crate::ipc_right;
use crate::types::{EntryBits, PortType};
use crate::{IpcEntry, IpcSpace, IpcSpaceRecord};

use crate::error::Error;
use crate::platform::{IpcCache, Platform};
use core::ffi::{c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicPtr, Ordering};
use lock::RawRwLock;
use lock::lock_api::RawRwLock as _;
use mach_vm::param::VM_MIN_KERNEL_ADDRESS;

/// The name no entry holds.
const MACH_PORT_NAME_NULL: c_uint = 0;

/// The space holding the kernel's naked receive rights.
static KERNEL_SPACE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// The space holding the kernel's reply ports.
static REPLY_SPACE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// The placeholder every space's map holds for the reserved zeroth name.
struct ZeroEntry(IpcEntry);

// SAFETY: the entry is only ever read: every path that allocates a name
// refuses name 0 before it reaches the map, and an empty entry is never
// written, so every space can share the one value.
unsafe impl Sync for ZeroEntry {}

static ZERO_ENTRY: ZeroEntry = ZeroEntry(IpcEntry {
    name: 0,
    bits: EntryBits {
        type_: PortType::empty(),
        urefs: 0,
        marequest: false,
    },
    object: ptr::null_mut(),
    index: ptr::null_mut(),
});

impl IpcSpace {
    /// Takes the space's write lock.
    ///
    /// # Safety
    ///
    /// The space must be live, and this call must not already hold its lock.
    pub unsafe fn lock_write<P: Platform>(self) {
        unsafe { (*self.record::<P>()).lock.lock_exclusive() };
    }

    /// Takes the space's read lock.
    ///
    /// # Safety
    ///
    /// The space must be live, and this call must not already hold its lock.
    pub unsafe fn lock_read<P: Platform>(self) {
        unsafe { (*self.record::<P>()).lock.lock_shared() };
    }

    /// Releases the space's write lock.
    ///
    /// # Safety
    ///
    /// The space must be live, and this call must hold its write lock.
    pub unsafe fn unlock_write<P: Platform>(self) {
        unsafe { (*self.record::<P>()).lock.unlock_exclusive() };
    }

    /// Releases the space's read lock.
    ///
    /// # Safety
    ///
    /// The space must be live, and this call must hold its read lock.
    pub unsafe fn unlock_read<P: Platform>(self) {
        unsafe { (*self.record::<P>()).lock.unlock_shared() };
    }

    /// `is_active` of `struct ipc_space`.
    ///
    /// # Safety
    ///
    /// The space must be live.
    pub(crate) unsafe fn is_active<P: Platform>(self) -> bool {
        unsafe { (*self.record::<P>()).active != 0 }
    }

    /// The entry the reverse map holds for `object`, or `None`.
    ///
    /// # Safety
    ///
    /// The space must be live and read- or write-locked.
    pub(crate) unsafe fn reverse_lookup<P: Platform>(
        self,
        object: *mut c_void,
    ) -> Option<*mut IpcEntry> {
        let found = unsafe {
            (*self.record::<P>()).reverse_map.get(reverse_key(object))
        }?;
        Some(found.as_ptr())
    }

    /// Records `entry` as `object`'s reverse mapping.
    ///
    /// # Safety
    ///
    /// The space must be live and write-locked, and `entry` must be a live,
    /// non-null entry of it.
    pub(crate) unsafe fn reverse_insert<P: Platform>(
        self,
        object: *mut c_void,
        entry: *mut IpcEntry,
    ) -> Result<(), Error> {
        let entry = unsafe { NonNull::new_unchecked(entry.cast()) };

        unsafe {
            (*self.record::<P>())
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
    pub(crate) unsafe fn reverse_remove<P: Platform>(
        self,
        object: *mut c_void,
    ) -> Option<*mut IpcEntry> {
        unsafe {
            (*self.record::<P>())
                .reverse_map
                .remove(reverse_key(object))
        }
        .map(NonNull::as_ptr)
    }
}

/// The reverse map's key for `object`.
fn reverse_key(object: *mut c_void) -> u64 {
    (object.addr().wrapping_sub(VM_MIN_KERNEL_ADDRESS) >> 3) as u64
}

/// Allocates a space record from the cache, its lock made and free.
fn alloc<P: Platform>() -> Option<IpcSpace> {
    // SAFETY: `ipc_bootstrap()` initialized the cache before any space could
    // exist.
    let buf = unsafe { P::ipc_cache_alloc(IpcCache::Space)? };
    // SAFETY: the cache's buffers are `struct ipc_space` sized, as its init
    // recorded from the C size, and `alloc()` returned a live one.
    let space = unsafe { IpcSpace::from_raw(buf.as_ptr().cast()) };
    // Every space's lock is made here, so all spaces share one lock name.
    // SAFETY: the fresh allocation is unshared.
    unsafe {
        ptr::addr_of_mut!((*space.record::<P>()).lock)
            .write(RawRwLock::named("ipc space"));
    }
    Some(space)
}

/// Returns `space` to the cache.
///
/// # Safety
///
/// `space` must be an allocation from the space cache that nothing uses.
unsafe fn free<P: Platform>(space: IpcSpace) {
    unsafe {
        P::ipc_cache_free(
            IpcCache::Space,
            NonNull::new_unchecked(space.as_ptr().cast::<u8>()),
        );
    }
}

/// Takes a reference on `space`.
///
/// # Safety
///
/// The space must be live.
pub unsafe fn reference<P: Platform>(space: IpcSpace) {
    unsafe {
        let record = space.record::<P>();
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
pub unsafe fn release<P: Platform>(space: IpcSpace) {
    let references;

    unsafe {
        let record = space.record::<P>();
        (*record).ref_lock.lock();
        references = (*record).references.wrapping_sub(1);
        (*record).references = references;
        (*record).ref_lock.unlock();
    }

    if references == 0 {
        // SAFETY: the last reference is gone, so nothing can reach the space.
        unsafe { free::<P>(space) };
    }
}

/// Creates an empty space with one reference.
pub fn create<P: Platform>() -> Result<IpcSpace, Error> {
    let Some(space) = alloc::<P>() else {
        return Err(Error::ResourceShortage);
    };

    // SAFETY: the fresh allocation is unshared, and this call initializes it
    // as the C did.
    unsafe {
        let record = space.record::<P>();
        (*record).ref_lock.init();
        (*record).references = 2;
        (*record).active = 1;

        let map = ptr::addr_of_mut!((*record).map);
        map.write(crate::NameMap::<P>::new(
            <P as Platform>::Heap::default(),
            true,
        ));
        let reverse = ptr::addr_of_mut!((*record).reverse_map);
        reverse.write(crate::NameMap::<P>::new(
            <P as Platform>::Heap::default(),
            false,
        ));

        // The C ignored the insert result too; the zeroth entry is reserved.
        let zero = NonNull::from(&ZERO_ENTRY.0).cast();
        let _ = (*map).insert(0, zero);

        (*record).size = 1;
        (*record).free_list = ptr::null_mut();
        (*record).free_list_size = 0;
    }

    Ok(space)
}

/// Creates a special space: one that holds the kernel's rights and no entries.
pub(crate) fn create_special<P: Platform>() -> Result<IpcSpace, Error> {
    let Some(space) = alloc::<P>() else {
        return Err(Error::ResourceShortage);
    };

    // SAFETY: the fresh allocation is unshared, and this call initializes it
    // as the C did.  A special space has no map.
    unsafe {
        let record = space.record::<P>();
        (*record).ref_lock.init();
        (*record).references = 1;
        (*record).active = 0;
    }

    Ok(space)
}

/// Creates the kernel space and the reply space at boot.
pub(crate) fn create_specials<P: Platform>() {
    if let Ok(space) = create_special::<P>() {
        KERNEL_SPACE.store(space.as_ptr(), Ordering::Relaxed);
    }

    if let Ok(space) = create_special::<P>() {
        REPLY_SPACE.store(space.as_ptr(), Ordering::Relaxed);
    }
}

/// The kernel's space, live from `ipc_bootstrap()` on.
pub fn kernel() -> IpcSpace {
    // SAFETY: `create_specials()` is the only writer, and it runs in
    // `ipc_bootstrap()` before any caller that needs the space.
    unsafe { IpcSpace::from_raw(KERNEL_SPACE.load(Ordering::Relaxed)) }
}

/// The reply space, live from `ipc_bootstrap()` on.
pub fn reply() -> IpcSpace {
    // SAFETY: `create_specials()` is the only writer, and it runs in
    // `ipc_bootstrap()` before any caller that needs the space.
    unsafe { IpcSpace::from_raw(REPLY_SPACE.load(Ordering::Relaxed)) }
}

/// Destroys every right in `space` and marks it inactive.
///
/// # Safety
///
/// The space must be live, and nothing may be locked.
pub unsafe fn destroy<P: Platform>(space: IpcSpace) {
    let active = unsafe {
        space.lock_write::<P>();
        let record = space.record::<P>();
        let active = (*record).active != 0;
        (*record).active = 0;
        space.unlock_write::<P>();
        active
    };

    if !active {
        return;
    }

    let map = unsafe { ptr::addr_of_mut!((*space.record::<P>()).map) };

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
            if !(*entry).bits().type_.is_empty() {
                ipc_right::clean::<P>((*entry).name(), entry);
            }

            ipc_entry::free::<P>(entry);
        }
    }

    // SAFETY: the space is live and dead, so nothing else walks its maps.
    unsafe {
        (*map).clear();
        let reverse = ptr::addr_of_mut!((*space.record::<P>()).reverse_map);
        (*reverse).clear();
    }

    // SAFETY: the space is live and the dead space's active reference is the
    // one this releases.
    unsafe { release::<P>(space) };
}

/// The `kmem_cache_init()` call `ipc_bootstrap()` makes for the space cache.
pub(crate) fn init_cache<P: Platform>() {
    // SAFETY: `ipc_bootstrap()` runs once, before any space allocation.
    unsafe {
        P::ipc_cache_init(
            IpcCache::Space,
            b"ipc_space",
            size_of::<IpcSpaceRecord<P>>(),
        );
    }
}
