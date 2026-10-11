// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The translation-entry routines.

use crate::error::Error;
use crate::platform::{IpcCache, Platform};
use crate::types::EntryBits;
use crate::{IpcEntry, IpcSpace};
use core::ffi::{c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull};

/// No entry.
const IE_NULL: *mut IpcEntry = ptr::null_mut();
/// No object.
const IO_NULL: *mut c_void = ptr::null_mut();
/// The most free entries kept linked before they are returned to the cache.
const IS_FREE_LIST_SIZE_LIMIT: usize = 64;

impl IpcEntry {
    /// The name the entry is under.
    pub(crate) const fn name(&self) -> c_uint {
        self.name
    }

    /// Sets the entry's name.
    pub(crate) const fn set_name(&mut self, name: c_uint) {
        self.name = name;
    }

    /// What the entry holds.
    #[must_use]
    pub const fn bits(&self) -> EntryBits {
        self.bits
    }

    /// Sets what the entry holds.
    pub const fn set_bits(&mut self, bits: EntryBits) {
        self.bits = bits;
    }

    /// The object the entry names.
    #[must_use]
    pub const fn object(&self) -> *mut c_void {
        self.object
    }

    /// Sets the entry's object.
    pub const fn set_object(&mut self, object: *mut c_void) {
        self.object = object;
    }

    /// The next free entry, while the entry is free.
    pub(crate) const fn next_free(&self) -> *mut Self {
        self.index.cast()
    }

    /// Links the entry to `entry` on the free list.
    pub(crate) const fn set_next_free(&mut self, entry: *mut Self) {
        self.index = entry.cast();
    }

    /// The dead-name request index, while the entry is in use.
    pub(crate) const fn request(&self) -> c_uint {
        // SAFETY: the union's low word is the `request` member; the whole
        // field is readable.
        unsafe { ptr::addr_of!(self.index).cast::<c_uint>().read() }
    }

    /// Sets the entry's dead-name request index.
    pub(crate) const fn set_request(&mut self, request: c_uint) {
        // SAFETY: the union's low word is the `request` member; a `u32` write
        // at the field's address is the C's `index.request`.
        unsafe {
            ptr::addr_of_mut!(self.index)
                .cast::<c_uint>()
                .write(request);
        };
    }
}

/// The [`Error`] a radix-tree error stands for.
const fn map_error(error: kmem::RadixTreeError) -> Error {
    match error {
        kmem::RadixTreeError::Busy => Error::InvalidArgument,
        kmem::RadixTreeError::NoMemory => Error::ResourceShortage,
    }
}

/// Allocates an entry from the cache.
fn ie_alloc<P: Platform>() -> Option<*mut IpcEntry> {
    // SAFETY: `ipc_bootstrap()` initialized the cache before any entry could
    // exist.
    let buf = unsafe { P::ipc_cache_alloc(IpcCache::Entry)? };
    Some(buf.as_ptr().cast())
}

/// Returns `entry` to the cache.
///
/// # Safety
///
/// `entry` must be a live allocation from the entry cache that nothing uses.
pub(crate) unsafe fn free<P: Platform>(entry: *mut IpcEntry) {
    let Some(entry) = NonNull::new(entry.cast::<u8>()) else {
        return;
    };

    unsafe { P::ipc_cache_free(IpcCache::Entry, entry) };
}

/// Pulls an entry off the free list, or `None` when it is empty.
///
/// # Safety
///
/// The space must be live, active, and write-locked.
#[must_use]
pub unsafe fn entry_get<P: Platform>(
    space: IpcSpace,
) -> Option<(c_uint, *mut IpcEntry)> {
    unsafe {
        let record = space.record::<P>();
        let free = (*record).free_list;
        if free == IE_NULL {
            return None;
        }

        (*record).free_list = (*free).next_free();
        (*record).free_list_size = (*record).free_list_size.wrapping_sub(1);

        (*free).set_bits(EntryBits::default());
        (*free).set_request(0);

        (*record).size = (*record).size.wrapping_add(1);

        Some(((*free).name(), free))
    }
}

/// Returns an entry to the free list, or to the cache when the list is full.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `entry` must be the
/// live entry `name` denotes.
pub(crate) unsafe fn dealloc<P: Platform>(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
) {
    unsafe {
        let record = space.record::<P>();

        if (*record).free_list_size < IS_FREE_LIST_SIZE_LIMIT {
            (*record).free_list_size =
                (*record).free_list_size.wrapping_add(1);
            (*entry).set_bits(EntryBits::default());
            (*entry).set_next_free((*record).free_list);
            (*record).free_list = entry;
        } else {
            (*record).map.remove(u64::from(name));
            free::<P>(entry);
        }

        (*record).size = (*record).size.wrapping_sub(1);
    }
}

/// Unlinks the unused `entry` from the free list, when the name map already
/// holds it.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `entry` must be an
/// unused entry on the space's free list.
unsafe fn unlink_free<P: Platform>(space: IpcSpace, entry: *mut IpcEntry) {
    unsafe {
        let record = space.record::<P>();

        let mut prev = ptr::addr_of_mut!((*record).free_list);
        let mut current = (*record).free_list;
        while current != entry {
            prev = ptr::addr_of_mut!((*current).index).cast();
            current = (*current).next_free();
        }
        *prev = (*entry).next_free();

        (*record).free_list_size = (*record).free_list_size.wrapping_sub(1);
        (*entry).set_bits(EntryBits::default());
        (*entry).set_request(0);
        (*record).size = (*record).size.wrapping_add(1);
    }
}

/// Allocates an entry in `space` under a fresh name.
///
/// # Safety
///
/// The space must be live and write-locked, and may allocate memory.
pub(crate) unsafe fn alloc<P: Platform>(
    space: IpcSpace,
) -> Result<(c_uint, *mut IpcEntry), Error> {
    if !unsafe { space.is_active::<P>() } {
        return Err(Error::DeadSpace);
    }

    if let Some(found) = unsafe { entry_get::<P>(space) } {
        return Ok(found);
    }

    let Some(entry) = ie_alloc::<P>() else {
        return Err(Error::ResourceShortage);
    };

    let inserted = unsafe {
        (*space.record::<P>())
            .map
            .insert_alloc(NonNull::new_unchecked(entry.cast()))
    };

    let name = match inserted {
        Ok(key) => c_uint::try_from(key).map_err(|_| {
            // Names are 32 bits wide, so a key above them is never handed out.
            // SAFETY: the key was just allocated for this entry.
            unsafe { (*space.record::<P>()).map.remove(key) };
            Error::NoSpace
        }),
        Err(error) => Err(map_error(error)),
    };

    match name {
        Ok(name) => {
            unsafe {
                (*entry).set_bits(EntryBits::default());
                (*entry).set_object(IO_NULL);
                (*entry).set_request(0);
                (*entry).set_name(name);
                let record = space.record::<P>();
                (*record).size = (*record).size.wrapping_add(1);
            }

            Ok((name, entry))
        }
        Err(error) => {
            // SAFETY: the failed insert left the fresh entry unreferenced.
            unsafe { free::<P>(entry) };
            Err(error)
        }
    }
}

/// Allocates the entry for `name` in `space`, or finds the one already there.
///
/// # Safety
///
/// The space must be live and write-locked, and may allocate memory.
pub(crate) unsafe fn alloc_name<P: Platform>(
    space: IpcSpace,
    name: c_uint,
) -> Result<*mut IpcEntry, Error> {
    if !unsafe { space.is_active::<P>() } {
        return Err(Error::DeadSpace);
    }

    let existing = unsafe { (*space.record::<P>()).map.get(u64::from(name)) }
        .map(NonNull::as_ptr);

    let Some(entry) = existing else {
        let Some(fresh) = ie_alloc::<P>() else {
            return Err(Error::ResourceShortage);
        };

        // SAFETY: the fresh entry belongs to this call.
        unsafe {
            (*fresh).set_bits(EntryBits::default());
            (*fresh).set_object(IO_NULL);
            (*fresh).set_request(0);
            (*fresh).set_name(name);
        }

        let inserted = unsafe {
            (*space.record::<P>())
                .map
                .insert(u64::from(name), NonNull::new_unchecked(fresh.cast()))
        };
        if let Err(error) = inserted {
            // SAFETY: the failed insert left the entry unreferenced.
            unsafe { free::<P>(fresh) };
            return Err(map_error(error));
        }

        unsafe {
            let record = space.record::<P>();
            (*record).size = (*record).size.wrapping_add(1);
        }

        return Ok(fresh);
    };

    // SAFETY: a lookup result is a live entry.
    if !unsafe { (*entry).bits() }.type_.is_empty() {
        return Ok(entry);
    }

    // SAFETY: an unused entry in the map is on the free list.
    unsafe { unlink_free::<P>(space, entry) };
    Ok(entry)
}

/// The `kmem_cache_init()` call `ipc_bootstrap()` makes for the entry cache.
pub(crate) fn init_cache<P: Platform>() {
    // SAFETY: `ipc_bootstrap()` runs once, before any entry allocation.
    unsafe {
        P::ipc_cache_init(
            IpcCache::Entry,
            b"ipc_entry",
            size_of::<IpcEntry>(),
        );
    }
}
