// SPDX-License-Identifier: CMU-Mach
// Derived from ipc/ipc_entry.c and ipc/ipc_entry.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The translation-entry routines, which `ipc/ipc_entry.c` used to define and
//! `ipc/ipc_entry.h` declares.

use crate::ipc::{IE_BITS_TYPE_MASK, IpcEntry, IpcSpace};
use crate::kern::slab::{KmemCache, kmem_cache_init};
use crate::kern::types::KernError;
use core::ffi::{c_uint, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull};

/// `IE_NULL` of <`ipc/ipc_entry.h>`: no entry.
const IE_NULL: *mut IpcEntry = ptr::null_mut();
/// `IO_NULL` of <`ipc/ipc_object.h>`: no object.
const IO_NULL: *mut c_void = ptr::null_mut();
/// `IS_FREE_LIST_SIZE_LIMIT` of <`ipc/ipc_space.h>`: the most free entries kept
/// linked before they are returned to the cache.
const IS_FREE_LIST_SIZE_LIMIT: usize = 64;
/// `IE_BITS_GEN_MASK` of <`ipc/ipc_entry.h>`: the generation bits of an entry;
/// zero in this configuration.
const IE_BITS_GEN_MASK: u32 = 0;
/// `IE_BITS_GEN_ONE` of <`ipc/ipc_entry.h>`: one generation step; zero in this
/// configuration.
pub(crate) const IE_BITS_GEN_ONE: u32 = 0;

/// `ipc_entry_cache` of `ipc/ipc_entry.c`: the `struct ipc_entry` slab cache.
static mut IPC_ENTRY_CACHE: KmemCache = KmemCache::zeroed();

impl IpcEntry {
    /// `ie_name` of <`ipc/ipc_entry.h`>.
    pub(crate) const fn name(&self) -> c_uint {
        self.name
    }

    /// The `entry->ie_name = name` assignment.
    pub(crate) const fn set_name(&mut self, name: c_uint) {
        self.name = name;
    }

    /// `ie_bits` of <`ipc/ipc_entry.h`>.
    pub(crate) const fn bits(&self) -> u32 {
        self.bits
    }

    /// The `entry->ie_bits = bits` assignment.
    pub(crate) const fn set_bits(&mut self, bits: u32) {
        self.bits = bits;
    }

    /// The `entry->ie_bits |= bits` assignment.
    pub(crate) const fn or_bits(&mut self, bits: u32) {
        self.bits |= bits;
    }

    /// `ie_object` of <`ipc/ipc_entry.h`>.
    pub(crate) const fn object(&self) -> *mut c_void {
        self.object
    }

    /// The `entry->ie_object = object` assignment.
    pub(crate) const fn set_object(&mut self, object: *mut c_void) {
        self.object = object;
    }

    /// `ie_next_free` of <`ipc/ipc_entry.h>`: the `index.next_free` union
    /// member.
    pub(crate) const fn next_free(&self) -> *mut Self {
        self.index.cast()
    }

    /// The `entry->ie_next_free = entry` assignment.
    pub(crate) const fn set_next_free(&mut self, entry: *mut Self) {
        self.index = entry.cast();
    }

    /// `ie_request` of <`ipc/ipc_entry.h>`: the `index.request` union member.
    pub(crate) const fn request(&self) -> c_uint {
        // SAFETY: the union's low word is the `request` member; the whole
        // field is readable.
        unsafe { ptr::addr_of!(self.index).cast::<c_uint>().read() }
    }

    /// The `entry->ie_request = request` assignment.
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

/// The [`KernError`] a radix-tree error stands for.
const fn map_error(error: kmem::RadixTreeError) -> KernError {
    match error {
        kmem::RadixTreeError::Exists => KernError::InvalidArgument,
        kmem::RadixTreeError::ResourceShortage => KernError::ResourceShortage,
    }
}

/// `ie_alloc()` of <`ipc/ipc_entry.h`>.
fn ie_alloc() -> Option<*mut IpcEntry> {
    // SAFETY: `ipc_bootstrap()` initialized the cache before any entry could
    // exist.
    let buf = unsafe { (*ptr::addr_of_mut!(IPC_ENTRY_CACHE)).alloc()? };
    Some(buf.as_ptr().cast())
}

/// `ie_free()` of <`ipc/ipc_entry.h`>.
///
/// # Safety
///
/// `entry` must be a live allocation from the entry cache that nothing uses.
pub(crate) unsafe fn free(entry: *mut IpcEntry) {
    let Some(entry) = NonNull::new(entry.cast::<u8>()) else {
        return;
    };

    unsafe { (*ptr::addr_of_mut!(IPC_ENTRY_CACHE)).free(entry) };
}

/// `ipc_entry_get()` of <`ipc/ipc_space.h>`: pull an entry off the free list,
/// or `None` when it is empty.
///
/// # Safety
///
/// The space must be live, active, and write-locked.
pub(crate) unsafe fn entry_get(
    space: IpcSpace,
) -> Option<(c_uint, *mut IpcEntry)> {
    unsafe {
        let record = space.record();
        let free = (*record).free_list;
        if free == IE_NULL {
            return None;
        }

        (*record).free_list = (*free).next_free();
        (*record).free_list_size = (*record).free_list_size.wrapping_sub(1);

        let generation = (*free).bits().wrapping_add(IE_BITS_GEN_ONE);
        (*free).set_bits(generation);
        (*free).set_request(0);

        (*record).size = (*record).size.wrapping_add(1);

        // The generation is zero in this configuration, so the C's
        // `MACH_PORT_MAKE()` is the entry's stored name.
        Some(((*free).name(), free))
    }
}

/// `ipc_entry_dealloc()` of <`ipc/ipc_space.h>`: return an entry to the free
/// list, or to the cache when the list is full.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `entry` must be the
/// live entry `name` denotes.
pub(crate) unsafe fn dealloc(
    space: IpcSpace,
    name: c_uint,
    entry: *mut IpcEntry,
) {
    unsafe {
        let record = space.record();

        if (*record).free_list_size < IS_FREE_LIST_SIZE_LIMIT {
            (*record).free_list_size =
                (*record).free_list_size.wrapping_add(1);
            (*entry).set_bits((*entry).bits() & IE_BITS_GEN_MASK);
            (*entry).set_next_free((*record).free_list);
            (*record).free_list = entry;
        } else {
            (*record).map.remove(kmem::RadixKey::from_raw(name));
            free(entry);
        }

        (*record).size = (*record).size.wrapping_sub(1);
    }
}

/// The free-list removal `ipc_entry_alloc_name()` performs when the map
/// already holds an unused entry.
///
/// # Safety
///
/// The space must be live, active, and write-locked, and `entry` must be an
/// unused entry on the space's free list.
unsafe fn unlink_free(space: IpcSpace, entry: *mut IpcEntry) {
    unsafe {
        let record = space.record();

        let mut prev = ptr::addr_of_mut!((*record).free_list);
        let mut current = (*record).free_list;
        while current != entry {
            prev = ptr::addr_of_mut!((*current).index).cast();
            current = (*current).next_free();
        }
        *prev = (*entry).next_free();

        (*record).free_list_size = (*record).free_list_size.wrapping_sub(1);
        (*entry).set_bits(0);
        (*entry).set_request(0);
        (*record).size = (*record).size.wrapping_add(1);
    }
}

/// `ipc_entry_alloc()` in C.
///
/// # Safety
///
/// The space must be live and write-locked, and may allocate memory.
pub(crate) unsafe fn alloc(
    space: IpcSpace,
) -> Result<(c_uint, *mut IpcEntry), KernError> {
    if !unsafe { space.is_active() } {
        return Err(KernError::InvalidTask);
    }

    if let Some(found) = unsafe { entry_get(space) } {
        return Ok(found);
    }

    let Some(entry) = ie_alloc() else {
        return Err(KernError::ResourceShortage);
    };

    let inserted = unsafe {
        (*space.record())
            .map
            .insert_alloc(NonNull::new_unchecked(entry.cast()))
    };

    match inserted {
        Ok((key, _slot)) => {
            let name = key.into_raw();
            unsafe {
                (*entry).set_bits(0);
                (*entry).set_object(IO_NULL);
                (*entry).set_request(0);
                (*entry).set_name(name);
                let record = space.record();
                (*record).size = (*record).size.wrapping_add(1);
            }

            Ok((name, entry))
        }
        Err(error) => {
            // SAFETY: the failed insert left the fresh entry unreferenced.
            unsafe { free(entry) };
            Err(map_error(error))
        }
    }
}

/// `ipc_entry_alloc_name()` in C.
///
/// # Safety
///
/// The space must be live and write-locked, and may allocate memory.
pub(crate) unsafe fn alloc_name(
    space: IpcSpace,
    name: c_uint,
) -> Result<*mut IpcEntry, KernError> {
    if !unsafe { space.is_active() } {
        return Err(KernError::InvalidTask);
    }

    let existing =
        unsafe { (*space.record()).map.get(kmem::RadixKey::from_raw(name)) }
            .map(|entry| entry.as_ptr());

    let Some(entry) = existing else {
        let Some(fresh) = ie_alloc() else {
            return Err(KernError::ResourceShortage);
        };

        // SAFETY: the fresh entry belongs to this call.
        unsafe {
            (*fresh).set_bits(0);
            (*fresh).set_object(IO_NULL);
            (*fresh).set_request(0);
            (*fresh).set_name(name);
        }

        let inserted = unsafe {
            (*space.record()).map.insert(
                kmem::RadixKey::from_raw(name),
                NonNull::new_unchecked(fresh.cast()),
            )
        };
        if let Err(error) = inserted {
            // SAFETY: the failed insert left the entry unreferenced.
            unsafe { free(fresh) };
            return Err(map_error(error));
        }

        unsafe {
            let record = space.record();
            (*record).size = (*record).size.wrapping_add(1);
        }

        return Ok(fresh);
    };

    // SAFETY: a lookup result is a live entry.
    if unsafe { (*entry).bits() } & IE_BITS_TYPE_MASK != 0 {
        return Ok(entry);
    }

    // SAFETY: an unused entry in the map is on the free list.
    unsafe { unlink_free(space, entry) };
    Ok(entry)
}

/// The `kmem_cache_init()` call `ipc_bootstrap()` makes for the entry cache.
pub(crate) fn init_cache() {
    // SAFETY: `ipc_bootstrap()` runs once, before any entry allocation.
    unsafe {
        kmem_cache_init(
            ptr::addr_of_mut!(IPC_ENTRY_CACHE),
            c"ipc_entry".as_ptr(),
            size_of::<IpcEntry>(),
            0,
            None,
            0,
        );
    }
}
