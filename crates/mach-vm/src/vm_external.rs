// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! External (paged-out) page bookkeeping.

use crate::param::VmOffset;
use crate::platform::{CacheFlags, Platform, VmCache};
use crate::types::PAGE_SHIFT;
use core::ffi::c_int;
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};
use core::slice;
use core::sync::atomic::{AtomicU32, Ordering};

/// The byte size of a small existence bitmap.
const SMALL_SIZE: usize = 16;
/// The byte size of a large existence bitmap.
const LARGE_SIZE: usize = 1024;

/// The page is in the memory manager's backing store.
pub(crate) const VM_EXTERNAL_STATE_EXISTS: c_int = 1;
/// Nothing is known about the page.
const VM_EXTERNAL_STATE_UNKNOWN: c_int = 2;
/// The page is not in the backing store.
const VM_EXTERNAL_STATE_ABSENT: c_int = 3;

/// When set, every state query answers [`ExternalState::Unknown`].
static VM_EXTERNAL_UNSAFE: AtomicU32 = AtomicU32::new(0);

/// The state a page may be recorded in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExternalState {
    /// `VM_EXTERNAL_STATE_EXISTS`: written to external storage.
    Exists,
    /// `VM_EXTERNAL_STATE_UNKNOWN`: the map does not say.
    Unknown,
    /// `VM_EXTERNAL_STATE_ABSENT`: not written to external storage.
    Absent,
}

impl ExternalState {
    /// The state `state` encodes, or `None` when it encodes none.
    const fn from_c(state: c_int) -> Option<Self> {
        match state {
            VM_EXTERNAL_STATE_EXISTS => Some(Self::Exists),
            VM_EXTERNAL_STATE_UNKNOWN => Some(Self::Unknown),
            VM_EXTERNAL_STATE_ABSENT => Some(Self::Absent),
            _ => None,
        }
    }
}

/// The header of a bitmap of page states.
#[repr(C)]
pub struct VmExternal {
    /// Size in bytes of `existence_map`: `SMALL_SIZE` or `LARGE_SIZE`.
    existence_size: c_int,
    /// The bitmap, or nothing when the object has none.
    existence_map: Option<NonNull<u8>>,
}

const _: () = {
    assert!(size_of::<VmExternal>() == 16);
    assert!(align_of::<VmExternal>() == 8);
    assert!(offset_of!(VmExternal, existence_size) == 0);
    assert!(offset_of!(VmExternal, existence_map) == 8);
};

/// The bit of the page at `offset`. The page number `atop(offset)` is kept in
/// 32 bits, so a long offset contributes only its low 32 bits.
const fn page_bit(offset: VmOffset) -> usize {
    // Deliberate truncation: the C's `unsigned int bit` keeps the low 32 bits
    // of the 64-bit `vm_size_t atop(offset)`.
    (offset >> PAGE_SHIFT) as u32 as usize
}

impl VmExternal {
    /// Allocates a header and a zeroed bitmap sized for an object of `size`
    /// bytes, or `None` when a cache is out of memory.
    fn create<P: Platform>(size: VmOffset) -> Option<NonNull<Self>> {
        // SAFETY: the header cache is set up by
        // `vm_external_module_initialize()` before any caller.
        let header = unsafe { P::cache_alloc(VmCache::External) }
            .map(NonNull::cast::<Self>)?;

        let bytes = (size >> PAGE_SHIFT).wrapping_add(7) >> 3;
        let (cache, existence_size) = if bytes <= SMALL_SIZE {
            (VmCache::SmallExistenceMap, SMALL_SIZE)
        } else {
            (VmCache::LargeExistenceMap, LARGE_SIZE)
        };

        // SAFETY: the chosen map cache is initialized too, and its object
        // outlives the header until `destroy` returns it.
        let Some(map) =
            unsafe { P::cache_alloc(cache) }.map(NonNull::cast::<u8>)
        else {
            // SAFETY: the header is the live allocation from above.
            unsafe { P::cache_free(VmCache::External, header.cast::<u8>()) };
            return None;
        };

        // SAFETY: the map is a fresh allocation of `existence_size` bytes from
        // its cache, so the whole range is writable.
        unsafe { ptr::write_bytes(map.as_ptr(), 0, existence_size) };

        // SAFETY: the header is a fresh allocation, not yet shared.
        unsafe {
            header.as_ptr().write(Self {
                // 16 or 1024; both fit the C `int`.
                existence_size: existence_size as c_int,
                existence_map: Some(map),
            });
        };
        Some(header)
    }

    /// Returns the bitmap and the header to their caches.
    ///
    /// # Safety
    ///
    /// `e` must be a live object returned by `create`, and no reference to it
    /// may be used afterwards.
    unsafe fn destroy<P: Platform>(e: NonNull<Self>) {
        let this = unsafe { e.as_ref() };
        if let Some(map) = this.existence_map {
            // SMALL_SIZE is 16, so the C `int` comparison is exact.
            let cache = if this.existence_size <= SMALL_SIZE as c_int {
                VmCache::SmallExistenceMap
            } else {
                VmCache::LargeExistenceMap
            };
            // SAFETY: the map came from that cache and is not used again; the
            // header is still alive for the read above.
            unsafe { P::cache_free(cache, map.cast::<u8>()) };
        }
        // SAFETY: the header came from its cache, and nothing references it
        // after this point.
        unsafe { P::cache_free(VmCache::External, e.cast::<u8>()) };
    }

    /// The bitmap this object records page states in, when it has one.
    fn bitmap(&self) -> Option<&[u8]> {
        let map = self.existence_map?;
        let size = usize::try_from(self.existence_size).ok()?;
        if size == 0 {
            return None;
        }
        // SAFETY: `create` allocated `existence_size` bytes at `existence_map`
        // from a map cache, nothing else writes either field, and the borrow
        // of `self` keeps the bytes alive.
        Some(unsafe { slice::from_raw_parts(map.as_ptr(), size) })
    }

    /// The bitmap, mutably, when the object has one.
    // The exclusive borrow of `self` is what keeps the returned `&mut [u8]`
    // unique; `&self` would let two callers alias the same bytes.
    #[allow(clippy::needless_pass_by_ref_mut)]
    fn bitmap_mut(&mut self) -> Option<&mut [u8]> {
        let map = self.existence_map?;
        let size = usize::try_from(self.existence_size).ok()?;
        if size == 0 {
            return None;
        }
        // SAFETY: `create` allocated `existence_size` bytes at
        // `existence_map` from a map cache, and the exclusive borrow of
        // `self` rules out a second reference to the same bytes.
        Some(unsafe { slice::from_raw_parts_mut(map.as_ptr(), size) })
    }

    /// The state recorded for the page at `offset`.
    fn state_get(&self, offset: VmOffset) -> ExternalState {
        if VM_EXTERNAL_UNSAFE.load(Ordering::Relaxed) != 0 {
            return ExternalState::Unknown;
        }
        let Some(map) = self.bitmap() else {
            return ExternalState::Unknown;
        };
        let bit = page_bit(offset);
        match map.get(bit >> 3) {
            Some(value) if value & (1u8 << (bit & 7)) != 0 => {
                ExternalState::Exists
            }
            Some(_) => ExternalState::Absent,
            None => ExternalState::Unknown,
        }
    }

    /// Records `state` for the page at `offset`; only
    /// [`ExternalState::Exists`] is ever recorded.
    fn state_set(&mut self, offset: VmOffset, state: ExternalState) {
        if state != ExternalState::Exists {
            return;
        }
        let Some(map) = self.bitmap_mut() else {
            return;
        };
        let bit = page_bit(offset);
        let Some(value) = map.get_mut(bit >> 3) else {
            return;
        };
        *value |= 1u8 << (bit & 7);
    }
}

/// Allocates the bookkeeping for an object of `size` bytes, or null when a
/// cache is out of memory.
///
/// # Safety
///
/// `vm_external_module_initialize()` must have initialized the slab caches;
/// the caller owns the returned object and releases it with
/// `vm_external_destroy()`.
pub(crate) unsafe fn vm_external_create<P: Platform>(
    size: VmOffset,
) -> *mut VmExternal {
    VmExternal::create::<P>(size).map_or(ptr::null_mut(), NonNull::as_ptr)
}

/// Frees the bookkeeping `e`, when it is not null.
///
/// # Safety
///
/// A non-null `e` must be a live object from `vm_external_create()` that the
/// caller owns; the call frees it.
pub(crate) unsafe fn vm_external_destroy<P: Platform>(e: *mut VmExternal) {
    if let Some(e) = NonNull::new(e) {
        unsafe { VmExternal::destroy::<P>(e) };
    }
}

/// The state recorded for the page, or [`ExternalState::Unknown`] for a null
/// map.
///
/// # Safety
///
/// A non-null `e` must be a live object from `vm_external_create()`; the call
/// only reads it.
pub(crate) unsafe fn state_get(
    e: *mut VmExternal,
    offset: VmOffset,
) -> ExternalState {
    NonNull::new(e).map_or(ExternalState::Unknown, |e| unsafe {
        e.as_ref().state_get(offset)
    })
}

/// Records the state `state` encodes for the page at `offset`, when `e` is not
/// null and `state` encodes a state.
///
/// # Safety
///
/// A non-null `e` must be a live object from `vm_external_create()` that the
/// caller may mutate, and no other reference to the object may be live for the
/// duration of the call.
pub(crate) unsafe fn vm_external_state_set(
    e: *mut VmExternal,
    offset: VmOffset,
    state: c_int,
) {
    let Some(e) = NonNull::new(e) else {
        return;
    };
    let Some(state) = ExternalState::from_c(state) else {
        return;
    };
    unsafe { &mut *e.as_ptr() }.state_set(offset, state);
}

/// Sets up the header and bitmap caches.
///
/// # Safety
///
/// Must be called once, before any other routine of this module, from the
/// kernel's VM bootstrap.
pub(crate) unsafe fn vm_external_module_initialize<P: Platform>() {
    // SAFETY: this module defines the caches and they outlive the kernel; the
    // bootstrap calls this before anything allocates from them.
    unsafe {
        P::cache_init(
            VmCache::External,
            b"vm_external",
            size_of::<VmExternal>(),
            CacheFlags::empty(),
        );
        P::cache_init(
            VmCache::SmallExistenceMap,
            b"small_existence_map",
            SMALL_SIZE,
            CacheFlags::empty(),
        );
        P::cache_init(
            VmCache::LargeExistenceMap,
            b"large_existence_map",
            LARGE_SIZE,
            CacheFlags::empty(),
        );
    }
}
