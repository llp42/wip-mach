// SPDX-License-Identifier: CMU-Mach
// Derived from vm/vm_external.c and vm/vm_external.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! External (paged-out) page bookkeeping, which `vm/vm_external.c` used to
//! define and `vm/vm_external.h` declares.

use crate::arch::types::VmOffset;
use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::utils::cell::SyncCell;
use crate::vm::types::PAGE_SHIFT;
use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};
use core::slice;
use core::sync::atomic::{AtomicU32, Ordering};

/// `SMALL_SIZE` in `vm/vm_external.c`: the byte size of a small bitmap
/// (`VM_EXTERNAL_SMALL_SIZE/8`).
const SMALL_SIZE: usize = 16;
/// `LARGE_SIZE` in `vm/vm_external.c`: the byte size of a large bitmap
/// (`VM_EXTERNAL_LARGE_SIZE/8`).
const LARGE_SIZE: usize = 1024;

/// `VM_EXTERNAL_STATE_EXISTS` of <`vm/vm_external.h`>.
pub(crate) const VM_EXTERNAL_STATE_EXISTS: c_int = 1;
/// `VM_EXTERNAL_STATE_UNKNOWN` of <`vm/vm_external.h`>.
const VM_EXTERNAL_STATE_UNKNOWN: c_int = 2;
/// `VM_EXTERNAL_STATE_ABSENT` of <`vm/vm_external.h`>.
pub(crate) const VM_EXTERNAL_STATE_ABSENT: c_int = 3;

/// `vm_external_unsafe` in `vm/vm_external.c`: when set, every state query
/// answers `UNKNOWN`.
static VM_EXTERNAL_UNSAFE: AtomicU32 = AtomicU32::new(0);

/// The state a page may be recorded in; `vm_external_state_t` in C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExternalState {
    /// `VM_EXTERNAL_STATE_EXISTS`: written to external storage.
    Exists,
    /// `VM_EXTERNAL_STATE_UNKNOWN`: the map does not say.
    Unknown,
    /// `VM_EXTERNAL_STATE_ABSENT`: not written to external storage.
    Absent,
}

impl ExternalState {
    /// The C `vm_external_state_t` this state maps to.
    const fn as_c(self) -> c_int {
        match self {
            Self::Exists => VM_EXTERNAL_STATE_EXISTS,
            Self::Unknown => VM_EXTERNAL_STATE_UNKNOWN,
            Self::Absent => VM_EXTERNAL_STATE_ABSENT,
        }
    }

    /// The state a C `vm_external_state_t` names, or `None` when the value is
    /// not one.
    const fn from_c(state: c_int) -> Option<Self> {
        match state {
            VM_EXTERNAL_STATE_EXISTS => Some(Self::Exists),
            VM_EXTERNAL_STATE_UNKNOWN => Some(Self::Unknown),
            VM_EXTERNAL_STATE_ABSENT => Some(Self::Absent),
            _ => None,
        }
    }
}

/// `struct vm_external` of <`vm/vm_external.h>`: the header of a bitmap of page
/// states.
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

/// The page number `atop(offset)` names, as the C `_vm_external_state_get()`
/// holds it: `atop(offset)` is stored in an `unsigned int`, so a long offset
/// contributes only its low 32 bits.
const fn page_bit(offset: VmOffset) -> usize {
    // Deliberate truncation: the C's `unsigned int bit` keeps the low 32 bits
    // of the 64-bit `vm_size_t atop(offset)`.
    (offset >> PAGE_SHIFT) as u32 as usize
}

/// `vm_external_cache` of `vm/vm_external.c`.
static VM_EXTERNAL_CACHE: SyncCell<KmemCache> =
    SyncCell(UnsafeCell::new(KmemCache::zeroed()));

/// `vm_object_small_existence_map_cache` of `vm/vm_external.c`.
static SMALL_EXISTENCE_MAP_CACHE: SyncCell<KmemCache> =
    SyncCell(UnsafeCell::new(KmemCache::zeroed()));

/// `vm_object_large_existence_map_cache` of `vm/vm_external.c`.
static LARGE_EXISTENCE_MAP_CACHE: SyncCell<KmemCache> =
    SyncCell(UnsafeCell::new(KmemCache::zeroed()));

fn external_cache() -> *mut KmemCache {
    VM_EXTERNAL_CACHE.0.get()
}

fn small_existence_map_cache() -> *mut KmemCache {
    SMALL_EXISTENCE_MAP_CACHE.0.get()
}

fn large_existence_map_cache() -> *mut KmemCache {
    LARGE_EXISTENCE_MAP_CACHE.0.get()
}

impl VmExternal {
    /// `vm_external_create()` in C.
    fn create(size: VmOffset) -> Option<NonNull<Self>> {
        // SAFETY: `external_cache()` is initialized by
        // `vm_external_module_initialize()` before any caller.
        let header = unsafe { (*external_cache()).alloc() }
            .map(NonNull::cast::<Self>)?;

        let bytes = (size >> PAGE_SHIFT).wrapping_add(7) >> 3;
        let (cache, existence_size) = if bytes <= SMALL_SIZE {
            (small_existence_map_cache(), SMALL_SIZE)
        } else {
            (large_existence_map_cache(), LARGE_SIZE)
        };

        // SAFETY: the chosen map cache is initialized too, and its object
        // outlives the header until `destroy` returns it.
        let Some(map) = unsafe { (*cache).alloc() }.map(NonNull::cast::<u8>)
        else {
            // SAFETY: the header is the live allocation from above.
            unsafe { (*external_cache()).free(header.cast::<u8>()) };
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

    /// `vm_external_destroy()` in C.
    ///
    /// # Safety
    ///
    /// `e` must be a live object returned by `create`, and no reference to it
    /// may be used afterwards.
    unsafe fn destroy(e: NonNull<Self>) {
        let this = unsafe { e.as_ref() };
        if let Some(map) = this.existence_map {
            // SMALL_SIZE is 16, so the C `int` comparison is exact.
            let cache = if this.existence_size <= SMALL_SIZE as c_int {
                small_existence_map_cache()
            } else {
                large_existence_map_cache()
            };
            // SAFETY: the map came from that cache and is not used again; the
            // header is still alive for the read above.
            unsafe { (*cache).free(map.cast::<u8>()) };
        }
        // SAFETY: the header came from its cache, and nothing references it
        // after this point.
        unsafe { (*external_cache()).free(e.cast::<u8>()) };
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

    /// `_vm_external_state_get()` in C.
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

    /// `vm_external_state_set()` in C.
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

/// `vm_external_create()` in C.
///
/// # Safety
///
/// `vm_external_module_initialize()` must have initialized the slab caches;
/// the caller owns the returned object and releases it with
/// `vm_external_destroy()`.
pub(crate) unsafe fn vm_external_create(size: VmOffset) -> *mut VmExternal {
    VmExternal::create(size).map_or(ptr::null_mut(), NonNull::as_ptr)
}

/// `vm_external_destroy()` in C.
///
/// # Safety
///
/// A non-null `e` must be a live object from `vm_external_create()` that the
/// caller owns; the call frees it.
pub(crate) unsafe fn vm_external_destroy(e: *mut VmExternal) {
    if let Some(e) = NonNull::new(e) {
        unsafe { VmExternal::destroy(e) };
    }
}

/// `_vm_external_state_get()` in C; `vm_external_state_get()` is the macro
/// over it.
///
/// # Safety
///
/// A non-null `e` must be a live object from `vm_external_create()`; the call
/// only reads it.
pub(crate) unsafe fn vm_external_state_get(
    e: *mut VmExternal,
    offset: VmOffset,
) -> c_int {
    let Some(e) = NonNull::new(e) else {
        return ExternalState::Unknown.as_c();
    };
    unsafe { e.as_ref() }.state_get(offset).as_c()
}

/// `vm_external_state_get()` of <`vm/vm_external.h>`: the macro's null test
/// and the C state value, with `VM_EXTERNAL_STATE_UNKNOWN` for a null map.
///
/// # Safety
///
/// A non-null `e` must be a live object from `vm_external_create()`; the call
/// only reads it.
pub(crate) unsafe fn state_get(e: *mut VmExternal, offset: VmOffset) -> c_int {
    unsafe { vm_external_state_get(e, offset) }
}

/// `vm_external_state_set()` in C.
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

/// `vm_external_module_initialize()` in C.
///
/// # Safety
///
/// Must be called once, before any other routine of this module, from the
/// kernel's VM bootstrap.
pub(crate) unsafe fn vm_external_module_initialize() {
    // SAFETY: this module defines the caches and they outlive the kernel; the
    // bootstrap calls this before anything allocates from them.
    unsafe {
        (*external_cache()).init(
            b"vm_external",
            size_of::<VmExternal>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
        (*small_existence_map_cache()).init(
            b"small_existence_map",
            SMALL_SIZE,
            0,
            None,
            CacheInitFlags::EMPTY,
        );
        (*large_existence_map_cache()).init(
            b"large_existence_map",
            LARGE_SIZE,
            0,
            None,
            CacheInitFlags::EMPTY,
        );
    }
}
