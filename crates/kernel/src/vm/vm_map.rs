// SPDX-License-Identifier: CMU-Mach
// Derived from vm/vm_map.c and vm/vm_map.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Virtual memory maps, which `vm/vm_map.c` used to define and `vm/vm_map.h`
//! declares.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::pmap::KERNEL_PMAP;
use crate::arch::x86_64::pmap::KERNEL_VIRTUAL_END;
use crate::arch::x86_64::pmap::KERNEL_VIRTUAL_START;
use crate::arch::x86_64::pmap::pmap_create;
use crate::arch::x86_64::pmap::pmap_destroy;
use crate::arch::x86_64::pmap::pmap_enter;
use crate::arch::x86_64::pmap::pmap_page_protect;
use crate::arch::x86_64::pmap::pmap_pageable;
use crate::arch::x86_64::pmap::pmap_protect;
use crate::arch::x86_64::pmap::pmap_remove;
use crate::ipc::{IpcPort, IpcSpace, ipc_port};
use crate::kern::console::{CStrArg, kprint};
use crate::kern::debug::kpanic;
use crate::kern::lock::{LockData, SimpleLock};
use crate::kern::sched_prim::{
    THREAD_AWAKENED, assert_wait, thread_block, thread_wakeup_prim,
};
use crate::kern::slab::{CacheInitFlags, KmemCache, kalloc, kfree};
use crate::utils::cell::SyncCell;
use crate::vm::error::{
    Error, KERN_SUCCESS, error_from_kern_return, kern_return,
};
use crate::vm::memory_object_proxy;
use crate::vm::types::{
    PAGE_MASK, PAGE_SIZE, Pmap, VmInherit, VmObject, VmPage, VmProt,
};
use crate::vm::vm_fault;
use crate::vm::vm_kern::KERNEL_MAP;
use crate::vm::vm_kern::projected_buffer_collect;
use crate::vm::vm_object;
use crate::vm::vm_object::KERNEL_OBJECT;
use crate::vm::vm_object::VM_SUBMAP_OBJECT;
use crate::vm::vm_object::vm_object_allocate;
use crate::vm::vm_object::vm_object_coalesce;
use crate::vm::vm_object::vm_object_copy_slowly;
use crate::vm::vm_object::vm_object_copy_strategically;
use crate::vm::vm_object::vm_object_copy_temporary;
use crate::vm::vm_object::vm_object_pmap_protect;
use crate::vm::vm_object::vm_object_shadow;
use crate::vm::vm_object_ffi::vm_object_deallocate;
use crate::vm::vm_page;
use crate::vm::vm_resident;
use crate::vm::vm_resident::VM_PAGE_QUEUE_LOCK;
use collections::rb_tree::{self, RbTree};
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_uint, c_void};
use core::mem::{ManuallyDrop, offset_of, size_of};
use core::ops::Bound;
use core::ptr::{self, NonNull, addr_of_mut};
use core::sync::atomic::{AtomicU32, Ordering};

/// `VM_MAP_COPY_PAGE_LIST_MAX`: pages a page-list copy carries inline.
pub const VM_MAP_COPY_PAGE_LIST_MAX: usize = 64;

/// `VM_MAP_COPY_ENTRY_LIST`: the copy holds an entry list.
pub const VM_MAP_COPY_ENTRY_LIST: c_int = 1;
/// `VM_MAP_COPY_OBJECT`: the copy holds one object.
pub const VM_MAP_COPY_OBJECT: c_int = 2;
/// `VM_MAP_COPY_PAGE_LIST`: the copy holds a page list.
pub const VM_MAP_COPY_PAGE_LIST: c_int = 3;

/// `vm_map_cache` of `vm/vm_map.c`.
static VM_MAP_CACHE: SyncCell<KmemCache> =
    SyncCell(UnsafeCell::new(KmemCache::zeroed()));

/// `vm_map_entry_cache` of `vm/vm_map.c`.
static VM_MAP_ENTRY_CACHE: SyncCell<KmemCache> =
    SyncCell(UnsafeCell::new(KmemCache::zeroed()));

/// `vm_map_copy_cache` of `vm/vm_map.c`.
static VM_MAP_COPY_CACHE: SyncCell<KmemCache> =
    SyncCell(UnsafeCell::new(KmemCache::zeroed()));

fn map_cache() -> *mut KmemCache {
    VM_MAP_CACHE.0.get()
}

fn map_entry_cache() -> *mut KmemCache {
    VM_MAP_ENTRY_CACHE.0.get()
}

fn map_copy_cache() -> *mut KmemCache {
    VM_MAP_COPY_CACHE.0.get()
}

/// Pins our layout: size, alignment and the offsets of the fields the
/// rest of the file names.
macro_rules! assert_layout {
    ($t:ty, $size:expr, $align:expr, { $($f:ident: $off:expr),* $(,)? }) => {
        const _: () = assert!(size_of::<$t>() == $size);
        const _: () = assert!(align_of::<$t>() == $align);
        $(
            const _: () = assert!(offset_of!($t, $f) == $off);
        )*
    };
}

/// `struct vm_map_links`: the doubly-linked chain through the entries, sorted
/// by address.
#[repr(C)]
pub struct VmMapLinks {
    /// The previous entry, or the header.
    pub prev: Option<NonNull<VmMapEntry>>,
    /// The next entry, or the header.
    pub next: Option<NonNull<VmMapEntry>>,
    /// The first address the entry covers.
    pub start: VmOffset,
    /// The first address after the entry.
    pub end: VmOffset,
}

assert_layout!(VmMapLinks, 32, 8, {
    prev: 0, next: 8, start: 16, end: 24,
});

/// Bits of the `vm_map_entry` flag word, in declaration order.
pub const VME_IN_GAP_TREE: u32 = 1 << 0;
/// `VME_IS_SHARED`: the mapping is shared, not copied, on fork.
pub const VME_IS_SHARED: u32 = 1 << 1;
/// `VME_IS_SUB_MAP`: the entry's object is a sub-map, not a VM object.
pub const VME_IS_SUB_MAP: u32 = 1 << 2;
/// `VME_IN_TRANSITION`: an operation is in progress; wait rather than
/// touch the entry.
pub const VME_IN_TRANSITION: u32 = 1 << 3;
/// `VME_NEEDS_WAKEUP`: a thread is waiting for the transition to end.
pub const VME_NEEDS_WAKEUP: u32 = 1 << 4;
/// `VME_NEEDS_COPY`: the object must be copied before a write.
pub const VME_NEEDS_COPY: u32 = 1 << 5;

/// `struct vm_map_entry`: one mapping in a map.
#[repr(C)]
#[allow(missing_docs)]
pub struct VmMapEntry {
    pub links: VmMapLinks,
    /// Node in the address-ordered tree, `tree_node` in C.
    pub tree_node: rb_tree::Link,
    /// Node in the gap-size tree, `gap_node` in C.  The tree allows
    /// duplicate keys, so it indexes every entry with a nonzero gap.
    pub gap_node: rb_tree::Link,
    /// The gap after this entry, `gap_size` in C.
    pub gap_size: VmSize,
    /// The object or submap mapped, `object` in C.
    pub object: VmMapObject,
    /// Offset into the object, `offset` in C.
    pub offset: VmOffset,
    /// The packed boolean bits, `in_gap_tree` through `needs_copy`.
    pub flags: u32,
    pub protection: VmProt,
    pub max_protection: VmProt,
    pub inheritance: VmInherit,
    pub wired_count: u16,
    pub wired_access: VmProt,
    /// The projected-buffer tag, `projected_on` in C: null for a normal entry,
    /// all ones for a non-persistent kernel-map entry, or the matching
    /// kernel-map entry.
    pub projected_on: *mut Self,
}

assert_layout!(VmMapEntry, 136, 8, {
    links: 0, tree_node: 32, gap_node: 56, gap_size: 80,
    object: 88, offset: 96, flags: 104, protection: 108,
    max_protection: 112, inheritance: 116, wired_count: 120,
    wired_access: 124, projected_on: 128,
});

rb_tree::adapter!(
    /// The adapter for an entry's `tree_node` in [`VmMapHeader::tree`],
    /// keyed by the entry's first address.
    ///
    /// [`RbTree::upper_bound`] then returns the last entry at or before a
    /// looked-up address, which `lookup_entry()` range-checks.
    pub VmMapEntryTreeAdapter = VmMapEntry { tree_node } key(VmOffset) = |entry| entry.links.start
);

rb_tree::adapter!(
    /// The adapter for an entry's `gap_node` in [`VmMapHeader::gap_tree`],
    /// keyed by gap size.
    ///
    /// The tree allows duplicate keys, so it holds one node per entry
    /// with a nonzero gap.
    pub VmMapEntryGapAdapter = VmMapEntry { gap_node } key(VmSize) = |entry| entry.gap_size
);

// The links are the sizes the entry offsets above and below rely on; the
// tree heads are three words (ADR 0051).
const _: () = assert!(size_of::<rb_tree::Link>() == 24);
const _: () = assert!(align_of::<rb_tree::Link>() == 8);
const _: () = assert!(size_of::<RbTree<'static, VmMapEntryTreeAdapter>>() == 24);
const _: () = assert!(size_of::<RbTree<'static, VmMapEntryGapAdapter>>() == 24);

/// The object-or-submap tag of an entry, `union vm_map_object`.
#[repr(C)]
#[allow(missing_docs)]
pub union VmMapObject {
    pub vm_object: *mut VmObject,
    pub sub_map: *mut VmMap,
}

assert_layout!(VmMapObject, 8, 8, { vm_object: 0, sub_map: 0 });

/// Where an entry's wires came from, the three states of `projected_on`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Projection {
    /// The entry is normal.
    None,
    /// A non-persistent entry of the kernel map.
    NonPersistent,
    /// A projected region matched with this kernel-map entry.
    Entry(NonNull<VmMapEntry>),
}

// These accessors mirror the C bitfields one for one; the `VME_*`
// constants above carry the documentation, and a doc per getter/setter
// pair would only respell the field name.
#[allow(missing_docs)]
impl VmMapEntry {
    #[must_use]
    pub const fn is_shared(&self) -> bool {
        self.flags & VME_IS_SHARED != 0
    }

    pub const fn set_shared(&mut self, shared: bool) {
        self.set_flag(VME_IS_SHARED, shared);
    }

    #[must_use]
    pub const fn is_sub_map(&self) -> bool {
        self.flags & VME_IS_SUB_MAP != 0
    }

    pub const fn set_sub_map(&mut self, sub_map: bool) {
        self.set_flag(VME_IS_SUB_MAP, sub_map);
    }

    #[must_use]
    pub const fn in_gap_tree(&self) -> bool {
        self.flags & VME_IN_GAP_TREE != 0
    }

    pub const fn set_in_gap_tree(&mut self, value: bool) {
        self.set_flag(VME_IN_GAP_TREE, value);
    }

    #[must_use]
    pub const fn in_transition(&self) -> bool {
        self.flags & VME_IN_TRANSITION != 0
    }

    pub const fn set_in_transition(&mut self, value: bool) {
        self.set_flag(VME_IN_TRANSITION, value);
    }

    #[must_use]
    pub const fn needs_wakeup(&self) -> bool {
        self.flags & VME_NEEDS_WAKEUP != 0
    }

    pub const fn set_needs_wakeup(&mut self, value: bool) {
        self.set_flag(VME_NEEDS_WAKEUP, value);
    }

    #[must_use]
    pub const fn needs_copy(&self) -> bool {
        self.flags & VME_NEEDS_COPY != 0
    }

    pub const fn set_needs_copy(&mut self, value: bool) {
        self.set_flag(VME_NEEDS_COPY, value);
    }

    const fn set_flag(&mut self, bit: u32, value: bool) {
        if value {
            self.flags |= bit;
        } else {
            self.flags &= !bit;
        }
    }

    #[must_use]
    pub fn projection(&self) -> Projection {
        if self.projected_on.is_null() {
            Projection::None
        } else if self.projected_on.addr() == usize::MAX {
            Projection::NonPersistent
        } else {
            // SAFETY: not null, just checked.
            Projection::Entry(unsafe {
                NonNull::new_unchecked(self.projected_on)
            })
        }
    }

    /// Mark the entry non-persistent, `(vm_map_entry_t) -1` in C.
    pub const fn set_projection_non_persistent(&mut self) {
        self.projected_on = ptr::without_provenance_mut(usize::MAX);
    }
}

/// `struct vm_map_header`: the header of a map and of an entry-list copy.
#[repr(C)]
#[allow(missing_docs)]
pub struct VmMapHeader {
    /// First, last and bounds of the entry chain.
    pub links: VmMapLinks,
    /// The address-ordered tree.
    pub tree: RbTree<'static, VmMapEntryTreeAdapter>,
    /// The gap-size tree.
    pub gap_tree: RbTree<'static, VmMapEntryGapAdapter>,
    pub nentries: c_int,
}

assert_layout!(VmMapHeader, 88, 8, {
    links: 0, tree: 32, gap_tree: 56, nentries: 80,
});

impl VmMapHeader {
    /// The sentinel entry the header's links stand in for; `vm_map_to_entry()`
    /// and `vm_map_copy_to_entry()` in C.
    #[must_use]
    pub fn to_entry(&self) -> NonNull<VmMapEntry> {
        NonNull::from(&self.links).cast()
    }
}

/// Bits of the `vm_map` flag word, in declaration order.
pub const VM_MAP_WAIT_FOR_SPACE: u32 = 1 << 0;
/// `VM_MAP_WIRING_REQUIRED`: new mappings in the map are wired down.
pub const VM_MAP_WIRING_REQUIRED: u32 = 1 << 1;

/// `struct vm_map`: one address space.
#[repr(C)]
#[allow(missing_docs)]
pub struct VmMap {
    /// The sleep lock protecting the map data.
    pub lock: LockData,
    pub hdr: VmMapHeader,
    pub pmap: *mut Pmap,
    /// Current virtual size.
    pub size: VmSize,
    pub size_wired: VmSize,
    /// Size of the `VM_PROT_NONE` regions.
    pub size_none: VmSize,
    /// Reference count; guarded by `ref_lock`, so Rust reaches it through
    /// `UnsafeCell` while holding that lock.
    pub ref_count: UnsafeCell<c_int>,
    pub ref_lock: SimpleLock,
    /// Last used entry; guarded by `hint_lock`.
    pub hint: UnsafeCell<*mut VmMapEntry>,
    pub hint_lock: SimpleLock,
    pub first_free: *mut VmMapEntry,
    /// `wait_for_space` and `wiring_required`.
    pub flags: u32,
    /// Version number, bumped by every write lock.
    pub timestamp: c_uint,
    pub name: *const c_char,
    /// Current virtual-memory limit.
    pub size_cur_limit: VmSize,
    /// Largest limit an unprivileged task may set.
    pub size_max_limit: VmSize,
}

assert_layout!(VmMap, 200, 8, {
    lock: 0, hdr: 16, pmap: 104, size: 112, size_wired: 120,
    size_none: 128, ref_count: 136, ref_lock: 140, hint: 144,
    hint_lock: 152, first_free: 160, flags: 168, timestamp: 172,
    name: 176, size_cur_limit: 184, size_max_limit: 192,
});

impl VmMap {
    /// The zero image a C `static` of `struct vm_map` began with; the boot
    /// path fills it through `vm_map_init()` or `kmem_submap()`.
    pub(crate) const fn zeroed() -> Self {
        Self {
            lock: LockData::zeroed(),
            hdr: VmMapHeader {
                links: VmMapLinks {
                    prev: None,
                    next: None,
                    start: 0,
                    end: 0,
                },
                tree: RbTree::new(),
                gap_tree: RbTree::new(),
                nentries: 0,
            },
            pmap: ptr::null_mut(),
            size: 0,
            size_wired: 0,
            size_none: 0,
            ref_count: UnsafeCell::new(0),
            ref_lock: SimpleLock::new(),
            hint: UnsafeCell::new(ptr::null_mut()),
            hint_lock: SimpleLock::new(),
            first_free: ptr::null_mut(),
            flags: 0,
            timestamp: 0,
            name: ptr::null(),
            size_cur_limit: 0,
            size_max_limit: 0,
        }
    }

    /// The sentinel entry of this map's chain; `vm_map_to_entry()` in C.
    pub fn to_entry(&self) -> NonNull<VmMapEntry> {
        self.hdr.to_entry()
    }

    /// Whether callers wait for space instead of failing.
    pub const fn wait_for_space(&self) -> bool {
        self.flags & VM_MAP_WAIT_FOR_SPACE != 0
    }

    /// Whether new mappings are wired.
    pub const fn wiring_required(&self) -> bool {
        self.flags & VM_MAP_WIRING_REQUIRED != 0
    }
}

/// Round `x` up to a page boundary; `round_page()` in C.
pub(crate) const fn round_page(x: VmOffset) -> VmOffset {
    x.wrapping_add(PAGE_MASK) & !PAGE_MASK
}

/// Round `x` down to a page boundary; `trunc_page()` in C.
pub(crate) const fn trunc_page(x: VmOffset) -> VmOffset {
    x & !PAGE_MASK
}

/// The body `vm_map_glue_page_steal()` had in C: unlink the page from its
/// object and the queues, clearing a wired page's count.
///
/// # Safety
///
/// `page` must be a live page whose object lock the caller holds.
unsafe fn page_steal(page: *mut VmPage) {
    // SAFETY: the page-queues lock guards the queues and the wire count, and
    // `vm_page_remove()` requires the object lock the caller holds.
    unsafe {
        (*addr_of_mut!(VM_PAGE_QUEUE_LOCK)).lock();
        vm_resident::remove(NonNull::new_unchecked(page));
        if (*page).wire_count() > 0 {
            (*page).set_wire_count(0);
            vm_resident::VM_PAGE_WIRE_COUNT.fetch_sub(1, Ordering::Relaxed);
        } else {
            vm_page::queues_remove(page);
        }
        (*addr_of_mut!(VM_PAGE_QUEUE_LOCK)).unlock();
    }
}

/// The body `vm_map_glue_page_activate_if_idle()` had in C: activate a page
/// that is on no queue.
///
/// # Safety
///
/// `page` must be a live page whose object lock the caller holds.
unsafe fn page_activate_if_idle(page: *mut VmPage) {
    // SAFETY: the page-queues lock serializes the flags, the queues and
    // `vm_page_activate()`.
    unsafe {
        (*addr_of_mut!(VM_PAGE_QUEUE_LOCK)).lock();
        if !(*page).is_active() && !(*page).is_inactive() {
            vm_page::activate(page);
        }
        (*addr_of_mut!(VM_PAGE_QUEUE_LOCK)).unlock();
    }
}

impl VmMap {
    /// Copy the virtual-memory limits from `src` to `dst`, which
    /// `vm_map_copy_limits()` in C does.
    pub(crate) fn copy_limits(dst: NonNull<Self>, src: NonNull<Self>) {
        // SAFETY: the caller promises both maps are valid and distinct.
        unsafe {
            (*dst.as_ptr()).size_cur_limit = (*src.as_ptr()).size_cur_limit;
            (*dst.as_ptr()).size_max_limit = (*src.as_ptr()).size_max_limit;
        }
    }

    /// `vm_map_lock()` in C.
    pub(crate) fn lock(map: NonNull<Self>) {
        // SAFETY: the caller owns the map, and the sleep lock lives in its
        // storage.
        unsafe { (*map.as_ptr()).lock.write() };
        // SAFETY: `per_cpu::thread()` is the running thread, or null early in
        // boot; the C `vm_privilege++` wraps as an unsigned int.
        let thread = per_cpu::thread();
        if !thread.is_null() {
            // SAFETY: the thread is live as checked above.
            unsafe {
                (*thread).vm_privilege =
                    (*thread).vm_privilege.wrapping_add(1);
            };
        }
        // SAFETY: the write lock is held, so this is the only writer; the C
        // `timestamp++` wraps as an unsigned int.
        unsafe {
            let timestamp = addr_of_mut!((*map.as_ptr()).timestamp);
            timestamp.write(timestamp.read().wrapping_add(1));
        }
    }

    /// `vm_map_unlock()` in C.
    pub(crate) fn unlock(map: NonNull<Self>) {
        // SAFETY: `per_cpu::thread()` is the running thread, or null early in
        // boot, and the C code balances the privilege bump with this
        // decrement.
        let thread = per_cpu::thread();
        if !thread.is_null() {
            // SAFETY: the thread is live as checked above.
            unsafe {
                (*thread).vm_privilege =
                    (*thread).vm_privilege.wrapping_sub(1);
            };
        }
        // SAFETY: the caller holds the write lock on this map.
        unsafe { (*map.as_ptr()).lock.done() };
    }

    /// `vm_map_verify()` in C.
    pub(crate) fn verify(map: NonNull<Self>, version: &VmMapVersion) -> bool {
        // SAFETY: the caller owns the map.
        unsafe { (*map.as_ptr()).lock.read() };
        // SAFETY: reading the timestamp holds at least the read lock.
        let timestamp = unsafe { (*map.as_ptr()).timestamp };
        let result = timestamp == version.main_timestamp;
        if !result {
            // SAFETY: the read lock was taken above.
            unsafe { (*map.as_ptr()).lock.done() };
        }
        result
    }

    /// `vm_map_lookup_entry()` in C.
    pub(crate) fn lookup_entry(
        &self,
        address: VmOffset,
    ) -> (bool, NonNull<VmMapEntry>) {
        let sentinel = self.to_entry();

        self.hint_lock.lock();
        // SAFETY: `hint` is written only under `hint_lock`, held here.
        let hint = unsafe { *self.hint.get() };
        self.hint_lock.unlock();

        if hint != sentinel.as_ptr() {
            // SAFETY: the hint names a live entry of this map, and the
            // caller's map lock keeps the chain stable.
            let hint_entry = unsafe { &*hint };
            if address >= hint_entry.links.start {
                if address < hint_entry.links.end {
                    // SAFETY: the hint is not null, just checked.
                    return (true, unsafe { NonNull::new_unchecked(hint) });
                }
                let next = hint_entry.links.next;
                match next {
                    None => {
                        // SAFETY: the hint is not null, just checked.
                        return (false, unsafe {
                            NonNull::new_unchecked(hint)
                        });
                    }
                    Some(next) if next == sentinel => {
                        // SAFETY: the hint is not null, just checked.
                        return (false, unsafe {
                            NonNull::new_unchecked(hint)
                        });
                    }
                    Some(next) => {
                        // SAFETY: the chain is stable under the map lock the
                        // caller holds.
                        let next_start = unsafe { next.as_ref() }.links.start;
                        if address < next_start {
                            // SAFETY: the hint is not null, just checked.
                            return (false, unsafe {
                                NonNull::new_unchecked(hint)
                            });
                        }
                    }
                }
            }
        }

        // The tree orders entries by first address, so the last entry at or
        // before `address` is the only one that can contain it; the C
        // comparator folded the range check into the walk, this checks it
        // after the floor lookup.
        let cursor = self.hdr.tree.upper_bound(Bound::Included(&address));

        cursor.current_ptr().map_or_else(
            || {
                self.save_hint(sentinel);
                (false, sentinel)
            },
            |entry| {
                self.save_hint(entry);
                // SAFETY: the cursor named an entry of this tree, live under
                // the caller's lock.
                let end = unsafe { entry.as_ref() }.links.end;
                (address < end, entry)
            },
        )
    }

    /// The `SAVE_HINT()` macro in C.
    fn save_hint(&self, entry: NonNull<VmMapEntry>) {
        self.hint_lock.lock();
        // SAFETY: `hint` is written only under `hint_lock`, held here.
        unsafe { *self.hint.get() = entry.as_ptr() };
        self.hint_lock.unlock();
    }

    /// `vm_map_reference()` in C.
    pub(crate) fn reference(map: NonNull<Self>) {
        // SAFETY: the caller owns the map for the call.
        let this = unsafe { &*map.as_ptr() };

        this.ref_lock.lock();
        // SAFETY: `ref_count` is guarded by `ref_lock`, held here.
        unsafe {
            let count = &mut *this.ref_count.get();
            *count = count.wrapping_add(1);
        }
        this.ref_lock.unlock();
    }

    /// `vm_map_deallocate()` in C.
    pub(crate) fn deallocate(map: NonNull<Self>) {
        // SAFETY: the caller owns the map for the call.
        let this = unsafe { &*map.as_ptr() };

        this.ref_lock.lock();
        // SAFETY: `ref_count` is guarded by `ref_lock`, held here.
        let count = unsafe {
            let count = &mut *this.ref_count.get();
            *count = count.wrapping_sub(1);
            *count
        };
        this.ref_lock.unlock();

        if count > 0 {
            return;
        }

        let min = this.hdr.links.start;
        let max = this.hdr.links.end;
        let pmap = this.pmap;

        // The map is exclusively owned here, as the projected-buffer walk
        // requires.
        let _ = projected_buffer_collect(map);
        // SAFETY: `ref_count` is guarded by `ref_lock`, held here; the map is
        // unlocked, as the C contract of vm_map_delete requires when
        // the refcount is zero.
        unsafe { (*map.as_ptr()).delete(min, max) };
        // SAFETY: `ref_count` is guarded by `ref_lock`, held here; the map is
        // unlocked, as the C contract of `vm_map_delete` requires when
        // the refcount is zero, and the pmap is no longer used.
        unsafe { pmap_destroy(NonNull::new(pmap)) };
        // SAFETY: the map came from `map_cache()`, and nothing references it
        // now.
        unsafe { (*map_cache()).free(map.cast::<u8>()) };
    }

    /// `vm_map_init()` in C.
    ///
    /// # Safety
    ///
    /// Must run once, before any other routine of this module, so the caches
    /// are ready before the first allocation from them.
    pub(crate) unsafe fn init_module() {
        // SAFETY: this module defines the caches and they outlive the kernel;
        // the bootstrap calls this before anything allocates from them.
        unsafe {
            (*map_cache()).init(
                b"vm_map",
                size_of::<Self>(),
                0,
                None,
                CacheInitFlags::EMPTY,
            );
            (*map_entry_cache()).init(
                b"vm_map_entry",
                size_of::<VmMapEntry>(),
                0,
                None,
                CacheInitFlags::NOOFFSLAB | CacheInitFlags::PHYSMEM,
            );
            (*map_copy_cache()).init(
                b"vm_map_copy",
                size_of::<VmMapCopy>(),
                0,
                None,
                CacheInitFlags::EMPTY,
            );
        }
    }

    /// `vm_map_setup()` in C.
    pub(crate) fn setup(
        map: &mut Self,
        pmap: *mut Pmap,
        min: VmOffset,
        max: VmOffset,
    ) {
        let sentinel = map.to_entry();

        map.hdr.links.prev = Some(sentinel);
        map.hdr.links.next = Some(sentinel);
        map.hdr.nentries = 0;
        map.hdr.tree.clear();
        map.hdr.gap_tree.clear();

        map.size = 0;
        map.size_wired = 0;
        map.size_none = 0;
        // SAFETY: the map is freshly set up here, no lock needed yet.
        unsafe { *map.ref_count.get() = 1 };
        map.pmap = pmap;
        map.hdr.links.start = min;
        map.hdr.links.end = max;
        map.flags = 0;
        map.first_free = sentinel.as_ptr();
        // SAFETY: the map is freshly set up here, no lock needed yet.
        unsafe { *map.hint.get() = sentinel.as_ptr() };
        map.name = ptr::null();

        // TODO add to default limit the swap size
        // SAFETY: `kernel_pmap` is the boot pmap, never null.
        if pmap == unsafe { KERNEL_PMAP } {
            map.size_cur_limit = !0;
            map.size_max_limit = !0;
        } else {
            let mem_size = vm_page::mem_size();
            map.size_cur_limit = mem_size;
            map.size_max_limit = mem_size;
        }

        // SAFETY: the sleep lock lives in the caller's map storage.
        unsafe { LockData::init(addr_of_mut!(map.lock), true) };
        map.timestamp = 0;
        map.ref_lock.init();
        map.hint_lock.init();
    }

    /// `vm_map_create()` in C.
    pub(crate) fn create(
        pmap: *mut Pmap,
        min: VmOffset,
        max: VmOffset,
    ) -> Option<NonNull<Self>> {
        // SAFETY: `map_cache()` is initialized by `vm_map_init()` before any
        // map is created.
        let map = unsafe { (*map_cache()).alloc() }?.cast::<Self>();

        // SAFETY: the object is freshly allocated and unshared.
        Self::setup(unsafe { &mut *map.as_ptr() }, pmap, min, max);
        Some(map)
    }

    /// `vm_map_msync()` in C, including its unfinished tail: a request with
    /// work in it still reports `KERN_INVALID_ARGUMENT`.
    pub(crate) const fn msync(
        map: Option<NonNull<Self>>,
        address: VmOffset,
        size: VmSize,
        sync_flags: c_int,
    ) -> Result<(), Error> {
        const ASYNCHRONOUS: c_int = 0x01;
        const SYNCHRONOUS: c_int = 0x02;
        const BOTH: c_int = ASYNCHRONOUS | SYNCHRONOUS;

        if map.is_none() {
            return Err(Error::InvalidArgument);
        }

        if sync_flags & BOTH == BOTH {
            return Err(Error::InvalidArgument);
        }

        let size = round_page(address.wrapping_add(size))
            .wrapping_sub(trunc_page(address));

        if size == 0 {
            return Ok(());
        }

        // TODO: the C body has no msync implementation yet.
        Err(Error::InvalidArgument)
    }

    /// `vm_map_machine_attribute()` in C.
    pub(crate) fn machine_attribute(
        map: NonNull<Self>,
        address: VmOffset,
        size: VmSize,
    ) -> Result<(), Error> {
        // SAFETY: the caller owns the map for the call.
        let (min, max) = unsafe {
            let links = addr_of_mut!((*map.as_ptr()).hdr.links);
            ((*links).start, (*links).end)
        };

        if address < min || address.wrapping_add(size) > max {
            return Err(Error::InvalidArgument);
        }

        Self::lock(map);
        Self::unlock(map);

        Err(Error::InvalidAddress)
    }
}

/// The object, offset, protection and wiring a successful `vm_map_lookup()`
/// reports, with the timestamp that validates it.
pub(crate) struct VmMapLookup {
    /// The object `vaddr` faults into, returned locked.
    pub object: *mut VmObject,
    /// Offset into `object`.
    pub offset: VmOffset,
    /// The effective protection.
    pub protection: VmProt,
    pub wired: bool,
    /// The map's timestamp at the time of the lookup.
    pub timestamp: c_uint,
}

/// One locked pass of `vm_map_lookup()`: either it is done, it failed, it
/// found a submap to descend into, or the read-to-write upgrade was lost and
/// the caller must retry with no lock held.
enum LookupAttempt {
    /// The lookup succeeded with the map read-locked.
    Found(VmMapLookup),
    /// The lookup failed with the map read-locked.
    Failed(Error),
    /// The entry is a submap; the map is read-locked.
    SubMap(NonNull<VmMap>),
    /// The upgrade failed and released the read lock.
    Retry,
}

impl VmMap {
    /// Upgrade the map's read lock to a write lock, bumping the timestamp as
    /// the `vm_map_lock_read_to_write()` macro does when the upgrade succeeds.
    fn lock_read_to_write(map: NonNull<Self>) -> bool {
        // SAFETY: the caller holds the read lock; `LockData::read_to_write`
        // leaves the write lock held when the upgrade succeeds and releases
        // the read lock with no lock held when it fails.
        let failed = unsafe { (*map.as_ptr()).lock.read_to_write() };
        if !failed {
            // SAFETY: the write lock is held, so the timestamp is exclusively
            // ours; the macro's `map->timestamp++` wraps as an unsigned int.
            unsafe {
                let timestamp = addr_of_mut!((*map.as_ptr()).timestamp);
                timestamp.write(timestamp.read().wrapping_add(1));
            }
        }
        failed
    }

    /// One locked pass of `vm_map_lookup()`, without the submap loop.
    fn lookup_locked(
        map: NonNull<Self>,
        vaddr: VmOffset,
        fault_type_in: VmProt,
    ) -> LookupAttempt {
        // SAFETY: the caller holds the map lock, so the entries are stable and
        // no reference outlives it.
        let this = unsafe { &*map.as_ptr() };

        let (found, entry) = this.lookup_entry(vaddr);
        if !found {
            return LookupAttempt::Failed(Error::InvalidAddress);
        }

        // SAFETY: `entry` is a live entry of a locked map.
        if unsafe { (*entry.as_ptr()).is_sub_map() } {
            // SAFETY: a submap entry's union member is a live map.
            let submap = unsafe {
                NonNull::new_unchecked((*entry.as_ptr()).object.sub_map)
            };
            return LookupAttempt::SubMap(submap);
        }

        // SAFETY: the entry is live under the map lock.
        let mut prot = unsafe { (*entry.as_ptr()).protection };

        if !prot.contains(fault_type_in) {
            return LookupAttempt::Failed(
                if prot.contains(VmProt::NOTIFY)
                    && fault_type_in.contains(VmProt::WRITE)
                {
                    Error::WriteProtectionFailure
                } else {
                    Error::ProtectionFailure
                },
            );
        }

        // SAFETY: the entry is live under the map lock.
        let wired = unsafe { (*entry.as_ptr()).wired_count } != 0;
        let fault_type = if wired {
            // SAFETY: the entry is live under the map lock.
            prot = unsafe { (*entry.as_ptr()).protection };
            prot
        } else {
            fault_type_in
        };

        // SAFETY: the entry is live under the map lock.
        if unsafe { (*entry.as_ptr()).needs_copy() } {
            if fault_type.contains(VmProt::WRITE) {
                if Self::lock_read_to_write(map) {
                    return LookupAttempt::Retry;
                }
                // SAFETY: the write lock is held; the integer wraps.
                unsafe {
                    let timestamp = addr_of_mut!((*map.as_ptr()).timestamp);
                    timestamp.write(timestamp.read().wrapping_add(1));
                }

                // SAFETY: the entry is live under the write lock and
                // `vm_object_shadow` keeps the reference it replaces.
                unsafe {
                    vm_object_shadow(
                        addr_of_mut!((*entry.as_ptr()).object.vm_object),
                        addr_of_mut!((*entry.as_ptr()).offset),
                        (*entry.as_ptr())
                            .links
                            .end
                            .wrapping_sub((*entry.as_ptr()).links.start),
                    );
                    (*entry.as_ptr()).set_needs_copy(false);
                }

                // SAFETY: the write lock taken by the upgrade.
                unsafe { (*map.as_ptr()).lock.write_to_read() };
            } else {
                prot &= VmProt::from_bits(!VmProt::WRITE.bits());
            }
        }

        // SAFETY: the entry is live under the map lock.
        if unsafe { (*entry.as_ptr()).object.vm_object }.is_null() {
            if Self::lock_read_to_write(map) {
                return LookupAttempt::Retry;
            }

            // SAFETY: the write lock is held; the entry is live.
            unsafe {
                (*entry.as_ptr()).object.vm_object = vm_object_allocate(
                    (*entry.as_ptr())
                        .links
                        .end
                        .wrapping_sub((*entry.as_ptr()).links.start),
                );
                (*entry.as_ptr()).offset = 0;
            }

            // SAFETY: the write lock taken by the upgrade.
            unsafe { (*map.as_ptr()).lock.write_to_read() };
        }

        // SAFETY: the entry is live under the lock.
        let (object, offset, timestamp) = unsafe {
            let e = &*entry.as_ptr();
            (
                e.object.vm_object,
                vaddr.wrapping_sub(e.links.start).wrapping_add(e.offset),
                (*map.as_ptr()).timestamp,
            )
        };

        // SAFETY: the map lock keeps the entry's reference alive, and the
        // caller receives the object locked, as in C.
        unsafe { (*object).lock.lock() };

        LookupAttempt::Found(VmMapLookup {
            object,
            offset,
            protection: prot,
            wired,
            timestamp,
        })
    }

    /// `vm_map_lookup()` in C.
    pub(crate) fn lookup(
        var_map: &mut NonNull<Self>,
        vaddr: VmOffset,
        fault_type: VmProt,
        keep_map_locked: bool,
    ) -> Result<VmMapLookup, Error> {
        loop {
            let map = *var_map;
            // SAFETY: the caller owns the map for the call; the read lock
            // keeps the entries stable.
            unsafe { (*map.as_ptr()).lock.read() };

            match Self::lookup_locked(map, vaddr, fault_type) {
                LookupAttempt::Found(result) => {
                    if !keep_map_locked {
                        // SAFETY: the read lock taken above.
                        unsafe { (*map.as_ptr()).lock.done() };
                    }
                    return Ok(result);
                }
                LookupAttempt::Failed(error) => {
                    // SAFETY: the read lock taken above.
                    unsafe { (*map.as_ptr()).lock.done() };
                    return Err(error);
                }
                LookupAttempt::SubMap(submap) => {
                    // SAFETY: the read lock taken above.
                    unsafe { (*map.as_ptr()).lock.done() };
                    *var_map = submap;
                }
                LookupAttempt::Retry => {}
            }
        }
    }

    /// `vm_map_submap()` in C.
    pub(crate) fn submap(
        &mut self,
        start_in: VmOffset,
        end_in: VmOffset,
        submap: *mut Self,
    ) -> Result<(), Error> {
        let map = NonNull::from(&mut *self);
        Self::lock(map);

        let mut start = start_in;
        let mut end = end_in;
        self.range_check(&mut start, &mut end);

        let sentinel = self.to_entry();
        let (found, temp_entry) = self.lookup_entry(start);
        let entry = if found {
            // SAFETY: `temp_entry` contains `start`.
            unsafe { self.hdr.clip_start_at(temp_entry, start, true) };
            temp_entry
        } else {
            // SAFETY: `temp_entry` is the header or a live entry, so its
            // `next` is live or the header.
            unsafe { (*temp_entry.as_ptr()).links.next.unwrap_or(sentinel) }
        };

        // SAFETY: the entry is live under the map lock.
        if !self.hdr.is_sentinel(entry)
            // SAFETY: the entry is live under the map lock.
            && end < unsafe { (*entry.as_ptr()).links.end }
        {
            // SAFETY: `entry` is live and spans `end`; the map lock keeps it
            // stable.
            unsafe { self.hdr.clip_end(entry, end, true) };
        }

        let mut result = Err(Error::InvalidArgument);

        // SAFETY: `entry` is live and the map is locked.
        if !self.hdr.is_sentinel(entry)
            // SAFETY: `entry` is live and the map is locked.
            && start == unsafe { (*entry.as_ptr()).links.start }
            // SAFETY: `entry` is live and the map is locked.
            && end == unsafe { (*entry.as_ptr()).links.end }
            // SAFETY: `entry` is live and the map is locked.
            && !unsafe { (*entry.as_ptr()).is_sub_map() }
        {
            // SAFETY: the entry is live and not a submap, so the union's
            // `vm_object` member is the one to read.
            let object = unsafe { (*entry.as_ptr()).object.vm_object };
            // SAFETY: `vm_submap_object` is the boot placeholder and is live
            // for the life of the kernel.
            if object == unsafe { VM_SUBMAP_OBJECT }
                // SAFETY: the object is the placeholder just compared.
                && unsafe {
                    (*object).is_pristine_submap()
                }
            {
                // SAFETY: the map is write-locked and the entry is live.
                unsafe {
                    (*entry.as_ptr()).object.vm_object = ptr::null_mut();
                }
                // SAFETY: the entry held the placeholder's reference.
                unsafe { vm_object_deallocate(object) };
                // SAFETY: the entry held the placeholder's reference.
                unsafe { (*entry.as_ptr()).set_sub_map(true) };
                // SAFETY: the entry held the placeholder's reference.
                unsafe { (*entry.as_ptr()).object.sub_map = submap };
                if let Some(submap) = NonNull::new(submap) {
                    Self::reference(submap);
                }
                result = Ok(());
            }
        }

        Self::unlock(map);
        result
    }

    /// `vm_map_pmap_enter()` in C.
    pub(crate) fn pmap_enter(
        &self,
        addr_in: VmOffset,
        end_addr: VmOffset,
        object: *mut VmObject,
        offset_in: VmOffset,
        protection: VmProt,
    ) {
        let mut addr = addr_in;
        let mut offset = offset_in;

        while addr < end_addr {
            // SAFETY: the caller owns the object for the scan.
            unsafe {
                (*object).lock.lock();
                vm_object::paging_begin(object);
            }

            // SAFETY: the object lock is held, as `vm_resident::lookup`
            // requires.
            let page = unsafe {
                vm_resident::lookup(NonNull::new_unchecked(object), offset)
            };
            let Some(page) = page else {
                // SAFETY: the lock and paging reference taken above.
                unsafe {
                    vm_object::paging_end(object);
                    (*object).lock.unlock();
                }
                return;
            };
            // SAFETY: a tabled page came from the object just locked; the
            // absent bit below is read under that lock.
            let page = page.as_ptr();
            // SAFETY: a tabled page came from the object just locked; the
            // absent bit below is read under that lock; `page` is the
            // live tabled page.
            if unsafe { (*page).is_absent() } {
                // SAFETY: the lock and paging reference taken above.
                unsafe {
                    vm_object::paging_end(object);
                    (*object).lock.unlock();
                }
                return;
            }

            // The switch is written only by a debugger, so a relaxed read is
            // enough; nothing orders against it.
            if VM_MAP_PMAP_ENTER_PRINT.load(Ordering::Relaxed) != 0 {
                kprint!(
                    "vm_map_pmap_enter:map: {:x}, addr: {:x}, object: {:x}, \
                     offset: {:x}\n",
                    ptr::from_ref(self).expose_provenance(),
                    addr,
                    object.expose_provenance(),
                    offset,
                );
            }

            // SAFETY: the page is present and marked busy under the object
            // lock; the paging reference pins it while the lock is dropped.
            unsafe {
                (*page).set_busy(true);
                (*object).lock.unlock();
                pmap_enter(
                    NonNull::new(self.pmap),
                    addr,
                    (*page).phys_addr,
                    (protection & !(*page).page_lock()).bits(),
                    0,
                );
                (*object).lock.lock();
                vm_object::page_wakeup_done(page);
                page_activate_if_idle(page);
                vm_object::paging_end(object);
                (*object).lock.unlock();
            }

            offset = offset.wrapping_add(PAGE_SIZE);
            addr = addr.wrapping_add(PAGE_SIZE);
        }
    }
}

/// `struct vm_map_version`: a timestamp to validate a lookup.
#[repr(C)]
pub struct VmMapVersion {
    /// The map timestamp the lookup saw.
    pub main_timestamp: c_uint,
}

const _: () = assert!(size_of::<VmMapVersion>() == 4);
const _: () = assert!(align_of::<VmMapVersion>() == 4);

/// `vm_map_copy_cont_fn`: a page-list copy's continuation.
pub type VmMapCopyContFn = unsafe extern "C" fn(
    args: *mut VmMapCopyinArgs,
    new_copy: *mut *mut VmMapCopy,
) -> c_int;

/// The `OBJECT` variant of a copy, `c_u.c_o`.
#[repr(C)]
#[allow(missing_docs)]
pub struct VmMapCopyObject {
    pub object: *mut VmObject,
}

assert_layout!(VmMapCopyObject, 8, 8, { object: 0 });

/// The `PAGE_LIST` variant of a copy, `c_u.c_p`.
#[repr(C)]
pub struct VmMapCopyPageList {
    /// The pages, up to `VM_MAP_COPY_PAGE_LIST_MAX`.
    pub page_list: [*mut VmPage; VM_MAP_COPY_PAGE_LIST_MAX],
    /// How many of `page_list` are used.
    pub npages: c_int,
    /// The continuation that supplies more pages, if any.
    pub cont: Option<VmMapCopyContFn>,
    /// The continuation's argument.
    pub cont_args: *mut VmMapCopyinArgs,
}

assert_layout!(VmMapCopyPageList, 536, 8, {
    page_list: 0, npages: 512, cont: 520, cont_args: 528,
});

/// The `c_u` union of a copy.
#[repr(C)]
pub union VmMapCopyU {
    /// The `ENTRY_LIST` variant.
    pub hdr: ManuallyDrop<VmMapHeader>,
    /// The `OBJECT` variant.
    pub c_o: ManuallyDrop<VmMapCopyObject>,
    /// The `PAGE_LIST` variant.
    pub c_p: ManuallyDrop<VmMapCopyPageList>,
}

assert_layout!(VmMapCopyU, 536, 8, {});

/// `struct vm_map_copy`: a region of memory in transit between maps.
#[repr(C)]
#[allow(missing_docs)]
pub struct VmMapCopy {
    /// `VM_MAP_COPY_ENTRY_LIST`, `_OBJECT` or `_PAGE_LIST`.
    pub type_: c_int,
    /// Offset of the region within the object.
    pub offset: VmOffset,
    pub size: VmSize,
    /// The three shapes.
    pub c_u: VmMapCopyU,
}

assert_layout!(VmMapCopy, 560, 8, {
    type_: 0, offset: 8, size: 16, c_u: 24,
});

/// `struct vm_map_copyin_args_data`: what a page-list continuation remembers
/// about the copyin.
#[repr(C)]
#[allow(missing_docs)]
pub struct VmMapCopyinArgs {
    /// The map the copy came from.
    pub map: *mut VmMap,
    pub src_addr: VmOffset,
    pub src_len: VmSize,
    /// The address to destroy once copied.
    pub destroy_addr: VmOffset,
    /// The length to destroy.
    pub destroy_len: VmSize,
    /// Whether the pages were stolen.
    pub steal_pages: c_int,
}

assert_layout!(VmMapCopyinArgs, 48, 8, {
    map: 0, src_addr: 8, src_len: 16, destroy_addr: 24,
    destroy_len: 32, steal_pages: 40,
});

/// `VM_PAGE_HIGHMEM`: the `vm_page_grab()` flag asking for a page not
/// restricted to the direct map.
const VM_PAGE_HIGHMEM: c_uint = 0x08;

/// `VM_FAULT_SUCCESS` of <`vm/vm_fault.h`>.
const VM_FAULT_SUCCESS: c_int = 0;
const VM_FAULT_RETRY: c_int = 1;
const VM_FAULT_INTERRUPTED: c_int = 2;
const VM_FAULT_MEMORY_SHORTAGE: c_int = 3;
const VM_FAULT_FICTITIOUS_SHORTAGE: c_int = 4;
const VM_FAULT_MEMORY_ERROR: c_int = 5;

impl VmMapCopy {
    /// `kmem_cache_free()` on `vm_map_copy_cache` in C.
    ///
    /// # Safety
    ///
    /// `copy` must be a live copy from this cache that nothing uses any more.
    unsafe fn free(copy: NonNull<Self>) {
        unsafe { (*map_copy_cache()).free(copy.cast::<u8>()) };
    }

    /// The `cpy_hdr` accessors in C.
    ///
    /// # Safety
    ///
    /// `copy` must hold the `ENTRY_LIST` variant.
    unsafe fn header(copy: NonNull<Self>) -> NonNull<VmMapHeader> {
        unsafe {
            NonNull::new_unchecked(
                addr_of_mut!((*copy.as_ptr()).c_u).cast::<VmMapHeader>(),
            )
        }
    }

    /// The `c_p` variant accessors in C.
    ///
    /// # Safety
    ///
    /// `copy` must hold the `PAGE_LIST` variant.
    pub(crate) unsafe fn page_list(
        copy: NonNull<Self>,
    ) -> *mut VmMapCopyPageList {
        unsafe {
            addr_of_mut!((*copy.as_ptr()).c_u.c_p).cast::<VmMapCopyPageList>()
        }
    }

    /// The `cpy_object` accessor in C.
    ///
    /// # Safety
    ///
    /// `copy` must hold the `OBJECT` variant.
    unsafe fn object(copy: NonNull<Self>) -> *mut *mut VmObject {
        unsafe {
            addr_of_mut!((*copy.as_ptr()).c_u.c_o).cast::<*mut VmObject>()
        }
    }

    /// `vm_map_copy_first_entry()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must hold the `ENTRY_LIST` variant.
    unsafe fn first_entry(copy: NonNull<Self>) -> NonNull<VmMapEntry> {
        unsafe {
            let header = Self::header(copy);
            (*header.as_ptr())
                .links
                .next
                .unwrap_or_else(|| header.cast())
        }
    }

    /// `vm_map_copy_last_entry()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must hold the `ENTRY_LIST` variant.
    unsafe fn last_entry(copy: NonNull<Self>) -> NonNull<VmMapEntry> {
        unsafe {
            let header = Self::header(copy);
            (*header.as_ptr())
                .links
                .prev
                .unwrap_or_else(|| header.cast())
        }
    }

    /// Dispose of an entry-list copy's entries: unlink each one, drop its
    /// object reference and return it to the entry cache.
    ///
    /// # Safety
    ///
    /// `copy` must be a live entry-list copy the caller owns.
    unsafe fn discard_entry_list(copy: NonNull<Self>) {
        let sentinel = unsafe { Self::header(copy) };
        loop {
            // SAFETY: the chain always closes on the sentinel.
            let entry = unsafe { Self::first_entry(copy) };
            if entry == sentinel.cast() {
                break;
            }

            // SAFETY: `entry` is a live entry of the copy, and the copy is
            // exclusively owned for the discard.
            unsafe {
                (*sentinel.as_ptr()).entry_unlink(entry, false);
                vm_object_deallocate((*entry.as_ptr()).object.vm_object);
            }
            // SAFETY: the entry is unlinked and unused.
            unsafe { VmMapEntry::dispose(entry) };
        }
    }

    /// `vm_map_copy_steal_pages()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must be a live page-list copy the caller owns, with no null
    /// entry in its page list, and its `npages` must be at most
    /// `VM_MAP_COPY_PAGE_LIST_MAX` (64), the bound `vm_map_copyin_page_list`
    /// enforces in C (`vm/vm_map.c:1897`); a larger count read out of bounds
    /// in C and panics in this indexing.
    pub(crate) unsafe fn steal_pages(copy: NonNull<Self>) {
        let pages = unsafe { Self::page_list(copy) };
        // SAFETY: `pages` names the live variant.
        let npages = unsafe { (*pages).npages };
        let npages = usize::try_from(npages).unwrap_or(0);

        let mut i = 0;
        while i < npages {
            let m = unsafe { (*pages).page_list[i] };
            // SAFETY: a tabled page belongs to a live object that the copy
            // holds a paging reference on.
            if unsafe { (*m).is_tabled() } {
                // SAFETY: the allocator and `vm_page_wait` own the page
                // queues.
                let mut new_m = unsafe { vm_resident::grab(VM_PAGE_HIGHMEM) }
                    .map_or(ptr::null_mut(), NonNull::as_ptr);
                while new_m.is_null() {
                    unsafe { vm_page::wait(None) };
                    new_m = unsafe { vm_resident::grab(VM_PAGE_HIGHMEM) }
                        .map_or(ptr::null_mut(), NonNull::as_ptr);
                }

                // SAFETY: both pages are live.
                unsafe {
                    vm_resident::copy(
                        NonNull::new_unchecked(m),
                        NonNull::new_unchecked(new_m),
                    );
                };

                // SAFETY: the page is tabled, so it belongs to a live object
                // the copy holds a paging reference on.
                let object = unsafe { (*m).object };
                // SAFETY: the object lock and the page queue serialise the
                // page state, exactly as in the C.
                unsafe {
                    (*object).lock.lock();
                    page_activate_if_idle(m);
                    vm_object::page_wakeup_done(m);
                    vm_object::paging_end(object);
                    (*object).lock.unlock();
                }

                // SAFETY: the slot holds a live page the copy owns, replaced
                // by the private copy just made.
                unsafe { (*pages).page_list[i] = new_m };
            }

            i += 1;
        }
    }

    /// `vm_map_copy_page_discard()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must be a live page-list copy the caller owns, and its `npages`
    /// must be at most `VM_MAP_COPY_PAGE_LIST_MAX` (64), the bound
    /// `vm_map_copyin_page_list` enforces in C (`vm/vm_map.c:1897`); a larger
    /// count read out of bounds in C and panics in this indexing.
    pub(crate) unsafe fn page_discard(copy: NonNull<Self>) {
        let pages = unsafe { Self::page_list(copy) };
        loop {
            // SAFETY: `pages` names the live variant.
            let npages = unsafe { (*pages).npages };
            if npages <= 0 {
                break;
            }
            let Ok(index) = usize::try_from(npages - 1) else {
                break;
            };
            let page = unsafe { (*pages).page_list[index] };
            // SAFETY: `npages` is positive, so the decrement is the count the
            // C stored, and `pages` names the live variant.
            unsafe { (*pages).npages = npages - 1 };

            if page.is_null() {
                continue;
            }

            // SAFETY: the page is live; `tabled` tells whether the copy holds
            // a paging reference to its object.
            if unsafe { (*page).is_tabled() } {
                // SAFETY: a tabled page belongs to a live object the copy
                // holds a paging reference on.
                let object = unsafe { (*page).object };
                // SAFETY: the object lock and the page queue serialise the
                // page state, exactly as in the C.
                unsafe {
                    (*object).lock.lock();
                    page_activate_if_idle(page);
                    vm_object::page_wakeup_done(page);
                    vm_object::paging_end(object);
                    (*object).lock.unlock();
                }
            } else {
                // SAFETY: a stolen page is in no object, so it goes back to
                // the free list; the C `VM_PAGE_FREE` holds the page queue
                // lock across `vm_page_free`.
                unsafe {
                    (*addr_of_mut!(VM_PAGE_QUEUE_LOCK)).lock();
                    vm_resident::free(NonNull::new_unchecked(page));
                    (*addr_of_mut!(VM_PAGE_QUEUE_LOCK)).unlock();
                }
            }
        }
    }

    /// `vm_map_copy_has_cont()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must be a live page-list copy.
    pub(crate) unsafe fn has_cont(copy: NonNull<Self>) -> bool {
        let pages = unsafe { Self::page_list(copy) };
        // SAFETY: `pages` names the live variant.
        unsafe { (*pages).cont.is_some() }
    }

    /// `vm_map_copy_abort_cont()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must be a live page-list copy.
    pub(crate) unsafe fn abort_cont(copy: NonNull<Self>) {
        unsafe { Self::page_discard(copy) };

        // SAFETY: the copy holds the live PAGE_LIST variant, and the
        // continuation argument belongs to the continuation.
        let pages = unsafe { Self::page_list(copy) };
        // SAFETY: `pages` names the live variant.
        let (cont, args) = unsafe { ((*pages).cont, (*pages).cont_args) };
        let Some(cont) = cont else {
            return;
        };

        // SAFETY: the continuation owns its argument; a null result pointer is
        // the C's abort call.
        unsafe { cont(args, ptr::null_mut()) };

        // SAFETY: the copy is live; the C macro clears the fields so the
        // storage can be freed without aborting twice.
        unsafe {
            (*pages).cont = None;
            (*pages).cont_args = ptr::null_mut();
        }
    }

    /// `vm_map_copy_invoke_cont()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must be a live page-list copy with a continuation, and the
    /// caller must own it and every copy its continuation chain returns.
    pub(crate) unsafe fn invoke_cont(
        copy: NonNull<Self>,
    ) -> (c_int, *mut Self) {
        unsafe { Self::page_discard(copy) };

        // SAFETY: `copy` holds the live PAGE_LIST variant.
        let pages = unsafe { Self::page_list(copy) };
        // SAFETY: `pages` names the live variant.
        let (cont, args) = unsafe { ((*pages).cont, (*pages).cont_args) };
        let mut new_copy: *mut Self = ptr::null_mut();
        let result = cont.map_or(KERN_SUCCESS, |cont| {
            // SAFETY: the continuation owns its argument and writes the next
            // copy through the out-pointer.
            unsafe { cont(args, &raw mut new_copy) }
        });

        // SAFETY: the copy is live; the C macro clears the field so the
        // storage cannot be aborted twice.
        unsafe { (*pages).cont = None };

        (result, new_copy)
    }

    /// `vm_map_copy_discard()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must be a live copy the caller owns; this frees it, along with
    /// every page-list copy its continuation chain names.
    pub(crate) unsafe fn discard(copy: NonNull<Self>) {
        let mut copy = copy;

        loop {
            // SAFETY: `copy` is live; the loop replaces it only with a live
            // copy taken from a continuation.
            match unsafe { (*copy.as_ptr()).type_ } {
                VM_MAP_COPY_ENTRY_LIST => {
                    // SAFETY: the type word selects the live variant.
                    unsafe { Self::discard_entry_list(copy) };
                }
                VM_MAP_COPY_OBJECT => {
                    // SAFETY: the type word selects the live variant, and the
                    // copy holds the reference dropped here.
                    let object = unsafe { Self::object(copy) };
                    unsafe { vm_object_deallocate(*object) };
                }
                VM_MAP_COPY_PAGE_LIST => {
                    // SAFETY: the type word selects the live variant.
                    let pages = unsafe { Self::page_list(copy) };
                    // SAFETY: `pages` names the live variant.
                    let npages = unsafe { (*pages).npages };
                    if npages > 0 {
                        // SAFETY: `copy` is a live page-list copy.
                        unsafe { Self::page_discard(copy) };
                    }

                    // SAFETY: `pages` names the live variant.
                    let cont = unsafe { (*pages).cont };
                    if let Some(cont) = cont {
                        if is_discard_cont(cont) {
                            // SAFETY: the continuation stores the next live
                            // copy of the chain in its argument.
                            let next =
                                unsafe { (*pages).cont_args }.cast::<Self>();
                            // SAFETY: the copy is live and owned.
                            unsafe { Self::free(copy) };
                            let Some(next) = NonNull::new(next) else {
                                return;
                            };
                            copy = next;
                            continue;
                        }

                        // SAFETY: `copy` is a live page-list copy.
                        unsafe { Self::abort_cont(copy) };
                    }
                }
                _ => {}
            }

            // SAFETY: the copy is live and owned by this call.
            unsafe { Self::free(copy) };
            return;
        }
    }

    /// `vm_map_copy_discard_cont()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must be the live copy a continuation chain names, or nothing
    /// when the chain is empty.
    pub(crate) unsafe fn discard_cont(copy: Option<NonNull<Self>>) {
        if let Some(copy) = copy {
            unsafe { Self::discard(copy) };
        }
    }

    /// `vm_map_copy_copy()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must be a live copy the caller owns.
    #[must_use]
    pub(crate) unsafe fn duplicate(copy: NonNull<Self>) -> NonNull<Self> {
        // SAFETY: the copy cache is initialized by `vm_map_init()` before any
        // copy exists.
        let Some(new_copy) =
            unsafe { (*map_copy_cache()).alloc() }.map(NonNull::cast::<Self>)
        else {
            kpanic!("VmMapCopy::duplicate", "vm_map_copy_copy")
        };

        // SAFETY: both are live copies; the fresh allocation is overwritten
        // whole, exactly as the C structure assignment.
        unsafe {
            ptr::copy_nonoverlapping(copy.as_ptr(), new_copy.as_ptr(), 1);
        };

        // SAFETY: the type word was just copied.
        if unsafe { (*copy.as_ptr()).type_ } == VM_MAP_COPY_ENTRY_LIST {
            // SAFETY: the new copy is a live entry-list copy.
            let new_header = unsafe { Self::header(new_copy) };
            // SAFETY: the chain closes on the sentinel, so the first and last
            // entries are live.
            unsafe {
                let first = Self::first_entry(copy);
                let last = Self::last_entry(copy);
                (*first.as_ptr()).links.prev = Some(new_header.cast());
                (*last.as_ptr()).links.next = Some(new_header.cast());
            }
        }

        // SAFETY: the copy is live; the type word now selects the object
        // variant, whose field is nulled.
        unsafe {
            (*copy.as_ptr()).type_ = VM_MAP_COPY_OBJECT;
            *Self::object(copy) = ptr::null_mut();
        }

        new_copy
    }

    /// The header initialization of `vm_map_copyin()` in C.
    ///
    /// # Safety
    ///
    /// `vm_map_init()` must have initialized the copy cache.
    #[must_use]
    unsafe fn new_entry_list(
        src_addr: VmOffset,
        len: VmSize,
    ) -> NonNull<Self> {
        // SAFETY: `vm_map_copy_cache` is initialized by `vm_map_init()` before
        // any copy is created.
        let Some(copy) =
            unsafe { (*map_copy_cache()).alloc() }.map(NonNull::cast::<Self>)
        else {
            kpanic!("VmMapCopy::new_entry_list", "vm_map_copyin")
        };

        // SAFETY: the fresh allocation is unshared storage; the chain closes
        // on the sentinel and every field is written before the copy leaves
        // this function.
        unsafe {
            (*copy.as_ptr()).type_ = VM_MAP_COPY_ENTRY_LIST;
            (*copy.as_ptr()).offset = src_addr;
            (*copy.as_ptr()).size = len;

            let header = Self::header(copy);
            let sentinel = header.cast::<VmMapEntry>();
            (*header.as_ptr()).links.prev = Some(sentinel);
            (*header.as_ptr()).links.next = Some(sentinel);
            (*header.as_ptr()).nentries = 0;
            (*header.as_ptr()).tree.clear();
            (*header.as_ptr()).gap_tree.clear();
        }

        copy
    }

    /// `vm_map_copyin_object()` in C.
    ///
    /// # Safety
    ///
    /// `vm_map_init()` must have initialized the copy cache.
    #[must_use]
    pub(crate) unsafe fn copyin_object(
        object: *mut VmObject,
        offset: VmOffset,
        size: VmSize,
    ) -> NonNull<Self> {
        // SAFETY: `vm_map_copy_cache` is initialized by `vm_map_init()` before
        // any copy is created.
        let Some(copy) =
            unsafe { (*map_copy_cache()).alloc() }.map(NonNull::cast::<Self>)
        else {
            kpanic!("VmMapCopy::copyin_object", "vm_map_copyin_object")
        };

        // SAFETY: the type word below selects the `OBJECT` variant, whose
        // fields are the only ones read before the next whole write.
        unsafe {
            (*copy.as_ptr()).type_ = VM_MAP_COPY_OBJECT;
            (*copy.as_ptr()).offset = offset;
            (*copy.as_ptr()).size = size;
            (*Self::header(copy).as_ptr()).links.prev = None;
            (*Self::header(copy).as_ptr()).links.next = None;
            *Self::object(copy) = object;
        }

        copy
    }

    /// The header initialization of `vm_map_copyin_page_list()` in C.
    ///
    /// # Safety
    ///
    /// `vm_map_init()` must have initialized the copy cache.
    #[must_use]
    unsafe fn new_page_list(src_addr: VmOffset, len: VmSize) -> NonNull<Self> {
        // SAFETY: `vm_map_copy_cache` is initialized by `vm_map_init()` before
        // any copy is created.
        let Some(copy) =
            unsafe { (*map_copy_cache()).alloc() }.map(NonNull::cast::<Self>)
        else {
            kpanic!("VmMapCopy::new_page_list", "vm_map_copyin_page_list")
        };

        // SAFETY: the fresh allocation is unshared storage, and every field is
        // written before the copy leaves this function.
        unsafe {
            (*copy.as_ptr()).type_ = VM_MAP_COPY_PAGE_LIST;
            (*copy.as_ptr()).offset = src_addr;
            (*copy.as_ptr()).size = len;

            let pages = Self::page_list(copy);
            (*pages).npages = 0;
            (*pages).cont = None;
            (*pages).cont_args = ptr::null_mut();
        }

        copy
    }
}

/// `vm_map_copy_discard()` in C.
///
/// # Safety
///
/// A non-null `copy` must be a live copy the caller owns; the call frees it.
pub(crate) unsafe fn vm_map_copy_discard(copy: *mut VmMapCopy) {
    if let Some(copy) = NonNull::new(copy) {
        unsafe { VmMapCopy::discard(copy) };
    }
}

/// Whether `cont` is `vm_map_copy_discard_cont()` below, which
/// `vm_map_copy_discard()` recognizes and follows iteratively instead of
/// recursing once per link of a page-list chain.
fn is_discard_cont(cont: VmMapCopyContFn) -> bool {
    ptr::fn_addr_eq(cont, vm_map_copy_discard_cont as VmMapCopyContFn)
}

/// `vm_map_copy_discard_cont()` in C.
///
/// # Safety
///
/// `cont_args` must be null or the live copy a continuation chain names, and
/// `copy_result` must be null or point at writable storage for one copy
/// pointer.
pub(crate) unsafe extern "C" fn vm_map_copy_discard_cont(
    cont_args: *mut VmMapCopyinArgs,
    copy_result: *mut *mut VmMapCopy,
) -> c_int {
    unsafe {
        VmMapCopy::discard_cont(NonNull::new(cont_args.cast::<VmMapCopy>()));
    };
    if let Some(copy_result) = NonNull::new(copy_result) {
        unsafe { copy_result.as_ptr().write(ptr::null_mut()) };
    }
    KERN_SUCCESS
}

impl VmMapEntry {
    /// `_vm_map_entry_create()` in C, including its halt when the cache is
    /// exhausted.
    ///
    /// # Safety
    ///
    /// `vm_map_init()` must have initialized the entry cache.
    #[must_use]
    pub(crate) unsafe fn create() -> NonNull<Self> {
        // SAFETY: `vm_map_entry_cache` is initialized by `vm_map_init()`
        // before any entry is created.
        let entry = unsafe { (*map_entry_cache()).alloc() }.map_or_else(
            || kpanic!("VmMapEntry::create", "vm_map_entry_create"),
            NonNull::cast::<Self>,
        );
        // The tree links start unlinked; a stale image would make a later
        // insert panic.
        unsafe {
            ptr::write(
                addr_of_mut!((*entry.as_ptr()).tree_node),
                rb_tree::Link::new(),
            );
            ptr::write(
                addr_of_mut!((*entry.as_ptr()).gap_node),
                rb_tree::Link::new(),
            );
        }
        entry
    }
}

impl VmMapHeader {
    /// Whether `entry` is this header's sentinel.
    pub(crate) fn is_sentinel(&self, entry: NonNull<VmMapEntry>) -> bool {
        entry == self.to_entry()
    }

    /// `vm_map_gap_valid()` in C: the sentinel is no gap entry.
    fn gap_valid(&self, entry: NonNull<VmMapEntry>) -> bool {
        !self.is_sentinel(entry)
    }

    /// `vm_map_gap_compute()` in C.
    fn gap_compute(&self, entry: NonNull<VmMapEntry>) {
        // SAFETY: the caller names a live entry of this header.
        let next = unsafe { (*entry.as_ptr()).links.next };
        // SAFETY: the caller names a live entry of this header.
        let end = unsafe { (*entry.as_ptr()).links.end };

        let gap_end = match next {
            // SAFETY: the chain links live entries or the sentinel.
            Some(next) if self.gap_valid(next) => unsafe {
                (*next.as_ptr()).links.start
            },
            _ => self.links.end,
        };

        // SAFETY: the chain links live entries or the sentinel; the invariant
        // puts the next entry (or the header end) at or after this
        // entry's end.
        unsafe {
            (*entry.as_ptr()).gap_size = gap_end.wrapping_sub(end);
        }
    }

    /// `vm_map_gap_insert_single()` in C.
    fn gap_insert_single(&mut self, entry: NonNull<VmMapEntry>) {
        if !self.gap_valid(entry) {
            return;
        }
        self.gap_compute(entry);
        // SAFETY: `entry` is a live entry of this header.
        let gap_size = unsafe { (*entry.as_ptr()).gap_size };
        if gap_size == 0 {
            return;
        }

        // SAFETY: the map lock keeps the entry live and unmoved for as long
        // as the tree links it, and a re-insert always follows a remove.
        unsafe {
            self.gap_tree.insert_ptr(entry);
            (*entry.as_ptr()).set_in_gap_tree(true);
        }
    }

    /// `vm_map_gap_remove_single()` in C.
    fn gap_remove_single(&mut self, entry: NonNull<VmMapEntry>) {
        if !self.gap_valid(entry) {
            return;
        }
        // SAFETY: `entry` is a live entry of this header.
        if unsafe { (*entry.as_ptr()).gap_size } == 0 {
            return;
        }
        // SAFETY: `entry` is a live entry of this header.
        if !unsafe { (*entry.as_ptr()).in_gap_tree() } {
            return;
        }

        // SAFETY: the entry is linked in this gap tree, and the map lock
        // keeps it live and unmoved.
        unsafe {
            self.gap_tree.remove_ptr(entry);
            (*entry.as_ptr()).set_in_gap_tree(false);
        }
    }

    /// `vm_map_gap_update()` in C.
    fn gap_update(&mut self, entry: NonNull<VmMapEntry>) {
        self.gap_remove_single(entry);
        self.gap_insert_single(entry);
    }

    /// `vm_map_gap_insert()` in C.
    fn gap_insert(&mut self, entry: NonNull<VmMapEntry>) {
        // SAFETY: `entry` is a live entry, so its predecessor is.
        let prev = unsafe { (*entry.as_ptr()).links.prev };
        if let Some(prev) = prev {
            self.gap_remove_single(prev);
            self.gap_insert_single(prev);
        }
        self.gap_insert_single(entry);
    }

    /// The `_vm_map_entry_link()` macro in C.
    ///
    /// # Safety
    ///
    /// Both entries must be valid and live in this header, `entry` unlinked,
    /// and nothing else may touch the header during the call.
    pub(crate) unsafe fn entry_link(
        &mut self,
        after: NonNull<VmMapEntry>,
        entry: NonNull<VmMapEntry>,
        link_gap: bool,
    ) {
        self.nentries = self.nentries.wrapping_add(1);
        unsafe {
            let next = (*after.as_ptr()).links.next;
            (*entry.as_ptr()).links.prev = Some(after);
            (*entry.as_ptr()).links.next = next;
            (*after.as_ptr()).links.next = Some(entry);
            if let Some(next) = next {
                (*next.as_ptr()).links.prev = Some(entry);
            }

            // The tree node is unlinked caller storage, and the map lock
            // keeps the entry live and unmoved while the tree links it.
            // The chain splice already proved `after` precedes `entry`
            // and `entry` precedes `next`, so the address tree can take
            // the predecessor as a hint.  The sentinel is not on the
            // tree; a below-first insert is O(1) without one.
            if self.is_sentinel(after) {
                self.tree.insert_ptr(entry);
            } else {
                self.tree.insert_after_ptr(after, entry);
            }

            if link_gap {
                self.gap_insert(entry);
            }
        }
    }
}

impl VmMap {
    /// The first free-space hint, or the sentinel.
    fn first_free_entry(&self) -> NonNull<VmMapEntry> {
        NonNull::new(self.first_free).unwrap_or_else(|| self.to_entry())
    }

    /// The C allocation-failure diagnostic.
    fn no_room(&self) {
        // SAFETY: `self.name` is the map's NUL-terminated name.
        let name = unsafe { CStrArg::from_ptr(self.name) };
        kprint!(
            "no more room in {:x} ({})\n",
            ptr::from_ref(self).expose_provenance(),
            name,
        );
    }

    /// `vm_map_enforce_limit()` in C.
    fn enforce_limit(&self, size: VmSize) -> Result<(), Error> {
        // SAFETY: `kernel_pmap` is a boot global.
        if self.pmap == unsafe { KERNEL_PMAP } {
            return Ok(());
        }

        let allocated = self.size.wrapping_sub(self.size_none);
        let new_size = allocated.wrapping_add(size);
        if new_size < size {
            return Err(Error::InvalidArgument);
        }
        if new_size > self.size_cur_limit {
            return Err(Error::NoSpace);
        }
        Ok(())
    }

    /// `vm_map_find_entry_anywhere()` in C: on success, the returned entry is
    /// the one preceding the range and the returned address is its first one.
    fn find_entry_anywhere(
        &mut self,
        size: VmSize,
        mask_in: VmOffset,
        map_locked: bool,
    ) -> Option<(NonNull<VmMapEntry>, VmOffset)> {
        let mut mask = mask_in;
        let mut max = self.hdr.links.end;

        if !map_locked {
            Self::lock(NonNull::from(&mut *self));
        }

        if mask.wrapping_add(1) & mask != 0 {
            let first0 = (!mask).trailing_zeros() + 1;
            let lowmask = (1usize << (first0 - 1)).wrapping_sub(1);
            let himask = mask.wrapping_sub(lowmask);
            let second1 = himask.trailing_zeros() + 1;

            max = 1usize << (second1 - 1);

            if himask.wrapping_add(max) != 0 {
                kprint!("invalid mask {:x}\n", mask);
                return None;
            }

            mask = lowmask;
        }

        loop {
            if self.hdr.nentries == 0 {
                let entry = self.to_entry();
                let start = self.hdr.links.start.wrapping_add(mask) & !mask;
                let end = start.wrapping_add(size);

                if start < self.hdr.links.start || end <= start || end > max {
                    self.no_room();
                    return None;
                }

                return Some((entry, start));
            }

            let entry = self.first_free_entry();
            if !self.hdr.is_sentinel(entry) {
                // SAFETY: `entry` is a live entry of this map.
                let (entry_end, gap_size) = unsafe {
                    ((*entry.as_ptr()).links.end, (*entry.as_ptr()).gap_size)
                };
                let start = entry_end.wrapping_add(mask) & !mask;
                let end = start.wrapping_add(size);

                if start >= entry_end
                    && end > start
                    && end <= max
                    && end <= entry_end.wrapping_add(gap_size)
                {
                    return Some((entry, start));
                }
            }

            let max_size = size.wrapping_add(mask);
            if max_size < size {
                kprint!(
                    "max_size {} got smaller than size {} with mask {}\n",
                    max_size,
                    size,
                    mask,
                );
                self.no_room();
                return None;
            }

            let found = self
                .hdr
                .gap_tree
                .lower_bound(Bound::Included(&max_size))
                .current_ptr();

            let Some(mut entry) = found else {
                if map_locked || !self.wait_for_space() {
                    self.no_room();
                    return None;
                }

                // SAFETY: the map belongs to this thread for the call; sleep
                // on its address as the C code does and retry after waking.
                unsafe {
                    assert_wait(NonNull::new(ptr::from_mut(self).cast()), 1);
                    Self::unlock(NonNull::from(&mut *self));
                    thread_block(None);
                    Self::lock(NonNull::from(&mut *self));
                }
                continue;
            };

            // The C took the tail of the leader's equal-gap list, the most
            // recently inserted entry of this size.  Equal keys sit to the
            // right, so the last node at or below this size is that tail.
            // SAFETY: `entry` is a live entry.
            let gap_size = unsafe { (*entry.as_ptr()).gap_size };
            let last = self
                .hdr
                .gap_tree
                .upper_bound(Bound::Included(&gap_size))
                .current_ptr();
            if let Some(last) = last {
                entry = last;
            }

            // SAFETY: `entry` is a live entry.
            let entry_end = unsafe { (*entry.as_ptr()).links.end };
            let start = entry_end.wrapping_add(mask) & !mask;
            let end = start.wrapping_add(size);
            if end > max {
                kprint!("{:x} does not respect {:x}\n", end, max);
                return None;
            }

            return Some((entry, start));
        }
    }

    /// `vm_map_find_entry()` in C, with the caller holding the map lock and
    /// the out-parameters returned as a pair.
    pub(crate) fn find_entry(
        map: &mut Self,
        size: VmSize,
        mask: VmOffset,
        object: Option<NonNull<VmObject>>,
        protection: VmProt,
        max_protection: VmProt,
    ) -> Result<(VmOffset, NonNull<VmMapEntry>), Error> {
        if max_protection != VmProt::NONE {
            map.enforce_limit(size)?;
        }

        let (entry, start) = map
            .find_entry_anywhere(size, mask, true)
            .ok_or(Error::NoSpace)?;
        let end = start.wrapping_add(size);

        let object = object.map_or(ptr::null_mut(), NonNull::as_ptr);
        let extend = !object.is_null()
            && !map.hdr.is_sentinel(entry)
            // SAFETY: `entry` is live or the sentinel under the map lock.
            && unsafe {
                let before = &*entry.as_ptr();
                before.links.end == start
                    && !before.is_shared()
                    && !before.is_sub_map()
                    && !before.in_transition()
                    && before.object.vm_object == object
                    && !before.needs_copy()
                    && before.inheritance == VmInherit::COPY
                    && before.protection == protection
                    && before.max_protection == max_protection
                    && before.wired_count != 0
                    && before.projected_on.is_null()
            };

        let new_entry = if extend {
            // SAFETY: `entry` is live, and the map lock is held.
            unsafe { (*entry.as_ptr()).links.end = end };
            map.hdr.gap_update(entry);
            entry
        } else {
            // SAFETY: the entry cache is initialized and the map lock is held.
            let new_entry = unsafe { VmMapEntry::create() };
            // SAFETY: `new_entry` is unlinked, freshly allocated storage; the
            // link below makes it reachable.
            unsafe {
                let e = new_entry.as_ptr();
                (*e).links.start = start;
                (*e).links.end = end;
                (*e).set_shared(false);
                (*e).set_sub_map(false);
                (*e).object.vm_object = ptr::null_mut();
                (*e).offset = 0;
                (*e).set_needs_copy(false);
                (*e).inheritance = VmInherit::COPY;
                (*e).protection = protection;
                (*e).max_protection = max_protection;
                (*e).wired_count = 1;
                (*e).wired_access = VmProt::READ | VmProt::WRITE;
                (*e).set_in_transition(false);
                (*e).set_needs_wakeup(false);
                (*e).projected_on = ptr::null_mut();

                map.hdr.entry_link(entry, new_entry, true);
            }
            new_entry
        };

        map.size = map.size.wrapping_add(size);
        if max_protection == VmProt::NONE {
            map.size_none = map.size_none.wrapping_add(size);
        }
        map.first_free = new_entry.as_ptr();
        map.save_hint(new_entry);

        Ok((start, new_entry))
    }
}

impl VmMapEntry {
    /// `_vm_map_entry_dispose()` in C.
    ///
    /// # Safety
    ///
    /// `entry` must be unlinked and came from `create()`.
    pub(crate) unsafe fn dispose(entry: NonNull<Self>) {
        unsafe { (*map_entry_cache()).free(entry.cast::<u8>()) };
    }

    /// `vm_map_entry_copy_full()` in C; used for splitting and for projected
    /// entries.
    ///
    /// # Safety
    ///
    /// Both must be distinct live entry storage, and `dst` unlinked.
    pub(crate) const unsafe fn copy_full(
        dst: NonNull<Self>,
        src: NonNull<Self>,
    ) {
        unsafe { ptr::copy_nonoverlapping(src.as_ptr(), dst.as_ptr(), 1) };
        // The copy carries `src`'s link images, which may be linked; the
        // tree links of an unlinked `dst` start unlinked.
        unsafe {
            ptr::write(
                addr_of_mut!((*dst.as_ptr()).tree_node),
                rb_tree::Link::new(),
            );
            ptr::write(
                addr_of_mut!((*dst.as_ptr()).gap_node),
                rb_tree::Link::new(),
            );
        }
    }

    /// `vm_map_entry_copy()` in C.
    ///
    /// # Safety
    ///
    /// Same contract as `copy_full`.
    pub(crate) unsafe fn copy(dst: NonNull<Self>, src: NonNull<Self>) {
        unsafe {
            ptr::copy_nonoverlapping(src.as_ptr(), dst.as_ptr(), 1);
            // The copy carries `src`'s link images, which may be linked; the
            // tree links of an unlinked `dst` start unlinked.
            ptr::write(
                addr_of_mut!((*dst.as_ptr()).tree_node),
                rb_tree::Link::new(),
            );
            ptr::write(
                addr_of_mut!((*dst.as_ptr()).gap_node),
                rb_tree::Link::new(),
            );
            (*dst.as_ptr()).set_shared(false);
            (*dst.as_ptr()).set_needs_wakeup(false);
            (*dst.as_ptr()).set_in_transition(false);
            (*dst.as_ptr()).wired_count = 0;
            (*dst.as_ptr()).wired_access = VmProt::NONE;
        }
    }
}

impl VmMapHeader {
    /// `_vm_map_clip_start()` in C.
    ///
    /// # Safety
    ///
    /// `entry` must be a live entry of this header, and `start` must lie
    /// inside it.
    pub(crate) unsafe fn clip_start(
        &mut self,
        entry: NonNull<VmMapEntry>,
        start: VmOffset,
        link_gap: bool,
    ) {
        unsafe {
            let new_entry = VmMapEntry::create();
            VmMapEntry::copy_full(new_entry, entry);

            (*new_entry.as_ptr()).links.end = start;
            let entry_start = (*entry.as_ptr()).links.start;
            (*entry.as_ptr()).offset = (*entry.as_ptr())
                .offset
                .wrapping_add(start.wrapping_sub(entry_start));
            (*entry.as_ptr()).links.start = start;

            let prev = (*entry.as_ptr()).links.prev;
            if let Some(prev) = prev {
                self.entry_link(prev, new_entry, link_gap);
            }

            if (*new_entry.as_ptr()).is_sub_map() {
                let submap = NonNull::new_unchecked(
                    (*new_entry.as_ptr()).object.sub_map,
                );
                VmMap::reference(submap);
            } else {
                vm_object::reference((*new_entry.as_ptr()).object.vm_object);
            }
        }
    }

    /// The guarded `vm_map_clip_start()` macro: split `entry` only when
    /// `start` lies strictly inside it, leaving a start on the entry boundary
    /// alone.
    ///
    /// # Safety
    ///
    /// `entry` must be a live entry of this header, and `start` at or after
    /// its start.
    pub(crate) unsafe fn clip_start_at(
        &mut self,
        entry: NonNull<VmMapEntry>,
        start: VmOffset,
        link_gap: bool,
    ) {
        if start > unsafe { (*entry.as_ptr()).links.start } {
            unsafe { self.clip_start(entry, start, link_gap) };
        }
    }

    /// The guarded `vm_map_clip_end()` macro: split `entry` only when `end`
    /// lies strictly inside it, leaving an end on the entry boundary alone.
    ///
    /// # Safety
    ///
    /// `entry` must be a live entry of this header, and `end` at or before its
    /// end.
    pub(crate) unsafe fn clip_end_at(
        &mut self,
        entry: NonNull<VmMapEntry>,
        end: VmOffset,
        link_gap: bool,
    ) {
        if end < unsafe { (*entry.as_ptr()).links.end } {
            unsafe { self.clip_end(entry, end, link_gap) };
        }
    }

    /// `_vm_map_clip_end()` in C.
    ///
    /// # Safety
    ///
    /// `entry` must be a live entry of this header, and `end` must lie inside
    /// it.
    pub(crate) unsafe fn clip_end(
        &mut self,
        entry: NonNull<VmMapEntry>,
        end: VmOffset,
        link_gap: bool,
    ) {
        unsafe {
            let new_entry = VmMapEntry::create();
            VmMapEntry::copy_full(new_entry, entry);

            (*new_entry.as_ptr()).links.start = end;
            (*entry.as_ptr()).links.end = end;
            let entry_start = (*entry.as_ptr()).links.start;
            (*new_entry.as_ptr()).offset = (*new_entry.as_ptr())
                .offset
                .wrapping_add(end.wrapping_sub(entry_start));

            self.entry_link(entry, new_entry, link_gap);

            if (*entry.as_ptr()).is_sub_map() {
                let submap = NonNull::new_unchecked(
                    (*new_entry.as_ptr()).object.sub_map,
                );
                VmMap::reference(submap);
            } else {
                vm_object::reference((*new_entry.as_ptr()).object.vm_object);
            }
        }
    }

    /// The `_vm_map_entry_unlink()` macro in C.
    ///
    /// # Safety
    ///
    /// `entry` must be linked in this header, and nothing else may touch the
    /// header during the call.
    pub(crate) unsafe fn entry_unlink(
        &mut self,
        entry: NonNull<VmMapEntry>,
        unlink_gap: bool,
    ) {
        self.nentries = self.nentries.wrapping_sub(1);
        unsafe {
            let prev = (*entry.as_ptr()).links.prev;
            let next = (*entry.as_ptr()).links.next;
            if let Some(next) = next {
                (*next.as_ptr()).links.prev = prev;
            }
            if let Some(prev) = prev {
                (*prev.as_ptr()).links.next = next;
            }

            // SAFETY: the entry is linked in this tree, and the map lock
            // keeps it live and unmoved.
            self.tree.remove_ptr(entry);

            if unlink_gap {
                self.gap_remove(entry);
            }
        }
    }

    /// `vm_map_gap_remove()` in C.
    fn gap_remove(&mut self, entry: NonNull<VmMapEntry>) {
        self.gap_remove_single(entry);
        // SAFETY: `entry` is a live entry, so its predecessor is.
        let prev = unsafe { (*entry.as_ptr()).links.prev };
        if let Some(prev) = prev {
            self.gap_remove_single(prev);
            self.gap_insert_single(prev);
        }
    }
}

impl VmMap {
    fn hint(&self) -> *mut VmMapEntry {
        // SAFETY: `hint` is written only under `hint_lock`; this is a
        // snapshot, as the C `SAVE_HINT` readers take.
        unsafe { *self.hint.get() }
    }

    /// `vm_map_entry_reset_wired()` in C.
    fn entry_reset_wired(&mut self, entry: NonNull<VmMapEntry>) {
        // SAFETY: `entry` is a live entry of this map.
        unsafe {
            if (*entry.as_ptr()).wired_count != 0 {
                let size = (*entry.as_ptr())
                    .links
                    .end
                    .wrapping_sub((*entry.as_ptr()).links.start);
                self.size_wired = self.size_wired.wrapping_sub(size);
                (*entry.as_ptr()).wired_count = 0;
            }
        }
    }

    /// Wait for `in_transition` to clear: sleep on the header address with the
    /// map unlocked, as `vm_map_entry_wait()` in C does.
    fn entry_wait(&self) {
        // SAFETY: the map belongs to this thread; sleeping on the header
        // address is the C protocol.
        unsafe {
            assert_wait(
                NonNull::new(
                    ptr::from_ref(&self.hdr).cast_mut().cast::<c_void>(),
                ),
                0,
            );
        }
    }

    /// `vm_map_entry_delete()` in C.
    ///
    /// # Safety
    ///
    /// `entry` must be linked in this map and the map write lock held.
    pub(crate) unsafe fn entry_delete(&mut self, entry: NonNull<VmMapEntry>) {
        let (s, e, size) = unsafe {
            let start = (*entry.as_ptr()).links.start;
            let end = (*entry.as_ptr()).links.end;
            (start, end, end.wrapping_sub(start))
        };

        // SAFETY: the map is write-locked.
        if ptr::from_mut(self).cast::<c_void>()
            // SAFETY: `KERNEL_MAP` is the bootstrap's kernel map pointer.
            != unsafe { KERNEL_MAP.cast::<c_void>() }
            // SAFETY: `entry` is live and the map is locked.
            && !unsafe { (*entry.as_ptr()).projected_on.is_null() }
        {
            match unsafe { (*entry.as_ptr()).projection() } {
                Projection::Entry(kernel_entry) => {
                    let persistent =
                        // SAFETY: `kernel_entry` is the live projection
                        // target.
                        unsafe { (*kernel_entry.as_ptr()).projected_on }
                            .is_null();
                    if persistent {
                        unsafe { (*entry.as_ptr()).wired_count = 0 };
                    } else {
                        return;
                    }
                }
                Projection::NonPersistent => return,
                Projection::None => {}
            }
        }

        // SAFETY: the entry is live and the map is locked.
        let object = unsafe { (*entry.as_ptr()).object.vm_object };

        if !object.is_null() {
            // SAFETY: `entry` is live and the map is locked.
            if unsafe { (*entry.as_ptr()).wired_count } != 0 {
                self.entry_reset_wired(entry);
                // SAFETY: the map and the linked entry are valid.
                unsafe { vm_fault::unwire(self, entry) };
            }

            // SAFETY: `KERNEL_OBJECT` is the bootstrap's kernel object.
            if object == unsafe { KERNEL_OBJECT } {
                // SAFETY: the object is valid and the lock serializes its page
                // table.
                unsafe {
                    (*object).lock.lock();
                    vm_object::page_remove(
                        object,
                        (*entry.as_ptr()).offset,
                        (*entry.as_ptr()).offset.wrapping_add(size),
                    );
                    (*object).lock.unlock();
                }
            // SAFETY: `entry` is live and the map is locked.
            } else if unsafe { (*entry.as_ptr()).is_shared() } {
                unsafe {
                    vm_object::pmap_remove(
                        object,
                        (*entry.as_ptr()).offset,
                        (*entry.as_ptr()).offset.wrapping_add(size),
                    );
                }
            } else {
                // SAFETY: the map is locked and the pmap valid.
                unsafe { pmap_remove(NonNull::new(self.pmap), s, e) };
                // SAFETY: the object lock guards its counters.
                unsafe {
                    (*object).lock.lock();
                    if (*object).can_release() {
                        vm_object::page_remove(
                            object,
                            (*entry.as_ptr()).offset,
                            (*entry.as_ptr()).offset.wrapping_add(size),
                        );
                    }
                    (*object).lock.unlock();
                }
            }
        }

        // SAFETY: the entry holds the reference being dropped.
        if unsafe { (*entry.as_ptr()).is_sub_map() } {
            // SAFETY: the union member is a non-null submap pointer.
            let submap = unsafe {
                NonNull::new_unchecked((*entry.as_ptr()).object.sub_map)
            };
            Self::deallocate(submap);
        } else {
            // SAFETY: the entry held the only reference to the object.
            unsafe { vm_object_deallocate(object) };
        }

        unsafe {
            self.hdr.entry_unlink(entry, true);
        }
        self.size = self.size.wrapping_sub(size);
        // SAFETY: the entry is live and the map is locked.
        if unsafe { (*entry.as_ptr()).max_protection } == VmProt::NONE {
            self.size_none = self.size_none.wrapping_sub(size);
        }
        // SAFETY: the entry is now unlinked and unused.
        unsafe { VmMapEntry::dispose(entry) };
    }

    /// `vm_map_delete()` in C.
    pub(crate) fn delete(&mut self, start: VmOffset, end: VmOffset) {
        // SAFETY: `kernel_pmap`, `kernel_virtual_start` and
        // `kernel_virtual_end` are boot globals.
        if self.pmap == unsafe { KERNEL_PMAP }
            // SAFETY: `kernel_pmap`, `kernel_virtual_start` and
            // `kernel_virtual_end` are boot globals; the boot global
            // is the live kernel range.
            && (start < unsafe { KERNEL_VIRTUAL_START }
                // SAFETY: `kernel_pmap`, `kernel_virtual_start` and
                // `kernel_virtual_end` are boot globals; the boot
                // global is the live kernel range.
                || end > unsafe { KERNEL_VIRTUAL_END })
        {
            kpanic!(
                "VmMap::delete",
                "vm_map_delete({:x}-{:x}) falls in physical memory area!\n",
                start,
                end
            );
        }

        let sentinel = self.to_entry();
        let (found, first_entry) = self.lookup_entry(start);
        let mut entry = if found {
            // SAFETY: the entry is live and the map is locked.
            unsafe { self.hdr.clip_start_at(first_entry, start, true) };
            // SAFETY: `first_entry` is live and the map is locked.
            let prev = unsafe { (*first_entry.as_ptr()).links.prev };
            if let Some(prev) = prev {
                self.save_hint(prev);
            }
            first_entry
        } else {
            // SAFETY: the returned entry is the sentinel or live.
            unsafe { (*first_entry.as_ptr()).links.next.unwrap_or(sentinel) }
        };

        let first_free = self.first_free_entry();
        // SAFETY: `first_free` is live under the map lock.
        if unsafe { (*first_free.as_ptr()).links.start } >= start {
            // SAFETY: `entry` is live under the map lock.
            let prev = unsafe { (*entry.as_ptr()).links.prev };
            if let Some(prev) = prev {
                self.first_free = prev.as_ptr();
            }
        }

        // SAFETY: every entry touched here is linked while the map lock is
        // held.
        while !self.hdr.is_sentinel(entry)
            // SAFETY: `entry` is live or the sentinel under the map lock.
            && unsafe { (*entry.as_ptr()).links.start } < end
        {
            // SAFETY: `entry` is live and the map is locked.
            if end < unsafe { (*entry.as_ptr()).links.end } {
                // SAFETY: the entry is live and the map is locked.
                unsafe { self.hdr.clip_end(entry, end, true) };
            }

            // SAFETY: `entry` is live and the map is locked.
            if unsafe { (*entry.as_ptr()).in_transition() } {
                // SAFETY: the entry is live and the map is locked; the wakeup
                // flag is the C wait protocol.
                unsafe {
                    (*entry.as_ptr()).set_needs_wakeup(true);
                    self.entry_wait();
                }
                // SAFETY: the entry is live.
                let map = NonNull::from(&mut *self);
                Self::unlock(map);
                // SAFETY: the C protocol sleeps with the map unlocked.
                unsafe { thread_block(None) };
                Self::lock(map);

                let (found, looked) = self.lookup_entry(start);
                entry = if found {
                    looked
                } else {
                    // SAFETY: the returned entry is the sentinel or live.
                    unsafe {
                        (*looked.as_ptr()).links.next.unwrap_or(sentinel)
                    }
                };
                continue;
            }

            // SAFETY: `entry` is live and the map is locked.
            let next = unsafe { (*entry.as_ptr()).links.next };
            // SAFETY: the entry is linked and the map is locked.
            unsafe { self.entry_delete(entry) };
            entry = next.unwrap_or(sentinel);
        }

        if self.wait_for_space() {
            // SAFETY: the C code wakes the map address, which is the event
            // `assert_wait` sleeps on.
            unsafe {
                thread_wakeup_prim(
                    ptr::from_mut(self).cast::<c_void>(),
                    0,
                    THREAD_AWAKENED,
                )
            };
        }
    }

    /// `vm_map_remove()` in C.
    // The C declares `kern_return_t`, and the callers below keep its error
    // plumbing; the current ported body cannot fail.
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn remove(
        &mut self,
        start: VmOffset,
        end: VmOffset,
    ) -> Result<(), Error> {
        let map = NonNull::from(&mut *self);
        Self::lock(map);

        let mut start = start;
        let mut end = end;
        self.range_check(&mut start, &mut end);

        self.delete(start, end);

        Self::unlock(map);
        Ok(())
    }

    /// `vm_map_coalesce_entry()` in C.
    ///
    /// # Safety
    ///
    /// `entry` must be a live entry of this map.
    pub(crate) unsafe fn coalesce_entry(
        &mut self,
        entry: NonNull<VmMapEntry>,
    ) -> bool {
        let Some(prev) = (unsafe { (*entry.as_ptr()).links.prev }) else {
            return false;
        };

        let prev_end = unsafe { (*prev.as_ptr()).links.end };
        let entry_start = unsafe { (*entry.as_ptr()).links.start };
        if self.hdr.is_sentinel(entry)
            || self.hdr.is_sentinel(prev)
            || prev_end != entry_start
            || unsafe { (*prev.as_ptr()).is_shared() }
            || unsafe { (*entry.as_ptr()).is_shared() }
            || unsafe { (*prev.as_ptr()).is_sub_map() }
            || unsafe { (*entry.as_ptr()).is_sub_map() }
            || unsafe { (*prev.as_ptr()).inheritance }
                != unsafe { (*entry.as_ptr()).inheritance }
            || unsafe { (*prev.as_ptr()).protection }
                != unsafe { (*entry.as_ptr()).protection }
            || unsafe { (*prev.as_ptr()).max_protection }
                != unsafe { (*entry.as_ptr()).max_protection }
            || unsafe { (*prev.as_ptr()).needs_copy() }
                != unsafe { (*entry.as_ptr()).needs_copy() }
            || unsafe { (*prev.as_ptr()).in_transition() }
            || unsafe { (*entry.as_ptr()).in_transition() }
            || unsafe { (*prev.as_ptr()).wired_count }
                != unsafe { (*entry.as_ptr()).wired_count }
            || !unsafe { (*prev.as_ptr()).projected_on.is_null() }
            || !unsafe { (*entry.as_ptr()).projected_on.is_null() }
        {
            return false;
        }

        let prev_size = unsafe {
            (*prev.as_ptr())
                .links
                .end
                .wrapping_sub((*prev.as_ptr()).links.start)
        };
        let entry_size = unsafe {
            (*entry.as_ptr())
                .links
                .end
                .wrapping_sub((*entry.as_ptr()).links.start)
        };

        // SAFETY: both entries are live and the map is locked.
        let coalesced = unsafe {
            vm_object_coalesce(
                (*prev.as_ptr()).object.vm_object,
                (*entry.as_ptr()).object.vm_object,
                (*prev.as_ptr()).offset,
                (*entry.as_ptr()).offset,
                prev_size,
                entry_size,
                addr_of_mut!((*prev.as_ptr()).object.vm_object),
                addr_of_mut!((*prev.as_ptr()).offset),
            )
        };
        if coalesced == 0 {
            return false;
        }

        if self.hint() == entry.as_ptr() {
            self.save_hint(prev);
        }
        if self.first_free_entry() == entry {
            self.first_free = prev.as_ptr();
        }

        // SAFETY: both entries are live and the map is locked.
        unsafe {
            (*prev.as_ptr()).links.end = (*entry.as_ptr()).links.end;
            self.hdr.entry_unlink(entry, true);
        }
        // SAFETY: the entry is now unlinked and unused.
        unsafe { VmMapEntry::dispose(entry) };

        true
    }
}

impl VmMap {
    /// `vm_map_entry_inc_wired()` in C.
    fn entry_inc_wired(&mut self, entry: NonNull<VmMapEntry>) {
        // SAFETY: `entry` is a live entry of this map.
        unsafe {
            if (*entry.as_ptr()).wired_count > 1 {
                return;
            }
            if (*entry.as_ptr()).wired_count == 0 {
                let size = (*entry.as_ptr())
                    .links
                    .end
                    .wrapping_sub((*entry.as_ptr()).links.start);
                self.size_wired = self.size_wired.wrapping_add(size);
            }
            (*entry.as_ptr()).wired_count =
                (*entry.as_ptr()).wired_count.wrapping_add(1);
        }
    }

    /// The `VM_MAP_RANGE_CHECK()` macro: clamp a range to the map's bounds.
    const fn range_check(&self, start: &mut VmOffset, end: &mut VmOffset) {
        let min = self.hdr.links.start;
        let max = self.hdr.links.end;
        if *start < min {
            *start = min;
        }
        if *end > max {
            *end = max;
        }
        if *start > *end {
            *start = *end;
        }
    }

    /// `vm_map_pageable_scan()` in C.
    fn pageable_scan(
        &mut self,
        start_entry: NonNull<VmMapEntry>,
        end: VmOffset,
    ) {
        let sentinel = self.to_entry();
        let mut do_wire_faults = false;

        let mut entry = start_entry;
        while !self.hdr.is_sentinel(entry)
            // SAFETY: `entry` is live or the sentinel under the map lock.
            && unsafe { (*entry.as_ptr()).links.start } < end
        {
            // SAFETY: the entries are live and the map is locked.
            let next =
                unsafe { (*entry.as_ptr()).links.next }.unwrap_or(sentinel);
            // SAFETY: `entry` is live and the map is locked.
            unsafe {
                if (*entry.as_ptr()).wired_access == VmProt::NONE {
                    if (*entry.as_ptr()).wired_count != 0 {
                        self.entry_reset_wired(entry);
                        vm_fault::unwire(self, entry);
                    }
                    entry = next;
                    continue;
                }

                if (*entry.as_ptr()).protection == VmProt::NONE {
                    if (*entry.as_ptr()).wired_count == 0 {
                        entry = next;
                        continue;
                    }
                    self.entry_reset_wired(entry);
                    vm_fault::unwire(self, entry);
                    entry = next;
                    continue;
                }

                if (*entry.as_ptr()).wired_count == 0 {
                    if (*entry.as_ptr()).needs_copy()
                        && (*entry.as_ptr()).protection & VmProt::WRITE
                            != VmProt::NONE
                    {
                        let size = (*entry.as_ptr())
                            .links
                            .end
                            .wrapping_sub((*entry.as_ptr()).links.start);
                        let mut object = (*entry.as_ptr()).object.vm_object;
                        let mut offset = (*entry.as_ptr()).offset;

                        vm_object_shadow(
                            &raw mut object,
                            &raw mut offset,
                            size,
                        );

                        (*entry.as_ptr()).object.vm_object = object;
                        (*entry.as_ptr()).offset = offset;
                        (*entry.as_ptr()).set_needs_copy(false);
                    }

                    if (*entry.as_ptr()).object.vm_object.is_null() {
                        let size = (*entry.as_ptr())
                            .links
                            .end
                            .wrapping_sub((*entry.as_ptr()).links.start);
                        (*entry.as_ptr()).object.vm_object =
                            vm_object_allocate(size);
                        (*entry.as_ptr()).offset = 0;
                    }
                }

                self.entry_inc_wired(entry);

                if (*entry.as_ptr()).wired_count == 1 {
                    do_wire_faults = true;
                }
            }
            entry = next;
        }

        if !do_wire_faults {
            return;
        }

        self.pageable_scan_faults(start_entry, end);
    }

    /// The fault phase of `pageable_scan()`: wire the entries the scan marked,
    /// bracketing the unlocked faults with the kernel map's transition flags.
    fn pageable_scan_faults(
        &mut self,
        start_entry: NonNull<VmMapEntry>,
        end: VmOffset,
    ) {
        let sentinel = self.to_entry();
        let map = NonNull::from(&mut *self);

        // SAFETY: `KERNEL_PMAP` is the bootstrap's global pmap pointer.
        let is_kernel = self.pmap == unsafe { KERNEL_PMAP };

        if is_kernel {
            let mut entry = start_entry;
            while !self.hdr.is_sentinel(entry)
                // SAFETY: `entry` is live or the sentinel under the map lock.
                && unsafe { (*entry.as_ptr()).links.end } <= end
            {
                // SAFETY: the entries are live and the map lock is held; the
                // flags keep them out of coalescing while the kernel map is
                // unlocked for the faults.
                unsafe {
                    (*entry.as_ptr()).set_in_transition(true);
                    (*entry.as_ptr()).set_needs_wakeup(false);
                }
                // SAFETY: the entries are live and the map lock is held; the
                // flags keep them out of coalescing while the kernel
                // map is unlocked for the faults; `entry` is live and
                // the map is locked.
                entry = unsafe { (*entry.as_ptr()).links.next }
                    .unwrap_or(sentinel);
            }
            Self::unlock(map);
        } else {
            // SAFETY: the map lock is held; the downgrade is the C protocol
            // for faulting with a read lock.
            unsafe {
                (*map.as_ptr()).lock.set_recursive();
                (*map.as_ptr()).lock.write_to_read();
            }
        }

        let mut entry = start_entry;
        while !self.hdr.is_sentinel(entry)
            // SAFETY: `entry` is live or the sentinel under the map lock.
            && unsafe { (*entry.as_ptr()).links.end } <= end
        {
            // SAFETY: `entry` is live or the sentinel under the map lock.
            if unsafe { (*entry.as_ptr()).wired_count } == 1 {
                // SAFETY: the map may be read-locked and `entry` is one of its
                // live entries; the C code assumes the faults always succeed.
                unsafe { vm_fault::wire(self, entry) };
            }
            entry =
                // SAFETY: `entry` is live under the map lock.
                unsafe { (*entry.as_ptr()).links.next }.unwrap_or(sentinel);
        }

        if is_kernel {
            Self::lock(map);
            let mut entry = start_entry;
            while !self.hdr.is_sentinel(entry)
                // SAFETY: `entry` is live or the sentinel under the map lock.
                && unsafe { (*entry.as_ptr()).links.end } <= end
            {
                // SAFETY: the entries are live and the map is locked.
                unsafe { (*entry.as_ptr()).set_in_transition(false) };
                // SAFETY: `entry` is live and the map is locked.
                entry = unsafe { (*entry.as_ptr()).links.next }
                    .unwrap_or(sentinel);
            }
        } else {
            // SAFETY: the map read lock is held.
            unsafe { (*map.as_ptr()).lock.clear_recursive() };
        }
    }

    /// `vm_map_protect()` in C.
    pub(crate) fn protect(
        &mut self,
        start_in: VmOffset,
        end_in: VmOffset,
        new_prot: VmProt,
        set_max: bool,
    ) -> Result<(), Error> {
        let map = NonNull::from(&mut *self);
        Self::lock(map);

        let mut start = start_in;
        let mut end = end_in;
        self.range_check(&mut start, &mut end);

        let sentinel = self.to_entry();
        let (found, temp_entry) = self.lookup_entry(start);
        let entry = if found {
            // SAFETY: the entry contains `start`.
            unsafe { self.hdr.clip_start_at(temp_entry, start, true) };
            temp_entry
        } else {
            // SAFETY: the entry before the range is live.
            unsafe { (*temp_entry.as_ptr()).links.next.unwrap_or(sentinel) }
        };

        let mut current = entry;
        while !self.hdr.is_sentinel(current)
            // SAFETY: `current` is live or the sentinel under the map lock.
            && unsafe { (*current.as_ptr()).links.start } < end
        {
            // SAFETY: `current` is live and the map is locked.
            if unsafe { (*current.as_ptr()).is_sub_map() } {
                Self::unlock(map);
                return Err(Error::InvalidArgument);
            }
            // SAFETY: `current` is live and the map is locked.
            let max = unsafe { (*current.as_ptr()).max_protection };
            if new_prot.bits() & (VmProt::NOTIFY.bits() | max.bits())
                != new_prot.bits()
            {
                Self::unlock(map);
                return Err(Error::ProtectionFailure);
            }
            current =
                // SAFETY: `current` is live under the map lock.
                unsafe { (*current.as_ptr()).links.next }.unwrap_or(sentinel);
        }

        current = entry;
        while !self.hdr.is_sentinel(current)
            // SAFETY: `current` is live or the sentinel under the map lock.
            && unsafe { (*current.as_ptr()).links.start } < end
        {
            // SAFETY: `current` is live and the map is locked.
            if end < unsafe { (*current.as_ptr()).links.end } {
                // SAFETY: the entry spans `end`.
                unsafe { self.hdr.clip_end(current, end, true) };
            }

            // SAFETY: the entry is live and the map is locked.
            let old_prot = unsafe { (*current.as_ptr()).protection };
            if set_max {
                // SAFETY: `current` is live and the map is locked.
                if unsafe { (*current.as_ptr()).max_protection } != new_prot
                    && new_prot == VmProt::NONE
                {
                    // SAFETY: `current` is live and the map is locked.
                    let size = unsafe {
                        (*current.as_ptr())
                            .links
                            .end
                            .wrapping_sub((*current.as_ptr()).links.start)
                    };
                    self.size_none = self.size_none.wrapping_add(size);
                }
                // SAFETY: `current` is live and the map is locked.
                unsafe {
                    (*current.as_ptr()).max_protection = new_prot;
                    (*current.as_ptr()).protection = new_prot & old_prot;
                }
            } else {
                // SAFETY: `current` is live and the map is locked.
                unsafe { (*current.as_ptr()).protection = new_prot };
            }

            // SAFETY: `current` is live and the map is locked.
            if unsafe { (*current.as_ptr()).protection } != VmProt::NONE
                // SAFETY: `current` is live and the map is locked; `current`
                // is still live.
                && (unsafe { (*current.as_ptr()).wired_access }
                    != VmProt::NONE
                    || self.wiring_required())
            {
                // SAFETY: `current` is live and the map is locked.
                unsafe {
                    (*current.as_ptr()).wired_access =
                        (*current.as_ptr()).protection;
                };
            }

            // SAFETY: `current` is live and the map is locked.
            if unsafe { (*current.as_ptr()).protection } != old_prot {
                // SAFETY: the pmap is valid and the map is locked.
                unsafe {
                    pmap_protect(
                        NonNull::new(self.pmap),
                        (*current.as_ptr()).links.start,
                        (*current.as_ptr()).links.end,
                        (*current.as_ptr()).protection.bits(),
                    );
                };
            }

            // SAFETY: `current` is live and the map is locked.
            let next = unsafe { (*current.as_ptr()).links.next };
            // SAFETY: the entry is live and the map is locked.
            let _ = unsafe { self.coalesce_entry(current) };
            current = next.unwrap_or(sentinel);
        }

        // SAFETY: `current` is the sentinel or a live entry of the locked map.
        let _ = unsafe { self.coalesce_entry(current) };

        self.pageable_scan(entry, end);

        Self::unlock(map);
        Ok(())
    }

    /// `vm_map_inherit()` in C.
    pub(crate) fn inherit(
        &mut self,
        start_in: VmOffset,
        end_in: VmOffset,
        new_inheritance: VmInherit,
    ) {
        let map = NonNull::from(&mut *self);
        Self::lock(map);

        let mut start = start_in;
        let mut end = end_in;
        self.range_check(&mut start, &mut end);

        let sentinel = self.to_entry();
        let (found, temp_entry) = self.lookup_entry(start);
        let mut entry = if found {
            // SAFETY: the entry contains `start`.
            unsafe { self.hdr.clip_start_at(temp_entry, start, true) };
            temp_entry
        } else {
            // SAFETY: the entry before the range is live.
            unsafe { (*temp_entry.as_ptr()).links.next.unwrap_or(sentinel) }
        };

        while !self.hdr.is_sentinel(entry)
            // SAFETY: `entry` is live or the sentinel under the map lock.
            && unsafe { (*entry.as_ptr()).links.start } < end
        {
            // SAFETY: `entry` is live and the map is locked.
            if end < unsafe { (*entry.as_ptr()).links.end } {
                // SAFETY: the entry spans `end`.
                unsafe { self.hdr.clip_end(entry, end, true) };
            }
            // SAFETY: the entry spans `end`; `entry` is live.
            unsafe { (*entry.as_ptr()).inheritance = new_inheritance };

            // SAFETY: the entry spans `end`; `entry` is live.
            let next = unsafe { (*entry.as_ptr()).links.next };
            // SAFETY: the entry is live and the map is locked.
            let _ = unsafe { self.coalesce_entry(entry) };
            entry = next.unwrap_or(sentinel);
        }

        // SAFETY: the map is locked; coalescing the sentinel is a no-op that
        // the C also attempts.
        let _ = unsafe { self.coalesce_entry(entry) };

        Self::unlock(map);
    }

    /// `vm_map_pageable()` in C.
    pub(crate) fn pageable(
        &mut self,
        start_in: VmOffset,
        end_in: VmOffset,
        access_type: VmProt,
        lock_map: bool,
        check_range: bool,
    ) -> Result<(), Error> {
        let map = NonNull::from(&mut *self);
        if lock_map {
            Self::lock(map);
        }

        let mut start = start_in;
        let mut end = end_in;
        self.range_check(&mut start, &mut end);

        let (found, start_entry) = self.lookup_entry(start);
        if !found {
            if lock_map {
                Self::unlock(map);
            }
            return Err(Error::NoSpace);
        }
        // SAFETY: the entry contains `start`.
        unsafe { self.hdr.clip_start_at(start_entry, start, true) };

        let sentinel = self.to_entry();
        let mut entry = start_entry;
        while !self.hdr.is_sentinel(entry)
            // SAFETY: `entry` is live or the sentinel under the map lock.
            && unsafe { (*entry.as_ptr()).links.start } < end
        {
            // SAFETY: `entry` is live and the map is locked.
            if end < unsafe { (*entry.as_ptr()).links.end } {
                // SAFETY: the entry spans `end`.
                unsafe { self.hdr.clip_end(entry, end, true) };
            }

            if check_range {
                // SAFETY: `entry` is live under the map lock.
                let entry_end = unsafe { (*entry.as_ptr()).links.end };
                // SAFETY: `entry` is live under the map lock; `entry` is still
                // live.
                let next = unsafe { (*entry.as_ptr()).links.next };
                let hole = entry_end < end
                    && match next {
                        None => true,
                        Some(next) if next == sentinel => true,
                        Some(next) => {
                            // SAFETY: the next entry is live.
                            let next_start =
                                unsafe { (*next.as_ptr()).links.start };
                            next_start > entry_end
                        }
                    };
                // SAFETY: `entry` is live under the map lock.
                let protection = unsafe { (*entry.as_ptr()).protection };
                if hole
                    || protection.bits() & access_type.bits()
                        != access_type.bits()
                {
                    if lock_map {
                        Self::unlock(map);
                    }
                    return Err(Error::NoSpace);
                }
            }

            entry =
                // SAFETY: `entry` is live under the map lock.
                unsafe { (*entry.as_ptr()).links.next }.unwrap_or(sentinel);
        }
        let end_entry = entry;

        let mut entry = start_entry;
        while entry != end_entry {
            // SAFETY: the entries up to `end_entry` are live and the map is
            // locked.
            unsafe { (*entry.as_ptr()).wired_access = access_type };
            entry =
                // SAFETY: the entries up to `end_entry` are live and the map
                // is locked.
                unsafe { (*entry.as_ptr()).links.next }.unwrap_or(sentinel);
        }

        self.pageable_scan(start_entry, end);

        if lock_map {
            Self::unlock(map);
        }
        Ok(())
    }

    /// `vm_map_pageable_current()` in C.
    fn pageable_current(&mut self, access_type: VmProt) -> Result<(), Error> {
        let Some(min) = self.hdr.tree.front().map(NonNull::from) else {
            return Ok(());
        };
        let Some(max) = self.hdr.tree.back().map(NonNull::from) else {
            return Ok(());
        };
        // SAFETY: the tree named live entries of this map's entry tree.
        let min_address = unsafe { (*min.as_ptr()).links.start };
        // SAFETY: `max` is live from the tree above.
        let max_address = unsafe { (*max.as_ptr()).links.end };

        self.pageable(min_address, max_address, access_type, false, false)
    }

    /// `vm_map_pageable_all()` in C.
    pub(crate) fn pageable_all(&mut self, flags: c_int) -> Result<(), Error> {
        const WIRE_NONE: c_int = 0;
        const WIRE_CURRENT: c_int = 1;
        const WIRE_FUTURE: c_int = 2;
        const WIRE_ALL: c_int = WIRE_CURRENT | WIRE_FUTURE;

        if flags & !WIRE_ALL != 0 {
            return Err(Error::InvalidArgument);
        }

        let map = NonNull::from(&mut *self);
        Self::lock(map);

        if flags == WIRE_NONE {
            self.flags &= !VM_MAP_WIRING_REQUIRED;
            let result = self.pageable_current(VmProt::NONE);
            Self::unlock(map);
            return result;
        }

        let wiring_required = self.wiring_required();

        if flags & WIRE_FUTURE != 0 {
            self.flags |= VM_MAP_WIRING_REQUIRED;
        }

        if flags & WIRE_CURRENT != 0 {
            let result = self.pageable_current(VmProt::READ | VmProt::WRITE);

            if result.is_err() {
                if flags & WIRE_FUTURE != 0 {
                    if wiring_required {
                        self.flags |= VM_MAP_WIRING_REQUIRED;
                    } else {
                        self.flags &= !VM_MAP_WIRING_REQUIRED;
                    }
                }
                Self::unlock(map);
                return result;
            }
        }

        Self::unlock(map);
        Ok(())
    }
}

/// `vm_map_pmap_enter_print`: the debugging switch that prints each page the
/// scan enters.
static VM_MAP_PMAP_ENTER_PRINT: AtomicU32 = AtomicU32::new(0);

/// `vm_map_pmap_enter_enable`: the debugging switch that lets `vm_map_enter`
/// run the pmap scan over a new entry.
static VM_MAP_PMAP_ENTER_ENABLE: AtomicU32 = AtomicU32::new(0);

/// The mapping `vm_map_enter()` asks for.
pub(crate) struct EnterRequest<'a> {
    /// The requested address, written on the anywhere path.
    pub(crate) address: &'a mut VmOffset,
    /// Size of the mapping; must be nonzero.
    pub(crate) size: VmSize,
    /// Alignment mask.
    pub(crate) mask: VmOffset,
    /// Whether the map chooses the address.
    pub(crate) anywhere: bool,
    /// The object to map, or null.
    pub(crate) object: *mut VmObject,
    /// Offset into `object`.
    pub(crate) offset: VmOffset,
    pub(crate) needs_copy: bool,
    /// Protection of the new mapping.
    pub(crate) cur_protection: VmProt,
    pub(crate) max_protection: VmProt,
    pub(crate) inheritance: VmInherit,
}

/// The locked part of `vm_map_enter()`: the C's `RETURN`/`BailOut` paths.
enum EnterOutcome {
    /// Nothing more to do; the C's `RETURN(KERN_SUCCESS)`.
    Done,
    /// A new entry covers `[start, end)`; the caller may run the pmap scan
    /// after unlocking.
    Entered {
        /// The first address of the new range.
        start: VmOffset,
        /// The first address after it.
        end: VmOffset,
    },
    /// The C's `BailOut`: report this error after unlocking.
    Error(Error),
}

impl VmMap {
    /// `vm_map_enter()` in C.
    pub(crate) fn enter(
        &mut self,
        mut request: EnterRequest<'_>,
    ) -> Result<(), Error> {
        if request.size == 0 {
            return Err(Error::InvalidArgument);
        }

        if !request.anywhere && *request.address & request.mask != 0 {
            return Err(Error::NoSpace);
        }

        let map = NonNull::from(&mut *self);
        let outcome = self.enter_locked(&mut request);

        Self::unlock(map);

        match outcome {
            EnterOutcome::Done => Ok(()),
            EnterOutcome::Entered { start, end } => {
                if !request.object.is_null()
                    && VM_MAP_PMAP_ENTER_ENABLE.load(Ordering::Relaxed) != 0
                    && !request.anywhere
                    && !request.needs_copy
                    && request.size < 128 * 1024
                {
                    self.pmap_enter(
                        start,
                        end,
                        request.object,
                        request.offset,
                        request.cur_protection,
                    );
                }
                Ok(())
            }
            EnterOutcome::Error(error) => Err(error),
        }
    }

    /// The body of `vm_map_enter()` that runs with the map locked on return.
    fn enter_locked(
        &mut self,
        request: &mut EnterRequest<'_>,
    ) -> EnterOutcome {
        let (start, entry, next_entry, end) = match self.enter_lookup(request)
        {
            Ok(found) => found,
            Err(outcome) => return outcome,
        };

        if request.max_protection != VmProt::NONE
            && let Err(error) = self.enforce_limit(request.size)
        {
            return EnterOutcome::Error(error);
        }

        if let Some(outcome) =
            self.try_coalesce(request, entry, next_entry, start, end)
        {
            return outcome;
        }

        // SAFETY: the entry cache is initialized and the map is locked.
        let new_entry = unsafe { VmMapEntry::create() };
        // SAFETY: the entry is freshly allocated and unlinked; every field is
        // written before it is linked.
        unsafe {
            let e = new_entry.as_ptr();
            (*e).links.start = start;
            (*e).links.end = end;
            (*e).set_shared(false);
            (*e).set_sub_map(false);
            (*e).object.vm_object = request.object;
            (*e).offset = request.offset;
            (*e).set_needs_copy(request.needs_copy);
            (*e).inheritance = request.inheritance;
            (*e).protection = request.cur_protection;
            (*e).max_protection = request.max_protection;
            (*e).wired_count = 0;
            (*e).wired_access = VmProt::NONE;
            (*e).set_in_transition(false);
            (*e).set_needs_wakeup(false);
            (*e).projected_on = ptr::null_mut();

            self.hdr.entry_link(entry, new_entry, true);
        }
        self.size = self.size.wrapping_add(request.size);
        if request.max_protection == VmProt::NONE {
            self.size_none = self.size_none.wrapping_add(request.size);
        }

        if self.first_free == entry.as_ptr() {
            let prev_end = if self.hdr.is_sentinel(entry) {
                self.hdr.links.start
            } else {
                // SAFETY: `entry` is live under the map lock.
                unsafe { (*entry.as_ptr()).links.end }
            };
            if prev_end >= start {
                self.first_free = new_entry.as_ptr();
            }
        }

        self.save_hint(new_entry);

        if self.wiring_required() {
            let result = self.pageable(
                start,
                end,
                request.cur_protection,
                false,
                false,
            );
            if result.is_err() {
                return EnterOutcome::Done;
            }
        }

        EnterOutcome::Entered { start, end }
    }

    /// The initial lookup of `enter_locked()`: lock the map when the request
    /// names its address, and find the entry before the new range with its
    /// successor.  On error the map is left locked, as `enter()` expects.
    fn enter_lookup(
        &mut self,
        request: &mut EnterRequest<'_>,
    ) -> Result<
        (VmOffset, NonNull<VmMapEntry>, NonNull<VmMapEntry>, VmOffset),
        EnterOutcome,
    > {
        let mut start = *request.address;

        if request.anywhere {
            let Some((entry, found)) =
                self.find_entry_anywhere(request.size, request.mask, false)
            else {
                return Err(EnterOutcome::Error(Error::NoSpace));
            };
            start = found;
            let end = start.wrapping_add(request.size);
            *request.address = start;
            // SAFETY: `entry` is the header or a live entry of the locked map,
            // and so is its next link.
            let next_entry = unsafe { (*entry.as_ptr()).links.next }
                .unwrap_or_else(|| self.to_entry());
            return Ok((start, entry, next_entry, end));
        }

        let map = NonNull::from(&mut *self);
        Self::lock(map);

        let end = start.wrapping_add(request.size);

        if start < self.hdr.links.start
            || end > self.hdr.links.end
            || start >= end
        {
            return Err(EnterOutcome::Error(Error::InvalidAddress));
        }

        let (found, temp_entry) = self.lookup_entry(start);
        if found {
            return Err(EnterOutcome::Error(Error::NoSpace));
        }

        let entry = temp_entry;
        // SAFETY: `entry` is the header or a live entry of the locked map,
        // and so is its next link.
        let next_entry = unsafe { (*entry.as_ptr()).links.next }
            .unwrap_or_else(|| self.to_entry());

        if next_entry != self.to_entry()
            // SAFETY: `next_entry` is live or the sentinel under the map lock.
            && unsafe { (*next_entry.as_ptr()).links.start } < end
        {
            return Err(EnterOutcome::Error(Error::NoSpace));
        }

        Ok((start, entry, next_entry, end))
    }

    /// The C's two coalescing branches of `vm_map_enter()`: try to extend the
    /// entry before the new range, then the entry after it.  Returns the
    /// outcome when one of them covered the whole request.
    fn try_coalesce(
        &mut self,
        request: &EnterRequest<'_>,
        entry: NonNull<VmMapEntry>,
        next_entry: NonNull<VmMapEntry>,
        start: VmOffset,
        end: VmOffset,
    ) -> Option<EnterOutcome> {
        let cur_protection = request.cur_protection;

        // SAFETY: `entry` is live under the map lock.
        let extend_prev = !self.hdr.is_sentinel(entry)
            && unsafe {
                let before = &*entry.as_ptr();
                before.links.end == start
                    && !before.is_shared()
                    && !before.is_sub_map()
                    && !before.in_transition()
                    && before.inheritance == request.inheritance
                    && before.protection == cur_protection
                    && before.max_protection == request.max_protection
                    && before.wired_count == 0
                    && before.projected_on.is_null()
            };

        if extend_prev {
            // SAFETY: `entry` is live and the map is locked, so
            // `vm_object_coalesce` may write both out-parameters.
            let coalesced = unsafe {
                let before = &mut *entry.as_ptr();
                vm_object_coalesce(
                    before.object.vm_object,
                    request.object,
                    before.offset,
                    request.offset,
                    before.links.end.wrapping_sub(before.links.start),
                    request.size,
                    addr_of_mut!(before.object.vm_object),
                    addr_of_mut!(before.offset),
                )
            } != 0;

            if coalesced {
                self.size = self.size.wrapping_add(request.size);
                if request.max_protection == VmProt::NONE {
                    self.size_none = self.size_none.wrapping_add(request.size);
                }
                // SAFETY: `entry` is live and the map is locked.
                unsafe { (*entry.as_ptr()).links.end = end };
                self.hdr.gap_update(entry);
                // SAFETY: the C attempts to coalesce the entry after the one
                // just extended, which may be the header.
                let _ = unsafe { self.coalesce_entry(next_entry) };
                return Some(EnterOutcome::Done);
            }
        }

        // SAFETY: `next_entry` is the header or a live entry under the map
        // lock.
        let extend_next = !self.hdr.is_sentinel(next_entry)
            && unsafe {
                let after = &*next_entry.as_ptr();
                after.links.start == end
                    && !after.is_shared()
                    && !after.is_sub_map()
                    && !after.in_transition()
                    && after.inheritance == request.inheritance
                    && after.protection == cur_protection
                    && after.max_protection == request.max_protection
                    && after.wired_count == 0
                    && after.projected_on.is_null()
            };

        if extend_next {
            // SAFETY: `next_entry` is live and the map is locked, so
            // `vm_object_coalesce` may write both out-parameters.
            let coalesced = unsafe {
                let after = &mut *next_entry.as_ptr();
                vm_object_coalesce(
                    request.object,
                    after.object.vm_object,
                    request.offset,
                    after.offset,
                    request.size,
                    after.links.end.wrapping_sub(after.links.start),
                    addr_of_mut!(after.object.vm_object),
                    addr_of_mut!(after.offset),
                )
            } != 0;

            if coalesced {
                self.size = self.size.wrapping_add(request.size);
                if request.max_protection == VmProt::NONE {
                    self.size_none = self.size_none.wrapping_add(request.size);
                }
                // SAFETY: `next_entry` is live and the map is locked.
                unsafe { (*next_entry.as_ptr()).links.start = start };
                self.hdr.gap_update(entry);
                // SAFETY: the C attempts to coalesce the entry it just
                // extended, which is still live.
                let _ = unsafe { self.coalesce_entry(next_entry) };
                return Some(EnterOutcome::Done);
            }
        }

        None
    }
}

impl VmMap {
    /// `vm_map_fork()` in C.
    pub(crate) fn fork(old_map: NonNull<Self>) -> Option<NonNull<Self>> {
        // SAFETY: the caller owns the old map for the call.
        let new_pmap = unsafe { pmap_create(0) };
        if new_pmap.is_null() {
            return None;
        }

        Self::lock(old_map);

        // SAFETY: the old map is valid and now locked.
        let (min, max) = unsafe {
            (
                (*old_map.as_ptr()).hdr.links.start,
                (*old_map.as_ptr()).hdr.links.end,
            )
        };
        let Some(forked_map) = Self::create(new_pmap, min, max) else {
            Self::unlock(old_map);
            // SAFETY: the pmap came from `pmap_create` above.
            unsafe { pmap_destroy(NonNull::new(new_pmap)) };
            return None;
        };

        // SAFETY: the header is valid and the chain is stable under the map
        // lock.
        let sentinel = unsafe { (*old_map.as_ptr()).to_entry() };
        // SAFETY: the first link is the first entry or the header.
        let mut old_entry =
            unsafe { (*old_map.as_ptr()).hdr.links.next }.unwrap_or(sentinel);

        let mut new_size: VmSize = 0;
        let mut new_size_none: VmSize = 0;

        while old_entry != sentinel {
            // SAFETY: `old_entry` is a live entry of the locked map.
            if unsafe { (*old_entry.as_ptr()).is_sub_map() } {
                kpanic!("VmMap::fork", "vm_map_fork: encountered a submap");
            }

            // SAFETY: `old_entry` is a live entry of the locked map.
            let entry_size = unsafe {
                (*old_entry.as_ptr())
                    .links
                    .end
                    .wrapping_sub((*old_entry.as_ptr()).links.start)
            };

            // SAFETY: `old_entry` is a live entry of the locked map.
            let inheritance = unsafe { (*old_entry.as_ptr()).inheritance };

            if inheritance == VmInherit::NONE {
                // The region is dropped from the new map.
            } else if inheritance == VmInherit::SHARE {
                // SAFETY: the old map is locked and owns `old_entry`, and
                // `forked_map` is private to this call.
                unsafe {
                    Self::fork_share_entry(
                        old_map,
                        forked_map,
                        old_entry,
                        entry_size,
                        &mut new_size,
                        &mut new_size_none,
                    );
                }
            } else if inheritance == VmInherit::COPY {
                // SAFETY: the old map is locked and owns `old_entry`, and
                // `forked_map` is private to this call.
                if let Some(next) = unsafe {
                    Self::fork_copy_entry(
                        old_map,
                        forked_map,
                        old_entry,
                        entry_size,
                        &mut new_size,
                        &mut new_size_none,
                    )
                } {
                    old_entry = next;
                    continue;
                }
            }

            // SAFETY: `old_entry` is live and the map is locked.
            old_entry = unsafe { (*old_entry.as_ptr()).links.next }
                .unwrap_or(sentinel);
        }

        // SAFETY: `forked_map` is private until it is returned.
        unsafe {
            (*forked_map.as_ptr()).size = new_size;
            (*forked_map.as_ptr()).size_none = new_size_none;
        }
        Self::copy_limits(forked_map, old_map);
        Self::unlock(old_map);

        Some(forked_map)
    }

    /// The `VM_INHERIT_SHARE` case of `vm_map_fork()`: point the new map's
    /// entry at the old entry's object.
    ///
    /// # Safety
    ///
    /// `old_map` must be locked and own `old_entry`; `forked_map` must be the
    /// private map this call is building.
    unsafe fn fork_share_entry(
        old_map: NonNull<Self>,
        forked_map: NonNull<Self>,
        old_entry: NonNull<VmMapEntry>,
        entry_size: VmSize,
        new_size: &mut VmSize,
        new_size_none: &mut VmSize,
    ) {
        // SAFETY: the union member of a non-submap entry.
        let mut object = unsafe { (*old_entry.as_ptr()).object.vm_object };

        if object.is_null() {
            // SAFETY: the entry is live and the map is locked.
            object = unsafe { vm_object_allocate(entry_size) };
            // SAFETY: `old_entry` is live and the map is locked.
            unsafe {
                (*old_entry.as_ptr()).offset = 0;
                (*old_entry.as_ptr()).object.vm_object = object;
            }
        } else {
            // SAFETY: the entry and object are live; the object's sharing
            // fields are read.
            let needs_shadow = unsafe {
                (*object).needs_shadow(
                    entry_size,
                    (*old_entry.as_ptr()).needs_copy(),
                    (*old_entry.as_ptr()).is_shared(),
                )
            };
            if needs_shadow {
                // SAFETY: the entry is live under the map lock;
                // `vm_object_shadow` owns the object reference it replaces.
                unsafe {
                    vm_object_shadow(
                        addr_of_mut!((*old_entry.as_ptr()).object.vm_object),
                        addr_of_mut!((*old_entry.as_ptr()).offset),
                        entry_size,
                    );
                }

                // SAFETY: the entry is live under the map lock.
                if unsafe {
                    !(*old_entry.as_ptr()).needs_copy()
                        && ((*old_entry.as_ptr()).protection & VmProt::WRITE)
                            != VmProt::NONE
                } {
                    // SAFETY: the pmap and the range are valid under the map
                    // lock.
                    unsafe {
                        pmap_protect(
                            NonNull::new((*old_map.as_ptr()).pmap),
                            (*old_entry.as_ptr()).links.start,
                            (*old_entry.as_ptr()).links.end,
                            ((*old_entry.as_ptr()).protection
                                & VmProt::from_bits(!VmProt::WRITE.bits()))
                            .bits(),
                        );
                    }
                }
                // SAFETY: the entry is live under the map lock.
                unsafe { (*old_entry.as_ptr()).set_needs_copy(false) };
                // SAFETY: the entry is live under the map lock; the object was
                // just replaced by the shadow.
                object = unsafe { (*old_entry.as_ptr()).object.vm_object };
            }
        }

        // SAFETY: the object is live and shared by this call.
        unsafe { vm_object::make_shared(object) };

        // SAFETY: the entry cache is initialized and the map is locked.
        let new_entry = unsafe { VmMapEntry::create() };

        // SAFETY: `new_entry` is unlinked storage; the copy fills it before it
        // is linked.
        if unsafe { !(*old_entry.as_ptr()).projected_on.is_null() } {
            // SAFETY: both entries are live; `new_entry` is unlinked storage.
            unsafe { VmMapEntry::copy_full(new_entry, old_entry) };
        } else {
            // SAFETY: both entries are live and `new_entry` is unlinked
            // storage.
            unsafe {
                VmMapEntry::copy(new_entry, old_entry);
                (*old_entry.as_ptr()).set_shared(true);
                (*new_entry.as_ptr()).set_shared(true);
            }
        }

        // SAFETY: `forked_map` is private and unlocked; its last link is the
        // last entry or the header.
        unsafe {
            let new = &mut *forked_map.as_ptr();
            let last = new.hdr.links.prev.unwrap_or_else(|| new.to_entry());
            new.hdr.entry_link(last, new_entry, true);
        }

        *new_size = (*new_size).wrapping_add(entry_size);
        // SAFETY: the entry is live under the map lock.
        if unsafe { (*old_entry.as_ptr()).max_protection } == VmProt::NONE {
            *new_size_none = (*new_size_none).wrapping_add(entry_size);
        }
    }

    /// The `VM_INHERIT_COPY` case of `vm_map_fork()`: give the new map a
    /// private copy, either via `vm_object_copy_temporary` or the core
    /// `copyin`.  Returns the entry to resume the scan at when the map was
    /// unlocked for the copy.
    ///
    /// # Safety
    ///
    /// `old_map` must be locked and own `old_entry`; `forked_map` must be the
    /// private map this call is building.
    unsafe fn fork_copy_entry(
        old_map: NonNull<Self>,
        forked_map: NonNull<Self>,
        old_entry: NonNull<VmMapEntry>,
        entry_size: VmSize,
        new_size: &mut VmSize,
        new_size_none: &mut VmSize,
    ) -> Option<NonNull<VmMapEntry>> {
        let mut optimized = false;

        // SAFETY: the entry is live under the map lock.
        if unsafe { (*old_entry.as_ptr()).wired_count } == 0 {
            // SAFETY: the entry cache is initialized and the map is locked.
            let new_entry = unsafe { VmMapEntry::create() };
            // SAFETY: `new_entry` is unlinked storage.
            unsafe { VmMapEntry::copy(new_entry, old_entry) };

            let mut src_needs_copy: c_int = 0;
            let mut new_needs_copy: c_int = 0;
            // SAFETY: `new_entry` is live and unlinked; the object copy writes
            // both out-parameters.
            let copied = unsafe {
                vm_object_copy_temporary(
                    addr_of_mut!((*new_entry.as_ptr()).object.vm_object),
                    addr_of_mut!((*new_entry.as_ptr()).offset),
                    &raw mut src_needs_copy,
                    &raw mut new_needs_copy,
                ) != 0
            };

            if copied {
                // SAFETY: the entry is live under the map lock.
                if src_needs_copy != 0
                    && unsafe { !(*old_entry.as_ptr()).needs_copy() }
                {
                    // SAFETY: the old entry and its object are live under the
                    // map lock.
                    unsafe {
                        vm_object_pmap_protect(
                            (*old_entry.as_ptr()).object.vm_object,
                            (*old_entry.as_ptr()).offset,
                            entry_size,
                            if (*old_entry.as_ptr()).is_shared() {
                                ptr::null_mut()
                            } else {
                                (*old_map.as_ptr()).pmap
                            },
                            (*old_entry.as_ptr()).links.start,
                            ((*old_entry.as_ptr()).protection
                                & VmProt::from_bits(!VmProt::WRITE.bits()))
                            .bits(),
                        );
                    }
                    // SAFETY: the entry is live under the map lock.
                    unsafe {
                        (*old_entry.as_ptr()).set_needs_copy(true);
                    };
                }

                // SAFETY: `new_entry` is live and unlinked.
                unsafe {
                    (*new_entry.as_ptr()).set_needs_copy(new_needs_copy != 0);
                };

                // SAFETY: `forked_map` is private and unlocked.
                unsafe {
                    let new = &mut *forked_map.as_ptr();
                    let last =
                        new.hdr.links.prev.unwrap_or_else(|| new.to_entry());
                    new.hdr.entry_link(last, new_entry, true);
                }

                *new_size = (*new_size).wrapping_add(entry_size);
                // SAFETY: the entry is live under the map lock.
                if unsafe { (*old_entry.as_ptr()).max_protection }
                    == VmProt::NONE
                {
                    *new_size_none = (*new_size_none).wrapping_add(entry_size);
                }
                optimized = true;
            } else {
                // SAFETY: the entry is unlinked and unused.
                unsafe { VmMapEntry::dispose(new_entry) };
            }
        }

        if !optimized {
            return Some(unsafe {
                Self::fork_copy_core(
                    old_map,
                    forked_map,
                    old_entry,
                    entry_size,
                    new_size,
                    new_size_none,
                )
            });
        }

        None
    }

    /// The core-`copyin` path of `fork_copy_entry()`: copy the entry while
    /// the old map is unlocked, then relock and resume.  Returns the entry
    /// the fork scan restarts at.
    ///
    /// # Safety
    ///
    /// `old_map` must be locked and own `old_entry`; `forked_map` must be the
    /// private map this call is building.
    unsafe fn fork_copy_core(
        old_map: NonNull<Self>,
        forked_map: NonNull<Self>,
        old_entry: NonNull<VmMapEntry>,
        entry_size: VmSize,
        new_size: &mut VmSize,
        new_size_none: &mut VmSize,
    ) -> NonNull<VmMapEntry> {
        // SAFETY: `old_map` is the locked map the caller owns.
        let sentinel = unsafe { (*old_map.as_ptr()).to_entry() };
        // SAFETY: the entry is live under the map lock.
        let start = unsafe { (*old_entry.as_ptr()).links.start };
        // SAFETY: the entry is live under the map lock.
        let old_max_none =
            unsafe { (*old_entry.as_ptr()).max_protection } == VmProt::NONE;
        // SAFETY: `forked_map` is private and unlocked.
        let last = unsafe { (*forked_map.as_ptr()).hdr.links.prev }
            .unwrap_or_else(|| unsafe { (*forked_map.as_ptr()).to_entry() });

        Self::unlock(old_map);

        let Ok(copy) =
            (unsafe { (*old_map.as_ptr()).copyin(start, entry_size, false) })
        else {
            Self::lock(old_map);
            // SAFETY: the map is locked again.
            let (found, looked) =
                unsafe { (*old_map.as_ptr()).lookup_entry(start) };
            return if found {
                looked
            } else {
                // SAFETY: `looked` is a live entry or the header.
                unsafe { (*looked.as_ptr()).links.next }.unwrap_or(sentinel)
            };
        };

        // SAFETY: the copy chain came from the core `copyin` and the new
        // map is private to this call.
        unsafe { (*forked_map.as_ptr()).copy_insert(last, copy) };
        *new_size = (*new_size).wrapping_add(entry_size);
        if old_max_none {
            *new_size_none = (*new_size_none).wrapping_add(entry_size);
        }

        Self::lock(old_map);
        let next_start = start.wrapping_add(entry_size);
        // SAFETY: the map is locked again.
        let (found, looked) =
            unsafe { (*old_map.as_ptr()).lookup_entry(next_start) };
        if found {
            // SAFETY: `looked` contains `next_start` and the map is locked.
            unsafe {
                (*old_map.as_ptr())
                    .hdr
                    .clip_start_at(looked, next_start, true);
            };
            looked
        } else {
            // SAFETY: `looked` is a live entry or the header.
            unsafe { (*looked.as_ptr()).links.next }.unwrap_or(sentinel)
        }
    }
}

/// How `copyin()` proceeds after one source entry was copied.
enum CopyinStep {
    /// The new entry is complete and ready to be linked into the copy.
    Link(NonNull<VmMapEntry>),
    /// The map changed while it was unlocked; restart at this entry.
    Retry(NonNull<VmMapEntry>),
}

/// What `copyout_page_list()`'s drain left behind.
struct PageDrain {
    /// The destination address, once the drain completed.
    dst_addr: Option<VmOffset>,
    /// The last continuation copy, which the caller owns.
    current: Option<NonNull<VmMapCopy>>,
    /// Whether a continuation was invoked.
    cont_invoked: bool,
    /// The drain's error, if it failed.
    error: Option<Error>,
}

/// The gather state of `copyin_page_list()`, carried between its loops.
struct PageListState {
    /// The caller's source address, which the continuation's length uses.
    src_addr: VmOffset,
    /// The caller's length, which the continuation's length uses.
    len: VmSize,
    /// The first address of the range still to gather.
    src_start: VmOffset,
    /// The first address after the range.
    src_end: VmOffset,
    /// Size of the current entry's remaining range.
    src_size: VmSize,
    /// The current source entry of the locked map.
    src_entry: NonNull<VmMapEntry>,
    /// Whether the fault path released the map lock.
    need_map_lookup: bool,
}

/// How `copyin_page_list()`'s entry loop stopped.
enum PageEntryStep {
    /// The range is complete; the map is locked on return.
    Done,
    /// The fault path released the map; the caller must redo the lookup.
    Lookup,
}

/// How the fault path of `copyin_page_list()`'s page loop finished.
enum PageFaultStep {
    /// The page was faulted in.
    Got(*mut VmPage),
    /// The map was relocked and the copy takes a continuation.
    Continuation,
}

impl VmMap {
    /// `vm_map_copy_insert()` in C: static until the Rust callers needed it, a
    /// private method again now that they call it directly.
    ///
    /// # Safety
    ///
    /// The map must be write-locked, or private to the caller (fork links an
    /// entry chain into an unpublished map), `where_` a live entry of it, and
    /// `copy` a live entry-list copy the caller owns.
    pub(crate) unsafe fn copy_insert(
        &mut self,
        mut where_: NonNull<VmMapEntry>,
        copy: NonNull<VmMapCopy>,
    ) {
        let copy_header = unsafe { VmMapCopy::header(copy) };
        loop {
            let entry = unsafe { VmMapCopy::first_entry(copy) };
            if entry == copy_header.cast() {
                break;
            }

            // SAFETY: `entry` is a live entry of the copy, which this call
            // owns exclusively, and the map is locked.
            unsafe {
                (*copy_header.as_ptr()).entry_unlink(entry, false);
                self.hdr.entry_link(where_, entry, true);
            }
            where_ = entry;
        }

        // SAFETY: the chain is empty, so the copy holds nothing.
        unsafe { VmMapCopy::free(copy) };
    }

    /// `vm_map_copyin()` in C.
    pub(crate) fn copyin(
        &mut self,
        src_addr: VmOffset,
        len: VmSize,
        src_destroy: bool,
    ) -> Result<NonNull<VmMapCopy>, Error> {
        if src_addr.wrapping_add(len) <= src_addr {
            return Err(Error::InvalidAddress);
        }

        let mut src_start = trunc_page(src_addr);
        let src_end = round_page(src_addr.wrapping_add(len));

        if src_end == 0 {
            return Err(Error::InvalidAddress);
        }

        // SAFETY: `vm_map_init()` initialized the caches before any map
        // exists.
        let copy = unsafe { VmMapCopy::new_entry_list(src_addr, len) };
        // SAFETY: the copy holds the live `ENTRY_LIST` variant.
        let copy_header = unsafe { VmMapCopy::header(copy) };

        let map = NonNull::from(&mut *self);
        Self::lock(map);

        let sentinel = self.to_entry();
        let (found, mut tmp_entry) = self.lookup_entry(src_start);
        if !found {
            Self::unlock(map);
            // SAFETY: the copy is live and owned by this call.
            unsafe { VmMapCopy::discard(copy) };
            return Err(Error::InvalidAddress);
        }
        // SAFETY: `tmp_entry` contains `src_start` and the map is locked; the
        // guarded `vm_map_clip_start()` splits only an entry that starts
        // before `src_start`.
        unsafe { self.hdr.clip_start_at(tmp_entry, src_start, true) };

        'entry: loop {
            let mut entry = tmp_entry;
            // SAFETY: `entry` is a live entry of the locked map.
            let protection = unsafe { (*entry.as_ptr()).protection };

            if !protection.contains(VmProt::READ) {
                Self::unlock(map);
                // SAFETY: the copy is live and owned by this call.
                unsafe { VmMapCopy::discard(copy) };
                return Err(Error::ProtectionFailure);
            }

            // SAFETY: `entry` is live and spans `src_end`; the guarded
            // `vm_map_clip_end()` splits only an entry that ends after it.
            unsafe { self.hdr.clip_end_at(entry, src_end, true) };

            // SAFETY: the entry cache is initialized and the map is locked.
            let new_entry = unsafe { VmMapEntry::create() };
            // SAFETY: `new_entry` is unlinked storage; the copy fills it
            // before it is linked below.
            unsafe { VmMapEntry::copy(new_entry, entry) };

            let copy_successful =
                self.copyin_fast(entry, new_entry, src_destroy, src_start);

            if !copy_successful {
                match self
                    .copyin_slow(map, copy, entry, new_entry, src_start)?
                {
                    CopyinStep::Link(updated) => entry = updated,
                    CopyinStep::Retry(next) => {
                        tmp_entry = next;
                        continue 'entry;
                    }
                }
            }

            // SAFETY: the copy header is live, the new entry is unlinked, and
            // the map is locked.
            unsafe {
                let last = VmMapCopy::last_entry(copy);
                (*copy_header.as_ptr()).entry_link(last, new_entry, false);
            }

            // SAFETY: `new_entry` is now linked in the copy.
            src_start = unsafe { (*new_entry.as_ptr()).links.end };
            if src_start >= src_end && src_end != 0 {
                break;
            }

            // SAFETY: `entry` is live under the map lock, and its next link is
            // live or the sentinel.
            tmp_entry =
                unsafe { (*entry.as_ptr()).links.next }.unwrap_or(sentinel);
            // SAFETY: `tmp_entry` is live or the sentinel.
            if unsafe { (*tmp_entry.as_ptr()).links.start } != src_start {
                Self::unlock(map);
                // SAFETY: the copy is live and owned here.
                unsafe { VmMapCopy::discard(copy) };
                return Err(Error::InvalidAddress);
            }
        }

        if src_destroy {
            self.delete(trunc_page(src_addr), src_end);
        }

        Self::unlock(map);

        Ok(copy)
    }

    /// The fast path of `copyin()`: keep the source object alive, or copy it
    /// temporarily.  Returns whether the new entry became self-contained.
    fn copyin_fast(
        &mut self,
        entry: NonNull<VmMapEntry>,
        new_entry: NonNull<VmMapEntry>,
        src_destroy: bool,
        src_start: VmOffset,
    ) -> bool {
        // SAFETY: `entry` is a live entry of the locked map.
        let (
            src_size,
            src_object,
            src_offset,
            was_wired,
            protection,
            entry_shared,
        ) = unsafe {
            let e = &*entry.as_ptr();
            (
                e.links.end.wrapping_sub(src_start),
                e.object.vm_object,
                e.offset,
                e.wired_count != 0,
                e.protection,
                e.is_shared(),
            )
        };

        let mut copy_successful = if src_destroy
            && (src_object.is_null()
                || (unsafe {
                    // SAFETY: `src_object` is live under the map lock.
                    (*src_object).is_temporary()
                } && !unsafe {
                    // SAFETY: `src_object` is live under the map lock; the
                    // object's shared-copy bit is read.
                    (*src_object).use_shared_copy()
                })) {
            // SAFETY: `new_entry` holds the object reference, and the extra
            // one taken here keeps the object alive until the source entry is
            // destroyed at the end.
            unsafe { vm_object::reference(src_object) };
            true
        } else {
            false
        };

        if !copy_successful && !was_wired {
            let mut src_needs_copy: c_int = 0;
            let mut new_entry_needs_copy: c_int = 0;
            // SAFETY: `new_entry` is live unlinked storage; the object routine
            // writes both out-parameters and the object/offset it is handed.
            let optimized = unsafe {
                vm_object_copy_temporary(
                    addr_of_mut!((*new_entry.as_ptr()).object.vm_object),
                    addr_of_mut!((*new_entry.as_ptr()).offset),
                    &raw mut src_needs_copy,
                    &raw mut new_entry_needs_copy,
                ) != 0
            };

            if optimized {
                // SAFETY: `new_entry` is live unlinked storage.
                unsafe {
                    (*new_entry.as_ptr())
                        .set_needs_copy(new_entry_needs_copy != 0);
                };

                if src_needs_copy != 0
                    && !unsafe {
                        // SAFETY: `entry` is a live entry of the locked map.
                        (*entry.as_ptr()).needs_copy()
                    }
                {
                    // SAFETY: `entry` and `src_object` are live under the map
                    // lock; the shared case passes a null pmap, as the C
                    // `PMAP_NULL` does.
                    unsafe {
                        vm_object_pmap_protect(
                            src_object,
                            src_offset,
                            src_size,
                            if entry_shared {
                                ptr::null_mut()
                            } else {
                                self.pmap
                            },
                            (*entry.as_ptr()).links.start,
                            (protection
                                & VmProt::from_bits(!VmProt::WRITE.bits()))
                            .bits(),
                        );
                    }
                    // SAFETY: `entry` is live under the map lock.
                    unsafe { (*entry.as_ptr()).set_needs_copy(true) };
                }

                copy_successful = true;
            }
        }

        copy_successful
    }

    /// The slow path of `copyin()`: copy the source object while the map is
    /// unlocked.  Returns [`CopyinStep::Retry`] when the map changed and the
    /// caller must restart at the returned entry.
    fn copyin_slow(
        &mut self,
        map: NonNull<Self>,
        copy: NonNull<VmMapCopy>,
        mut entry: NonNull<VmMapEntry>,
        new_entry: NonNull<VmMapEntry>,
        src_start: VmOffset,
    ) -> Result<CopyinStep, Error> {
        // SAFETY: `entry` is a live entry of the locked map.
        let (src_size, src_object, src_offset, was_wired) = unsafe {
            let e = &*entry.as_ptr();
            (
                e.links.end.wrapping_sub(src_start),
                e.object.vm_object,
                e.offset,
                e.wired_count != 0,
            )
        };

        // SAFETY: `new_entry` is live unlinked storage.
        unsafe { (*new_entry.as_ptr()).set_needs_copy(false) };

        // SAFETY: the entry holds the object reference.
        unsafe { vm_object::reference(src_object) };

        // SAFETY: the map is locked, so its timestamp is stable.
        let version = VmMapVersion {
            // SAFETY: the map is locked, so its timestamp is stable; the map
            // is locked.
            main_timestamp: unsafe { (*map.as_ptr()).timestamp },
        };

        // SAFETY: `new_entry` is live unlinked storage and `entry` holds the
        // object reference.
        Self::copyin_copy_slowly(
            map, copy, new_entry, src_object, src_offset, src_size, was_wired,
        )?;

        Self::lock(map); // increments the timestamp once

        if version.main_timestamp.wrapping_add(1)
            != unsafe {
                // SAFETY: the write lock just taken makes this timestamp read
                // stable.
                (*map.as_ptr()).timestamp
            }
        {
            let (found, looked) = self.lookup_entry(src_start);
            if !found {
                // SAFETY: `new_entry` is live and unlinked.
                unsafe { VmMapEntry::dispose(new_entry) };
                Self::unlock(map);
                // SAFETY: the copy is live and owned here.
                unsafe { VmMapCopy::discard(copy) };
                return Err(Error::InvalidAddress);
            }
            entry = looked;
            // SAFETY: `entry` contains `src_start` and the map is locked.
            unsafe { self.hdr.clip_start_at(entry, src_start, true) };
            // SAFETY: `entry` is a live entry of the locked map, and
            // `new_entry` is live unlinked storage.
            let verified = unsafe {
                let e = &*entry.as_ptr();
                if e.protection.contains(VmProt::READ) {
                    if e.links.end < (*new_entry.as_ptr()).links.end {
                        (*new_entry.as_ptr()).links.end = e.links.end;
                    }
                    e.object.vm_object == src_object && e.offset == src_offset
                } else {
                    false
                }
            };

            if !verified {
                // SAFETY: `new_entry` holds the reference dropped here and is
                // unlinked.
                unsafe {
                    vm_object_deallocate(
                        (*new_entry.as_ptr()).object.vm_object,
                    );
                    VmMapEntry::dispose(new_entry);
                }
                return Ok(CopyinStep::Retry(entry));
            }
        }

        Ok(CopyinStep::Link(entry))
    }

    /// Copy the source object while `copyin()`'s map is unlocked; the caller
    /// retakes the lock on return.
    fn copyin_copy_slowly(
        map: NonNull<Self>,
        copy: NonNull<VmMapCopy>,
        new_entry: NonNull<VmMapEntry>,
        src_object: *mut VmObject,
        src_offset: VmOffset,
        src_size: VmSize,
        was_wired: bool,
    ) -> Result<(), Error> {
        Self::unlock(map);

        if was_wired {
            // SAFETY: `src_object` is live and the entry holds its reference.
            unsafe {
                (*src_object).lock.lock();
                vm_object_copy_slowly(
                    src_object,
                    src_offset,
                    src_size,
                    0,
                    addr_of_mut!((*new_entry.as_ptr()).object.vm_object),
                );
            }
            // SAFETY: `new_entry` is live unlinked storage.
            unsafe {
                (*new_entry.as_ptr()).offset = 0;
                (*new_entry.as_ptr()).set_needs_copy(false);
            }
        } else {
            let mut new_entry_needs_copy: c_int = 0;
            // SAFETY: `new_entry` is live unlinked storage; the object routine
            // writes its object, offset and flag.
            let result = unsafe {
                vm_object_copy_strategically(
                    src_object,
                    src_offset,
                    src_size,
                    addr_of_mut!((*new_entry.as_ptr()).object.vm_object),
                    addr_of_mut!((*new_entry.as_ptr()).offset),
                    &raw mut new_entry_needs_copy,
                )
            };
            // SAFETY: `new_entry` is live unlinked storage.
            unsafe {
                (*new_entry.as_ptr())
                    .set_needs_copy(new_entry_needs_copy != 0);
            };

            if result != KERN_SUCCESS {
                // SAFETY: `new_entry` is live and unlinked.
                unsafe { VmMapEntry::dispose(new_entry) };
                Self::lock(map);
                Self::unlock(map);
                // SAFETY: the copy is live and owned here.
                unsafe { VmMapCopy::discard(copy) };
                let error = if let Err(error) = error_from_kern_return(result)
                {
                    error
                } else {
                    Error::Failure
                };
                return Err(error);
            }
        }

        // SAFETY: the reference taken above.
        unsafe { vm_object_deallocate(src_object) };

        Ok(())
    }
}

/// The two `vm_map_copyin_args_data` setups of `vm_map_copyin_page_list()` in
/// C.
fn set_page_list_cont(
    map: NonNull<VmMap>,
    copy: NonNull<VmMapCopy>,
    src_addr: VmOffset,
    src_len: VmSize,
    destroy_addr: VmOffset,
    destroy_len: VmSize,
    steal_pages: bool,
) {
    // `vm_map_init()` initialized the allocator.
    let Some(args) = kalloc(size_of::<VmMapCopyinArgs>())
        .map(NonNull::cast::<VmMapCopyinArgs>)
    else {
        kpanic!("set_page_list_cont", "vm_map_copyin_page_list")
    };

    // SAFETY: `args` is fresh storage, and every field is written before the
    // continuation can run.
    unsafe {
        (*args.as_ptr()).map = map.as_ptr();
        (*args.as_ptr()).src_addr = src_addr;
        (*args.as_ptr()).src_len = src_len;
        (*args.as_ptr()).destroy_addr = destroy_addr;
        (*args.as_ptr()).destroy_len = destroy_len;
        (*args.as_ptr()).steal_pages = c_int::from(steal_pages);

        // SAFETY: the copy holds the live `PAGE_LIST` variant.
        let pages = VmMapCopy::page_list(copy);
        (*pages).cont_args = args.as_ptr();
        (*pages).cont = Some(vm_map_copyin_page_list_cont);
    }

    VmMap::reference(map);
}

/// `vm_map_copyin_page_list_cont()` in C.
///
/// # Safety
///
/// `cont_args` must be a live argument block created by
/// `VmMap::copyin_page_list`, and `copy_result` null (the abort call) or
/// writable storage for one copy pointer.
unsafe extern "C" fn vm_map_copyin_page_list_cont(
    cont_args: *mut VmMapCopyinArgs,
    copy_result: *mut *mut VmMapCopy,
) -> c_int {
    let args = unsafe { &*cont_args };
    let do_abort = copy_result.is_null();
    let src_destroy = args.destroy_len != 0;
    let src_destroy_only = args.src_len == 0;

    let Some(map) = NonNull::new(args.map) else {
        kpanic!("vm_map_copyin_page_list_cont", "vm_map_copyin_page_list")
    };

    let mut result = KERN_SUCCESS;

    if do_abort || src_destroy_only {
        if src_destroy {
            // SAFETY: the argument block holds the live map reference the
            // continuation was given.
            result = kern_return(unsafe {
                (*map.as_ptr()).remove(
                    args.destroy_addr,
                    args.destroy_addr.wrapping_add(args.destroy_len),
                )
            });
        }
        if !do_abort {
            unsafe { copy_result.write(ptr::null_mut()) };
        }
    } else {
        let mut returned_copy = None;
        // SAFETY: the argument block holds the live map reference the
        // continuation was given, and the map is unlocked.
        result = match unsafe {
            (*map.as_ptr()).copyin_page_list(
                args.src_addr,
                args.src_len,
                src_destroy,
                args.steal_pages != 0,
                true,
            )
        } {
            Ok(copy) => {
                unsafe {
                    copy_result
                        .write(copy.map_or(ptr::null_mut(), NonNull::as_ptr));
                };
                returned_copy = copy;
                KERN_SUCCESS
            }
            Err(error) => error.as_kern_return(),
        };

        if src_destroy && args.steal_pages == 0 {
            // Unlike the C, which faults on the null a failed inner copyin
            // leaves in the out pointer, this uses the copy just returned.
            if let Some(new_copy) = returned_copy
                // SAFETY: a successful page-list copyin yields the live
                // `PAGE_LIST` variant.
                && unsafe { (*VmMapCopy::page_list(new_copy)).cont.is_some() }
            {
                // SAFETY: the continuation of a live page-list copy is always
                // created with its argument block.
                let new_args = unsafe {
                    NonNull::new_unchecked(
                        (*VmMapCopy::page_list(new_copy)).cont_args,
                    )
                };
                // SAFETY: the new continuation's argument block is live and
                // belongs to this chain.
                unsafe {
                    (*new_args.as_ptr()).destroy_addr = args.destroy_addr;
                    (*new_args.as_ptr()).destroy_len = args.destroy_len;
                }
            }
        }
    }

    VmMap::deallocate(map);
    // SAFETY: `cont_args` came from `kalloc` in `set_page_list_cont` and is no
    // longer used.
    unsafe {
        kfree(
            NonNull::new_unchecked(cont_args.cast::<u8>()),
            size_of::<VmMapCopyinArgs>(),
        );
    };

    result
}

impl VmMap {
    /// `vm_map_copyin_page_list()` in C.
    pub(crate) fn copyin_page_list(
        &mut self,
        src_addr: VmOffset,
        len: VmSize,
        src_destroy: bool,
        steal_pages: bool,
        is_cont: bool,
    ) -> Result<Option<NonNull<VmMapCopy>>, Error> {
        if len == 0 {
            return Ok(None);
        }

        if src_addr.wrapping_add(len) <= src_addr {
            return Err(Error::InvalidAddress);
        }

        let src_start = trunc_page(src_addr);
        let src_end = round_page(src_addr.wrapping_add(len));

        if src_end == 0 {
            return Err(Error::InvalidAddress);
        }

        // SAFETY: `vm_map_init()` initialized the copy cache before any map
        // exists.
        let copy = unsafe { VmMapCopy::new_page_list(src_addr, len) };
        // SAFETY: the copy holds the live `PAGE_LIST` variant.
        let pages = unsafe { VmMapCopy::page_list(copy) };

        let map = NonNull::from(&mut *self);
        let sentinel = self.to_entry();
        let mut state = PageListState {
            src_addr,
            len,
            src_start,
            src_end,
            src_size: 0,
            src_entry: sentinel,
            need_map_lookup: false,
        };

        // SAFETY: `copy` holds the live page-list variant and the map is
        // valid and unlocked.
        Self::copyin_page_gather(
            map,
            copy,
            pages,
            &mut state,
            src_destroy,
            steal_pages,
            is_cont,
        )?;

        // SAFETY: `copy` holds the live page-list variant and the map is valid
        // and unlocked; the gather leaves the map locked and the state
        // describing the range it consumed.
        self.copyin_page_steal(
            map,
            copy,
            pages,
            &mut state,
            src_destroy,
            steal_pages,
        );

        Self::unlock(map);

        Ok(Some(copy))
    }

    /// The gather loop of `copyin_page_list()`: look up each source entry and
    /// collect its pages into the copy.
    ///
    /// # Safety
    ///
    /// `copy` must hold the live page-list variant and the map must be valid
    /// and unlocked.
    fn copyin_page_gather(
        map: NonNull<Self>,
        copy: NonNull<VmMapCopy>,
        pages: *mut VmMapCopyPageList,
        state: &mut PageListState,
        src_destroy: bool,
        steal_pages: bool,
        is_cont: bool,
    ) -> Result<(), Error> {
        loop {
            Self::lock(map);
            // SAFETY: the map was just locked.
            let this = unsafe { &mut *map.as_ptr() };

            let (found, entry) = this.lookup_entry(state.src_start);
            if !found {
                Self::unlock(map);
                // SAFETY: the copy is live and owned by this call.
                unsafe { VmMapCopy::discard(copy) };
                return Err(Error::InvalidAddress);
            }
            state.src_entry = entry;
            state.need_map_lookup = false;

            if matches!(
                Self::copyin_page_entry(
                    map,
                    copy,
                    pages,
                    state,
                    src_destroy,
                    steal_pages,
                    is_cont,
                )?,
                PageEntryStep::Done
            ) {
                break;
            }
        }

        Ok(())
    }

    /// The per-entry loop of `copyin_page_list()`: gather one entry's pages,
    /// following the range into the next entry.
    fn copyin_page_entry(
        map: NonNull<Self>,
        copy: NonNull<VmMapCopy>,
        pages: *mut VmMapCopyPageList,
        state: &mut PageListState,
        src_destroy: bool,
        steal_pages: bool,
        is_cont: bool,
    ) -> Result<PageEntryStep, Error> {
        // SAFETY: the map is valid and locked whenever this runs.
        let this = unsafe { &mut *map.as_ptr() };
        let sentinel = this.to_entry();

        loop {
            // SAFETY: `state.src_entry` is a live entry of the locked map.
            let (protection, entry_start, entry_end, entry_object) = unsafe {
                let e = &*state.src_entry.as_ptr();
                (e.protection, e.links.start, e.links.end, e.object.vm_object)
            };

            if !protection.contains(VmProt::READ) {
                Self::unlock(map);
                // SAFETY: the copy is live and owned by this call.
                unsafe { VmMapCopy::discard(copy) };
                return Err(Error::ProtectionFailure);
            }

            if state.src_end > entry_end {
                state.src_size = entry_end.wrapping_sub(state.src_start);
            } else {
                state.src_size = state.src_end.wrapping_sub(state.src_start);
            }

            let mut src_object = entry_object;
            if src_object.is_null() {
                // SAFETY: the object allocator is initialized.
                src_object = unsafe {
                    vm_object_allocate(entry_end.wrapping_sub(entry_start))
                };
                // SAFETY: the entry is live and the map is locked.
                unsafe {
                    (*state.src_entry.as_ptr()).object.vm_object = src_object;
                };
            }

            let make_continuation = Self::copyin_page_pages(
                map,
                copy,
                pages,
                state,
                src_object,
                src_destroy,
                is_cont,
            )?;

            if make_continuation {
                Self::copyin_page_cont(
                    map,
                    copy,
                    state,
                    src_destroy,
                    steal_pages,
                );
            }

            if state.src_start >= state.src_end && state.src_end != 0 {
                if state.need_map_lookup {
                    Self::lock(map);
                }
                return Ok(PageEntryStep::Done);
            }
            if state.need_map_lookup {
                return Ok(PageEntryStep::Lookup);
            }

            state.src_start = entry_end;
            // SAFETY: `state.src_entry` is live and the map is locked; its
            // next link is live or the sentinel.
            state.src_entry =
                unsafe { (*state.src_entry.as_ptr()).links.next }
                    .unwrap_or(sentinel);
            // SAFETY: `state.src_entry` is live or the sentinel.
            if unsafe { (*state.src_entry.as_ptr()).links.start }
                != state.src_start
            {
                Self::unlock(map);
                // SAFETY: the copy is live and owned by this call.
                unsafe { VmMapCopy::discard(copy) };
                return Err(Error::InvalidAddress);
            }
        }
    }

    /// The page loop of `copyin_page_entry()`: gather the pages of one
    /// object range.  Returns whether the list filled up on a continuation.
    fn copyin_page_pages(
        map: NonNull<Self>,
        copy: NonNull<VmMapCopy>,
        pages: *mut VmMapCopyPageList,
        state: &mut PageListState,
        src_object: *mut VmObject,
        src_destroy: bool,
        is_cont: bool,
    ) -> Result<bool, Error> {
        // SAFETY: `state.src_entry` is a live entry of the locked map.
        let (protection, entry_start, entry_offset) = unsafe {
            let e = &*state.src_entry.as_ptr();
            (e.protection, e.links.start, e.offset)
        };
        let mut src_offset = entry_offset
            .wrapping_add(state.src_start.wrapping_sub(entry_start));
        let src_last_offset = src_offset.wrapping_add(state.src_size);
        let mut make_continuation = false;

        while src_offset < src_last_offset && !state.need_map_lookup {
            // SAFETY: `pages` names the live variant.
            let npages = unsafe { (*pages).npages };
            let index = usize::try_from(npages).unwrap_or(0);
            if index == VM_MAP_COPY_PAGE_LIST_MAX {
                make_continuation = true;
                break;
            }

            // SAFETY: the object lock and the paging reference serialise the
            // page's state; the map is locked.
            unsafe {
                (*src_object).lock.lock();
                vm_object::paging_begin(src_object);
            }
            // SAFETY: the object lock is held, as `vm_resident::lookup`
            // requires.
            let mut m = unsafe {
                vm_resident::lookup(
                    NonNull::new_unchecked(src_object),
                    src_offset,
                )
            }
            .map_or(ptr::null_mut(), NonNull::as_ptr);
            // SAFETY: a non-null page came from the object just locked; its
            // bits are read under that lock.
            if !unsafe {
                Self::copyin_page_present(
                    src_object,
                    m,
                    protection,
                    src_destroy,
                )
            } {
                let got = Self::copyin_page_fault(
                    map, copy, pages, state, src_object, src_offset, is_cont,
                );
                match got? {
                    PageFaultStep::Got(page) => m = page,
                    PageFaultStep::Continuation => {
                        make_continuation = true;
                        break;
                    }
                }
            }

            // SAFETY: `pages` names the live variant, and the count is below
            // the array's length.
            unsafe {
                (*pages).page_list[index] = m;
                (*pages).npages = (*pages).npages.wrapping_add(1);
                // SAFETY: the page's object is the one left locked for it, as
                // the C `m->object` is.
                (*(*m).object).lock.unlock();
            }

            src_offset = src_offset.wrapping_add(PAGE_SIZE);
            state.src_start = state.src_start.wrapping_add(PAGE_SIZE);
        }

        Ok(make_continuation)
    }

    /// Try to claim the resident page `m` of `copyin_page_list()`'s current
    /// object, applying the page protection the copy needs.
    ///
    /// # Safety
    ///
    /// The object lock must be held and `m` must be the page the lookup
    /// found.
    unsafe fn copyin_page_present(
        src_object: *mut VmObject,
        m: *mut VmPage,
        protection: VmProt,
        src_destroy: bool,
    ) -> bool {
        // SAFETY: a non-null page came from the object just locked; its bits
        // are read under that lock.
        if m.is_null()
            || unsafe { (*m).is_busy() }
            || unsafe { (*m).is_fictitious() }
            || unsafe { (*m).is_absent() }
            || unsafe { (*m).is_error() }
        {
            return false;
        }

        // SAFETY: the object lock is held; setting the busy bit is the C's
        // own lock discipline.
        unsafe { (*m).set_busy(true) };

        if !src_destroy
            || unsafe {
                // SAFETY: `src_object` is live and locked; its shared-copy
                // bit is read.
                (*src_object).use_shared_copy()
            }
        {
            // SAFETY: `m` is live and its object is locked; the mask keeps
            // the page's `page_lock` and write bits clear.
            unsafe {
                pmap_page_protect(
                    (*m).phys_addr,
                    (protection & !(*m).page_lock() & !VmProt::WRITE).bits(),
                );
            };
        }

        true
    }

    /// Take a page-list continuation at the current source position, the
    /// `VM_MAP_COPY_PAGE_LIST_MAX` boundary of `copyin_page_entry()`.
    fn copyin_page_cont(
        map: NonNull<Self>,
        copy: NonNull<VmMapCopy>,
        state: &mut PageListState,
        src_destroy: bool,
        steal_pages: bool,
    ) {
        let rest = state
            .len
            .wrapping_sub(state.src_start.wrapping_sub(state.src_addr));
        set_page_list_cont(
            map,
            copy,
            state.src_start,
            rest,
            if src_destroy { state.src_start } else { 0 },
            if src_destroy { rest } else { 0 },
            steal_pages,
        );
        state.src_end = state.src_start;
        // SAFETY: the map is valid and locked.
        let this = unsafe { &mut *map.as_ptr() };
        // SAFETY: `state.src_entry` is live and the map is locked; this is
        // the guarded `vm_map_clip_end()`.
        unsafe { this.hdr.clip_end_at(state.src_entry, state.src_end, true) };
    }

    /// Fault one page of `copyin_page_list()` in, handling the fault
    /// routine's retry statuses.
    fn copyin_page_fault(
        map: NonNull<Self>,
        copy: NonNull<VmMapCopy>,
        pages: *mut VmMapCopyPageList,
        state: &mut PageListState,
        src_object: *mut VmObject,
        src_offset: VmOffset,
        is_cont: bool,
    ) -> Result<PageFaultStep, Error> {
        // SAFETY: the map is valid and locked whenever this runs.
        let this = unsafe { &mut *map.as_ptr() };
        Self::unlock(map);
        state.need_map_lookup = true;

        loop {
            // SAFETY: `src_object` is live and holds the lock and paging
            // reference the fault consumes.
            let fault = unsafe {
                vm_fault::fault_page(
                    src_object,
                    src_offset,
                    VmProt::READ,
                    false,
                    false,
                    VmProt::READ,
                    false,
                    None,
                )
            };

            if fault.result == VM_FAULT_SUCCESS {
                if !fault.top_page.is_null() {
                    // SAFETY: the fault returned a top page holding a paging
                    // reference on `src_object`; free it and drop both.
                    unsafe {
                        (*src_object).lock.lock();
                        (*addr_of_mut!(VM_PAGE_QUEUE_LOCK)).lock();
                        vm_resident::free(NonNull::new_unchecked(
                            fault.top_page,
                        ));
                        (*addr_of_mut!(VM_PAGE_QUEUE_LOCK)).unlock();
                        vm_object::paging_end(src_object);
                        (*src_object).lock.unlock();
                    }
                }
                return Ok(PageFaultStep::Got(fault.result_page));
            }

            match fault.result {
                VM_FAULT_INTERRUPTED | VM_FAULT_RETRY => {
                    // SAFETY: the fault consumed the lock and paging
                    // reference; take them again before retrying.
                    unsafe {
                        (*src_object).lock.lock();
                        vm_object::paging_begin(src_object);
                    }
                }
                VM_FAULT_MEMORY_SHORTAGE => {
                    // SAFETY: `vm_page_wait` owns the page queues.
                    unsafe { vm_page::wait(None) };
                    // SAFETY: `vm_page_wait` owns the page queues.
                    unsafe {
                        (*src_object).lock.lock();
                        vm_object::paging_begin(src_object);
                    }
                }
                VM_FAULT_FICTITIOUS_SHORTAGE => {
                    // SAFETY: the page allocator owns its fictitious supply.
                    unsafe { vm_resident::more_fictitious() };
                    // SAFETY: the page allocator owns its fictitious supply.
                    unsafe {
                        (*src_object).lock.lock();
                        vm_object::paging_begin(src_object);
                    }
                }
                VM_FAULT_MEMORY_ERROR => {
                    Self::lock(map);
                    state.need_map_lookup = false;
                    // SAFETY: `pages` names the live variant.
                    if is_cont
                        // SAFETY: `pages` names the live variant; `pages`
                        // still names the live variant.
                        && unsafe { (*pages).npages } != 0
                    {
                        let (found, entry) =
                            this.lookup_entry(state.src_start);
                        if !found {
                            Self::unlock(map);
                            // SAFETY: the copy is live and owned by this
                            // call.
                            unsafe { VmMapCopy::discard(copy) };
                            return Err(Error::InvalidAddress);
                        }
                        state.src_entry = entry;
                        // SAFETY: `state.src_entry` is a live entry of the
                        // locked map.
                        let entry_end =
                            unsafe { (*state.src_entry.as_ptr()).links.end };
                        state.src_size = if state.src_end > entry_end {
                            entry_end.wrapping_sub(state.src_start)
                        } else {
                            state.src_end.wrapping_sub(state.src_start)
                        };
                        return Ok(PageFaultStep::Continuation);
                    }
                    Self::unlock(map);
                    // SAFETY: the copy is live and owned by this call.
                    unsafe { VmMapCopy::discard(copy) };
                    return Err(Error::MemoryError);
                }
                _ => {}
            }
        }
    }

    /// The steal phase of `copyin_page_list()`: hand each gathered page to
    /// the copy and optionally destroy the source range.
    fn copyin_page_steal(
        &mut self,
        map: NonNull<Self>,
        copy: NonNull<VmMapCopy>,
        pages: *mut VmMapCopyPageList,
        state: &mut PageListState,
        src_destroy: bool,
        steal_pages: bool,
    ) {
        state.src_start = trunc_page(state.src_addr);
        if steal_pages {
            let mut unwire_end = state.src_start;
            // SAFETY: `pages` names the live variant.
            let npages =
                usize::try_from(unsafe { (*pages).npages }).unwrap_or(0);
            let mut i = 0;
            while i < npages {
                // SAFETY: `i` is below the count, which the copy keeps at
                // most `VM_MAP_COPY_PAGE_LIST_MAX`.
                let m = unsafe { (*pages).page_list[i] };
                // SAFETY: the copy holds a paging reference on the page's
                // object.
                let src_object = unsafe { (*m).object };
                // SAFETY: the page belongs to a live object; the lock
                // serialises its state.
                unsafe { (*src_object).lock.lock() };

                // SAFETY: `src_object` is locked and `m` is live.
                if src_destroy
                    // SAFETY: `src_object` is locked and `m` is live.
                    && unsafe { (*src_object).is_temporary() }
                    // SAFETY: `src_object` is locked and `m` is live.
                    && !unsafe { (*src_object).is_shadowed() }
                    // SAFETY: `src_object` is locked and `m` is live.
                    && !unsafe { (*src_object).use_shared_copy() }
                    // SAFETY: `src_object` is locked and `m` is live.
                    && !unsafe { (*m).is_precious() }
                {
                    let page_vaddr = state
                        .src_start
                        .wrapping_add(i.wrapping_mul(PAGE_SIZE));
                    // SAFETY: the object lock is held; the wire count is
                    // read under it.
                    if unsafe { (*m).wire_count() } > 0 {
                        // SAFETY: the object lock is dropped for the map
                        // operations the C performs here.
                        unsafe { (*src_object).lock.unlock() };
                        if page_vaddr >= unwire_end {
                            // SAFETY: the map is locked and holds the wired
                            // entry.
                            let (found, entry) = self.lookup_entry(page_vaddr);
                            if !found {
                                kpanic!(
                                    "VmMap::copyin_page_list",
                                    "vm_map_copyin_page_list: missing wired map entry"
                                )
                            }
                            let src_entry = entry;
                            // SAFETY: `src_entry` contains `page_vaddr` and
                            // the map is locked; the guarded
                            // `vm_map_clip_start()`.
                            unsafe {
                                self.hdr.clip_start_at(
                                    src_entry, page_vaddr, true,
                                );
                            };
                            // SAFETY: `src_entry` is live and the map is
                            // locked; the guarded `vm_map_clip_end()` the C
                            // performs.
                            unsafe {
                                self.hdr.clip_end_at(
                                    src_entry,
                                    state
                                        .src_start
                                        .wrapping_add(state.src_size),
                                    true,
                                );
                            };
                            self.entry_reset_wired(src_entry);
                            // SAFETY: the entry is live under the map lock.
                            unwire_end =
                                unsafe { (*src_entry.as_ptr()).links.end };
                            pmap_pageable(
                                self.pmap, page_vaddr, unwire_end, 1,
                            );
                        }
                        // SAFETY: the page's object is live; relock it as
                        // the C does.
                        unsafe { (*src_object).lock.lock() };
                    }

                    // SAFETY: the page queue and object locks order the
                    // page's state, exactly as the C block does.
                    unsafe { page_steal(m) };
                } else {
                    // SAFETY: the object lock was taken above.
                    unsafe { (*src_object).lock.unlock() };
                    Self::unlock(map);
                    // SAFETY: the copy is a live page-list copy the caller
                    // owns.
                    unsafe { VmMapCopy::steal_pages(copy) };
                    Self::lock(map);
                    break;
                }

                // SAFETY: the page holds a paging reference on the object
                // and the object lock is held.
                unsafe {
                    vm_object::paging_end(src_object);
                    (*src_object).lock.unlock();
                }
                i += 1;
            }

            if src_destroy {
                self.delete(state.src_start, state.src_end);
            }
        } else if src_destroy {
            // SAFETY: `pages` names the live variant.
            let has_cont = unsafe { (*pages).cont.is_some() };
            if !has_cont {
                set_page_list_cont(
                    map,
                    copy,
                    0,
                    0,
                    state.src_start,
                    state.src_end.wrapping_sub(state.src_start),
                    false,
                );
            }
        }
    }
}

/// `vm_map_copyin_page_list()` in C.
///
/// # Safety
///
/// `src_map` must point at a valid, unlocked map and `copy_result` at writable
/// storage for one copy pointer.
pub(crate) unsafe fn vm_map_copyin_page_list(
    src_map: *mut VmMap,
    src_addr: VmOffset,
    len: VmSize,
    src_destroy: c_int,
    steal_pages: c_int,
    copy_result: *mut *mut VmMapCopy,
    is_cont: c_int,
) -> c_int {
    let map = unsafe { &mut *src_map };
    match map.copyin_page_list(
        src_addr,
        len,
        src_destroy != 0,
        steal_pages != 0,
        is_cont != 0,
    ) {
        Ok(copy) => {
            unsafe {
                copy_result
                    .write(copy.map_or(ptr::null_mut(), NonNull::as_ptr));
            };
            KERN_SUCCESS
        }
        Err(error) => error.as_kern_return(),
    }
}

impl VmMap {
    /// `vm_map_copyout()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must be a live copy the caller owns, and the map must be valid
    /// and unlocked.
    pub(crate) unsafe fn copyout(
        &mut self,
        copy: NonNull<VmMapCopy>,
    ) -> Result<VmOffset, Error> {
        match unsafe { (*copy.as_ptr()).type_ } {
            VM_MAP_COPY_OBJECT => unsafe { self.copyout_object(copy) },
            VM_MAP_COPY_PAGE_LIST => unsafe { self.copyout_page_list(copy) },
            // SAFETY: the C treats every other type as an entry list, and the
            // caller promises a live copy.
            _ => unsafe { self.copyout_entry_list(copy) },
        }
    }

    /// The `VM_MAP_COPY_OBJECT` arm of `vm_map_copyout()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must be a live `OBJECT` copy the caller owns.
    unsafe fn copyout_object(
        &mut self,
        copy: NonNull<VmMapCopy>,
    ) -> Result<VmOffset, Error> {
        let (object, offset, size) = unsafe {
            (
                *VmMapCopy::object(copy),
                (*copy.as_ptr()).offset,
                (*copy.as_ptr()).size,
            )
        };

        let mut address: VmOffset = 0;
        let result = self.enter(EnterRequest {
            address: &mut address,
            size,
            mask: 0,
            anywhere: true,
            object,
            offset,
            needs_copy: false,
            cur_protection: VmProt::READ | VmProt::WRITE,
            max_protection: VmProt::ALL,
            inheritance: VmInherit::COPY,
        });
        if result.is_ok() {
            // SAFETY: the copy is live and consumed; the object reference
            // moved to the new entry.
            unsafe { VmMapCopy::free(copy) };
        }
        result.map(|()| address)
    }

    /// The fall-through of `vm_map_copyout()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must be a live entry-list copy the caller owns, and the map must
    /// be valid and unlocked.
    unsafe fn copyout_entry_list(
        &mut self,
        copy: NonNull<VmMapCopy>,
    ) -> Result<VmOffset, Error> {
        let (copy_offset, copy_size) =
            unsafe { ((*copy.as_ptr()).offset, (*copy.as_ptr()).size) };
        let vm_copy_start = trunc_page(copy_offset);
        let size = round_page(copy_offset.wrapping_add(copy_size))
            .wrapping_sub(vm_copy_start);

        let map = NonNull::from(&mut *self);
        let Some((last, start)) = self.find_entry_anywhere(size, 0, false)
        else {
            Self::unlock(map);
            return Err(Error::NoSpace);
        };

        if let Err(error) = self.enforce_limit(size) {
            Self::unlock(map);
            return Err(error);
        }

        let sentinel: NonNull<VmMapEntry> =
            unsafe { VmMapCopy::header(copy) }.cast();
        let last_copy_entry = unsafe { VmMapCopy::last_entry(copy) };

        let adjustment = start.wrapping_sub(vm_copy_start);
        // SAFETY: the copy is live and owned by the caller.
        let mut entry = unsafe { VmMapCopy::first_entry(copy) };
        while entry != sentinel {
            // SAFETY: `entry` is a live entry of the copy, which the caller
            // owns exclusively.
            unsafe {
                let e = entry.as_ptr();
                let entry_start = (*e).links.start.wrapping_add(adjustment);
                let entry_end = (*e).links.end.wrapping_add(adjustment);
                (*e).links.start = entry_start;
                (*e).links.end = entry_end;

                (*e).inheritance = VmInherit::COPY;
                (*e).protection = VmProt::READ | VmProt::WRITE;
                (*e).max_protection = VmProt::ALL;
                (*e).projected_on = ptr::null_mut();

                if (*e).wired_count != 0 {
                    let object = (*e).object.vm_object;
                    let mut offset = (*e).offset;
                    let mut va = entry_start;

                    pmap_pageable(self.pmap, entry_start, entry_end, 1);

                    while va < entry_end {
                        (*object).lock.lock();
                        vm_object::paging_begin(object);

                        // SAFETY: the object lock is held; a wired entry's
                        // pages are in the top object, as the C asserts by
                        // panicking otherwise.
                        let page = vm_resident::lookup(
                            NonNull::new_unchecked(object),
                            offset,
                        )
                        .map_or(ptr::null_mut(), NonNull::as_ptr);
                        if page.is_null()
                            || (*page).wire_count() == 0
                            || (*page).is_absent()
                        {
                            kpanic!(
                                "VmMap::copyout_entry_list",
                                "vm_map_copyout: wiring {:x}",
                                page.expose_provenance()
                            );
                        }

                        (*page).set_busy(true);
                        (*object).lock.unlock();

                        pmap_enter(
                            NonNull::new(self.pmap),
                            va,
                            (*page).phys_addr,
                            ((*e).protection & !(*page).page_lock()).bits(),
                            1,
                        );

                        (*object).lock.lock();
                        vm_object::page_wakeup_done(page);
                        vm_object::paging_end(object);
                        (*object).lock.unlock();

                        offset = offset.wrapping_add(PAGE_SIZE);
                        va = va.wrapping_add(PAGE_SIZE);
                    }
                }

                entry = (*e).links.next.unwrap_or(sentinel);
            }
        }

        let dst_addr =
            start.wrapping_add(copy_offset.wrapping_sub(vm_copy_start));

        if self.first_free == last.as_ptr() {
            self.first_free = last_copy_entry.as_ptr();
        }
        self.save_hint(last_copy_entry);
        self.size = self.size.wrapping_add(size);

        // SAFETY: the map is locked, `last` is a live entry of it, and the
        // copy is live and owned.
        unsafe { self.copy_insert(last, copy) };

        if self.wiring_required() {
            let result = self.pageable(
                start,
                start.wrapping_add(size),
                VmProt::READ | VmProt::WRITE,
                false,
                false,
            );
            if let Err(error) = result {
                Self::unlock(map);
                return Err(error);
            }
        }

        Self::unlock(map);
        Ok(dst_addr)
    }

    /// `vm_map_copyout_page_list()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must be a live page-list copy the caller owns, with at least one
    /// page and at most `VM_MAP_COPY_PAGE_LIST_MAX` of them, and the map must
    /// be valid and unlocked.
    pub(crate) unsafe fn copyout_page_list(
        &mut self,
        copy: NonNull<VmMapCopy>,
    ) -> Result<VmOffset, Error> {
        let first_page = unsafe { (*VmMapCopy::page_list(copy)).page_list[0] };
        // SAFETY: a tabled page belongs to a live object the copy holds a
        // paging reference on.
        if unsafe { (*first_page).is_tabled() } {
            unsafe { VmMapCopy::steal_pages(copy) };
        }

        let (copy_offset, copy_size) =
            unsafe { ((*copy.as_ptr()).offset, (*copy.as_ptr()).size) };
        let size = round_page(copy_offset.wrapping_add(copy_size))
            .wrapping_sub(trunc_page(copy_offset));

        let map = NonNull::from(&mut *self);
        Self::lock(map);

        let Some((last, start)) = self.find_entry_anywhere(size, 0, true)
        else {
            Self::unlock(map);
            return Err(Error::NoSpace);
        };

        if let Err(error) = self.enforce_limit(size) {
            Self::unlock(map);
            return Err(error);
        }

        let end = start.wrapping_add(size);
        let must_wire = self.wiring_required();

        let (object, last) =
            self.copyout_page_setup(last, start, end, size, must_wire);

        let PageDrain {
            dst_addr,
            current,
            cont_invoked,
            error,
        } = unsafe {
            Self::copyout_page_drain(
                map, copy, object, last, start, size, must_wire,
            )
        };
        let result = error.map_or(Ok(()), Err);

        let mut needs_wakeup = false;
        if cont_invoked {
            let (found, mut entry) = self.lookup_entry(start);
            if !found {
                kpanic!(
                    "VmMap::copyout_page_list",
                    "vm_map_copyout_page_list: missing entry"
                );
            }
            let sentinel = self.to_entry();
            while entry != sentinel
                // SAFETY: `entry` is a live entry of the locked map.
                && unsafe { (*entry.as_ptr()).links.start } < end
            {
                // SAFETY: `entry` is a live entry of the locked map.
                unsafe {
                    (*entry.as_ptr()).set_in_transition(false);
                    if (*entry.as_ptr()).needs_wakeup() {
                        (*entry.as_ptr()).set_needs_wakeup(false);
                        needs_wakeup = true;
                    }
                    entry = (*entry.as_ptr()).links.next.unwrap_or(sentinel);
                }
            }
        } else {
            // SAFETY: `last` is a live entry of the locked map.
            unsafe { (*last.as_ptr()).set_in_transition(false) };
        }

        if result.is_err() {
            self.delete(start, end);
        }

        Self::unlock(map);

        if needs_wakeup {
            // SAFETY: the map is unlocked; the wakeup event is the map header,
            // as the C `vm_map_entry_wakeup()` uses.
            unsafe {
                thread_wakeup_prim(
                    addr_of_mut!((*map.as_ptr()).hdr).cast::<c_void>(),
                    0,
                    THREAD_AWAKENED,
                )
            };
        }

        if let Some(current_copy) = current
            && current != Some(copy)
        {
            // SAFETY: the last continuation copy is live and owned.
            unsafe { VmMapCopy::free(current_copy) };
        }
        if result.is_ok() {
            // SAFETY: the original copy is live and owned.
            unsafe { VmMapCopy::free(copy) };
        }

        result.map(|()| dst_addr.unwrap_or(0))
    }

    /// The destination setup of `copyout_page_list()`: extend the entry
    /// before `start`, or create a fresh one, and lock the destination
    /// object.  Returns the object and the entry the pages go into.
    fn copyout_page_setup(
        &mut self,
        last: NonNull<VmMapEntry>,
        start: VmOffset,
        end: VmOffset,
        size: VmSize,
        must_wire: bool,
    ) -> (*mut VmObject, NonNull<VmMapEntry>) {
        let can_extend = !self.hdr.is_sentinel(last)
            // SAFETY: `last` is live or the sentinel under the map lock.
            && unsafe {
                let before = &*last.as_ptr();
                before.links.end == start
                    && !before.is_shared()
                    && !before.is_sub_map()
                    && before.inheritance == VmInherit::COPY
                    && before.protection == VmProt::READ | VmProt::WRITE
                    && before.max_protection == VmProt::ALL
                    && !before.in_transition()
                    && if must_wire {
                        before.wired_count != 0
                    } else {
                        before.wired_count == 0
                    }
            };

        let mut object: *mut VmObject = ptr::null_mut();
        let mut extended = false;
        if can_extend {
            (object, extended) = Self::copyout_page_extend(last, start, size);
        }

        if extended {
            self.size = self.size.wrapping_add(size);
            // SAFETY: `last` is live and the map is locked.
            unsafe { (*last.as_ptr()).links.end = end };
            self.hdr.gap_update(last);
            self.save_hint(last);
            (object, last)
        } else {
            // SAFETY: the object allocator is initialized.
            object = unsafe { vm_object_allocate(size) };
            // SAFETY: the entry cache is initialized.
            let entry = unsafe { VmMapEntry::create() };
            // SAFETY: `entry` is freshly allocated and unlinked; every field
            // is written before it is linked, and the map is locked.
            unsafe {
                let e = entry.as_ptr();
                (*e).object.vm_object = object;
                (*e).offset = 0;
                (*e).set_shared(false);
                (*e).set_sub_map(false);
                (*e).set_needs_copy(false);
                (*e).wired_count = 0;
                if must_wire {
                    self.entry_inc_wired(entry);
                    (*e).wired_access = VmProt::READ | VmProt::WRITE;
                } else {
                    (*e).wired_access = VmProt::NONE;
                }
                (*e).set_in_transition(true);
                (*e).set_needs_wakeup(false);
                (*e).links.start = start;
                (*e).links.end = end;
                (*e).inheritance = VmInherit::COPY;
                (*e).protection = VmProt::READ | VmProt::WRITE;
                (*e).max_protection = VmProt::ALL;
                (*e).projected_on = ptr::null_mut();

                (*object).lock.lock();

                if self.first_free == last.as_ptr() {
                    self.first_free = e;
                }
                self.save_hint(entry);
                self.size = self.size.wrapping_add(size);

                self.hdr.entry_link(last, entry, true);
            }
            (object, entry)
        }
    }

    /// The extend arm of `copyout_page_setup()`: reuse the entry before
    /// `start` and grow its object, or report that a fresh entry is needed.
    fn copyout_page_extend(
        last: NonNull<VmMapEntry>,
        start: VmOffset,
        size: VmSize,
    ) -> (*mut VmObject, bool) {
        // SAFETY: `last` is a live entry of the locked map.
        let last_object = unsafe { (*last.as_ptr()).object.vm_object };
        if last_object.is_null() {
            // SAFETY: `last` is a live entry of the locked map.
            let entry_size = unsafe {
                (*last.as_ptr())
                    .links
                    .end
                    .wrapping_sub((*last.as_ptr()).links.start)
            };
            // SAFETY: the object allocator is initialized.
            let object =
                unsafe { vm_object_allocate(entry_size.wrapping_add(size)) };
            // SAFETY: `last` is live, the map is locked, and the object lock
            // is taken for the page insertion that follows.
            unsafe {
                (*last.as_ptr()).object.vm_object = object;
                (*last.as_ptr()).offset = 0;
                (*object).lock.lock();
            }
            (object, true)
        } else {
            // SAFETY: `last` is a live entry of the locked map.
            let prev_offset = unsafe { (*last.as_ptr()).offset };
            // SAFETY: `last` is a live entry of the locked map.
            let prev_size =
                start.wrapping_sub(unsafe { (*last.as_ptr()).links.start });
            let object = last_object;
            // SAFETY: the object is live; the lock is taken before the
            // collapse probe.
            unsafe {
                (*object).lock.lock();
                vm_object::collapse(object);
            }
            // SAFETY: the object lock is held.
            if unsafe { (*object).can_coalesce() } {
                let new_size =
                    prev_offset.wrapping_add(prev_size).wrapping_add(size);
                // SAFETY: the object is live and locked.
                unsafe { (*object).extend_size(new_size) };
                (object, true)
            } else {
                // SAFETY: the object lock was taken above.
                unsafe { (*object).lock.unlock() };
                (object, false)
            }
        }
    }

    /// Drain the copy's page list into the destination object, invoking the
    /// continuation chain at each boundary.  Runs with the map, object and
    /// page queue locks held.
    ///
    /// # Safety
    ///
    /// The map must be locked and own `last`; `object` must be the live
    /// destination object with its lock held, and `copy` the live page-list
    /// copy the caller owns.
    unsafe fn copyout_page_drain(
        map: NonNull<Self>,
        copy: NonNull<VmMapCopy>,
        object: *mut VmObject,
        last: NonNull<VmMapEntry>,
        start: VmOffset,
        size: VmSize,
        must_wire: bool,
    ) -> PageDrain {
        let dst_offset = unsafe { (*copy.as_ptr()).offset } & PAGE_MASK;
        let mut cont_invoked = false;
        let orig_copy = copy;
        let mut current = Some(copy);
        let mut pages = unsafe { VmMapCopy::page_list(copy) };
        let mut page_index = 0usize;

        // SAFETY: `last` is live and the map is locked.
        unsafe { (*last.as_ptr()).set_in_transition(true) };
        // SAFETY: `last` is a live entry of the locked map.
        let old_last_offset = unsafe { (*last.as_ptr()).offset }.wrapping_add(
            start.wrapping_sub(unsafe { (*last.as_ptr()).links.start }),
        );

        // SAFETY: the page queue lock orders the page state, and the object
        // lock is held from the extension or creation above.
        unsafe { (*addr_of_mut!(VM_PAGE_QUEUE_LOCK)).lock() };

        let mut dst_addr: Option<VmOffset> = None;
        let result: Result<(), Error>;
        'pages: {
            let mut offset = 0;
            while offset < size {
                let Some(current_copy) = current else {
                    kpanic!("VmMap::copyout_page_list", "missing page copy")
                };

                let m = unsafe { (*pages).page_list[page_index] };

                // SAFETY: `m` is a live page of the copy and the page queue
                // lock is held.
                unsafe {
                    (*m).set_busy(false);
                    (*m).set_dirty(true);
                    vm_resident::replace(
                        NonNull::new_unchecked(m),
                        NonNull::new_unchecked(object),
                        old_last_offset.wrapping_add(offset),
                    );
                }

                // SAFETY: the map and page-queue locks are held and `m` is
                // live.
                unsafe {
                    Self::copyout_page_enter(map, m, last, must_wire);
                }

                // SAFETY: the slot holds a page the copy owns; the copy's
                // count is decremented next.
                unsafe { (*pages).page_list[page_index] = ptr::null_mut() };
                page_index += 1;
                // SAFETY: the count was positive, so the C's prefix decrement
                // is this wrapping subtraction.
                let npages = unsafe { (*pages).npages.wrapping_sub(1) };
                // SAFETY: `pages` names the live variant.
                unsafe { (*pages).npages = npages };

                if npages == 0 && unsafe { (*pages).cont.is_some() } {
                    cont_invoked = true;

                    // SAFETY: the map, object and page queue locks were taken
                    // above; the C drops all three around the continuation
                    // call.
                    unsafe {
                        (*addr_of_mut!(VM_PAGE_QUEUE_LOCK)).unlock();
                        (*object).lock.unlock();
                    }
                    Self::unlock(map);

                    // SAFETY: `current_copy` is the live copy whose pages were
                    // just drained and whose continuation supplies the next
                    // one.
                    let (cont_result, new_copy) =
                        unsafe { VmMapCopy::invoke_cont(current_copy) };

                    if cont_result != KERN_SUCCESS {
                        result = error_from_kern_return(cont_result);
                        Self::lock(map);
                        break 'pages;
                    }

                    if current != Some(orig_copy) {
                        // SAFETY: the previous continuation copy is live and
                        // this call owns it.
                        unsafe { VmMapCopy::discard(current_copy) };
                    }

                    current = NonNull::new(new_copy);
                    if let Some(new_copy) = current {
                        // SAFETY: the continuation's copy holds the live
                        // page-list variant, with at least one page.
                        pages = unsafe { VmMapCopy::page_list(new_copy) };
                        page_index = 0;
                        // SAFETY: `pages` names the live variant.
                        let first = unsafe { (*pages).page_list[0] };
                        // SAFETY: `first` is the live page the variant holds.
                        if unsafe { (*first).is_tabled() } {
                            unsafe { VmMapCopy::steal_pages(new_copy) };
                        }
                    }

                    // SAFETY: the C retakes the map, object and page queue
                    // locks in that order.
                    Self::lock(map);
                    // SAFETY: `object` is live and the page-queues lock is
                    // the live lock.
                    unsafe {
                        (*object).lock.lock();
                        (*addr_of_mut!(VM_PAGE_QUEUE_LOCK)).lock();
                    }
                }

                offset = offset.wrapping_add(PAGE_SIZE);
            }

            // SAFETY: the page queue and object locks were taken before the
            // loop and the C releases them here.
            unsafe {
                (*addr_of_mut!(VM_PAGE_QUEUE_LOCK)).unlock();
                (*object).lock.unlock();
            }

            dst_addr = Some(start.wrapping_add(dst_offset));
            result = Ok(());
        }

        PageDrain {
            dst_addr,
            current,
            cont_invoked,
            error: result.err(),
        }
    }

    /// Insert the drained page `m` into the destination entry's object,
    /// wiring it when the destination requires wired memory.
    ///
    /// # Safety
    ///
    /// The map and page-queue locks must be held and `m` must be live.
    unsafe fn copyout_page_enter(
        map: NonNull<Self>,
        m: *mut VmPage,
        last: NonNull<VmMapEntry>,
        must_wire: bool,
    ) {
        if must_wire {
            // SAFETY: the page queue lock is held and `m` is live.
            unsafe {
                vm_page::wire(NonNull::new_unchecked(m));
                let entry_start = (*last.as_ptr()).links.start;
                let entry_offset = (*last.as_ptr()).offset;
                let page_offset = (*m).offset;
                pmap_enter(
                    NonNull::new((*map.as_ptr()).pmap),
                    entry_start
                        .wrapping_add(page_offset)
                        .wrapping_sub(entry_offset),
                    (*m).phys_addr,
                    ((*last.as_ptr()).protection & !(*m).page_lock()).bits(),
                    1,
                );
            }
        } else {
            // SAFETY: the page queue lock is held.
            unsafe { vm_page::activate(m) };
        }
    }
}

/// `vm_map_copyout()` in C.
///
/// # Safety
///
/// `dst_map` must be a valid, unlocked map and `dst_addr` writable storage for
/// one address.
pub(crate) unsafe fn vm_map_copyout(
    dst_map: *mut VmMap,
    dst_addr: *mut VmOffset,
    copy: *mut VmMapCopy,
) -> c_int {
    let Some(copy) = NonNull::new(copy) else {
        unsafe { dst_addr.write(0) };
        return KERN_SUCCESS;
    };
    let map = unsafe { &mut *dst_map };
    match unsafe { map.copyout(copy) } {
        Ok(address) => {
            unsafe { dst_addr.write(address) };
            KERN_SUCCESS
        }
        Err(error) => error.as_kern_return(),
    }
}

impl VmMap {
    /// `vm_map_copy_overwrite()` in C.
    ///
    /// # Safety
    ///
    /// `copy` must be a live `ENTRY_LIST` copy the caller owns, and `self`
    /// must be an unlocked map with a valid pmap.
    pub(crate) unsafe fn copy_overwrite(
        &mut self,
        dst_addr: VmOffset,
        copy: NonNull<VmMapCopy>,
    ) -> Result<(), Error> {
        let (copy_offset, copy_size) =
            unsafe { ((*copy.as_ptr()).offset, (*copy.as_ptr()).size) };

        if copy_offset & PAGE_MASK != 0
            || copy_size & PAGE_MASK != 0
            || dst_addr & PAGE_MASK != 0
        {
            return Err(Error::InvalidArgument);
        }

        let mut size = copy_size;
        if size == 0 {
            unsafe { VmMapCopy::discard(copy) };
            return Ok(());
        }

        let map = NonNull::from(&mut *self);
        let copy_sentinel: NonNull<VmMapEntry> =
            unsafe { VmMapCopy::header(copy) }.cast();

        let mut tmp_entry = self.copy_overwrite_lookup(map, dst_addr, size)?;

        let mut start = dst_addr;
        loop {
            // SAFETY: the copy holds the live `ENTRY_LIST` variant, and its
            // chain always closes on the sentinel.
            let copy_entry = unsafe { VmMapCopy::first_entry(copy) };
            if copy_entry == copy_sentinel {
                break;
            }
            // SAFETY: `copy_entry` is a live entry of the copy.
            let mut copy_entry_size = unsafe {
                (*copy_entry.as_ptr())
                    .links
                    .end
                    .wrapping_sub((*copy_entry.as_ptr()).links.start)
            };

            let entry = tmp_entry;
            // SAFETY: `entry` is a live entry of the locked map.
            size = unsafe {
                (*entry.as_ptr())
                    .links
                    .end
                    .wrapping_sub((*entry.as_ptr()).links.start)
            };

            // SAFETY: `entry` is live and the map is locked.
            if unsafe { (*entry.as_ptr()).links.start } != start {
                Self::unlock(map);
                return Err(Error::InvalidAddress);
            }

            if unsafe { (*entry.as_ptr()).protection } & VmProt::WRITE
                == VmProt::NONE
            {
                Self::unlock(map);
                return Err(Error::ProtectionFailure);
            }

            if copy_entry_size < size {
                // SAFETY: `entry` is live and the map is locked; this is the
                // guarded `vm_map_clip_end()` macro.
                let end = unsafe {
                    (*entry.as_ptr()).links.start.wrapping_add(copy_entry_size)
                };
                // SAFETY: `entry` is live and the map is locked.
                unsafe { self.hdr.clip_end_at(entry, end, true) };
                size = copy_entry_size;
            }

            if size < copy_entry_size {
                // SAFETY: `copy_entry` is live in the copy.
                let end = unsafe {
                    (*copy_entry.as_ptr()).links.start.wrapping_add(size)
                };
                // SAFETY: the copy holds the live `ENTRY_LIST` variant; this
                // is the guarded `vm_map_copy_clip_end()` macro.
                let copy_header = unsafe { VmMapCopy::header(copy) };
                // SAFETY: `copy_header` is the copy's live header.
                unsafe {
                    (*copy_header.as_ptr())
                        .clip_end_at(copy_entry, end, false);
                };
                copy_entry_size = size;
            }

            // SAFETY: `entry` is live and the map is locked.
            let object = unsafe { (*entry.as_ptr()).object.vm_object };
            let shared = unsafe { (*entry.as_ptr()).is_shared() };
            // SAFETY: a non-null object is live; its `temporary` bit is
            // read.
            let temporary =
                !object.is_null() && unsafe { (*object).is_temporary() };

            if !shared && (object.is_null() || temporary) {
                (start, tmp_entry) = self
                    .copy_overwrite_take(copy, copy_entry, tmp_entry, size);
            } else {
                (start, tmp_entry) = self.copy_overwrite_copy(
                    map, copy, copy_entry, tmp_entry, size, start,
                )?;
            }
        }

        Self::unlock(map);

        // SAFETY: the copy is live and this call consumed it.
        unsafe { VmMapCopy::discard(copy) };

        Ok(())
    }

    /// The first pass of `copy_overwrite()`: find the destination entry
    /// covering the copy and clip it at `dst_addr`.
    fn copy_overwrite_lookup(
        &mut self,
        map: NonNull<Self>,
        dst_addr: VmOffset,
        mut size: VmSize,
    ) -> Result<NonNull<VmMapEntry>, Error> {
        let map_sentinel = self.to_entry();
        'pass_1: loop {
            Self::lock(map);
            let (found, looked) = self.lookup_entry(dst_addr);
            if !found {
                Self::unlock(map);
                return Err(Error::InvalidAddress);
            }
            let tmp_entry = looked;
            // SAFETY: `tmp_entry` contains `dst_addr` and the map is locked;
            // this is the guarded `vm_map_clip_start()` macro.
            unsafe { self.hdr.clip_start_at(tmp_entry, dst_addr, true) };

            let mut entry = tmp_entry;
            loop {
                // SAFETY: `entry` is a live entry of the locked map.
                let (entry_start, entry_end) = unsafe {
                    (
                        (*entry.as_ptr()).links.start,
                        (*entry.as_ptr()).links.end,
                    )
                };
                let sub_size = entry_end.wrapping_sub(entry_start);
                // SAFETY: `entry` is a live entry of the locked map.
                let next = unsafe { (*entry.as_ptr()).links.next }
                    .unwrap_or(map_sentinel);

                // SAFETY: `entry` is a live entry of the locked map.
                if unsafe { (*entry.as_ptr()).protection } & VmProt::WRITE
                    == VmProt::NONE
                {
                    Self::unlock(map);
                    return Err(Error::ProtectionFailure);
                }

                // SAFETY: `entry` is a live entry of the locked map.
                if unsafe { (*entry.as_ptr()).in_transition() } {
                    // SAFETY: `entry` is a live entry of the locked map; the C
                    // wait protocol marks the entry and sleeps on the
                    // map's header with the lock released.
                    unsafe { (*entry.as_ptr()).set_needs_wakeup(true) };
                    self.entry_wait();
                    Self::unlock(map);
                    // SAFETY: the lock was released just above.
                    unsafe { thread_block(None) };
                    continue 'pass_1;
                }

                if size <= sub_size {
                    return Ok(tmp_entry);
                }

                // SAFETY: `next` is a live entry or the sentinel.
                if next == map_sentinel
                    // SAFETY: `next` is a live entry or the sentinel; `next`
                    // is live or the sentinel.
                    || unsafe { (*next.as_ptr()).links.start } != entry_end
                {
                    Self::unlock(map);
                    return Err(Error::InvalidAddress);
                }

                size = size.wrapping_sub(sub_size);
                entry = next;
            }
        }
    }

    /// The fast path of `copy_overwrite()`: hand the destination entry the
    /// copy entry's object without copying pages.
    fn copy_overwrite_take(
        &mut self,
        copy: NonNull<VmMapCopy>,
        copy_entry: NonNull<VmMapEntry>,
        mut tmp_entry: NonNull<VmMapEntry>,
        size: VmSize,
    ) -> (VmOffset, NonNull<VmMapEntry>) {
        let map_sentinel = self.to_entry();
        // SAFETY: `tmp_entry` is live and the map is locked.
        let (old_object, old_offset) = unsafe {
            (
                (*tmp_entry.as_ptr()).object.vm_object,
                (*tmp_entry.as_ptr()).offset,
            )
        };

        // SAFETY: both entries are live; a copy entry is never a submap, so
        // the union member written is the object.
        unsafe {
            (*tmp_entry.as_ptr()).object.vm_object =
                (*copy_entry.as_ptr()).object.vm_object;
            (*tmp_entry.as_ptr()).offset = (*copy_entry.as_ptr()).offset;
            (*tmp_entry.as_ptr())
                .set_needs_copy((*copy_entry.as_ptr()).needs_copy());
        }
        self.entry_reset_wired(tmp_entry);

        // SAFETY: `copy_entry` is linked in the copy, which this call owns.
        let copy_header = unsafe { VmMapCopy::header(copy) };
        // SAFETY: `copy_header` is the copy's live header.
        unsafe {
            (*copy_header.as_ptr()).entry_unlink(copy_entry, false);
        }
        // SAFETY: the entry is unlinked and unused.
        unsafe { VmMapEntry::dispose(copy_entry) };

        // SAFETY: the old object is live and the map is locked.
        unsafe {
            vm_object_pmap_protect(
                old_object,
                old_offset,
                size,
                self.pmap,
                (*tmp_entry.as_ptr()).links.start,
                VmProt::NONE.bits(),
            );
        };

        // SAFETY: the entry kept the reference dropped here.
        unsafe { vm_object_deallocate(old_object) };

        // SAFETY: `tmp_entry` is live and the map is locked.
        let start = unsafe { (*tmp_entry.as_ptr()).links.end };
        // SAFETY: `tmp_entry` is live and the map is locked.
        tmp_entry = unsafe { (*tmp_entry.as_ptr()).links.next }
            .unwrap_or(map_sentinel);
        (start, tmp_entry)
    }

    /// The copy path of `copy_overwrite()`: copy one copy entry into the
    /// destination through `vm_fault_copy`, dancing around the unlocked map.
    fn copy_overwrite_copy(
        &mut self,
        map: NonNull<Self>,
        copy: NonNull<VmMapCopy>,
        copy_entry: NonNull<VmMapEntry>,
        mut tmp_entry: NonNull<VmMapEntry>,
        size: VmSize,
        mut start: VmOffset,
    ) -> Result<(VmOffset, NonNull<VmMapEntry>), Error> {
        let map_sentinel = self.to_entry();

        // SAFETY: `tmp_entry` is live and the map is locked.
        let (dst_object, dst_offset) = unsafe {
            (
                (*tmp_entry.as_ptr()).object.vm_object,
                (*tmp_entry.as_ptr()).offset,
            )
        };

        // SAFETY: the entry holds a reference to the object.
        unsafe { vm_object::reference(dst_object) };
        // SAFETY: the map is locked, so the timestamp is stable.
        let version = VmMapVersion {
            // SAFETY: the map is locked, so the timestamp is stable; the map
            // is locked.
            main_timestamp: unsafe { (*map.as_ptr()).timestamp },
        };

        Self::unlock(map);

        let mut copy_entry_size = size;
        // SAFETY: the copy entry's object is live (the copy holds a
        // reference), the map is unlocked and the version, size and map are
        // valid, as `vm_fault_copy` requires.
        let r = unsafe {
            vm_fault::copy(
                NonNull::new((*copy_entry.as_ptr()).object.vm_object),
                (*copy_entry.as_ptr()).offset,
                &mut copy_entry_size,
                dst_object,
                dst_offset,
                map,
                &version,
                false,
            )
        };

        // SAFETY: the reference taken above.
        unsafe { vm_object_deallocate(dst_object) };

        if r != KERN_SUCCESS {
            error_from_kern_return(r)?;
        }

        if copy_entry_size != 0 {
            // SAFETY: `copy_entry` is live in the copy.
            let end = unsafe {
                (*copy_entry.as_ptr())
                    .links
                    .start
                    .wrapping_add(copy_entry_size)
            };
            // SAFETY: the copy holds the live `ENTRY_LIST` variant; guarded
            // `vm_map_copy_clip_end()`.
            let copy_header = unsafe { VmMapCopy::header(copy) };
            // SAFETY: `copy_header` is the copy's live header.
            unsafe {
                (*copy_header.as_ptr()).clip_end_at(copy_entry, end, false);
            };
            // SAFETY: `copy_entry` is linked in the copy, which this call
            // owns.
            unsafe {
                (*copy_header.as_ptr()).entry_unlink(copy_entry, false);
                vm_object_deallocate((*copy_entry.as_ptr()).object.vm_object);
            }
            // SAFETY: the entry is unlinked and unused.
            unsafe { VmMapEntry::dispose(copy_entry) };
        }

        start = start.wrapping_add(copy_entry_size);
        Self::lock(map);
        // SAFETY: the map is locked again.
        if version.main_timestamp.wrapping_add(1)
            // SAFETY: the map is locked again; the map is locked.
            == unsafe { (*map.as_ptr()).timestamp }
        {
            // SAFETY: `tmp_entry` is live and the map is locked.
            unsafe { self.hdr.clip_end_at(tmp_entry, start, true) };
            // SAFETY: `tmp_entry` is live and the map is locked.
            tmp_entry = unsafe { (*tmp_entry.as_ptr()).links.next }
                .unwrap_or(map_sentinel);
        } else {
            let (found, looked) = self.lookup_entry(start);
            if !found {
                Self::unlock(map);
                return Err(Error::InvalidAddress);
            }
            tmp_entry = looked;
            // SAFETY: `tmp_entry` contains `start` and the map is locked; the
            // guarded `vm_map_clip_start()` macro.
            unsafe { self.hdr.clip_start_at(tmp_entry, start, true) };
        }

        Ok((start, tmp_entry))
    }
}

/// The region `vm_region()` describes: the C's out-parameters as one value.
pub(crate) struct VmMapRegion {
    /// The region's first address, which replaces the caller's.
    pub address: VmOffset,
    pub size: VmSize,
    /// The region's current protection.
    pub protection: VmProt,
    pub max_protection: VmProt,
    pub inheritance: VmInherit,
    pub is_shared: bool,
    /// A naked send right naming the region's pager, or `None` for `IP_NULL`.
    pub object_name: Option<IpcPort>,
    /// Offset of the address into the object.
    pub offset: VmOffset,
}

/// What the locked half of `region_create_proxy()` reads.
struct RegionProxy {
    /// The requested protection limited to the entry's maximum.
    max_protection: VmProt,
    /// The send right copied from the entry's pager, if it has one.
    pager: Option<IpcPort>,
    /// The offset of the address into the object.
    start: VmOffset,
}

impl VmMap {
    /// The entry `address` falls in, or the first one above it.
    fn region_entry(
        &self,
        address: VmOffset,
    ) -> Result<NonNull<VmMapEntry>, Error> {
        let (found, tmp_entry) = self.lookup_entry(address);
        if found {
            return Ok(tmp_entry);
        }

        let sentinel = self.to_entry();
        // SAFETY: `tmp_entry` is a live entry or the sentinel of the locked
        // map, and the chain is stable under its lock.
        let entry =
            unsafe { (*tmp_entry.as_ptr()).links.next }.unwrap_or(sentinel);
        if entry == sentinel {
            return Err(Error::NoSpace);
        }
        Ok(entry)
    }

    /// `vm_region()` in C.
    pub(crate) fn region(
        &self,
        address: VmOffset,
    ) -> Result<VmMapRegion, Error> {
        let map = NonNull::from(self);
        // SAFETY: the caller owns the map; the read lock keeps the entries
        // stable and the named object alive below.
        unsafe { (*map.as_ptr()).lock.read() };

        let region = self.region_entry(address).map(|entry| {
            // SAFETY: `entry` is a live entry of the read-locked map;
            // `vm_object_name` takes the object's own lock and keeps its
            // reference alive under the map lock.
            unsafe {
                let e = &*entry.as_ptr();
                let start = e.links.start;
                let is_sub_map = e.is_sub_map();
                VmMapRegion {
                    address: start,
                    size: e.links.end.wrapping_sub(start),
                    protection: e.protection,
                    max_protection: e.max_protection,
                    inheritance: e.inheritance,
                    is_shared: !is_sub_map && e.is_shared(),
                    object_name: if is_sub_map {
                        None
                    } else {
                        IpcPort::new(vm_object::name(NonNull::new(
                            e.object.vm_object,
                        )))
                    },
                    offset: e.offset,
                }
            }
        });

        // SAFETY: the read lock taken above.
        unsafe { (*map.as_ptr()).lock.done() };

        region
    }

    /// The half of `region_create_proxy()` that runs under the map's read
    /// lock: find the entry, limit the arguments and copy the entry pager's
    /// send right.
    fn region_create_proxy_locked(
        &self,
        address: VmOffset,
        max_protection: VmProt,
        len: VmSize,
    ) -> Result<RegionProxy, Error> {
        let entry = self.region_entry(address)?;

        // SAFETY: `entry` is a live entry of the read-locked map.
        let (start, end, entry_max, offset, object, is_sub_map) = unsafe {
            let e = &*entry.as_ptr();
            (
                e.links.start,
                e.links.end,
                e.max_protection,
                e.offset,
                e.object.vm_object,
                e.is_sub_map(),
            )
        };

        if is_sub_map {
            return Err(Error::InvalidArgument);
        }

        if len > end.wrapping_sub(start) {
            return Err(Error::InvalidArgument);
        }
        let max_protection = max_protection & entry_max;

        // SAFETY: the entry's object is alive under the map lock, and the
        // object lock is the C's own discipline around the pager.
        let pager = unsafe {
            (*object).lock.lock();
            vm_object::pager_create(object);
            let pager = IpcPort::new(ipc_port::copy_send((*object).pager));
            (*object).lock.unlock();
            pager
        };

        Ok(RegionProxy {
            max_protection,
            pager,
            start: address.wrapping_sub(start).wrapping_add(offset),
        })
    }

    /// `vm_region_create_proxy()` in C.
    pub(crate) fn region_create_proxy(
        &self,
        space: Option<IpcSpace>,
        address: VmOffset,
        max_protection: VmProt,
        len: VmSize,
    ) -> Result<Option<IpcPort>, Error> {
        let map = NonNull::from(self);
        // SAFETY: the caller owns the map; the read lock keeps the entry and
        // its object stable while the pager is copied.
        unsafe { (*map.as_ptr()).lock.read() };

        let locked =
            self.region_create_proxy_locked(address, max_protection, len);

        // SAFETY: the read lock taken above; the C drops it before the proxy
        // call, which no longer needs the map.
        unsafe { (*map.as_ptr()).lock.done() };

        let RegionProxy {
            max_protection,
            pager,
            start,
        } = locked?;

        let object = pager.map_or(ptr::null_mut(), IpcPort::as_ptr);
        let offset: VmOffset = 0;
        // SAFETY: the proxy call's contract is one object, one offset, one
        // start and one length, and no lock is held.
        let result = unsafe {
            memory_object_proxy::create_proxy(
                space,
                max_protection,
                &[object],
                &[offset],
                &[start],
                &[len],
            )
        };

        match result {
            Ok(port) => Ok(Some(port)),
            Err(error) => {
                if let Some(pager) = pager {
                    // SAFETY: `pager` is the send right copied above and still
                    // owned here.
                    unsafe { ipc_port::release_send(pager) };
                }
                Err(error)
            }
        }
    }
}
