// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! VM scalar and handle types: protections and inheritance, the VM object and
//! statistics records, and the opaque pointers of the VM interfaces.

pub use crate::param::{PAGE_MASK, PAGE_SHIFT, PAGE_SIZE};
use crate::param::{VmOffset, VmSize};
use crate::simple_lock::SimpleLock;
use crate::vm_page::ListqList;
use collections::list::{self, List};
use core::ffi::{c_int, c_uint, c_void};
use core::pin::Pin;
use core::sync::atomic::AtomicI32;
use zerocopy::{Immutable, IntoBytes};

pub use mach_page::types::VmProt;

bitflags::bitflags! {
    /// The flag word of a map entry.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct EntryFlags: u32 {
        /// The entry has a node in its map's gap tree.
        const IN_GAP_TREE = 1 << 0;
        /// The mapping is shared, not copied, on fork.
        const IS_SHARED = 1 << 1;
        /// The entry's object is a sub-map, not a VM object.
        const IS_SUB_MAP = 1 << 2;
        /// An operation is in progress; wait rather than touch the entry.
        const IN_TRANSITION = 1 << 3;
        /// A thread is waiting for the transition to end.
        const NEEDS_WAKEUP = 1 << 4;
        /// The object must be copied before a write.
        const NEEDS_COPY = 1 << 5;
    }
}

bitflags::bitflags! {
    /// The flag word of a map.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct MapFlags: u32 {
        /// An allocation that finds no room waits for some.
        const WAIT_FOR_SPACE = 1 << 0;
        /// New mappings in the map are wired down.
        const WIRING_REQUIRED = 1 << 1;
    }
}

bitflags::bitflags! {
    /// Which physical segments a page allocation may draw from.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PageSelect: c_uint {
        /// The direct-mapped segment.
        const DIRECTMAP = 0x02;
        /// The 32-bit DMA segment.
        const DMA32 = 0x04;
        /// High physical memory, outside the direct map.
        const HIGHMEM = 0x08;
    }
}

bitflags::bitflags! {
    /// How `vm_msync` flushes; userspace may set the bits it does not name.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct SyncFlags: c_int {
        /// Start the writes and return.
        const ASYNCHRONOUS = 0x01;
        /// Wait for the writes.
        const SYNCHRONOUS = 0x02;
        // The bits the kernel does not name.
        const _ = !0;
    }
}

bitflags::bitflags! {
    /// `VOI_STATE_*`: the object state a debugging query reports.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct ObjectInfoState: c_uint {
        const PAGER_CREATED = 0x0000_0001;
        const PAGER_INITIALIZED = 0x0000_0002;
        const PAGER_READY = 0x0000_0004;
        const CAN_PERSIST = 0x0000_0008;
        const INTERNAL = 0x0000_0010;
        const TEMPORARY = 0x0000_0020;
        const ALIVE = 0x0000_0040;
        const LOCK_IN_PROGRESS = 0x0000_0080;
        const LOCK_RESTART = 0x0000_0100;
    }
}

bitflags::bitflags! {
    /// `VPI_STATE_*`: the page state a debugging query reports.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct PageInfoState: c_uint {
        const BUSY = 0x0000_0001;
        const WANTED = 0x0000_0002;
        const TABLED = 0x0000_0004;
        const FICTITIOUS = 0x0000_0008;
        const PRIVATE = 0x0000_0010;
        const ABSENT = 0x0000_0020;
        const ERROR = 0x0000_0040;
        const DIRTY = 0x0000_0080;
        const PRECIOUS = 0x0000_0100;
        const OVERWRITING = 0x0000_0200;
        const INACTIVE = 0x0000_0400;
        const ACTIVE = 0x0000_0800;
        const LAUNDRY = 0x0000_1000;
        const FREE = 0x0000_2000;
        const REFERENCE = 0x0000_4000;
    }
}

impl PageInfoState {
    /// `VPI_STATE_NODATA`: the bits that mean the page holds no data to
    /// inspect.
    pub(crate) const NODATA: Self = Self::BUSY
        .union(Self::FICTITIOUS)
        .union(Self::PRIVATE)
        .union(Self::ABSENT);
}

/// `vm_inherit_t`: what a child task's map inherits from a range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct VmInherit(c_int);

impl VmInherit {
    /// `VM_INHERIT_SHARE`.
    pub const SHARE: Self = Self(0);
    /// `VM_INHERIT_COPY`.
    pub const COPY: Self = Self(1);
    /// `VM_INHERIT_NONE`.
    pub const NONE: Self = Self(2);

    /// The `c_int` the C side passes and stores.
    #[must_use]
    pub const fn bits(self) -> c_int {
        self.0
    }

    /// An inheritance value from the C side.
    #[must_use]
    pub const fn from_bits(bits: c_int) -> Self {
        Self(bits)
    }
}

/// `hash_info_bucket_t`: one bucket count, as a hash-table report gives it.
#[repr(transparent)]
pub struct HashInfoBucket {
    /// How many entries hash to the bucket.
    pub hib_count: c_uint,
}

const _: () = {
    assert!(size_of::<HashInfoBucket>() == size_of::<c_uint>());
    assert!(align_of::<HashInfoBucket>() == align_of::<c_uint>());
    assert!(core::mem::offset_of!(HashInfoBucket, hib_count) == 0);
};

bitfield::bitfield! {
    /// The paging-in-progress count in the low half of [`ObjectFlags`].
    struct ObjectCount(u32);
    u32;
    paging_in_progress, set_paging_in_progress: 15, 0;
}

bitflags::bitflags! {
    /// The flag word of [`VmObject`]: the paging-in-progress count in bits 0
    /// to 15, then one bit per boolean flag, from bit 16 through bit 28.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct ObjectFlags: u32 {
        const USED_FOR_PAGEOUT = 1 << 16;
        const PAGER_CREATED = 1 << 17;
        const PAGER_INITIALIZED = 1 << 18;
        const PAGER_READY = 1 << 19;
        const CAN_PERSIST = 1 << 20;
        const INTERNAL = 1 << 21;
        const TEMPORARY = 1 << 22;
        const ALIVE = 1 << 23;
        const LOCK_IN_PROGRESS = 1 << 24;
        const LOCK_RESTART = 1 << 25;
        const USE_SHARED_COPY = 1 << 26;
        const SHADOWED = 1 << 27;
        const CACHED = 1 << 28;
        // The paging-in-progress count.
        const _ = 0xffff;
    }
}

/// The memory object a page belongs to and an entry maps.
#[repr(C)]
#[allow(missing_docs)]
pub struct VmObject {
    /// `memq`: the object's resident-page queue head.
    pub memq: ListqList,
    pub lock: SimpleLock,
    pub size: VmSize,
    pub ref_count: c_int,
    pub resident_page_count: usize,
    pub copy: *mut Self,
    pub shadow: *mut Self,
    pub shadow_offset: VmOffset,
    /// `pager`: the memory-object port, or null.
    pub pager: *mut c_void,
    pub paging_offset: VmOffset,
    pub pager_request: *mut c_void,
    pub pager_name: *mut c_void,
    pub copy_strategy: c_int,
    pub absent_count: c_uint,
    pub all_wanted: c_uint,
    flags: ObjectFlags,
    pub cached_list: list::Link,
    pub last_alloc: VmOffset,
    pub existence_info: *mut c_void,
}

const _: () = {
    assert!(size_of::<VmObject>() == 152);
    assert!(align_of::<VmObject>() == 8);
    assert!(core::mem::offset_of!(VmObject, memq) == 0);
    assert!(core::mem::offset_of!(VmObject, lock) == 16);
    assert!(core::mem::offset_of!(VmObject, size) == 24);
    assert!(core::mem::offset_of!(VmObject, ref_count) == 32);
    assert!(core::mem::offset_of!(VmObject, resident_page_count) == 40);
    assert!(core::mem::offset_of!(VmObject, copy) == 48);
    assert!(core::mem::offset_of!(VmObject, shadow) == 56);
    assert!(core::mem::offset_of!(VmObject, shadow_offset) == 64);
    assert!(core::mem::offset_of!(VmObject, pager) == 72);
    assert!(core::mem::offset_of!(VmObject, paging_offset) == 80);
    assert!(core::mem::offset_of!(VmObject, pager_request) == 88);
    assert!(core::mem::offset_of!(VmObject, pager_name) == 96);
    assert!(core::mem::offset_of!(VmObject, copy_strategy) == 104);
    assert!(core::mem::offset_of!(VmObject, absent_count) == 108);
    assert!(core::mem::offset_of!(VmObject, all_wanted) == 112);
    assert!(core::mem::offset_of!(VmObject, flags) == 116);
    assert!(core::mem::offset_of!(VmObject, cached_list) == 120);
    assert!(core::mem::offset_of!(VmObject, last_alloc) == 136);
    assert!(core::mem::offset_of!(VmObject, existence_info) == 144);
};

list::adapter!(
    /// The adapter for an object's `cached_list` in the global cached list.
    pub VmObjectCachedAdapter = VmObject { cached_list }
);

/// The objects kept after their last reference went away. Nothing walks it,
/// so the order is unobservable.
pub type VmObjectCachedList = List<'static, VmObjectCachedAdapter>;

// The link and the page queue head are two words each, so the offsets above
// hold.
const _: () = assert!(size_of::<list::Link>() == 16);
const _: () = assert!(size_of::<ListqList>() == 16);

// These accessors mirror the C bitfields one for one; the bit constants
// above carry the documentation, and a doc per getter/setter pair would
// only respell the field name.
#[allow(missing_docs)]
impl VmObject {
    /// The resident-page queue of `object`, pinned.
    ///
    /// # Safety
    ///
    /// `object` must be live, and the caller must hold its lock for as long
    /// as it uses the queue. An object never moves while it holds pages: it
    /// is a slab object or a static.
    pub(crate) unsafe fn memq_pinned<'a>(
        object: *mut Self,
    ) -> Pin<&'a mut ListqList> {
        // SAFETY: the object is live and stays in place, and the lock the
        // caller holds keeps anything else from reaching the queue.
        unsafe {
            Pin::new_unchecked(&mut *core::ptr::addr_of_mut!((*object).memq))
        }
    }

    /// A fresh object of `size` bytes, as the C's template stamped one: one
    /// reference, internal, temporary and alive, and everything else zero.
    pub(crate) const fn fresh(size: VmSize) -> Self {
        let mut object = Self::zeroed();
        object.size = size;
        object.ref_count = 1;
        object.set_internal(true);
        object.set_temporary(true);
        object.set_alive(true);
        object
    }

    /// The all-zero object [`fresh`](Self::fresh) starts from.
    const fn zeroed() -> Self {
        Self {
            memq: ListqList::new(),
            lock: SimpleLock::new(),
            size: 0,
            ref_count: 0,
            resident_page_count: 0,
            copy: core::ptr::null_mut(),
            shadow: core::ptr::null_mut(),
            shadow_offset: 0,
            pager: core::ptr::null_mut(),
            paging_offset: 0,
            pager_request: core::ptr::null_mut(),
            pager_name: core::ptr::null_mut(),
            copy_strategy: 0,
            absent_count: 0,
            all_wanted: 0,
            flags: ObjectFlags::empty(),
            cached_list: list::Link::new(),
            last_alloc: 0,
            existence_info: core::ptr::null_mut(),
        }
    }

    /// `paging_in_progress`; the C bitfield holds sixteen bits.
    pub fn paging_in_progress(&self) -> u32 {
        ObjectCount(self.flags.bits()).paging_in_progress()
    }

    pub fn set_paging_in_progress(&mut self, count: u32) {
        let mut word = ObjectCount(self.flags.bits());
        word.set_paging_in_progress(count);
        self.flags = ObjectFlags::from_bits_retain(word.0);
    }

    pub const fn is_used_for_pageout(&self) -> bool {
        self.flag(ObjectFlags::USED_FOR_PAGEOUT)
    }

    pub const fn set_used_for_pageout(&mut self, on: bool) {
        self.set_flag(ObjectFlags::USED_FOR_PAGEOUT, on);
    }

    pub const fn is_pager_created(&self) -> bool {
        self.flag(ObjectFlags::PAGER_CREATED)
    }

    pub const fn set_pager_created(&mut self, on: bool) {
        self.set_flag(ObjectFlags::PAGER_CREATED, on);
    }

    pub const fn is_pager_initialized(&self) -> bool {
        self.flag(ObjectFlags::PAGER_INITIALIZED)
    }

    pub const fn set_pager_initialized(&mut self, on: bool) {
        self.set_flag(ObjectFlags::PAGER_INITIALIZED, on);
    }

    pub const fn is_pager_ready(&self) -> bool {
        self.flag(ObjectFlags::PAGER_READY)
    }

    pub const fn set_pager_ready(&mut self, on: bool) {
        self.set_flag(ObjectFlags::PAGER_READY, on);
    }

    pub const fn can_persist(&self) -> bool {
        self.flag(ObjectFlags::CAN_PERSIST)
    }

    pub const fn set_can_persist(&mut self, on: bool) {
        self.set_flag(ObjectFlags::CAN_PERSIST, on);
    }

    pub const fn is_internal(&self) -> bool {
        self.flag(ObjectFlags::INTERNAL)
    }

    pub const fn set_internal(&mut self, on: bool) {
        self.set_flag(ObjectFlags::INTERNAL, on);
    }

    pub const fn is_temporary(&self) -> bool {
        self.flag(ObjectFlags::TEMPORARY)
    }

    pub const fn set_temporary(&mut self, on: bool) {
        self.set_flag(ObjectFlags::TEMPORARY, on);
    }

    pub const fn is_alive(&self) -> bool {
        self.flag(ObjectFlags::ALIVE)
    }

    pub const fn set_alive(&mut self, on: bool) {
        self.set_flag(ObjectFlags::ALIVE, on);
    }

    pub const fn use_shared_copy(&self) -> bool {
        self.flag(ObjectFlags::USE_SHARED_COPY)
    }

    pub const fn set_use_shared_copy(&mut self, on: bool) {
        self.set_flag(ObjectFlags::USE_SHARED_COPY, on);
    }

    pub const fn is_shadowed(&self) -> bool {
        self.flag(ObjectFlags::SHADOWED)
    }

    pub const fn set_shadowed(&mut self, on: bool) {
        self.set_flag(ObjectFlags::SHADOWED, on);
    }

    pub const fn set_cached(&mut self, on: bool) {
        self.set_flag(ObjectFlags::CACHED, on);
    }

    /// Records that a thread waits for `event`.
    pub const fn want(&mut self, event: u32) {
        self.all_wanted |= 1 << event;
    }

    /// Whether a thread waits for `event`.
    pub const fn wants(&self, event: u32) -> bool {
        self.all_wanted & (1 << event) != 0
    }

    /// Clears the waiters of `event`.
    pub const fn clear_want(&mut self, event: u32) {
        self.all_wanted &= !(1 << event);
    }

    /// Whether the object holds neither references nor pages, so it may be
    /// collected.
    pub const fn is_collectable(&self) -> bool {
        self.ref_count == 0 && self.resident_page_count == 0
    }

    /// Whether a lock request is running on the object.
    pub const fn is_lock_in_progress(&self) -> bool {
        self.flag(ObjectFlags::LOCK_IN_PROGRESS)
    }

    /// Whether a lock request on the object must restart.
    pub const fn is_lock_restart(&self) -> bool {
        self.flag(ObjectFlags::LOCK_RESTART)
    }

    /// The submap placeholder has never held a page.
    pub const fn is_pristine_submap(&self) -> bool {
        self.resident_page_count == 0
            && self.copy.is_null()
            && self.shadow.is_null()
            && !self.is_pager_created()
    }

    /// Whether a mapping of `size` bytes needs a shadow object first.
    pub const fn needs_shadow(
        &self,
        size: VmSize,
        needs_copy: bool,
        is_shared: bool,
    ) -> bool {
        needs_copy
            || self.is_shadowed()
            || (self.is_temporary() && !is_shared && self.size > size)
    }

    /// Whether the object may be freed with its mapping: it has no pager and
    /// no other user.
    pub fn can_release(&self) -> bool {
        !self.is_pager_created()
            && self.ref_count == 1
            && self.paging_in_progress() == 0
    }

    /// Whether a neighbouring mapping may be extended into the object.
    pub fn can_coalesce(&self) -> bool {
        self.ref_count <= 1
            && !self.is_pager_created()
            && self.shadow.is_null()
            && self.copy.is_null()
            && self.paging_in_progress() == 0
    }

    /// Grows the object to at least `size` bytes.
    pub const fn extend_size(&mut self, size: VmSize) {
        if size > self.size {
            self.size = size;
        }
    }

    const fn flag(&self, bit: ObjectFlags) -> bool {
        self.flags.contains(bit)
    }

    const fn set_flag(&mut self, bit: ObjectFlags, on: bool) {
        self.flags = if on {
            self.flags.union(bit)
        } else {
            self.flags.difference(bit)
        };
    }
}

/// `struct vm_statistics`: the system-wide paging counters.
#[repr(C)]
#[allow(missing_docs)]
#[derive(IntoBytes, Immutable)]
pub struct VmStatistics {
    pub pagesize: c_int,
    pub free_count: c_int,
    pub active_count: c_int,
    pub inactive_count: c_int,
    pub wire_count: c_int,
    pub zero_fill_count: c_int,
    pub reactivations: c_int,
    pub pageins: c_int,
    pub pageouts: c_int,
    pub faults: c_int,
    pub cow_faults: c_int,
    pub lookups: c_int,
    pub hits: c_int,
}

const _: () = assert!(size_of::<VmStatistics>() == 13 * size_of::<c_int>());
const _: () = assert!(align_of::<VmStatistics>() == align_of::<c_int>());
const _: () =
    assert!(core::mem::offset_of!(VmStatistics, reactivations) == 24);

/// The counted half of [`VmStatistics`], which `vm_statistics()` reports
/// with the live page counts beside it. Any CPU bumps a counter with one
/// relaxed increment, and like the C's `int`s they wrap.
#[allow(missing_docs)]
pub(crate) struct PagingCounters {
    pub zero_fill_count: AtomicI32,
    pub reactivations: AtomicI32,
    pub pageins: AtomicI32,
    pub pageouts: AtomicI32,
    pub faults: AtomicI32,
    pub cow_faults: AtomicI32,
    pub lookups: AtomicI32,
    pub hits: AtomicI32,
}

impl PagingCounters {
    /// Every counter at zero.
    pub(crate) const fn new() -> Self {
        Self {
            zero_fill_count: AtomicI32::new(0),
            reactivations: AtomicI32::new(0),
            pageins: AtomicI32::new(0),
            pageouts: AtomicI32::new(0),
            faults: AtomicI32::new(0),
            cow_faults: AtomicI32::new(0),
            lookups: AtomicI32::new(0),
            hits: AtomicI32::new(0),
        }
    }
}

pub use crate::vm_page::VmPage;
