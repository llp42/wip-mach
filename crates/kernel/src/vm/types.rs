// SPDX-License-Identifier: CMU-Mach
// Derived from include/mach/vm_prot.h, include/mach/vm_inherit.h and
// include/mach/vm_statistics.h, from vm/vm_object.h, and from the opaque
// handle of vm/pmap.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! VM scalar and handle types, from `mach/vm_prot.h` and `vm_inherit.h`,
//! the `struct vm_object` and `struct vm_statistics` records, and the VM
//! headers' opaque pointers.

use crate::arch::types::{VmOffset, VmSize};
pub(crate) use crate::arch::vm_param::{PAGE_MASK, PAGE_SHIFT, PAGE_SIZE};
use crate::kern::lock::SimpleLock;
use crate::vm::vm_page::ListqList;
use collections::list::{self, List};
use core::ffi::{c_int, c_uint, c_void};
use core::pin::Pin;

/// `vm_prot_t` of <`mach/vm_prot.h>`: a set of bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct VmProt(c_int);

impl VmProt {
    /// `VM_PROT_NONE`.
    pub const NONE: Self = Self(0x0);
    /// `VM_PROT_READ`.
    pub const READ: Self = Self(0x1);
    /// `VM_PROT_WRITE`.
    pub const WRITE: Self = Self(0x2);
    /// `VM_PROT_EXECUTE`.
    pub const EXECUTE: Self = Self(0x4);
    /// `VM_PROT_ALL`: read, write and execute.
    pub const ALL: Self = Self(Self::READ.0 | Self::WRITE.0 | Self::EXECUTE.0);
    /// `VM_PROT_NO_CHANGE`: a marker `vm_map_protect` refuses to set.
    pub const NO_CHANGE: Self = Self(0x08);
    /// `VM_PROT_NOTIFY`: a marker bit for callers of `vm_map_protect`.
    pub const NOTIFY: Self = Self(0x10);

    /// The `c_int` the C side passes and stores.
    #[must_use]
    pub const fn bits(self) -> c_int {
        self.0
    }

    /// A protection value from the C side.
    #[must_use]
    pub const fn from_bits(bits: c_int) -> Self {
        Self(bits)
    }

    /// Whether every bit of `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for VmProt {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for VmProt {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl core::ops::BitAnd for VmProt {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl core::ops::BitAndAssign for VmProt {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl core::ops::Not for VmProt {
    type Output = Self;

    fn not(self) -> Self {
        Self(!self.0)
    }
}

/// `vm_inherit_t` of <`mach/vm_inherit.h`>.
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

/// `pmap_t`: the machine-dependent physical map of a VM map, whose mirror
/// lives in the arch tree.
pub use crate::arch::x86_64::pmap::Pmap;

/// The `unsigned int` run of flags in `struct vm_object`, in the C
/// declaration order the compiler packs: `paging_in_progress` in bits 0 to
/// 15, then one bit per boolean flag, `used_for_pageout` at bit 16 through
/// `cached` at bit 28.
const VM_OBJECT_PAGING_IN_PROGRESS_MASK: u32 = 0xffff;
const VM_OBJECT_USED_FOR_PAGEOUT_BIT: u32 = 1 << 16;
const VM_OBJECT_PAGER_CREATED_BIT: u32 = 1 << 17;
const VM_OBJECT_PAGER_INITIALIZED_BIT: u32 = 1 << 18;
const VM_OBJECT_PAGER_READY_BIT: u32 = 1 << 19;
const VM_OBJECT_CAN_PERSIST_BIT: u32 = 1 << 20;
const VM_OBJECT_INTERNAL_BIT: u32 = 1 << 21;
const VM_OBJECT_TEMPORARY_BIT: u32 = 1 << 22;
const VM_OBJECT_ALIVE_BIT: u32 = 1 << 23;
const VM_OBJECT_LOCK_IN_PROGRESS_BIT: u32 = 1 << 24;
const VM_OBJECT_LOCK_RESTART_BIT: u32 = 1 << 25;
const VM_OBJECT_USE_SHARED_COPY_BIT: u32 = 1 << 26;
const VM_OBJECT_SHADOWED_BIT: u32 = 1 << 27;
const VM_OBJECT_CACHED_BIT: u32 = 1 << 28;

/// `struct vm_object` of <`vm/vm_object.h>`: the memory object a page belongs
/// to and an entry maps.
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
    flags: u32,
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

    /// The zero image a C `static` of `struct vm_object` began with, before
    /// `vm_object_bootstrap()` filled the template.
    pub(crate) const fn zeroed() -> Self {
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
            flags: 0,
            cached_list: list::Link::new(),
            last_alloc: 0,
            existence_info: core::ptr::null_mut(),
        }
    }

    /// `paging_in_progress`; the C bitfield holds sixteen bits.
    pub const fn paging_in_progress(&self) -> u32 {
        self.flags & VM_OBJECT_PAGING_IN_PROGRESS_MASK
    }

    pub const fn set_paging_in_progress(&mut self, count: u32) {
        self.flags = (self.flags & !VM_OBJECT_PAGING_IN_PROGRESS_MASK)
            | (count & VM_OBJECT_PAGING_IN_PROGRESS_MASK);
    }

    pub const fn is_used_for_pageout(&self) -> bool {
        self.flag(VM_OBJECT_USED_FOR_PAGEOUT_BIT)
    }

    pub const fn set_used_for_pageout(&mut self, on: bool) {
        self.set_flag(VM_OBJECT_USED_FOR_PAGEOUT_BIT, on);
    }

    pub const fn is_pager_created(&self) -> bool {
        self.flag(VM_OBJECT_PAGER_CREATED_BIT)
    }

    pub const fn set_pager_created(&mut self, on: bool) {
        self.set_flag(VM_OBJECT_PAGER_CREATED_BIT, on);
    }

    pub const fn is_pager_initialized(&self) -> bool {
        self.flag(VM_OBJECT_PAGER_INITIALIZED_BIT)
    }

    pub const fn set_pager_initialized(&mut self, on: bool) {
        self.set_flag(VM_OBJECT_PAGER_INITIALIZED_BIT, on);
    }

    pub const fn is_pager_ready(&self) -> bool {
        self.flag(VM_OBJECT_PAGER_READY_BIT)
    }

    pub const fn set_pager_ready(&mut self, on: bool) {
        self.set_flag(VM_OBJECT_PAGER_READY_BIT, on);
    }

    pub const fn can_persist(&self) -> bool {
        self.flag(VM_OBJECT_CAN_PERSIST_BIT)
    }

    pub const fn set_can_persist(&mut self, on: bool) {
        self.set_flag(VM_OBJECT_CAN_PERSIST_BIT, on);
    }

    pub const fn is_internal(&self) -> bool {
        self.flag(VM_OBJECT_INTERNAL_BIT)
    }

    pub const fn set_internal(&mut self, on: bool) {
        self.set_flag(VM_OBJECT_INTERNAL_BIT, on);
    }

    pub const fn is_temporary(&self) -> bool {
        self.flag(VM_OBJECT_TEMPORARY_BIT)
    }

    pub const fn set_temporary(&mut self, on: bool) {
        self.set_flag(VM_OBJECT_TEMPORARY_BIT, on);
    }

    pub const fn is_alive(&self) -> bool {
        self.flag(VM_OBJECT_ALIVE_BIT)
    }

    pub const fn set_alive(&mut self, on: bool) {
        self.set_flag(VM_OBJECT_ALIVE_BIT, on);
    }

    pub const fn use_shared_copy(&self) -> bool {
        self.flag(VM_OBJECT_USE_SHARED_COPY_BIT)
    }

    pub const fn set_use_shared_copy(&mut self, on: bool) {
        self.set_flag(VM_OBJECT_USE_SHARED_COPY_BIT, on);
    }

    pub const fn is_shadowed(&self) -> bool {
        self.flag(VM_OBJECT_SHADOWED_BIT)
    }

    pub const fn set_shadowed(&mut self, on: bool) {
        self.set_flag(VM_OBJECT_SHADOWED_BIT, on);
    }

    pub const fn is_cached(&self) -> bool {
        self.flag(VM_OBJECT_CACHED_BIT)
    }

    pub const fn set_cached(&mut self, on: bool) {
        self.set_flag(VM_OBJECT_CACHED_BIT, on);
    }

    /// `all_wanted |= 1 << event`, the first line of the
    /// `vm_object_wait()`/`vm_object_assert_wait()` macros.
    pub const fn want(&mut self, event: u32) {
        self.all_wanted |= 1 << event;
    }

    /// The `all_wanted & (1 << event)` test of `vm_object_wakeup()`.
    pub const fn wants(&self, event: u32) -> bool {
        self.all_wanted & (1 << event) != 0
    }

    /// `all_wanted &= ~(1 << event)`, the last line of `vm_object_wakeup()`.
    pub const fn clear_want(&mut self, event: u32) {
        self.all_wanted &= !(1 << event);
    }

    /// `vm_object_collectable()` of <`vm/vm_object.h`>.
    pub const fn is_collectable(&self) -> bool {
        self.ref_count == 0 && self.resident_page_count == 0
    }

    /// `lock_in_progress`; the C bitfield holds one bit.
    pub const fn is_lock_in_progress(&self) -> bool {
        self.flag(VM_OBJECT_LOCK_IN_PROGRESS_BIT)
    }

    /// `lock_restart`; the C bitfield holds one bit.
    pub const fn is_lock_restart(&self) -> bool {
        self.flag(VM_OBJECT_LOCK_RESTART_BIT)
    }

    /// `vm_map_glue_object_is_pristine_submap()` in C: the submap placeholder
    /// has never held a page.
    pub const fn is_pristine_submap(&self) -> bool {
        self.resident_page_count == 0
            && self.copy.is_null()
            && self.shadow.is_null()
            && !self.is_pager_created()
    }

    /// `vm_map_glue_object_needs_shadow()` in C.
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

    /// `vm_map_glue_object_can_release()` in C.
    pub const fn can_release(&self) -> bool {
        !self.is_pager_created()
            && self.ref_count == 1
            && self.paging_in_progress() == 0
    }

    /// `vm_map_glue_object_can_coalesce()` in C.
    pub const fn can_coalesce(&self) -> bool {
        self.ref_count <= 1
            && !self.is_pager_created()
            && self.shadow.is_null()
            && self.copy.is_null()
            && self.paging_in_progress() == 0
    }

    /// `vm_map_glue_object_extend_size()` in C.
    pub const fn extend_size(&mut self, size: VmSize) {
        if size > self.size {
            self.size = size;
        }
    }

    const fn flag(&self, bit: u32) -> bool {
        self.flags & bit != 0
    }

    const fn set_flag(&mut self, bit: u32, on: bool) {
        if on {
            self.flags |= bit;
        } else {
            self.flags &= !bit;
        }
    }
}

/// `struct vm_statistics` of <`mach/vm_statistics.h`>.
#[repr(C)]
#[allow(missing_docs)]
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

impl VmStatistics {
    /// The zero image the C `vm_stat` static began with.
    pub(crate) const fn zeroed() -> Self {
        Self {
            pagesize: 0,
            free_count: 0,
            active_count: 0,
            inactive_count: 0,
            wire_count: 0,
            zero_fill_count: 0,
            reactivations: 0,
            pageins: 0,
            pageouts: 0,
            faults: 0,
            cow_faults: 0,
            lookups: 0,
            hits: 0,
        }
    }
}

pub use crate::vm::vm_page::VmPage;
