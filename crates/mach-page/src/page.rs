// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The physical page descriptor.

use crate::param::VmOffset;
use crate::types::{PageFlags, VmProt};
use collections::tail_queue::{self, TailQueue};
use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::NonNull;

/// A physical page descriptor, owned by an `O`.
///
/// The segments keep one per physical page, whatever owns it.  The owner is
/// VM's object, which the allocator never reads, so the segment table holds
/// `Page<()>` and each call converts; `O` changes no field's layout.
///
/// C packs the three bitfield runs into two 32-bit words: `flags` carries
/// the wire count in bits 0 to 14 and the seventeen single-bit flags in bits
/// 15 to 31, and `LockBits` the rest.
#[repr(C)]
pub struct Page<O> {
    /// The link of a free list, a CPU pool or a page queue.
    pub node: tail_queue::Link,
    /// The link of an LRU queue.
    pub node_lru: tail_queue::Link,
    /// The owner's private data.
    pub priv_: *mut c_void,
    /// The physical address of the page.
    pub phys_addr: VmOffset,
    /// The link of the owning object's resident list.
    pub listq: tail_queue::Link,
    /// The next page in the owning object's hash bucket.
    pub next: *mut Self,
    /// The owning object, or null.
    pub object: *mut O,
    /// The page's offset in the owning object.
    pub offset: VmOffset,
    flags: PageFlags,
    lock_bits: LockBits,
}

const _: () = {
    assert!(size_of::<Page<()>>() == 96);
    assert!(align_of::<Page<()>>() == 8);
    assert!(offset_of!(Page<()>, node) == 0);
    assert!(offset_of!(Page<()>, node_lru) == 16);
    assert!(offset_of!(Page<()>, priv_) == 32);
    assert!(offset_of!(Page<()>, phys_addr) == 40);
    assert!(offset_of!(Page<()>, listq) == 48);
    assert!(offset_of!(Page<()>, next) == 64);
    assert!(offset_of!(Page<()>, object) == 72);
    assert!(offset_of!(Page<()>, offset) == 80);
    assert!(offset_of!(Page<()>, flags) == 88);
    assert!(offset_of!(Page<()>, lock_bits) == 92);
};

tail_queue::adapter!(
    /// The adapter for a page's `node` in the free lists and CPU pools.
    pub(crate) NodeAdapter = Page<()> { node }
);

/// A free list or a CPU pool, on the pages' `node`.
pub(crate) type NodeList = TailQueue<'static, NodeAdapter>;

// The links are two words, so the offsets above hold.
const _: () = assert!(size_of::<tail_queue::Link>() == 16);

/// The page type of a free page.
pub const PT_FREE: u16 = 0;
/// The page type of a reserved page, never handed out.
pub const PT_RESERVED: u16 = 1;
/// The page type of a page of the descriptor table itself.
pub const PT_TABLE: u16 = 2;

/// The number of buddy free lists, one per block order.
pub(crate) const NR_FREE_LISTS: usize = 11;

/// The order of a page that is not the head of a free block.
pub const ORDER_UNLISTED: u16 = (NR_FREE_LISTS + 1) as u16;

const _: () = assert!(ORDER_UNLISTED < 1 << 4);

bitfield::bitfield! {
    /// The count `flags` carries in bits 0 to 14, below the flags
    /// [`PageFlags`] names.
    struct FlagsCount(u32);
    u32;
    wire_count, set_wire_count: 14, 0;
}

bitfield::bitfield! {
    /// The descriptor's second word: `page_lock` in bits 0 to 2,
    /// `unlock_request` in bits 3 to 5, and the `unsigned short` run in bits
    /// 8 to 15, `type`, `seg_index` and `order`.  Bits 6 and 7 are the C
    /// compiler's hole between the two runs.
    #[derive(Clone, Copy)]
    struct LockBits(u32);
    u8;
    page_lock, set_page_lock: 2, 0;
    unlock_request, set_unlock_request: 5, 3;
    u16;
    page_type, set_page_type: 9, 8;
    seg_index, set_seg_index: 11, 10;
    order, set_order: 15, 12;
}

#[expect(
    missing_docs,
    reason = "the accessors mirror the C bitfields one for one; the flags \
              and `LockBits` carry the documentation, and a doc per \
              getter/setter pair would only respell the field name"
)]
impl<O> Page<O> {
    /// `wire_count`; the C bitfield holds fifteen bits.
    #[must_use]
    pub fn wire_count(&self) -> u32 {
        FlagsCount(self.flags.bits()).wire_count()
    }

    pub fn set_wire_count(&mut self, count: u32) {
        let mut word = FlagsCount(self.flags.bits());
        word.set_wire_count(count);
        self.flags = PageFlags::from_bits_retain(word.0);
    }

    #[must_use]
    pub const fn is_inactive(&self) -> bool {
        self.flag(PageFlags::INACTIVE)
    }
    pub const fn set_inactive(&mut self, on: bool) {
        self.set_flag(PageFlags::INACTIVE, on);
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.flag(PageFlags::ACTIVE)
    }
    pub const fn set_active(&mut self, on: bool) {
        self.set_flag(PageFlags::ACTIVE, on);
    }

    #[must_use]
    pub const fn is_laundry(&self) -> bool {
        self.flag(PageFlags::LAUNDRY)
    }
    pub const fn set_laundry(&mut self, on: bool) {
        self.set_flag(PageFlags::LAUNDRY, on);
    }

    #[must_use]
    pub const fn is_external_laundry(&self) -> bool {
        self.flag(PageFlags::EXTERNAL_LAUNDRY)
    }
    pub const fn set_external_laundry(&mut self, on: bool) {
        self.set_flag(PageFlags::EXTERNAL_LAUNDRY, on);
    }

    #[must_use]
    pub const fn is_free(&self) -> bool {
        self.flag(PageFlags::FREE)
    }
    pub const fn set_free(&mut self, on: bool) {
        self.set_flag(PageFlags::FREE, on);
    }

    #[must_use]
    pub const fn is_reference(&self) -> bool {
        self.flag(PageFlags::REFERENCE)
    }
    pub const fn set_reference(&mut self, on: bool) {
        self.set_flag(PageFlags::REFERENCE, on);
    }

    #[must_use]
    pub const fn is_external(&self) -> bool {
        self.flag(PageFlags::EXTERNAL)
    }
    pub const fn set_external(&mut self, on: bool) {
        self.set_flag(PageFlags::EXTERNAL, on);
    }

    #[must_use]
    pub const fn is_busy(&self) -> bool {
        self.flag(PageFlags::BUSY)
    }
    pub const fn set_busy(&mut self, on: bool) {
        self.set_flag(PageFlags::BUSY, on);
    }

    #[must_use]
    pub const fn is_wanted(&self) -> bool {
        self.flag(PageFlags::WANTED)
    }
    pub const fn set_wanted(&mut self, on: bool) {
        self.set_flag(PageFlags::WANTED, on);
    }

    #[must_use]
    pub const fn is_tabled(&self) -> bool {
        self.flag(PageFlags::TABLED)
    }
    pub const fn set_tabled(&mut self, on: bool) {
        self.set_flag(PageFlags::TABLED, on);
    }

    #[must_use]
    pub const fn is_fictitious(&self) -> bool {
        self.flag(PageFlags::FICTITIOUS)
    }
    pub const fn set_fictitious(&mut self, on: bool) {
        self.set_flag(PageFlags::FICTITIOUS, on);
    }

    #[must_use]
    pub const fn is_private(&self) -> bool {
        self.flag(PageFlags::PRIVATE)
    }
    pub const fn set_private(&mut self, on: bool) {
        self.set_flag(PageFlags::PRIVATE, on);
    }

    #[must_use]
    pub const fn is_absent(&self) -> bool {
        self.flag(PageFlags::ABSENT)
    }
    pub const fn set_absent(&mut self, on: bool) {
        self.set_flag(PageFlags::ABSENT, on);
    }

    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.flag(PageFlags::ERROR)
    }
    pub const fn set_error(&mut self, on: bool) {
        self.set_flag(PageFlags::ERROR, on);
    }

    #[must_use]
    pub const fn is_dirty(&self) -> bool {
        self.flag(PageFlags::DIRTY)
    }
    pub const fn set_dirty(&mut self, on: bool) {
        self.set_flag(PageFlags::DIRTY, on);
    }

    #[must_use]
    pub const fn is_precious(&self) -> bool {
        self.flag(PageFlags::PRECIOUS)
    }
    pub const fn set_precious(&mut self, on: bool) {
        self.set_flag(PageFlags::PRECIOUS, on);
    }

    #[must_use]
    pub const fn is_overwriting(&self) -> bool {
        self.flag(PageFlags::OVERWRITING)
    }
    const fn flag(&self, bit: PageFlags) -> bool {
        self.flags.contains(bit)
    }

    const fn set_flag(&mut self, bit: PageFlags, on: bool) {
        self.flags = if on {
            self.flags.union(bit)
        } else {
            self.flags.difference(bit)
        };
    }

    #[must_use]
    pub fn page_lock(&self) -> VmProt {
        VmProt::from_bits_retain(c_int::from(self.lock_bits.page_lock()))
    }

    pub fn set_page_lock(&mut self, protection: VmProt) {
        // The field keeps the low three bits, as the C bitfield did.
        self.lock_bits.set_page_lock(protection.bits() as u8);
    }

    #[must_use]
    pub fn unlock_request(&self) -> VmProt {
        VmProt::from_bits_retain(c_int::from(self.lock_bits.unlock_request()))
    }

    pub fn set_unlock_request(&mut self, protection: VmProt) {
        // The field keeps the low three bits, as the C bitfield did.
        self.lock_bits.set_unlock_request(protection.bits() as u8);
    }

    #[must_use]
    pub fn page_type(&self) -> u16 {
        self.lock_bits.page_type()
    }

    pub fn set_page_type(&mut self, type_: u16) {
        self.lock_bits.set_page_type(type_);
    }

    #[must_use]
    pub fn seg_index(&self) -> u16 {
        self.lock_bits.seg_index()
    }

    pub fn set_seg_index(&mut self, index: u16) {
        self.lock_bits.set_seg_index(index);
    }

    #[must_use]
    pub fn order(&self) -> u16 {
        self.lock_bits.order()
    }

    pub fn set_order(&mut self, order: u16) {
        self.lock_bits.set_order(order);
    }

    /// Copies `src`'s object, offset and flags into this page, keeping its own
    /// `type`, `seg_index` and `order`.
    pub fn copy_body_from(&mut self, src: &Self) {
        self.object = src.object;
        self.offset = src.offset;
        self.flags = src.flags;
        self.lock_bits.set_page_lock(src.lock_bits.page_lock());
        self.lock_bits
            .set_unlock_request(src.lock_bits.unlock_request());
    }
}

/// Stamps `type_` on a run of `1 << order` pages.
///
/// # Safety
///
/// `page` must point at the first of `1 << order` live, contiguous page
/// descriptors, and the caller must serialize access to them.
pub unsafe fn set_type<O>(page: NonNull<Page<O>>, order: c_uint, type_: u16) {
    // The C shifted an `int` by `order`, and x86 masks the count; the
    // wrapping shift spells the same placement.
    let nr_pages = 1u32.wrapping_shl(order);

    for i in 0..nr_pages {
        // The cast cannot truncate: `i < nr_pages` and `usize` is at least
        // 32 bits wide.
        let offset = i as usize;
        unsafe { (*page.as_ptr().add(offset)).set_page_type(type_) };
    }
}
