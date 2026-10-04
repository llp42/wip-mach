// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from vm/vm_page.c and vm/vm_page.h:
//   Copyright (c) 2010-2014 Richard Braun.
//   Copyright (c) 1993-1988 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The physical-page module, which `vm/vm_page.c` used to define, and the
//! `struct vm_page` mirror of `vm/vm_page.h`.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::{PAGE_SHIFT, PAGE_SIZE};
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::pmap::kernel_pmap_ptr;
use crate::arch::x86_64::pmap::pmap_clear_modify;
use crate::arch::x86_64::pmap::pmap_clear_reference;
use crate::arch::x86_64::pmap::pmap_extract;
use crate::arch::x86_64::pmap::pmap_is_modified;
use crate::arch::x86_64::pmap::pmap_is_referenced;
use crate::arch::x86_64::pmap::pmap_page_protect;
use crate::config::MAX_NCPUS;
use crate::kern::console::{CStrArg, kprint};
use crate::kern::debug::kpanic;
use crate::kern::lock::SimpleLock;
use crate::kern::sched_prim::{
    THREAD_AWAKENED, assert_wait, thread_block, thread_wakeup_prim,
};
use crate::utils::cell::SyncCell;
use crate::vm::memory_object::default_manager;
use crate::vm::types::{VmObject, VmProt};
use crate::vm::vm_object;
use crate::vm::vm_pageout::{vm_pageout_page, vm_pageout_start};
use crate::vm::vm_resident;
use crate::vm::vm_resident::VM_PAGE_FICTITIOUS_ADDR;
use crate::vm::vm_resident::VM_PAGE_QUEUE_FREE_LOCK;
use crate::vm::vm_resident::VM_PAGE_QUEUE_LOCK;
use crate::vm::vm_user::VM_STAT;
use collections::tail_queue::{self, TailQueue};
use core::cell::UnsafeCell;
use core::cmp::min;
use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::pin::Pin;
use core::ptr::{self, NonNull, addr_of_mut, null_mut};
use core::sync::atomic::{AtomicBool, Ordering};

/// `struct vm_page` of <`vm/vm_page.h`>.
///
/// C packs the three bitfield runs into two 32-bit words, and the accessors
/// below mask and shift within them in declaration order:
///
/// * `flags` carries `wire_count` in bits 0 to 14 and the seventeen
///   single-bit flags from bit 15 to bit 31, `inactive` through
///   `overwriting`.
/// * `lock_bits` carries `page_lock` in bits 0 to 2, `unlock_request` in
///   bits 3 to 5, and the `unsigned short` run in bits 8 to 15: `type` in
///   bits 8 and 9, `seg_index` in bits 10 and 11, `order` in bits 12 to 15.
///   Bits 6 and 7 are the C compiler's hole between the two runs.
#[repr(C)]
#[allow(missing_docs)]
pub struct VmPage {
    pub node: tail_queue::Link,
    pub node_lru: tail_queue::Link,
    /// The C `priv`.
    pub priv_: *mut c_void,
    pub phys_addr: VmOffset,
    pub listq: tail_queue::Link,
    pub next: *mut Self,
    pub object: *mut VmObject,
    pub offset: VmOffset,
    flags: u32,
    lock_bits: u32,
}

const _: () = {
    assert!(size_of::<VmPage>() == 96);
    assert!(align_of::<VmPage>() == 8);
    assert!(offset_of!(VmPage, node) == 0);
    assert!(offset_of!(VmPage, node_lru) == 16);
    assert!(offset_of!(VmPage, priv_) == 32);
    assert!(offset_of!(VmPage, phys_addr) == 40);
    assert!(offset_of!(VmPage, listq) == 48);
    assert!(offset_of!(VmPage, next) == 64);
    assert!(offset_of!(VmPage, object) == 72);
    assert!(offset_of!(VmPage, offset) == 80);
    assert!(offset_of!(VmPage, flags) == 88);
    assert!(offset_of!(VmPage, lock_bits) == 92);
};

tail_queue::adapter!(
    /// The adapter for a page's `node` in the free lists, CPU pools and page
    /// queues.
    pub VmPageNodeAdapter = VmPage { node }
);

tail_queue::adapter!(
    /// The adapter for a page's `node_lru` in the LRU queues.
    pub VmPageLruAdapter = VmPage { node_lru }
);

tail_queue::adapter!(
    /// The adapter for a page's `listq` in its object's resident list.
    pub VmPageListqAdapter = VmPage { listq }
);

/// A queue of pages on their `node`: a buddy free list, a CPU pool, a segment
/// page queue, or the fictitious pages.
///
/// All of them share the link, so it takes the strictest need: `push_back`
/// on the page queues, and removal from the middle in O(1).
pub type NodeList = TailQueue<'static, VmPageNodeAdapter>;

/// A global LRU queue, on the pages' `node_lru`.
pub type LruList = TailQueue<'static, VmPageLruAdapter>;

/// An object's resident pages, on their `listq`.
pub type ListqList = TailQueue<'static, VmPageListqAdapter>;

// The links are two words, so the offsets above hold.
const _: () = assert!(size_of::<tail_queue::Link>() == 16);

/// Pins a queue head of `STATE`.
///
/// # Safety
///
/// `head` must be a field of `STATE`, which never moves.
const unsafe fn pin_head<'a, A: tail_queue::Adapter>(
    head: &'a mut TailQueue<'static, A>,
) -> Pin<&'a mut TailQueue<'static, A>> {
    // SAFETY: the caller promises the head never moves.
    unsafe { Pin::new_unchecked(head) }
}

const WIRE_COUNT_MASK: u32 = 0x7fff;
const INACTIVE_BIT: u32 = 1 << 15;
const ACTIVE_BIT: u32 = 1 << 16;
const LAUNDRY_BIT: u32 = 1 << 17;
const EXTERNAL_LAUNDRY_BIT: u32 = 1 << 18;
const FREE_BIT: u32 = 1 << 19;
const REFERENCE_BIT: u32 = 1 << 20;
const EXTERNAL_BIT: u32 = 1 << 21;
const BUSY_BIT: u32 = 1 << 22;
const WANTED_BIT: u32 = 1 << 23;
const TABLED_BIT: u32 = 1 << 24;
const FICTITIOUS_BIT: u32 = 1 << 25;
const PRIVATE_BIT: u32 = 1 << 26;
const ABSENT_BIT: u32 = 1 << 27;
const ERROR_BIT: u32 = 1 << 28;
const DIRTY_BIT: u32 = 1 << 29;
const PRECIOUS_BIT: u32 = 1 << 30;
const OVERWRITING_BIT: u32 = 1 << 31;

const PAGE_LOCK_SHIFT: u32 = 0;
const PAGE_LOCK_MASK: u32 = 0x7;
const UNLOCK_REQUEST_SHIFT: u32 = 3;
const UNLOCK_REQUEST_MASK: u32 = 0x7;
const TYPE_SHIFT: u32 = 8;
const TYPE_MASK: u32 = 0x3;
const SEG_INDEX_SHIFT: u32 = 10;
const SEG_INDEX_MASK: u32 = 0x3;
const ORDER_SHIFT: u32 = 12;
const ORDER_MASK: u32 = 0xf;

// These accessors mirror the C bitfields one for one; the bit and mask
// constants above carry the documentation, and a doc per getter/setter
// pair would only respell the field name.
#[allow(missing_docs)]
impl VmPage {
    /// `wire_count`; the C bitfield holds fifteen bits.
    #[must_use]
    pub const fn wire_count(&self) -> u32 {
        self.flags & WIRE_COUNT_MASK
    }

    pub const fn set_wire_count(&mut self, count: u32) {
        self.flags =
            (self.flags & !WIRE_COUNT_MASK) | (count & WIRE_COUNT_MASK);
    }

    #[must_use]
    pub const fn is_inactive(&self) -> bool {
        self.flag(INACTIVE_BIT)
    }
    pub const fn set_inactive(&mut self, on: bool) {
        self.set_flag(INACTIVE_BIT, on);
    }

    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.flag(ACTIVE_BIT)
    }
    pub const fn set_active(&mut self, on: bool) {
        self.set_flag(ACTIVE_BIT, on);
    }

    #[must_use]
    pub const fn is_laundry(&self) -> bool {
        self.flag(LAUNDRY_BIT)
    }
    pub const fn set_laundry(&mut self, on: bool) {
        self.set_flag(LAUNDRY_BIT, on);
    }

    #[must_use]
    pub const fn is_external_laundry(&self) -> bool {
        self.flag(EXTERNAL_LAUNDRY_BIT)
    }
    pub const fn set_external_laundry(&mut self, on: bool) {
        self.set_flag(EXTERNAL_LAUNDRY_BIT, on);
    }

    #[must_use]
    pub const fn is_free(&self) -> bool {
        self.flag(FREE_BIT)
    }
    pub const fn set_free(&mut self, on: bool) {
        self.set_flag(FREE_BIT, on);
    }

    #[must_use]
    pub const fn is_reference(&self) -> bool {
        self.flag(REFERENCE_BIT)
    }
    pub const fn set_reference(&mut self, on: bool) {
        self.set_flag(REFERENCE_BIT, on);
    }

    #[must_use]
    pub const fn is_external(&self) -> bool {
        self.flag(EXTERNAL_BIT)
    }
    pub const fn set_external(&mut self, on: bool) {
        self.set_flag(EXTERNAL_BIT, on);
    }

    #[must_use]
    pub const fn is_busy(&self) -> bool {
        self.flag(BUSY_BIT)
    }
    pub const fn set_busy(&mut self, on: bool) {
        self.set_flag(BUSY_BIT, on);
    }

    #[must_use]
    pub const fn is_wanted(&self) -> bool {
        self.flag(WANTED_BIT)
    }
    pub const fn set_wanted(&mut self, on: bool) {
        self.set_flag(WANTED_BIT, on);
    }

    #[must_use]
    pub const fn is_tabled(&self) -> bool {
        self.flag(TABLED_BIT)
    }
    pub const fn set_tabled(&mut self, on: bool) {
        self.set_flag(TABLED_BIT, on);
    }

    #[must_use]
    pub const fn is_fictitious(&self) -> bool {
        self.flag(FICTITIOUS_BIT)
    }
    pub const fn set_fictitious(&mut self, on: bool) {
        self.set_flag(FICTITIOUS_BIT, on);
    }

    #[must_use]
    pub const fn is_private(&self) -> bool {
        self.flag(PRIVATE_BIT)
    }
    pub const fn set_private(&mut self, on: bool) {
        self.set_flag(PRIVATE_BIT, on);
    }

    #[must_use]
    pub const fn is_absent(&self) -> bool {
        self.flag(ABSENT_BIT)
    }
    pub const fn set_absent(&mut self, on: bool) {
        self.set_flag(ABSENT_BIT, on);
    }

    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.flag(ERROR_BIT)
    }
    pub const fn set_error(&mut self, on: bool) {
        self.set_flag(ERROR_BIT, on);
    }

    #[must_use]
    pub const fn is_dirty(&self) -> bool {
        self.flag(DIRTY_BIT)
    }
    pub const fn set_dirty(&mut self, on: bool) {
        self.set_flag(DIRTY_BIT, on);
    }

    #[must_use]
    pub const fn is_precious(&self) -> bool {
        self.flag(PRECIOUS_BIT)
    }
    pub const fn set_precious(&mut self, on: bool) {
        self.set_flag(PRECIOUS_BIT, on);
    }

    #[must_use]
    pub const fn is_overwriting(&self) -> bool {
        self.flag(OVERWRITING_BIT)
    }
    pub const fn set_overwriting(&mut self, on: bool) {
        self.set_flag(OVERWRITING_BIT, on);
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

    #[must_use]
    pub const fn page_lock(&self) -> VmProt {
        // The mask bounds the field to three bits, so it fits a `c_int`.
        VmProt::from_bits((self.lock_bits & PAGE_LOCK_MASK) as c_int)
    }

    pub const fn set_page_lock(&mut self, protection: VmProt) {
        self.set_lock_field(
            PAGE_LOCK_SHIFT,
            PAGE_LOCK_MASK,
            protection.bits() as u32,
        );
    }

    #[must_use]
    pub const fn unlock_request(&self) -> VmProt {
        VmProt::from_bits(
            self.lock_field(UNLOCK_REQUEST_SHIFT, UNLOCK_REQUEST_MASK)
                as c_int,
        )
    }

    pub const fn set_unlock_request(&mut self, protection: VmProt) {
        self.set_lock_field(
            UNLOCK_REQUEST_SHIFT,
            UNLOCK_REQUEST_MASK,
            protection.bits() as u32,
        );
    }

    #[must_use]
    pub const fn page_type(&self) -> u16 {
        self.lock_field(TYPE_SHIFT, TYPE_MASK) as u16
    }

    pub fn set_page_type(&mut self, type_: u16) {
        self.set_lock_field(TYPE_SHIFT, TYPE_MASK, u32::from(type_));
    }

    #[must_use]
    pub const fn seg_index(&self) -> u16 {
        self.lock_field(SEG_INDEX_SHIFT, SEG_INDEX_MASK) as u16
    }

    pub fn set_seg_index(&mut self, index: u16) {
        self.set_lock_field(SEG_INDEX_SHIFT, SEG_INDEX_MASK, u32::from(index));
    }

    #[must_use]
    pub const fn order(&self) -> u16 {
        self.lock_field(ORDER_SHIFT, ORDER_MASK) as u16
    }

    pub fn set_order(&mut self, order: u16) {
        self.set_lock_field(ORDER_SHIFT, ORDER_MASK, u32::from(order));
    }

    const fn lock_field(&self, shift: u32, mask: u32) -> u32 {
        (self.lock_bits >> shift) & mask
    }

    const fn set_lock_field(&mut self, shift: u32, mask: u32, value: u32) {
        self.lock_bits =
            (self.lock_bits & !(mask << shift)) | ((value & mask) << shift);
    }

    /// `memcpy(&dest->vm_page_header, &src->vm_page_header,
    /// VM_PAGE_BODY_SIZE)` of `vm_page_seg_balance_page()`: copy `object`,
    /// `offset` and the flags, keeping the destination's own `type`,
    /// `seg_index` and `order`.
    pub(crate) const fn copy_body_from(&mut self, src: &Self) {
        self.object = src.object;
        self.offset = src.offset;
        self.flags = src.flags;
        self.lock_bits = (self.lock_bits & !BODY_LOCK_BITS)
            | (src.lock_bits & BODY_LOCK_BITS);
    }
}

/// The `VM_PAGE_BODY_SIZE` bytes of the C struct: `lock_bits` bits 0 to 7,
/// below the `type`/`seg_index`/`order` run the body copy leaves alone.
const BODY_LOCK_BITS: u32 =
    PAGE_LOCK_MASK | (UNLOCK_REQUEST_MASK << UNLOCK_REQUEST_SHIFT);

/// `vm_page_set_type()` in C: stamp `type` on a run of `1 << order` pages.
///
/// # Safety
///
/// `page` must point at the first of `1 << order` live, contiguous page
/// descriptors, and the caller must serialize access to them.
pub(crate) unsafe fn set_type(
    page: NonNull<VmPage>,
    order: c_uint,
    type_: u16,
) {
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

/// `vm_page_wire()` in C: mark the page wired down by yet another map,
/// removing it from the paging queues when it was unwired.
///
/// # Safety
///
/// `page` must be a live page, and the caller must hold its object lock and
/// the page-queues lock, as the C requires.
pub(crate) unsafe fn wire(page: NonNull<VmPage>) {
    let ptr = page.as_ptr();

    unsafe { check(ptr) };

    if unsafe { (*ptr).wire_count() } == 0 {
        unsafe { queues_remove(ptr) };

        // SAFETY: the page-queues lock guards the page's flags.
        if !unsafe { (*ptr).is_private() }
            && !unsafe { (*ptr).is_fictitious() }
        {
            // The page-queues lock guards the global count, as in the C;
            // the atomic only makes the update indivisible.
            vm_resident::VM_PAGE_WIRE_COUNT.fetch_add(1, Ordering::Relaxed);
        }
    }

    // SAFETY: the page is live and the caller's locks serialize the field.
    unsafe { (*ptr).set_wire_count((*ptr).wire_count() + 1) };
}

/// `VM_PAGE_SEG_DMA` of <`machine/vm_param.h`>.
pub(crate) const SEG_DMA: c_uint = 0;
/// `VM_PAGE_SEG_DIRECTMAP` of <`machine/vm_param.h`>.
pub(crate) const SEG_DIRECTMAP: c_uint = 1;
/// `VM_PAGE_SEG_DMA32` of <`machine/vm_param.h`>.
pub(crate) const SEG_DMA32: c_uint = 2;
/// `VM_PAGE_SEG_HIGHMEM` of <`machine/vm_param.h`>.
pub(crate) const SEG_HIGHMEM: c_uint = 3;

/// `vm_page_seg_name()` in C: the name of a physical segment index.
pub(crate) const fn seg_name(seg_index: c_uint) -> Option<&'static CStr> {
    if seg_index == SEG_HIGHMEM {
        Some(c"HIGHMEM")
    } else if seg_index == SEG_DIRECTMAP {
        Some(c"DIRECTMAP")
    } else if seg_index == SEG_DMA32 {
        Some(c"DMA32")
    } else if seg_index == SEG_DMA {
        Some(c"DMA")
    } else {
        None
    }
}

/// `VM_PAGE_MAX_SEGS` of <`machine/vm_param.h>`: the number of physical
/// segments.
pub(crate) const VM_PAGE_MAX_SEGS: usize = 4;

/// `VM_PAGE_SEL_*` of <`vm/vm_page.h>`: the selectors `vm_page_grab()` and
/// `vm_page_alloc_pa()` take, ordered by physical reach.
pub(crate) const SEL_DMA: c_uint = 0;
pub(crate) const SEL_DIRECTMAP: c_uint = 1;
pub(crate) const SEL_DMA32: c_uint = 2;
pub(crate) const SEL_HIGHMEM: c_uint = 3;

/// `VM_PT_FREE`, `VM_PT_RESERVED` and `VM_PT_TABLE` of <`vm/vm_page.h`>;
/// `VM_PT_KERNEL` lives in `vm_resident.rs`.
const VM_PT_FREE: u16 = 0;
const VM_PT_RESERVED: u16 = 1;
const VM_PT_TABLE: u16 = 2;

/// `VM_PAGE_NR_FREE_LISTS` of `vm_page.c`.
const VM_PAGE_NR_FREE_LISTS: usize = 11;

/// `VM_PAGE_ORDER_UNLISTED`: a page that is not the head of a free block.
const VM_PAGE_ORDER_UNLISTED: u16 = (VM_PAGE_NR_FREE_LISTS + 1) as u16;

const VM_PAGE_CPU_POOL_RATIO: usize = 1024;
const VM_PAGE_CPU_POOL_MAX_SIZE: usize = 128;
const VM_PAGE_CPU_POOL_TRANSFER_RATIO: usize = 2;

const VM_PAGE_SEG_THRESHOLD_MIN_NUM: usize = 5;
const VM_PAGE_SEG_THRESHOLD_MIN_DENOM: usize = 100;
const VM_PAGE_SEG_THRESHOLD_MIN: usize = 500;
const VM_PAGE_SEG_THRESHOLD_LOW_NUM: usize = 6;
const VM_PAGE_SEG_THRESHOLD_LOW_DENOM: usize = 100;
const VM_PAGE_SEG_THRESHOLD_LOW: usize = 600;
const VM_PAGE_SEG_THRESHOLD_HIGH_NUM: usize = 10;
const VM_PAGE_SEG_THRESHOLD_HIGH_DENOM: usize = 100;
const VM_PAGE_SEG_THRESHOLD_HIGH: usize = 1000;
const VM_PAGE_SEG_MIN_PAGES: usize = 2000;

const VM_PAGE_HIGH_ACTIVE_PAGE_NUM: usize = 1;
const VM_PAGE_HIGH_ACTIVE_PAGE_DENOM: usize = 3;

const VM_PAGE_MAX_LAUNDRY: c_int = 5;
const VM_PAGE_MAX_EVICTIONS: usize = 5;

const _: () = assert!(VM_PAGE_ORDER_UNLISTED < 1 << 4);
const _: () = assert!(VM_PAGE_SEG_THRESHOLD_LOW > VM_PAGE_SEG_THRESHOLD_MIN);
const _: () = assert!(VM_PAGE_SEG_THRESHOLD_HIGH > VM_PAGE_SEG_THRESHOLD_LOW);
const _: () = assert!(VM_PAGE_SEG_MIN_PAGES > VM_PAGE_SEG_THRESHOLD_HIGH);

/// `vm_page_atop()` of <`vm/vm_page.h>`: a byte address to a page number.
pub(crate) const fn atop(addr: VmOffset) -> usize {
    addr >> PAGE_SHIFT
}

/// `vm_page_ptoa()` of <`vm/vm_page.h>`: a page number to a byte address.
pub(crate) const fn ptoa(page: usize) -> VmOffset {
    page << PAGE_SHIFT
}

/// `vm_page_round()` of <`vm/vm_page.h`>.
pub(crate) const fn round_page(addr: VmOffset) -> VmOffset {
    addr.wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// `panic()` of `vm_page.c`.
fn die(func: &'static str, message: &'static str) -> ! {
    kpanic!(func, "{}", message)
}

/// `struct vm_page_cpu_pool` of `vm_page.c`.
struct CpuPool {
    lock: SimpleLock,
    size: c_int,
    transfer_size: c_int,
    nr_pages: c_int,
    pages: NodeList,
}

impl CpuPool {
    const fn new() -> Self {
        Self {
            lock: SimpleLock::new(),
            size: 0,
            transfer_size: 0,
            nr_pages: 0,
            pages: NodeList::new(),
        }
    }
}

/// `struct vm_page_free_list` of `vm_page.c`.
struct FreeList {
    size: usize,
    blocks: NodeList,
}

impl FreeList {
    const fn new() -> Self {
        Self {
            size: 0,
            blocks: NodeList::new(),
        }
    }
}

/// `struct vm_page_list` of `vm_page.c`.
struct PageList {
    pages: NodeList,
    nr_pages: usize,
}

impl PageList {
    const fn new() -> Self {
        Self {
            pages: NodeList::new(),
            nr_pages: 0,
        }
    }
}

/// `struct vm_page_queue` of `vm_page.c`.
struct PageQueue {
    internal: PageList,
    external: PageList,
}

impl PageQueue {
    const fn new() -> Self {
        Self {
            internal: PageList::new(),
            external: PageList::new(),
        }
    }
}

/// `struct vm_page_lru_queue` of `vm_page.c`.
struct LruQueue {
    internal: LruList,
    external: LruList,
}

impl LruQueue {
    const fn new() -> Self {
        Self {
            internal: LruList::new(),
            external: LruList::new(),
        }
    }
}

/// `struct vm_page_seg` of `vm_page.c`.  File-private after this port, so
/// it keeps Rust layout.
struct VmPageSeg {
    cpu_pools: [CpuPool; MAX_NCPUS],
    start: VmOffset,
    end: VmOffset,
    pages: *mut VmPage,
    pages_end: *mut VmPage,
    lock: SimpleLock,
    free_lists: [FreeList; VM_PAGE_NR_FREE_LISTS],
    nr_free_pages: usize,
    min_free_pages: usize,
    low_free_pages: usize,
    high_free_pages: usize,
    active_pages: PageQueue,
    high_active_pages: usize,
    inactive_pages: PageQueue,
}

impl VmPageSeg {
    const fn new() -> Self {
        Self {
            cpu_pools: [const { CpuPool::new() }; MAX_NCPUS],
            start: 0,
            end: 0,
            pages: null_mut(),
            pages_end: null_mut(),
            lock: SimpleLock::new(),
            free_lists: [const { FreeList::new() }; VM_PAGE_NR_FREE_LISTS],
            nr_free_pages: 0,
            min_free_pages: 0,
            low_free_pages: 0,
            high_free_pages: 0,
            active_pages: PageQueue::new(),
            high_active_pages: 0,
            inactive_pages: PageQueue::new(),
        }
    }
}

/// `struct vm_page_boot_seg` of `vm_page.c`.
struct BootSeg {
    start: VmOffset,
    end: VmOffset,
    heap_present: bool,
    avail_start: VmOffset,
    avail_end: VmOffset,
}

impl BootSeg {
    const fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            heap_present: false,
            avail_start: 0,
            avail_end: 0,
        }
    }
}

/// The module's `static` state: the segment table, the boot table and the
/// two LRU queues the C kept at file scope.  The C locks serialize it.
struct PageState {
    segs: [VmPageSeg; VM_PAGE_MAX_SEGS],
    boot_segs: [BootSeg; VM_PAGE_MAX_SEGS],
    segs_size: u32,
    is_ready: bool,
    alloc_paused: bool,
    active_lru: LruQueue,
    inactive_lru: LruQueue,
}

impl PageState {
    const fn new() -> Self {
        Self {
            segs: [const { VmPageSeg::new() }; VM_PAGE_MAX_SEGS],
            boot_segs: [const { BootSeg::new() }; VM_PAGE_MAX_SEGS],
            segs_size: 0,
            is_ready: false,
            alloc_paused: false,
            active_lru: LruQueue::new(),
            inactive_lru: LruQueue::new(),
        }
    }
}

static STATE: SyncCell<PageState> =
    SyncCell(UnsafeCell::new(PageState::new()));

/// The C `static boolean_t warned` of `vm_page_evict()`.
static WARNED: AtomicBool = AtomicBool::new(false);

fn state() -> *mut PageState {
    STATE.0.get()
}

/// The segment at `index`, which every caller keeps below
/// `VM_PAGE_MAX_SEGS`, as the C's unguarded array indexing assumed.
fn seg_ptr(index: usize) -> *mut VmPageSeg {
    debug_assert!(index < VM_PAGE_MAX_SEGS);
    // SAFETY: the caller promises `index` is in range; the array is static
    // storage that never moves.
    unsafe { addr_of_mut!((*state()).segs).cast::<VmPageSeg>().add(index) }
}

fn segs_size() -> usize {
    // SAFETY: the state is live for the kernel's lifetime.
    unsafe { (*state()).segs_size as usize }
}

/// The boot segment at `index`.
///
/// # Safety
///
/// `index` must be below `VM_PAGE_MAX_SEGS`.
unsafe fn boot_seg(index: usize) -> *mut BootSeg {
    if index >= VM_PAGE_MAX_SEGS {
        die("vm_page_load", "vm_page: invalid segment index");
    }
    // SAFETY: the check above bounds the index.
    unsafe {
        addr_of_mut!((*state()).boot_segs)
            .cast::<BootSeg>()
            .add(index)
    }
}

/// `vm_page_init_pa()` in C.
///
/// # Safety
///
/// `page` must point at writable storage for one descriptor, not yet visible
/// to any other thread.
unsafe fn init_pa(page: *mut VmPage, seg_index: u16, pa: VmOffset) {
    unsafe {
        ptr::write_bytes(page, 0, 1);
        vm_resident::init(&mut *page);
        (*page).set_page_type(VM_PT_RESERVED);
        (*page).set_seg_index(seg_index);
        (*page).set_order(VM_PAGE_ORDER_UNLISTED);
        (*page).priv_ = null_mut();
        (*page).phys_addr = pa;
    }
}

/// `vm_page_pageable()` in C.
///
/// # Safety
///
/// `page` must be a live descriptor.
const unsafe fn pageable(page: *const VmPage) -> bool {
    unsafe {
        !(*page).object.is_null()
            && (*page).wire_count() == 0
            && ((*page).is_active() || (*page).is_inactive())
    }
}

/// `vm_page_can_move()` in C.
///
/// # Safety
///
/// `page` must be a live descriptor on a page queue, holding its object
/// lock, as the C's callers did.
unsafe fn can_move(page: *const VmPage) -> bool {
    unsafe {
        !(*page).is_busy()
            && !(*page).is_wanted()
            && !(*page).is_absent()
            && (*(*page).object).is_alive()
    }
}

/// `vm_page_remove_mappings()` in C.
///
/// # Safety
///
/// `page` must be a live descriptor.
unsafe fn remove_mappings(page: *mut VmPage) {
    unsafe {
        (*page).set_busy(true);
        pmap_page_protect((*page).phys_addr, VmProt::NONE.bits());
        if !(*page).is_dirty() {
            (*page).set_dirty(pmap_is_modified((*page).phys_addr) != 0);
        }
    }
}

/// `vm_page_free_list_init()` in C.
const fn free_list_init(free_list: &mut FreeList) {
    free_list.size = 0;
    free_list.blocks = NodeList::new();
}

/// `vm_page_free_list_insert()` in C.
fn free_list_insert(free_list: &mut FreeList, page: *mut VmPage) {
    free_list.size += 1;
    // SAFETY: the free list is in `STATE`; the caller holds the segment lock,
    // and the page descriptor stays at its address while linked.
    unsafe {
        pin_head(&mut free_list.blocks)
            .push_front_ptr(NonNull::new_unchecked(page));
    }
}

/// `vm_page_free_list_remove()` in C.
fn free_list_remove(free_list: &mut FreeList, page: *mut VmPage) {
    free_list.size -= 1;
    // SAFETY: the free list is in `STATE`; the caller holds the segment lock,
    // and the page is linked in this free list.
    unsafe {
        pin_head(&mut free_list.blocks)
            .remove_ptr(NonNull::new_unchecked(page));
    }
}

/// `vm_page_cpu_pool_init()` in C.
fn cpu_pool_init(cpu_pool: &mut CpuPool, size: c_int) {
    cpu_pool.lock.init();
    cpu_pool.size = size;
    cpu_pool.transfer_size =
        (size + (VM_PAGE_CPU_POOL_TRANSFER_RATIO as c_int) - 1)
            / (VM_PAGE_CPU_POOL_TRANSFER_RATIO as c_int);
    cpu_pool.nr_pages = 0;
    cpu_pool.pages = NodeList::new();
}

/// `vm_page_cpu_pool_get()` in C.
///
/// # Safety
///
/// `seg` must be a live segment.
unsafe fn cpu_pool_get(seg: *mut VmPageSeg) -> *mut CpuPool {
    // SAFETY: `cpu_id()` is below `MAX_NCPUS`, the array's length, so the
    // element the offset reaches is inside the array.
    unsafe {
        addr_of_mut!((*seg).cpu_pools)
            .cast::<CpuPool>()
            .add(cpu_id().as_usize())
    }
}

/// `vm_page_cpu_pool_pop()` in C.
///
/// # Safety
///
/// The pool lock must be held and the pool must not be empty.
fn cpu_pool_pop(cpu_pool: &mut CpuPool) -> *mut VmPage {
    cpu_pool.nr_pages -= 1;
    // SAFETY: the pool is in `STATE`, and the caller holds its lock.
    let page = unsafe { pin_head(&mut cpu_pool.pages) }
        .cursor_front_mut()
        .remove_current();
    let Some(page) = page else {
        die("vm_page_cpu_pool_pop", "vm_page: empty CPU pool");
    };
    ptr::from_mut(page)
}

/// `vm_page_cpu_pool_push()` in C.
///
/// # Safety
///
/// The pool lock must be held and `page` must be a live descriptor not on any
/// other list.
fn cpu_pool_push(cpu_pool: &mut CpuPool, page: *mut VmPage) {
    cpu_pool.nr_pages += 1;
    // SAFETY: the pool is in `STATE`; the caller holds the pool lock and the
    // page stays put.
    unsafe {
        pin_head(&mut cpu_pool.pages)
            .push_front_ptr(NonNull::new_unchecked(page));
    }
}

/// `vm_page_cpu_pool_fill()` in C.
///
/// # Safety
///
/// `seg` must be a live segment, the caller must hold `vm_page_queue_free_lock`,
/// and the pool lock must not be held.
unsafe fn cpu_pool_fill(cpu_pool: *mut CpuPool, seg: *mut VmPageSeg) -> c_int {
    unsafe { (*seg).lock.lock() };

    let mut i = 0;
    // SAFETY: `cpu_pool` points at a live pool of the segment.
    while i < unsafe { (*cpu_pool).transfer_size } {
        // SAFETY: the free lock is held, as the backend requires.
        let page = unsafe { seg_alloc_from_buddy(seg, 0) };
        if page.is_null() {
            break;
        }
        // SAFETY: the pool lock is held and the page came off the buddy.
        unsafe { cpu_pool_push(&mut *cpu_pool, page) };
        i += 1;
    }

    // SAFETY: the lock was taken above.
    unsafe { (*seg).lock.unlock() };

    i
}

/// `vm_page_cpu_pool_drain()` in C.
///
/// # Safety
///
/// `seg` must be a live segment, the caller must hold `vm_page_queue_free_lock`,
/// and the pool lock must not be held.
unsafe fn cpu_pool_drain(cpu_pool: *mut CpuPool, seg: *mut VmPageSeg) {
    unsafe { (*seg).lock.lock() };

    // SAFETY: `cpu_pool` points at a live pool of the segment.
    let mut i = unsafe { (*cpu_pool).transfer_size };
    while i > 0 {
        // SAFETY: the pool was full, so the C's fixed transfer count is
        // available.
        let page = cpu_pool_pop(unsafe { &mut *cpu_pool });
        // SAFETY: the segment lock is held.
        unsafe { seg_free_to_buddy(seg, page, 0) };
        i -= 1;
    }

    // SAFETY: the lock was taken above.
    unsafe { (*seg).lock.unlock() };
}

/// `vm_page_list_init()` in C.
const fn page_list_init(list: &mut PageList) {
    list.nr_pages = 0;
    list.pages = NodeList::new();
}

/// `vm_page_queue_init()` in C.
const fn page_queue_init(queue: &mut PageQueue) {
    page_list_init(&mut queue.internal);
    page_list_init(&mut queue.external);
}

/// `vm_page_queue_push()` in C.
///
/// # Safety
///
/// The page-queue lock must be held and `page` must be a live descriptor.
unsafe fn page_queue_push(queue: *mut PageQueue, page: *mut VmPage) {
    let list = if unsafe { (*page).is_external() } {
        unsafe { &mut (*queue).external }
    } else {
        unsafe { &mut (*queue).internal }
    };
    // SAFETY: the list is in `STATE`, and the page stays at its address while
    // linked.
    unsafe {
        pin_head(&mut list.pages).push_back_ptr(NonNull::new_unchecked(page));
    }
    list.nr_pages += 1;
}

/// `vm_page_queue_remove()` in C.
///
/// # Safety
///
/// The page-queue lock must be held and `page` must be linked in `queue`.
unsafe fn page_queue_remove(queue: *mut PageQueue, page: *mut VmPage) {
    let list = if unsafe { (*page).is_external() } {
        unsafe { &mut (*queue).external }
    } else {
        unsafe { &mut (*queue).internal }
    };
    // SAFETY: the list is in `STATE`, and the page is linked in it.
    unsafe {
        pin_head(&mut list.pages).remove_ptr(NonNull::new_unchecked(page));
    }
    list.nr_pages -= 1;
}

/// `vm_page_lru_queue_push()` in C.
///
/// # Safety
///
/// The page-queue lock must be held and `page` must be a live descriptor.
unsafe fn lru_queue_push(queue: *mut LruQueue, page: *mut VmPage) {
    let list = if unsafe { (*page).is_external() } {
        unsafe { &mut (*queue).external }
    } else {
        unsafe { &mut (*queue).internal }
    };
    // SAFETY: the list is in `STATE`, and the page stays at its address while
    // linked.
    unsafe { pin_head(list).push_back_ptr(NonNull::new_unchecked(page)) };
}

/// `vm_page_lru_queue_remove()` in C.
///
/// # Safety
///
/// The page-queue lock must be held and `page` must be linked in `queue`.
unsafe fn lru_queue_remove(queue: *mut LruQueue, page: *mut VmPage) {
    let list = if unsafe { (*page).is_external() } {
        unsafe { &mut (*queue).external }
    } else {
        unsafe { &mut (*queue).internal }
    };
    // SAFETY: the list is in `STATE`, and the page is linked in it.
    unsafe { pin_head(list).remove_ptr(NonNull::new_unchecked(page)) };
}

/// `vm_page_seg_index()` in C.
///
/// # Safety
///
/// `seg` must point inside the segment table.
unsafe fn seg_index(seg: *const VmPageSeg) -> usize {
    // SAFETY: the state is live for the kernel's lifetime.
    let base = unsafe { addr_of_mut!((*state()).segs).cast::<VmPageSeg>() };
    (seg as usize - base as usize) / size_of::<VmPageSeg>()
}

/// `vm_page_seg_size()` in C.
///
/// # Safety
///
/// `seg` must be a live segment.
const unsafe fn seg_size(seg: *const VmPageSeg) -> VmOffset {
    unsafe { (*seg).end - (*seg).start }
}

/// `vm_page_seg_compute_pool_size()` in C.
///
/// # Safety
///
/// `seg` must be a live segment.
const unsafe fn seg_compute_pool_size(seg: *const VmPageSeg) -> c_int {
    let mut size = atop(unsafe { seg_size(seg) }) / VM_PAGE_CPU_POOL_RATIO;

    if size == 0 {
        size = 1;
    } else if size > VM_PAGE_CPU_POOL_MAX_SIZE {
        size = VM_PAGE_CPU_POOL_MAX_SIZE;
    }

    size as c_int
}

/// `vm_page_seg_compute_pageout_thresholds()` in C.
///
/// # Safety
///
/// `seg` must be a live segment.
unsafe fn seg_compute_pageout_thresholds(seg: *mut VmPageSeg) {
    let nr_pages = atop(unsafe { seg_size(seg) });

    if nr_pages < VM_PAGE_SEG_MIN_PAGES {
        die(
            "vm_page_seg_compute_pageout_thresholds",
            "vm_page: segment too small",
        );
    }

    let min_free_pages = nr_pages.wrapping_mul(VM_PAGE_SEG_THRESHOLD_MIN_NUM)
        / VM_PAGE_SEG_THRESHOLD_MIN_DENOM;
    let low_free_pages = nr_pages.wrapping_mul(VM_PAGE_SEG_THRESHOLD_LOW_NUM)
        / VM_PAGE_SEG_THRESHOLD_LOW_DENOM;
    let high_free_pages = nr_pages
        .wrapping_mul(VM_PAGE_SEG_THRESHOLD_HIGH_NUM)
        / VM_PAGE_SEG_THRESHOLD_HIGH_DENOM;

    unsafe {
        (*seg).min_free_pages = min_free_pages.max(VM_PAGE_SEG_THRESHOLD_MIN);
        (*seg).low_free_pages = low_free_pages.max(VM_PAGE_SEG_THRESHOLD_LOW);
        (*seg).high_free_pages =
            high_free_pages.max(VM_PAGE_SEG_THRESHOLD_HIGH);
    }
}

/// `vm_page_seg_init()` in C.
///
/// # Safety
///
/// `seg` must be a live segment, `pages` must point at a table of
/// `atop(end - start)` writable descriptors, and no other thread may be
/// using either.
unsafe fn seg_init(
    seg: *mut VmPageSeg,
    start: VmOffset,
    end: VmOffset,
    pages: *mut VmPage,
) {
    unsafe {
        (*seg).start = start;
        (*seg).end = end;
    }
    let pool_size = unsafe { seg_compute_pool_size(seg) };

    let mut i = 0;
    while i < MAX_NCPUS {
        // SAFETY: `i` is below `MAX_NCPUS`.
        let cpu_pool =
            unsafe { addr_of_mut!((*seg).cpu_pools).cast::<CpuPool>().add(i) };
        // SAFETY: `i` is below `MAX_NCPUS`, so the pool is live.
        cpu_pool_init(unsafe { &mut *cpu_pool }, pool_size);
        i += 1;
    }

    unsafe {
        (*seg).pages = pages;
        (*seg).pages_end = pages.add(atop(seg_size(seg)));
        (*seg).lock.init();
    }

    let mut i = 0;
    while i < VM_PAGE_NR_FREE_LISTS {
        // SAFETY: `i` indexes the segment's free lists, which live.
        free_list_init(unsafe { &mut (*seg).free_lists[i] });
        i += 1;
    }

    unsafe {
        (*seg).nr_free_pages = 0;
    }
    unsafe { seg_compute_pageout_thresholds(seg) };
    page_queue_init(unsafe { &mut (*seg).active_pages });
    page_queue_init(unsafe { &mut (*seg).inactive_pages });

    // SAFETY: the segment is inside the table.
    let index = unsafe { seg_index(seg) } as u16;

    let mut pa = start;
    while pa < end {
        // SAFETY: `pa` runs over the segment's pages.
        let page = unsafe { (*seg).pages.add(atop(pa - start)) };
        // SAFETY: the descriptor is inside the freshly reserved table.
        unsafe { init_pa(page, index, pa) };
        pa = pa.wrapping_add(PAGE_SIZE);
    }
}

/// `vm_page_seg_alloc_from_buddy()` in C.
///
/// # Safety
///
/// `seg` must be a live segment and the caller must hold
/// `vm_page_queue_free_lock` and the segment lock, as the C's callers did.
unsafe fn seg_alloc_from_buddy(
    seg: *mut VmPageSeg,
    order: c_uint,
) -> *mut VmPage {
    let thread = per_cpu::thread();
    // The C's `per_cpu::thread() && !per_cpu::thread()->vm_privilege`: an
    // early-boot call with no thread is not paused.
    // SAFETY: the null check short-circuits, so `thread` is live.
    let limited = !thread.is_null() && unsafe { (*thread).vm_privilege } == 0;

    if unsafe { (*state()).alloc_paused } && limited {
        return null_mut();
    } else if unsafe { (*seg).nr_free_pages <= (*seg).low_free_pages } {
        // SAFETY: the C calls the daemon's entry point under the free lock.
        unsafe { vm_pageout_start() };

        if unsafe { (*seg).nr_free_pages <= (*seg).min_free_pages } && limited
        {
            // SAFETY: the free lock serializes the flag.
            unsafe { (*state()).alloc_paused = true };
            return null_mut();
        }
    }

    let mut i = order as usize;
    while i < VM_PAGE_NR_FREE_LISTS {
        if unsafe { (*seg).free_lists[i].size } != 0 {
            break;
        }
        i += 1;
    }

    if i == VM_PAGE_NR_FREE_LISTS {
        return null_mut();
    }

    // SAFETY: the list `i` is non-empty, so its head has a first node.
    let free_list = unsafe { &mut (*seg).free_lists[i] };
    let Some(node) = free_list.blocks.cursor_front().current_ptr() else {
        die("vm_page_seg_alloc_from_buddy", "vm_page: empty free list");
    };
    let page = node.as_ptr();
    free_list_remove(free_list, page);
    // SAFETY: the page is live and the segment lock is held.
    unsafe { (*page).set_order(VM_PAGE_ORDER_UNLISTED) };

    while i > order as usize {
        i -= 1;
        // SAFETY: the split buddy lies inside the segment's page table.
        let buddy = unsafe { page.add(1 << i) };
        // SAFETY: `i` indexes the segment's free lists, which live.
        free_list_insert(unsafe { &mut (*seg).free_lists[i] }, buddy);
        unsafe { (*buddy).set_order(i as u16) };
    }

    // SAFETY: the segment lock serializes the counters.
    unsafe {
        (*seg).nr_free_pages -= 1usize << order;
        if (*seg).nr_free_pages < (*seg).min_free_pages {
            (*state()).alloc_paused = true;
        }
    }

    page
}

/// `vm_page_seg_free_to_buddy()` in C.
///
/// # Safety
///
/// `seg` must be a live segment, the caller must hold its lock, and `page`
/// must be the first of `1 << order` free descriptors inside it.
unsafe fn seg_free_to_buddy(
    seg: *mut VmPageSeg,
    mut page: *mut VmPage,
    order: c_uint,
) {
    let mut order = order;
    let nr_pages = 1usize << order;
    let mut pa = unsafe { (*page).phys_addr };

    while order < (VM_PAGE_NR_FREE_LISTS as c_uint - 1) {
        let buddy_pa = pa ^ ptoa(1usize << order);
        // SAFETY: the segment's bounds are live fields.
        if buddy_pa < unsafe { (*seg).start }
            || buddy_pa >= unsafe { (*seg).end }
        {
            break;
        }
        // SAFETY: `buddy_pa` is inside the segment, so the offset indexes
        // its page table.
        let buddy = unsafe { (*seg).pages.add(atop(buddy_pa - (*seg).start)) };
        // SAFETY: the buddy descriptor is live.
        if unsafe { (*buddy).order() } != order as u16 {
            break;
        }
        free_list_remove(
            // SAFETY: `order` is below the free-list count.
            unsafe { &mut (*seg).free_lists[order as usize] },
            buddy,
        );
        // SAFETY: the buddy is live and the segment lock is held.
        unsafe { (*buddy).set_order(VM_PAGE_ORDER_UNLISTED) };
        order += 1;
        pa &= !(ptoa(1usize << order) - 1);
        // SAFETY: the merged block starts inside the segment.
        page = unsafe { (*seg).pages.add(atop(pa - (*seg).start)) };
    }

    // SAFETY: `order` is below the free-list count.
    free_list_insert(unsafe { &mut (*seg).free_lists[order as usize] }, page);
    // SAFETY: the page is live and the segment lock is held.
    unsafe {
        (*page).set_order(order as u16);
        (*seg).nr_free_pages += nr_pages;
    }
}

/// `vm_page_seg_alloc()` in C.
///
/// # Safety
///
/// `seg` must be a live segment and the caller must hold
/// `vm_page_queue_free_lock`, as the C's callers did.
unsafe fn seg_alloc(
    seg: *mut VmPageSeg,
    order: c_uint,
    type_: u16,
) -> *mut VmPage {
    let page;

    if order == 0 {
        let thread = per_cpu::thread();
        // SAFETY: the free lock serializes `alloc_paused`.
        if unsafe { (*state()).alloc_paused }
            && !thread.is_null()
            // SAFETY: the null check short-circuits, so `thread` is live.
            && unsafe { (*thread).vm_privilege } == 0
        {
            return null_mut();
        }

        let cpu_pool = unsafe { cpu_pool_get(seg) };
        // SAFETY: the pool lock serializes the pool.
        unsafe { (*cpu_pool).lock.lock() };

        // SAFETY: `cpu_pool` points at a live pool of the segment.
        if unsafe { (*cpu_pool).nr_pages } == 0 {
            // SAFETY: the pool and segment locks are held, and the free lock
            // was taken by the caller.
            let filled = unsafe { cpu_pool_fill(cpu_pool, seg) };

            if filled == 0 {
                // SAFETY: the pool lock was taken above.
                unsafe { (*cpu_pool).lock.unlock() };
                return null_mut();
            }
        }

        // SAFETY: the pool is non-empty and its lock is held.
        page = cpu_pool_pop(unsafe { &mut *cpu_pool });
        // SAFETY: the pool lock was taken above.
        unsafe { (*cpu_pool).lock.unlock() };
    } else {
        unsafe { (*seg).lock.lock() };
        // SAFETY: the segment lock is held.
        page = unsafe { seg_alloc_from_buddy(seg, order) };
        // SAFETY: the segment lock was taken above.
        unsafe { (*seg).lock.unlock() };

        if page.is_null() {
            return null_mut();
        }
    }

    // SAFETY: the freshly allocated page is live.
    unsafe { set_type(NonNull::new_unchecked(page), order, type_) };
    page
}

/// `vm_page_seg_free()` in C.
///
/// # Safety
///
/// `seg` must be a live segment and the caller must hold
/// `vm_page_queue_free_lock`, as the C's callers did.
unsafe fn seg_free(seg: *mut VmPageSeg, page: *mut VmPage, order: c_uint) {
    unsafe { set_type(NonNull::new_unchecked(page), order, VM_PT_FREE) };

    if order == 0 {
        let cpu_pool = unsafe { cpu_pool_get(seg) };
        // SAFETY: the pool lock serializes the pool.
        unsafe { (*cpu_pool).lock.lock() };

        // SAFETY: `cpu_pool` points at a live pool of the segment.
        if unsafe { (*cpu_pool).nr_pages == (*cpu_pool).size } {
            // SAFETY: the pool is full, the pool lock is held, and the free
            // lock was taken by the caller.
            unsafe { cpu_pool_drain(cpu_pool, seg) };
        }

        // SAFETY: the pool lock is held and the page is off every list.
        cpu_pool_push(unsafe { &mut *cpu_pool }, page);
        // SAFETY: the pool lock was taken above.
        unsafe { (*cpu_pool).lock.unlock() };
    } else {
        unsafe { (*seg).lock.lock() };
        // SAFETY: the segment and free locks are held.
        unsafe { seg_free_to_buddy(seg, page, order) };
        // SAFETY: the segment lock was taken above.
        unsafe { (*seg).lock.unlock() };
    }
}

/// `vm_page_seg_add_active_page()` in C.
///
/// # Safety
///
/// The segment and page-queues locks must be held, and `page` must be a live
/// descriptor not already queued.
unsafe fn seg_add_active_page(seg: *mut VmPageSeg, page: *mut VmPage) {
    unsafe {
        (*page).set_active(true);
        (*page).set_reference(true);
        page_queue_push(addr_of_mut!((*seg).active_pages), page);
        lru_queue_push(addr_of_mut!((*state()).active_lru), page);
    }
    vm_resident::VM_PAGE_ACTIVE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// `vm_page_seg_remove_active_page()` in C.
///
/// # Safety
///
/// The segment and page-queues locks must be held, and `page` must be queued
/// active.
unsafe fn seg_remove_active_page(seg: *mut VmPageSeg, page: *mut VmPage) {
    unsafe {
        (*page).set_active(false);
        page_queue_remove(addr_of_mut!((*seg).active_pages), page);
        lru_queue_remove(addr_of_mut!((*state()).active_lru), page);
    }
    vm_resident::VM_PAGE_ACTIVE_COUNT.fetch_sub(1, Ordering::Relaxed);
}

/// `vm_page_seg_add_inactive_page()` in C.
///
/// # Safety
///
/// The segment and page-queues locks must be held, and `page` must be a live
/// descriptor not already queued.
unsafe fn seg_add_inactive_page(seg: *mut VmPageSeg, page: *mut VmPage) {
    unsafe {
        (*page).set_inactive(true);
        page_queue_push(addr_of_mut!((*seg).inactive_pages), page);
        lru_queue_push(addr_of_mut!((*state()).inactive_lru), page);
    }
    vm_resident::VM_PAGE_INACTIVE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// `vm_page_seg_remove_inactive_page()` in C.
///
/// # Safety
///
/// The segment and page-queues locks must be held, and `page` must be queued
/// inactive.
unsafe fn seg_remove_inactive_page(seg: *mut VmPageSeg, page: *mut VmPage) {
    unsafe {
        (*page).set_inactive(false);
        page_queue_remove(addr_of_mut!((*seg).inactive_pages), page);
        lru_queue_remove(addr_of_mut!((*state()).inactive_lru), page);
    }
    vm_resident::VM_PAGE_INACTIVE_COUNT.fetch_sub(1, Ordering::Relaxed);
}

/// `vm_page_seg_pull_active_page()` in C.
///
/// # Safety
///
/// The segment and page-queues locks must be held.  On success the object
/// lock is held and the page is off the queues; the caller keeps the segment
/// lock.
unsafe fn seg_pull_active_page(
    seg: *mut VmPageSeg,
    external: bool,
) -> *mut VmPage {
    let page_list = if external {
        unsafe { addr_of_mut!((*seg).active_pages.external.pages) }
    } else {
        unsafe { addr_of_mut!((*seg).active_pages.internal.pages) }
    };
    let mut first: *mut VmPage = null_mut();

    // SAFETY: the page-queues lock is held and `page_list` is a live head.
    while let Some(page) = unsafe { (*page_list).cursor_front().current_ptr() }
    {
        let page = page.as_ptr();

        if page == first {
            break;
        }

        if first.is_null() {
            first = page;
        }

        // SAFETY: the page is queued active.
        unsafe { seg_remove_active_page(seg, page) };
        // SAFETY: the page is live and was queued active above.
        let object = unsafe { (*page).object };
        // SAFETY: a queued page has a live object and the page-queues lock
        // is held.
        let locked = unsafe { (*object).lock.try_lock() };

        if !locked {
            // SAFETY: the page was removed above.
            unsafe { seg_add_active_page(seg, page) };
            continue;
        }

        if !unsafe { can_move(page) } {
            unsafe { seg_add_active_page(seg, page) };
            // SAFETY: the object lock was taken above.
            unsafe { (*object).lock.unlock() };
            continue;
        }

        return page;
    }

    null_mut()
}

/// `vm_page_seg_pull_inactive_page()` in C.
///
/// # Safety
///
/// Same contract as [`seg_pull_active_page()`].
unsafe fn seg_pull_inactive_page(
    seg: *mut VmPageSeg,
    external: bool,
) -> *mut VmPage {
    let page_list = if external {
        unsafe { addr_of_mut!((*seg).inactive_pages.external.pages) }
    } else {
        unsafe { addr_of_mut!((*seg).inactive_pages.internal.pages) }
    };
    let mut first: *mut VmPage = null_mut();

    // SAFETY: the page-queues lock is held and `page_list` is a live head.
    while let Some(page) = unsafe { (*page_list).cursor_front().current_ptr() }
    {
        let page = page.as_ptr();

        if page == first {
            break;
        }

        if first.is_null() {
            first = page;
        }

        // SAFETY: the page is queued inactive.
        unsafe { seg_remove_inactive_page(seg, page) };
        // SAFETY: the page is live and was queued inactive above.
        let object = unsafe { (*page).object };
        // SAFETY: a queued page has a live object and the page-queues lock
        // is held.
        let locked = unsafe { (*object).lock.try_lock() };

        if !locked {
            // SAFETY: the page was removed above.
            unsafe { seg_add_inactive_page(seg, page) };
            continue;
        }

        // SAFETY: the object lock is held.
        if !unsafe { can_move(page) } {
            unsafe { seg_add_inactive_page(seg, page) };
            // SAFETY: the object lock was taken above.
            unsafe { (*object).lock.unlock() };
            continue;
        }

        return page;
    }

    null_mut()
}

/// `vm_page_pull_active_page()` in C.
///
/// # Safety
///
/// The page-queues lock must be held.  On success the segment and object
/// locks are held and the page is off the queues.
unsafe fn pull_active_page(external: bool) -> *mut VmPage {
    // SAFETY: the state is live.
    let page_list = if external {
        // SAFETY: the state is live for the kernel's lifetime.
        unsafe { addr_of_mut!((*state()).active_lru.external) }
    } else {
        unsafe { addr_of_mut!((*state()).active_lru.internal) }
    };
    let mut first: *mut VmPage = null_mut();

    // SAFETY: the page-queues lock is held and the LRU head is live.
    while let Some(page) = unsafe { (*page_list).cursor_front().current_ptr() }
    {
        let page = page.as_ptr();

        if page == first {
            break;
        }

        if first.is_null() {
            first = page;
        }

        // SAFETY: a queued page's segment index is in range.
        let seg = seg_ptr(unsafe { (*page).seg_index() } as usize);
        // SAFETY: the segment is live; the C takes its lock here.
        unsafe { (*seg).lock.lock() };

        // SAFETY: the segment lock and page-queues lock are held.
        unsafe { seg_remove_active_page(seg, page) };
        // SAFETY: the page is live and was queued active above.
        let object = unsafe { (*page).object };
        // SAFETY: a queued page has a live object.
        let locked = unsafe { (*object).lock.try_lock() };

        if !locked {
            // SAFETY: the page was removed above.
            unsafe { seg_add_active_page(seg, page) };
            // SAFETY: the segment lock was taken above.
            unsafe { (*seg).lock.unlock() };
            continue;
        }

        // SAFETY: the object lock is held.
        if !unsafe { can_move(page) } {
            unsafe { seg_add_active_page(seg, page) };
            // SAFETY: the object lock was taken above.
            unsafe { (*object).lock.unlock() };
            // SAFETY: the segment lock was taken above.
            unsafe { (*seg).lock.unlock() };
            continue;
        }

        return page;
    }

    null_mut()
}

/// `vm_page_pull_inactive_page()` in C.
///
/// # Safety
///
/// Same contract as [`pull_active_page()`].
unsafe fn pull_inactive_page(external: bool) -> *mut VmPage {
    // SAFETY: the state is live.
    let page_list = if external {
        // SAFETY: the state is live for the kernel's lifetime.
        unsafe { addr_of_mut!((*state()).inactive_lru.external) }
    } else {
        unsafe { addr_of_mut!((*state()).inactive_lru.internal) }
    };
    let mut first: *mut VmPage = null_mut();

    // SAFETY: the page-queues lock is held and the LRU head is live.
    while let Some(page) = unsafe { (*page_list).cursor_front().current_ptr() }
    {
        let page = page.as_ptr();

        if page == first {
            break;
        }

        if first.is_null() {
            first = page;
        }

        // SAFETY: a queued page's segment index is in range.
        let seg = seg_ptr(unsafe { (*page).seg_index() } as usize);
        // SAFETY: the segment is live; the C takes its lock here.
        unsafe { (*seg).lock.lock() };

        // SAFETY: the segment lock and page-queues lock are held.
        unsafe { seg_remove_inactive_page(seg, page) };
        // SAFETY: the page is live and was queued inactive above.
        let object = unsafe { (*page).object };
        // SAFETY: a queued page has a live object.
        let locked = unsafe { (*object).lock.try_lock() };

        if !locked {
            // SAFETY: the page was removed above.
            unsafe { seg_add_inactive_page(seg, page) };
            // SAFETY: the segment lock was taken above.
            unsafe { (*seg).lock.unlock() };
            continue;
        }

        // SAFETY: the object lock is held.
        if !unsafe { can_move(page) } {
            unsafe { seg_add_inactive_page(seg, page) };
            // SAFETY: the object lock was taken above.
            unsafe { (*object).lock.unlock() };
            // SAFETY: the segment lock was taken above.
            unsafe { (*seg).lock.unlock() };
            continue;
        }

        return page;
    }

    null_mut()
}

/// `vm_page_seg_page_available()` in C.
///
/// # Safety
///
/// `seg` must be a live segment.
const unsafe fn seg_page_available(seg: *const VmPageSeg) -> bool {
    unsafe { (*seg).nr_free_pages > (*seg).high_free_pages }
}

/// `vm_page_seg_usable()` in C.
///
/// # Safety
///
/// `seg` must be a live segment.
const unsafe fn seg_usable(seg: *const VmPageSeg) -> bool {
    let queued = unsafe {
        (*seg).active_pages.internal.nr_pages
            + (*seg).active_pages.external.nr_pages
            + (*seg).inactive_pages.internal.nr_pages
            + (*seg).inactive_pages.external.nr_pages
    };

    queued == 0 || unsafe { (*seg).nr_free_pages >= (*seg).high_free_pages }
}

/// `vm_page_seg_double_lock()` in C.
///
/// # Safety
///
/// `seg1` and `seg2` must be live, distinct segments, unlocked.
unsafe fn seg_double_lock(seg1: *mut VmPageSeg, seg2: *mut VmPageSeg) {
    unsafe {
        if (seg1 as usize) < (seg2 as usize) {
            (*seg1).lock.lock();
            (*seg2).lock.lock();
        } else {
            (*seg2).lock.lock();
            (*seg1).lock.lock();
        }
    }
}

/// `vm_page_seg_double_unlock()` in C.
///
/// # Safety
///
/// Both locks must be held.
unsafe fn seg_double_unlock(seg1: *mut VmPageSeg, seg2: *mut VmPageSeg) {
    unsafe {
        (*seg1).lock.unlock();
        (*seg2).lock.unlock();
    }
}

/// `vm_page_seg_balance_page()` in C.
///
/// # Safety
///
/// Both segments must be live and unlocked; the page-queues and free locks
/// must not be held.  Returns with every lock released.
unsafe fn seg_balance_page(
    seg: *mut VmPageSeg,
    remote_seg: *mut VmPageSeg,
    priv_alloc: bool,
) -> bool {
    VM_PAGE_QUEUE_LOCK.lock();
    VM_PAGE_QUEUE_FREE_LOCK.lock();
    unsafe { seg_double_lock(seg, remote_seg) };

    let unusable = unsafe { !seg_usable(seg) };
    let remote_full = if priv_alloc {
        // SAFETY: the segment lock is held.
        unsafe { (*remote_seg).nr_free_pages == 0 }
    } else {
        // SAFETY: the segment lock is held.
        unsafe { !seg_page_available(remote_seg) }
    };

    if !unusable || remote_full {
        // SAFETY: the locks were taken above.
        unsafe {
            seg_double_unlock(seg, remote_seg);
            VM_PAGE_QUEUE_FREE_LOCK.unlock();
            VM_PAGE_QUEUE_LOCK.unlock();
        }
        return false;
    }

    let mut was_active = true;
    // SAFETY: the locks the pull requires are held.
    let mut src = unsafe { seg_pull_active_page(seg, false) };
    if src.is_null() {
        src = unsafe { seg_pull_active_page(seg, true) };
    }

    if src.is_null() {
        was_active = false;
        src = unsafe { seg_pull_inactive_page(seg, false) };
        if src.is_null() {
            src = unsafe { seg_pull_inactive_page(seg, true) };
        }
    }

    if src.is_null() {
        // SAFETY: the locks were taken above.
        unsafe {
            seg_double_unlock(seg, remote_seg);
            VM_PAGE_QUEUE_FREE_LOCK.unlock();
            VM_PAGE_QUEUE_LOCK.unlock();
        }
        return false;
    }

    // SAFETY: the remote segment lock is held and the remote segment has
    // free pages, as the C's check above established.
    let dest = unsafe { seg_alloc_from_buddy(remote_seg, 0) };

    // SAFETY: the locks were taken above.
    unsafe {
        seg_double_unlock(seg, remote_seg);
        VM_PAGE_QUEUE_FREE_LOCK.unlock();
    }

    if dest.is_null() {
        die("vm_page_seg_balance_page", "vm_page: no dest page");
    }

    // SAFETY: the source object lock is held.
    if !was_active
        // SAFETY: the source page is live and its object lock is held.
        && !unsafe { (*src).is_reference() }
        && unsafe { pmap_is_referenced((*src).phys_addr) } != 0
    {
        // SAFETY: the page is live.
        unsafe { (*src).set_reference(true) };
    }

    // SAFETY: the source page holds its object lock and the page-queues
    // lock.
    let object = unsafe { (*src).object };
    // SAFETY: the source page is live and its object lock is held.
    let offset = unsafe { (*src).offset };
    unsafe { vm_resident::remove(NonNull::new_unchecked(src)) };

    // SAFETY: the page is live.
    unsafe { remove_mappings(src) };

    // SAFETY: both pages are live and the body copy is the C's memcpy of
    // `VM_PAGE_BODY_SIZE` bytes.
    unsafe {
        set_type(NonNull::new_unchecked(dest), 0, (*src).page_type());
        (*dest).copy_body_from(&*src);
    }
    // SAFETY: both pages are live and their object locks are held.
    unsafe {
        vm_resident::copy(
            NonNull::new_unchecked(src),
            NonNull::new_unchecked(dest),
        );
    };

    // SAFETY: the destination page is live.
    if !unsafe { (*src).is_dirty() } {
        // SAFETY: the destination page is live and its address is real.
        unsafe { pmap_clear_modify((*dest).phys_addr) };
    }
    // SAFETY: the destination page is live and off every queue.
    unsafe { (*dest).set_busy(false) };

    // SAFETY: the free lock and the segment lock are taken in the C's
    // order, and the source page is live.
    unsafe {
        VM_PAGE_QUEUE_FREE_LOCK.lock();
        vm_resident::init(&mut *src);
        (*src).set_free(true);
        (*seg).lock.lock();
        set_type(NonNull::new_unchecked(src), 0, VM_PT_FREE);
        seg_free_to_buddy(seg, src, 0);
        (*seg).lock.unlock();
        VM_PAGE_QUEUE_FREE_LOCK.unlock();
    }

    // SAFETY: the destination page is live, the object lock and the
    // page-queues lock are held, and the destination is not queued.
    unsafe {
        vm_resident::insert(
            NonNull::new_unchecked(dest),
            NonNull::new_unchecked(object),
            offset,
        );
        (*object).lock.unlock();

        if was_active {
            activate(dest);
        } else {
            deactivate(dest);
        }

        VM_PAGE_QUEUE_LOCK.unlock();
    }

    true
}

/// `vm_page_seg_balance()` in C.
///
/// # Safety
///
/// `seg` must be a live segment; the C's caller holds no page lock around
/// it.
unsafe fn seg_balance(seg: *mut VmPageSeg, priv_alloc: bool) -> bool {
    let mut i = segs_size().wrapping_sub(1);

    while i < segs_size() {
        // SAFETY: `i` is inside the segment table.
        let remote_seg = seg_ptr(i);

        if remote_seg != seg
            // SAFETY: both segments are live and unlocked, as required.
            && unsafe { seg_balance_page(seg, remote_seg, priv_alloc) }
        {
            return true;
        }

        i = i.wrapping_sub(1);
    }

    false
}

/// `vm_page_seg_compute_high_active_page()` in C.
///
/// # Safety
///
/// `seg` must be a live segment with its lock held.
unsafe fn seg_compute_high_active_page(seg: *mut VmPageSeg) {
    let nr_pages = unsafe {
        (*seg).active_pages.internal.nr_pages
            + (*seg).active_pages.external.nr_pages
            + (*seg).inactive_pages.internal.nr_pages
            + (*seg).inactive_pages.external.nr_pages
    };

    unsafe {
        (*seg).high_active_pages = nr_pages
            .wrapping_mul(VM_PAGE_HIGH_ACTIVE_PAGE_NUM)
            / VM_PAGE_HIGH_ACTIVE_PAGE_DENOM;
    }
}

/// `vm_page_seg_refill_inactive()` in C.
///
/// # Safety
///
/// `seg` must be a live segment whose lock is not held; the page-queues lock
/// must be held.
unsafe fn seg_refill_inactive(seg: *mut VmPageSeg) {
    unsafe { (*seg).lock.lock() };

    // SAFETY: the segment and page-queues locks are held.
    unsafe { seg_compute_high_active_page(seg) };

    loop {
        // SAFETY: the segment lock is held.
        let actives = unsafe {
            (*seg).active_pages.internal.nr_pages
                + (*seg).active_pages.external.nr_pages
        };
        // SAFETY: the segment lock is held.
        if actives <= unsafe { (*seg).high_active_pages } {
            break;
        }

        // SAFETY: the segment and page-queues locks are held.
        let mut page = unsafe { seg_pull_active_page(seg, true) };
        if page.is_null() {
            page = unsafe { seg_pull_active_page(seg, false) };
        }

        if page.is_null() {
            break;
        }

        // SAFETY: the pull holds the object lock; the page is live and the
        // segment lock is held.
        unsafe {
            (*page).set_reference(false);
            pmap_clear_reference((*page).phys_addr);
            seg_add_inactive_page(seg, page);
            (*(*page).object).lock.unlock();
        }
    }

    // SAFETY: the lock was taken above.
    unsafe { (*seg).lock.unlock() };
}

/// `vm_page_load()` in C.
pub(crate) fn load(seg_index: c_uint, start: VmOffset, end: VmOffset) {
    let index = seg_index as usize;
    // SAFETY: the architecture loader passes the segment index the C
    // declared, below `VM_PAGE_MAX_SEGS`.
    let seg = unsafe { boot_seg(index) };

    // SAFETY: the state is live and the boot loader runs single-threaded.
    unsafe {
        (*seg).start = start;
        (*seg).end = end;
        (*seg).heap_present = false;
        (*state()).segs_size += 1;
    }
}

/// `vm_page_load_heap()` in C.
pub(crate) fn load_heap(seg_index: c_uint, start: VmOffset, end: VmOffset) {
    let index = seg_index as usize;
    // SAFETY: the architecture loader passes the segment index the C
    // declared, below `VM_PAGE_MAX_SEGS`.
    let seg = unsafe { boot_seg(index) };

    // SAFETY: the state is live and the boot loader runs single-threaded.
    unsafe {
        (*seg).avail_start = start;
        (*seg).avail_end = end;
        (*seg).heap_present = true;
    }
}

/// `vm_page_ready()` in C.
pub(crate) fn is_ready() -> bool {
    // SAFETY: the state is live for the kernel's lifetime.
    unsafe { (*state()).is_ready }
}

/// `vm_page_select_alloc_seg()` in C.
fn select_alloc_seg(selector: c_uint) -> usize {
    let seg_index = match selector {
        SEL_DMA => SEG_DMA,
        SEL_DMA32 => SEG_DMA32,
        SEL_DIRECTMAP => SEG_DIRECTMAP,
        SEL_HIGHMEM => SEG_HIGHMEM,
        _ => die("vm_page_select_alloc_seg", "vm_page: invalid selector"),
    };

    // The C `MIN(vm_page_segs_size - 1, seg_index)` wraps to all ones on an
    // empty table, so the selector wins.
    // SAFETY: the state is live for the kernel's lifetime.
    min(unsafe { (*state()).segs_size }.wrapping_sub(1), seg_index) as usize
}

/// `vm_page_boot_seg_loaded()` in C.
///
/// # Safety
///
/// `seg` must be a live boot segment.
const unsafe fn boot_seg_loaded(seg: *const BootSeg) -> bool {
    unsafe { (*seg).end != 0 }
}

/// `vm_page_check_boot_segs()` in C.
fn check_boot_segs() {
    // SAFETY: the state is live for the kernel's lifetime.
    if unsafe { (*state()).segs_size } == 0 {
        die(
            "vm_page_check_boot_segs",
            "vm_page: no physical memory loaded",
        );
    }

    let mut i = 0;
    while i < VM_PAGE_MAX_SEGS {
        let expect_loaded = i < segs_size();
        // SAFETY: `i` is inside the boot table.
        let seg = unsafe { boot_seg(i) };

        // SAFETY: the descriptor is live.
        if unsafe { boot_seg_loaded(seg) } == expect_loaded {
            i += 1;
            continue;
        }

        die(
            "vm_page_check_boot_segs",
            "vm_page: invalid boot segment table",
        );
    }
}

/// `vm_page_boot_seg_size()` in C.
///
/// # Safety
///
/// `seg` must be a live boot segment.
const unsafe fn boot_seg_size(seg: *const BootSeg) -> VmOffset {
    unsafe { (*seg).end - (*seg).start }
}

/// `vm_page_boot_seg_avail_size()` in C.
///
/// # Safety
///
/// `seg` must be a live boot segment.
const unsafe fn boot_seg_avail_size(seg: *const BootSeg) -> VmOffset {
    unsafe { (*seg).avail_end - (*seg).avail_start }
}

/// `vm_page_bootalloc()` in C: an early allocation from the boot table.  The
/// C's exhaustion `panic()` is final.
pub(crate) fn bootalloc(size: VmSize) -> VmOffset {
    let mut i = select_alloc_seg(SEL_DIRECTMAP);

    while i < segs_size() {
        // SAFETY: `i` is inside the boot table.
        let seg = unsafe { boot_seg(i) };

        // SAFETY: the descriptor is live.
        if size <= unsafe { boot_seg_avail_size(seg) } {
            // SAFETY: the descriptor is live and the boot loader is
            // single-threaded.
            let pa = unsafe { (*seg).avail_start };
            // SAFETY: the descriptor is live and boot is single-threaded.
            unsafe { (*seg).avail_start += round_page(size) };
            return pa;
        }

        i = i.wrapping_sub(1);
    }

    die("vm_page_bootalloc", "vm_page: no physical memory available")
}

/// `vm_page_setup()` in C: build the page table and release the segments.
pub(crate) fn setup() {
    check_boot_segs();

    // SAFETY: the state is live and setup runs once, single-threaded.
    unsafe {
        (*state()).active_lru.internal = LruList::new();
        (*state()).active_lru.external = LruList::new();
        (*state()).inactive_lru.internal = LruList::new();
        (*state()).inactive_lru.external = LruList::new();
    }

    let mut nr_pages: usize = 0;
    let mut i = 0;
    while i < segs_size() {
        // SAFETY: `i` is inside the boot table.
        let seg = unsafe { boot_seg(i) };
        // SAFETY: the descriptor is live.
        nr_pages += atop(unsafe { boot_seg_size(seg) });
        i += 1;
    }

    let table_size = round_page(nr_pages.wrapping_mul(size_of::<VmPage>()));
    kprint!(
        "vm_page: page table size: {} entries ({}k)\n",
        nr_pages,
        table_size >> 10,
    );

    // The boot allocator panics if the kernel address space is exhausted,
    // as the C did.
    let table = match vm_resident::pmap_steal_memory(table_size) {
        Ok(addr) => addr,
        Err(size) => kpanic!(
            "pmap_steal_memory",
            "not enough kernel virtual space for {}MB virtual allocation!\n",
            size >> 20
        ),
    } as *mut VmPage;
    let va = table as usize;

    let mut table = table;
    let mut i = 0;
    while i < segs_size() {
        // SAFETY: `i` is inside the segment and boot tables.
        let seg = seg_ptr(i);
        // SAFETY: `i` is inside the boot table, so the descriptor is live.
        let boot = unsafe { boot_seg(i) };

        // SAFETY: the page table has room for every segment's descriptors,
        // and setup is single-threaded.
        unsafe {
            seg_init(seg, (*boot).start, (*boot).end, table);

            if (*boot).heap_present {
                let mut page = (*seg)
                    .pages
                    .add(atop((*boot).avail_start - (*boot).start));
                let end =
                    (*seg).pages.add(atop((*boot).avail_end - (*boot).start));

                while page < end {
                    (*page).set_page_type(VM_PT_FREE);
                    seg_free_to_buddy(seg, page, 0);
                    page = page.add(1);
                }
            }

            table = table.add(atop(seg_size(seg)));
        }

        i += 1;
    }

    let mut va = va;
    while va < (table as usize) {
        // SAFETY: `pmap_extract()` reads the boot pmap for a mapped address.
        let pa = unsafe { pmap_extract(kernel_pmap_ptr(), va) };
        // SAFETY: the address was just mapped by the pmap over the page
        // table, so it has a descriptor.
        let Some(page) = lookup_pa(pa) else {
            die("vm_page_setup", "vm_page: page table not in any segment");
        };

        // SAFETY: the descriptor is live and setup is single-threaded.
        unsafe { (*page.as_ptr()).set_page_type(VM_PT_TABLE) };
        va = va.wrapping_add(PAGE_SIZE);
    }

    // SAFETY: the state is live and setup runs once.
    unsafe { (*state()).is_ready = true };
}

/// `vm_page_manage()` in C.
///
/// # Safety
///
/// `page` must be a live descriptor the kernel is handing to the page module,
/// not yet on any list.
pub(crate) unsafe fn manage(page: *mut VmPage) {
    unsafe {
        set_type(NonNull::new_unchecked(page), 0, VM_PT_FREE);
        let seg = seg_ptr((*page).seg_index() as usize);
        seg_free_to_buddy(seg, page, 0);
    }
}

/// `vm_page_lookup_pa()` in C.
pub(crate) fn lookup_pa(pa: VmOffset) -> Option<NonNull<VmPage>> {
    let mut i = 0;
    while i < segs_size() {
        let seg = seg_ptr(i);
        // SAFETY: `i` is inside the segment table.
        let (start, end) = unsafe { ((*seg).start, (*seg).end) };

        if start <= pa && pa < end {
            // SAFETY: the physical address is inside the segment.
            let page = unsafe { (*seg).pages.add(atop(pa - start)) };
            return NonNull::new(page);
        }

        i += 1;
    }

    None
}

/// `vm_page_lookup_seg()` in C.
///
/// # Safety
///
/// `page` must be a live descriptor.
unsafe fn lookup_seg(page: *const VmPage) -> *mut VmPageSeg {
    let pa = unsafe { (*page).phys_addr };
    let mut i = 0;

    while i < segs_size() {
        let seg = seg_ptr(i);
        // SAFETY: `i` is inside the segment table.
        if pa >= unsafe { (*seg).start } && pa < unsafe { (*seg).end } {
            return seg;
        }

        i += 1;
    }

    null_mut()
}

/// `vm_page_check()` in C, whose `panic()` calls are final.
///
/// # Safety
///
/// `page` must be a live descriptor, and the caller must hold whatever lock
/// the C's `VM_PAGE_CHECK` call sites held.
pub(crate) unsafe fn check(page: *const VmPage) {
    if unsafe { (*page).is_fictitious() } {
        if unsafe { (*page).is_private() } {
            die("vm_page_check", "vm_page: page both fictitious and private");
        }

        if unsafe { (*page).phys_addr } != VM_PAGE_FICTITIOUS_ADDR {
            die("vm_page_check", "vm_page: invalid fictitious page");
        }

        return;
    }

    if unsafe { (*page).phys_addr } == VM_PAGE_FICTITIOUS_ADDR {
        die("vm_page_check", "vm_page: real page has fictitious address");
    }

    let seg = unsafe { lookup_seg(page) };

    if seg.is_null() {
        if !unsafe { (*page).is_private() } {
            die(
                "vm_page_check",
                "vm_page: page claims it's managed but not in any segment",
            );
        }
        return;
    }

    if unsafe { (*page).is_private() } {
        if unsafe { pageable(page) } {
            die("vm_page_check", "vm_page: private page is pageable");
        }

        // SAFETY: the page's physical address is inside a segment.
        let Some(real_page) = lookup_pa(unsafe { (*page).phys_addr }) else {
            die(
                "vm_page_check",
                "vm_page: couldn't allocate page underlying private page",
            );
        };

        if unsafe { pageable(real_page.as_ptr()) } {
            die(
                "vm_page_check",
                "vm_page: page underlying private page is pageable",
            );
        }

        if unsafe { real_page.as_ref().page_type() } == VM_PT_FREE
            || unsafe { real_page.as_ref().order() } != VM_PAGE_ORDER_UNLISTED
        {
            die(
                "vm_page_check",
                "vm_page: page underlying private pagei is free",
            );
        }
        return;
    }

    // SAFETY: the segment is live.
    let index = unsafe { seg_index(seg) };
    if index != unsafe { (*page).seg_index() } as usize {
        die("vm_page_check", "vm_page: page segment mismatch");
    }
}

/// `vm_page_alloc_pa()` in C.  Returns with `vm_page_queue_free_lock` held.
///
/// # Safety
///
/// The caller must not hold `vm_page_queue_free_lock` and must be ready to
/// release it, as the C's callers were.
pub(crate) unsafe fn alloc_pa(
    order: c_uint,
    selector: c_uint,
    type_: u16,
) -> *mut VmPage {
    let seg_index = select_alloc_seg(selector);

    loop {
        VM_PAGE_QUEUE_FREE_LOCK.lock();

        let mut i = seg_index;
        while i < segs_size() {
            // SAFETY: the free lock is held, as the backend requires.
            let page = unsafe { seg_alloc(seg_ptr(i), order, type_) };

            if !page.is_null() {
                return page;
            }

            i = i.wrapping_sub(1);
        }

        let thread = per_cpu::thread();
        // SAFETY: the null check short-circuits, so `thread` is live.
        if thread.is_null() || unsafe { (*thread).vm_privilege } != 0 {
            VM_PAGE_QUEUE_FREE_LOCK.unlock();

            let mut i = seg_index;
            while i < segs_size() {
                // SAFETY: the C's balancing caller holds no page lock.
                if unsafe { seg_balance(seg_ptr(i), true) } {
                    break;
                }

                i = i.wrapping_sub(1);
            }

            if i < segs_size() {
                continue;
            }

            die(
                "vm_page_alloc_pa",
                "vm_page: privileged thread unable to allocate page",
            );
        }

        return null_mut();
    }
}

/// `vm_page_free_pa()` in C.
///
/// # Safety
///
/// `page` must be the first of `1 << order` descriptors the module handed
/// out, and the caller must hold `vm_page_queue_free_lock`.
pub(crate) unsafe fn free_pa(page: *mut VmPage, order: c_uint) {
    let seg = seg_ptr(unsafe { (*page).seg_index() } as usize);
    // SAFETY: the free lock is held, as the backend requires.
    unsafe { seg_free(seg, page, order) };
}

/// `vm_page_seg_name()` in C at the caller's index, whose unknown index is
/// final.
fn name_ptr(seg_index: c_uint) -> *const c_char {
    seg_name(seg_index).map_or_else(
        || die("vm_page_seg_name", "vm_page: invalid segment index"),
        CStr::as_ptr,
    )
}

/// `vm_page_info_all()` in C.
pub(crate) fn info_all() {
    let mut i = 0;
    while i < segs_size() {
        let seg = seg_ptr(i);
        // SAFETY: `i` is inside the segment table.
        let pages =
            unsafe { (*seg).pages_end.offset_from((*seg).pages) as usize };
        let name = name_ptr(i as c_uint);

        // SAFETY: `i` is inside the segment table, so `seg` is live.
        let (free, min_free, low_free, high_free) = unsafe {
            (
                (*seg).nr_free_pages,
                (*seg).min_free_pages,
                (*seg).low_free_pages,
                (*seg).high_free_pages,
            )
        };
        // SAFETY: `name_ptr()` returned a segment's NUL-terminated name.
        let name = unsafe { CStrArg::from_ptr(name) };
        kprint!(
            "vm_page: {}: pages: {} ({}M), free: {} ({}M)\n",
            name,
            pages,
            pages >> (20 - PAGE_SHIFT),
            free,
            free >> (20 - PAGE_SHIFT),
        );
        kprint!(
            "vm_page: {}: min:{} low:{} high:{}\n",
            name,
            min_free,
            low_free,
            high_free,
        );

        i += 1;
    }
}

/// `vm_page_boot_table_size()` in C.
fn boot_table_size() -> usize {
    let mut nr_pages = 0;
    let mut i = 0;

    while i < segs_size() {
        // SAFETY: `i` is inside the boot table.
        let seg = unsafe { boot_seg(i) };
        // SAFETY: the descriptor is live.
        nr_pages += atop(unsafe { boot_seg_size(seg) });
        i += 1;
    }

    nr_pages
}

/// `vm_page_table_size()` in C.
pub(crate) fn table_size() -> usize {
    if !is_ready() {
        return boot_table_size();
    }

    let mut nr_pages = 0;
    let mut i = 0;
    while i < segs_size() {
        // SAFETY: the segment is live.
        nr_pages += atop(unsafe { seg_size(seg_ptr(i)) });
        i += 1;
    }

    nr_pages
}

/// `vm_page_table_index()` in C, whose missing address is final.
pub(crate) fn table_index(pa: VmOffset) -> usize {
    let mut index = 0;
    let mut i = 0;

    while i < segs_size() {
        let seg = seg_ptr(i);
        // SAFETY: the segment is live.
        let (start, end) = unsafe { ((*seg).start, (*seg).end) };

        if start <= pa && pa < end {
            return index + atop(pa - start);
        }

        // SAFETY: the segment is live, as the loop's walk established.
        index += atop(unsafe { seg_size(seg) });
        i += 1;
    }

    die("vm_page_table_index", "vm_page: invalid physical address")
}

/// `vm_page_mem_size()` in C.
pub(crate) fn mem_size() -> VmOffset {
    let mut total = 0;
    let mut i = 0;

    while i < segs_size() {
        // SAFETY: the segment is live.
        total += unsafe { seg_size(seg_ptr(i)) };
        i += 1;
    }

    total
}

/// `vm_page_mem_free()` in C.
pub(crate) fn mem_free() -> usize {
    let mut total = 0;
    let mut i = 0;

    while i < segs_size() {
        let seg = seg_ptr(i);
        // SAFETY: the segment is live.
        total += unsafe { (*seg).nr_free_pages };
        i += 1;
    }

    total
}

/// `vm_page_unwire()` in C.
///
/// # Safety
///
/// `page` must be a live page whose object lock and page-queues lock the
/// caller holds.
pub(crate) unsafe fn unwire(page: *mut VmPage) {
    unsafe { check(page) };

    let count = unsafe { (*page).wire_count() }.wrapping_sub(1);
    unsafe { (*page).set_wire_count(count) };

    if count != 0
        || unsafe { (*page).is_fictitious() }
        || unsafe { (*page).is_private() }
    {
        return;
    }

    let seg = seg_ptr(unsafe { (*page).seg_index() } as usize);
    // SAFETY: the C takes the segment lock under the page-queues lock.
    unsafe {
        (*seg).lock.lock();
        seg_add_active_page(seg, page);
        (*seg).lock.unlock();
    }
    vm_resident::VM_PAGE_WIRE_COUNT.fetch_sub(1, Ordering::Relaxed);
}

/// `vm_page_deactivate()` in C.
///
/// # Safety
///
/// `page` must be a live page and the caller must hold the page-queues lock.
pub(crate) unsafe fn deactivate(page: *mut VmPage) {
    unsafe { check(page) };

    if unsafe { (*page).is_active() }
        || (unsafe { (*page).is_inactive() }
            && unsafe { (*page).is_reference() })
    {
        if !unsafe { (*page).is_fictitious() }
            && !unsafe { (*page).is_private() }
            && !unsafe { (*page).is_absent() }
        {
            // SAFETY: the page is live and its physical address is real.
            unsafe { pmap_clear_reference((*page).phys_addr) };
        }

        unsafe {
            (*page).set_reference(false);
            queues_remove(page);
        }
    }

    if unsafe { (*page).wire_count() } == 0
        && !unsafe { (*page).is_fictitious() }
        && !unsafe { (*page).is_private() }
        && !unsafe { (*page).is_inactive() }
    {
        let seg = seg_ptr(unsafe { (*page).seg_index() } as usize);
        // SAFETY: the C takes the segment lock under the page-queues lock.
        unsafe {
            (*seg).lock.lock();
            seg_add_inactive_page(seg, page);
            (*seg).lock.unlock();
        }
    }
}

/// `vm_page_activate()` in C, whose double activation is final.
///
/// # Safety
///
/// `page` must be a live page and the caller must hold the page-queues lock.
pub(crate) unsafe fn activate(page: *mut VmPage) {
    unsafe { check(page) };

    unsafe { queues_remove(page) };

    if unsafe { (*page).wire_count() } == 0
        && !unsafe { (*page).is_fictitious() }
        && !unsafe { (*page).is_private() }
    {
        let seg = seg_ptr(unsafe { (*page).seg_index() } as usize);

        if unsafe { (*page).is_active() } {
            die("vm_page_activate", "vm_page_activate: already active");
        }

        // SAFETY: the C takes the segment lock under the page-queues lock.
        unsafe {
            (*seg).lock.lock();
            seg_add_active_page(seg, page);
            (*seg).lock.unlock();
        }
    }
}

/// `vm_page_queues_remove()` in C.
///
/// # Safety
///
/// `page` must be a live page and the caller must hold the page-queues lock
/// and, when the page is queued, its object lock, as the C required.
pub(crate) unsafe fn queues_remove(page: *mut VmPage) {
    if !unsafe { (*page).is_active() } && !unsafe { (*page).is_inactive() } {
        return;
    }

    let seg = seg_ptr(unsafe { (*page).seg_index() } as usize);
    // SAFETY: the C takes the segment lock under the page-queues lock.
    unsafe {
        (*seg).lock.lock();

        if (*page).is_active() {
            seg_remove_active_page(seg, page);
        } else {
            seg_remove_inactive_page(seg, page);
        }

        (*seg).lock.unlock();
    }
}

/// `vm_page_check_usable()` in C.  Returns with `vm_page_queue_free_lock`
/// held, as the C did.
///
/// # Safety
///
/// The caller must hold no page lock: neither the free lock nor the
/// page-queues lock.
unsafe fn check_usable() -> bool {
    VM_PAGE_QUEUE_FREE_LOCK.lock();

    let mut i = 0;
    while i < segs_size() {
        let seg = seg_ptr(i);
        // SAFETY: the C takes the segment lock under the free lock.
        unsafe {
            (*seg).lock.lock();
        }
        // SAFETY: the segment is live and its lock is held.
        let usable = unsafe { seg_usable(seg) };
        // SAFETY: the lock was taken above.
        unsafe {
            (*seg).lock.unlock();
        }

        if !usable {
            return false;
        }

        i += 1;
    }

    vm_resident::VM_PAGE_EXTERNAL_LAUNDRY_COUNT.store(-1, Ordering::Relaxed);

    // SAFETY: the free lock is held and the state is live.
    unsafe {
        (*state()).alloc_paused = false;
        thread_wakeup_prim(
            addr_of_mut!((*state()).alloc_paused).cast(),
            0,
            THREAD_AWAKENED,
        );
    }

    true
}

/// `vm_page_may_balance()` in C.
///
/// # Safety
///
/// The caller must hold no page lock; the function takes and releases
/// each segment's lock in turn to probe it.
unsafe fn may_balance() -> bool {
    let mut i = 0;
    while i < segs_size() {
        let seg = seg_ptr(i);
        // SAFETY: the C takes the segment lock for the probe.
        unsafe {
            (*seg).lock.lock();
        }
        // SAFETY: the segment is live and its lock is held.
        let available = unsafe { seg_page_available(seg) };
        // SAFETY: the lock was taken above.
        unsafe {
            (*seg).lock.unlock();
        }

        if available {
            return true;
        }

        i += 1;
    }

    false
}

/// `vm_page_balance_once()` in C.
///
/// # Safety
///
/// The caller must hold no page lock, as [`seg_balance`] requires.
unsafe fn balance_once() -> bool {
    let mut i = 0;
    while i < segs_size() {
        // SAFETY: `i` is inside the segment table.
        if unsafe { seg_balance(seg_ptr(i), false) } {
            return true;
        }

        i += 1;
    }

    false
}

/// `vm_page_balance()` in C.  Returns with `vm_page_queue_free_lock` held.
///
/// # Safety
///
/// The caller must hold no page lock.
pub(crate) unsafe fn balance() -> bool {
    while unsafe { may_balance() } {
        if !unsafe { balance_once() } {
            break;
        }
    }

    // SAFETY: the C's balancing caller holds no page lock.
    unsafe { check_usable() }
}

/// `vm_page_evict_one()` in C.
///
/// # Safety
///
/// No page lock may be held; the C's caller is the pageout path.
unsafe fn evict_one(external: bool, active: bool, alloc_paused: bool) -> bool {
    if !external && !default_manager::is_set() {
        return false;
    }

    let mut seg: *mut VmPageSeg = null_mut();
    let mut page: *mut VmPage = null_mut();
    let mut object: *mut VmObject;
    let mut double_paging = false;
    let mut reclaim;

    loop {
        VM_PAGE_QUEUE_LOCK.lock();

        if page.is_null() {
            page = unsafe {
                if active {
                    pull_active_page(external)
                } else {
                    pull_inactive_page(external)
                }
            };

            if page.is_null() {
                VM_PAGE_QUEUE_LOCK.unlock();
                return false;
            }

            // SAFETY: the page came off a queue.
            seg = seg_ptr(unsafe { (*page).seg_index() } as usize);
        } else {
            // SAFETY: the second pass re-takes the locks the C did.
            unsafe {
                (*seg).lock.lock();
                (*(*page).object).lock.lock();
            }
        }

        // SAFETY: the page is live and its object lock is held.
        object = unsafe { (*page).object };

        if !active
            // SAFETY: the page is live and its object lock is held.
            && (unsafe { (*page).is_reference() }
                || unsafe { pmap_is_referenced((*page).phys_addr) } != 0)
        {
            // SAFETY: the segment, object and page-queues locks are held.
            unsafe { evict_reactivate(seg, page, object) };

            seg = null_mut();
            page = null_mut();
            continue;
        }

        // SAFETY: the page is live.
        unsafe { remove_mappings(page) };

        // SAFETY: the page is live.
        reclaim = !unsafe { (*page).is_dirty() }
            && !unsafe { (*page).is_precious() };

        // SAFETY: the object lock is held.
        if !reclaim {
            // SAFETY: the object lock is held.
            if unsafe { (*object).is_internal() }
                || !alloc_paused
                || !default_manager::is_set()
                // SAFETY: the object lock is held, and its pager is live.
                || unsafe { default_manager::port((*object).pager) }
            {
                double_paging = false;
            } else {
                double_paging = true;
                // SAFETY: the page is live and its object lock is held.
                unsafe { (*page).set_laundry(true) };
            }
        }

        // The `out:` label of the C: release the segment lock, then decide
        // with the object lock still held.
        if !seg.is_null() {
            // SAFETY: the segment lock is held.
            unsafe { (*seg).lock.unlock() };
        }

        if reclaim {
            // SAFETY: `vm_page_free()` is the real C symbol and the
            // page-queues lock is held, as its C caller had it.
            unsafe {
                vm_resident::free(NonNull::new_unchecked(page));
                VM_PAGE_QUEUE_LOCK.unlock();

                if (*object).ref_count == 0
                    && (*object).resident_page_count == 0
                {
                    vm_object::collect(object);
                } else {
                    (*object).lock.unlock();
                }
            }

            return true;
        }

        VM_PAGE_QUEUE_LOCK.unlock();

        if default_manager::is_set() {
            // SAFETY: the object lock is held and the C calls the object's
            // pager entries.
            unsafe {
                if !(*object).is_pager_initialized() {
                    vm_object::collapse(object);
                }
                if !(*object).is_pager_initialized() {
                    vm_object::pager_create(object);
                }
            }

            // SAFETY: the object lock is held.
            if !unsafe { (*object).is_pager_initialized() } {
                die("vm_page_seg_evict", "vm_page_seg_evict");
            }
        }

        // SAFETY: the object lock is held, as the C's flush had it.
        unsafe {
            vm_pageout_page(page, 0, 1);
            (*object).lock.unlock();
        }

        if double_paging {
            continue;
        }

        return true;
    }
}

/// Reactivate a page the walk found referenced, as the C's restart path did.
///
/// # Safety
///
/// The segment, object and page-queue locks must be held, and `seg`, `page`
/// and `object` must be the live page, segment and object the walk holds.
unsafe fn evict_reactivate(
    seg: *mut VmPageSeg,
    page: *mut VmPage,
    object: *mut VmObject,
) {
    // SAFETY: the segment, object and page-queues locks are held.
    unsafe {
        seg_add_active_page(seg, page);
        (*seg).lock.unlock();
        (*object).lock.unlock();
        VM_STAT.reactivations += 1;
        let thread = per_cpu::thread();
        if !thread.is_null() {
            // SAFETY: the C's `current_task()->reactivations++`; the running
            // thread's task is live for as long as the thread.
            let task = (*thread).task;
            (*task).reactivations = (*task).reactivations.wrapping_add(1);
        }
        VM_PAGE_QUEUE_LOCK.unlock();
    }
}

/// `vm_page_evict_once()` in C.
///
/// # Safety
///
/// The caller must hold no page lock, as [`evict_one`] requires.
unsafe fn evict_once(alloc_paused: bool) -> bool {
    // SAFETY: the C tries the four combinations in order, short-circuiting.
    unsafe {
        evict_one(true, false, alloc_paused)
            || evict_one(false, false, alloc_paused)
            || evict_one(true, true, alloc_paused)
            || evict_one(false, true, alloc_paused)
    }
}

/// `vm_page_evict()` in C.  Returns with `vm_page_queue_free_lock` held.
///
/// # Safety
///
/// `should_wait` must be writable, and no page lock may be held.
pub(crate) unsafe fn evict(should_wait: *mut c_int) -> bool {
    unsafe { *should_wait = c_int::from(true) };

    VM_PAGE_QUEUE_FREE_LOCK.lock();
    vm_resident::VM_PAGE_EXTERNAL_LAUNDRY_COUNT.store(0, Ordering::Relaxed);
    // SAFETY: the state is live for the kernel's lifetime.
    let alloc_paused = unsafe { (*state()).alloc_paused };
    VM_PAGE_QUEUE_FREE_LOCK.unlock();

    VM_PAGE_QUEUE_LOCK.lock();
    let pause = vm_resident::VM_PAGE_LAUNDRY_COUNT.load(Ordering::Relaxed)
        >= VM_PAGE_MAX_LAUNDRY;
    VM_PAGE_QUEUE_LOCK.unlock();

    if pause {
        // The C returns with the free lock held.
        VM_PAGE_QUEUE_FREE_LOCK.lock();
        return false;
    }

    let mut evicted = false;
    let mut i = 0;
    while i < VM_PAGE_MAX_EVICTIONS {
        // SAFETY: no page lock is held here.
        evicted = unsafe { evict_once(alloc_paused) };

        if !evicted {
            break;
        }

        i += 1;
    }

    // The C re-takes the free lock before the decision.
    VM_PAGE_QUEUE_FREE_LOCK.lock();

    if vm_resident::VM_PAGE_LAUNDRY_COUNT.load(Ordering::Relaxed) == 0
        && vm_resident::VM_PAGE_EXTERNAL_LAUNDRY_COUNT.load(Ordering::Relaxed)
            == 0
    {
        if evicted {
            unsafe { *should_wait = c_int::from(false) };
            return false;
        }

        // The free lock serializes the latch; a later page only skips the
        // warning.
        if !WARNED.swap(true, Ordering::Relaxed) {
            kprint!("vm_page warning: unable to recycle any page\n");
        }
    }

    VM_PAGE_QUEUE_FREE_LOCK.unlock();

    // SAFETY: the C's eviction caller holds no page lock.
    unsafe { check_usable() }
}

/// `vm_page_refill_inactive()` in C.
pub(crate) fn refill_inactive() {
    VM_PAGE_QUEUE_LOCK.lock();

    let mut i = 0;
    while i < segs_size() {
        // SAFETY: the page-queues lock is held.
        unsafe { seg_refill_inactive(seg_ptr(i)) };
        i += 1;
    }

    VM_PAGE_QUEUE_LOCK.unlock();
}

/// `vm_page_wait()` in C.
///
/// # Safety
///
/// The caller must not hold `vm_page_queue_free_lock` and must be ready to
/// block.
pub(crate) unsafe fn wait(continuation: Option<unsafe extern "C" fn()>) {
    VM_PAGE_QUEUE_FREE_LOCK.lock();

    // SAFETY: the state is live for the kernel's lifetime.
    if !unsafe { (*state()).alloc_paused } {
        VM_PAGE_QUEUE_FREE_LOCK.unlock();
        return;
    }

    // SAFETY: the C waits on the static's own address under the free lock.
    unsafe {
        assert_wait(
            NonNull::new(addr_of_mut!((*state()).alloc_paused).cast()),
            0,
        );
        VM_PAGE_QUEUE_FREE_LOCK.unlock();
        thread_block(continuation);
    }
}
