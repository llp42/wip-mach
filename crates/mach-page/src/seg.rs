// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! A physical segment: its range and page descriptors, its buddy free lists,
//! its per-CPU pools and its free-page thresholds.

use crate::page::{
    NR_FREE_LISTS, NodeList, ORDER_UNLISTED, PT_FREE, PT_RESERVED, Page,
    set_type,
};
use crate::param::{MAX_NCPUS, PAGE_SIZE, VmOffset, atop, ptoa};
use crate::simple_lock::SimpleLock;
use crate::table::{die, state};
use crate::types::{CpuPool, FreeList};
use collections::tail_queue::{Adapter, TailQueue};
use core::ffi::{c_int, c_uint};
use core::pin::Pin;
use core::ptr::{self, NonNull, addr_of_mut, null_mut};

const CPU_POOL_RATIO: usize = 1024;
const CPU_POOL_MAX_SIZE: usize = 128;
const CPU_POOL_TRANSFER_RATIO: usize = 2;

const THRESHOLD_MIN_NUM: usize = 5;
const THRESHOLD_MIN_DENOM: usize = 100;
const THRESHOLD_MIN: usize = 500;
const THRESHOLD_LOW_NUM: usize = 6;
const THRESHOLD_LOW_DENOM: usize = 100;
const THRESHOLD_LOW: usize = 600;
const THRESHOLD_HIGH_NUM: usize = 10;
const THRESHOLD_HIGH_DENOM: usize = 100;
const THRESHOLD_HIGH: usize = 1000;
const MIN_PAGES: usize = 2000;

const _: () = assert!(THRESHOLD_LOW > THRESHOLD_MIN);
const _: () = assert!(THRESHOLD_HIGH > THRESHOLD_LOW);
const _: () = assert!(MIN_PAGES > THRESHOLD_HIGH);

/// A physical memory segment.
pub struct Seg {
    cpu_pools: [CpuPool; MAX_NCPUS],
    pub start: VmOffset,
    pub end: VmOffset,
    pub pages: *mut Page<()>,
    pub pages_end: *mut Page<()>,
    pub lock: SimpleLock,
    free_lists: [FreeList; NR_FREE_LISTS],
    pub nr_free_pages: usize,
    pub min_free_pages: usize,
    pub low_free_pages: usize,
    pub high_free_pages: usize,
}

impl Seg {
    pub const fn new() -> Self {
        Self {
            cpu_pools: [const { CpuPool::new() }; MAX_NCPUS],
            start: 0,
            end: 0,
            pages: null_mut(),
            pages_end: null_mut(),
            lock: SimpleLock::new(),
            free_lists: [const { FreeList::new() }; NR_FREE_LISTS],
            nr_free_pages: 0,
            min_free_pages: 0,
            low_free_pages: 0,
            high_free_pages: 0,
        }
    }
}

/// Pins a queue head of the segment table.
///
/// # Safety
///
/// `head` must be a field of the segment table, which never moves.
const unsafe fn pin_head<'a, A: Adapter>(
    head: &'a mut TailQueue<'static, A>,
) -> Pin<&'a mut TailQueue<'static, A>> {
    // SAFETY: the caller promises the head never moves.
    unsafe { Pin::new_unchecked(head) }
}

/// Initializes the descriptor of the reserved page at `pa` in segment
/// `seg_index`: zeroed, then busy, as a fresh page is.
///
/// # Safety
///
/// `page` must point at writable storage for one descriptor, not yet visible
/// to any other thread.
unsafe fn init_pa(page: *mut Page<()>, seg_index: u16, pa: VmOffset) {
    unsafe {
        ptr::write_bytes(page, 0, 1);
        (*page).set_busy(true);
        (*page).set_page_type(PT_RESERVED);
        (*page).set_seg_index(seg_index);
        (*page).set_order(ORDER_UNLISTED);
        (*page).phys_addr = pa;
    }
}

/// Adds the block at `page` to `free_list`.
fn free_list_insert(free_list: &mut FreeList, page: *mut Page<()>) {
    free_list.size += 1;
    // SAFETY: the free list is in the segment table; the caller holds the
    // segment lock, and the page descriptor stays at its address while
    // linked.
    unsafe {
        pin_head(&mut free_list.blocks)
            .push_front_ptr(NonNull::new_unchecked(page));
    }
}

/// Removes the block at `page` from `free_list`.
fn free_list_remove(free_list: &mut FreeList, page: *mut Page<()>) {
    free_list.size -= 1;
    // SAFETY: the free list is in the segment table; the caller holds the
    // segment lock, and the page is linked in this free list.
    unsafe {
        pin_head(&mut free_list.blocks)
            .remove_ptr(NonNull::new_unchecked(page));
    }
}

/// Initializes `cpu_pool` to hold up to `size` pages.
fn cpu_pool_init(cpu_pool: &mut CpuPool, size: c_int) {
    cpu_pool.lock.init();
    cpu_pool.size = size;
    cpu_pool.transfer_size = (size + (CPU_POOL_TRANSFER_RATIO as c_int) - 1)
        / (CPU_POOL_TRANSFER_RATIO as c_int);
    cpu_pool.nr_pages = 0;
    cpu_pool.pages = NodeList::new();
}

/// The pool of CPU `cpu` in `seg`.
///
/// # Safety
///
/// `seg` must be a live segment and `cpu` below `MAX_NCPUS`.
unsafe fn cpu_pool_get(seg: *mut Seg, cpu: usize) -> *mut CpuPool {
    debug_assert!(cpu < MAX_NCPUS);
    // SAFETY: `cpu` is below `MAX_NCPUS`, the array's length, so the
    // element the offset reaches is inside the array.
    unsafe { addr_of_mut!((*seg).cpu_pools).cast::<CpuPool>().add(cpu) }
}

/// Takes a page out of `cpu_pool`.
///
/// The pool lock must be held and the pool must not be empty.
fn cpu_pool_pop(cpu_pool: &mut CpuPool) -> *mut Page<()> {
    cpu_pool.nr_pages -= 1;
    // SAFETY: the pool is in the segment table, and the caller holds its
    // lock.
    let page = unsafe { pin_head(&mut cpu_pool.pages) }
        .cursor_front_mut()
        .remove_current();
    let Some(page) = page else {
        die("vm_page_cpu_pool_pop", "vm_page: empty CPU pool");
    };
    ptr::from_mut(page)
}

/// Puts `page` into `cpu_pool`.
///
/// The pool lock must be held and `page` must be a live descriptor not on
/// any other list.
fn cpu_pool_push(cpu_pool: &mut CpuPool, page: *mut Page<()>) {
    cpu_pool.nr_pages += 1;
    // SAFETY: the pool is in the segment table; the caller holds the pool
    // lock and the page stays put.
    unsafe {
        pin_head(&mut cpu_pool.pages)
            .push_front_ptr(NonNull::new_unchecked(page));
    }
}

/// Moves a batch of free pages from the buddy lists of `seg` into `cpu_pool`,
/// returning how many.
///
/// # Safety
///
/// `seg` must be a live segment, the caller must serialize allocation, and
/// the segment lock must not be held.
unsafe fn cpu_pool_fill(
    cpu_pool: *mut CpuPool,
    seg: *mut Seg,
    limited: bool,
) -> c_int {
    unsafe { (*seg).lock.lock() };

    let mut i = 0;
    // SAFETY: `cpu_pool` points at a live pool of the segment.
    while i < unsafe { (*cpu_pool).transfer_size } {
        // SAFETY: the segment lock is held and allocation is serialized.
        let page = unsafe { alloc_from_buddy(seg, 0, limited) };
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

/// Moves a batch of pages from `cpu_pool` back to the buddy lists of `seg`.
///
/// # Safety
///
/// `seg` must be a live segment, the caller must serialize allocation, and
/// the segment lock must not be held.
unsafe fn cpu_pool_drain(cpu_pool: *mut CpuPool, seg: *mut Seg) {
    unsafe { (*seg).lock.lock() };

    // SAFETY: `cpu_pool` points at a live pool of the segment.
    let mut i = unsafe { (*cpu_pool).transfer_size };
    while i > 0 {
        // SAFETY: the pool was full, so the C's fixed transfer count is
        // available.
        let page = cpu_pool_pop(unsafe { &mut *cpu_pool });
        // SAFETY: the segment lock is held.
        unsafe { free_to_buddy(seg, page, 0) };
        i -= 1;
    }

    // SAFETY: the lock was taken above.
    unsafe { (*seg).lock.unlock() };
}

/// The size of `seg` in bytes.
///
/// # Safety
///
/// `seg` must be a live segment.
pub const unsafe fn size(seg: *const Seg) -> VmOffset {
    unsafe { (*seg).end - (*seg).start }
}

/// The per-CPU pool size of `seg`: a fraction of its pages, at least one and
/// at most the pool maximum.
///
/// # Safety
///
/// `seg` must be a live segment.
const unsafe fn compute_pool_size(seg: *const Seg) -> c_int {
    let mut size = atop(unsafe { size(seg) }) / CPU_POOL_RATIO;

    if size == 0 {
        size = 1;
    } else if size > CPU_POOL_MAX_SIZE {
        size = CPU_POOL_MAX_SIZE;
    }

    size as c_int
}

/// Sets the minimum, low and high free-page thresholds of `seg` from its size.
///
/// # Safety
///
/// `seg` must be a live segment.
unsafe fn compute_pageout_thresholds(seg: *mut Seg) {
    let nr_pages = atop(unsafe { size(seg) });

    if nr_pages < MIN_PAGES {
        die(
            "vm_page_seg_compute_pageout_thresholds",
            "vm_page: segment too small",
        );
    }

    let min_free_pages =
        nr_pages.wrapping_mul(THRESHOLD_MIN_NUM) / THRESHOLD_MIN_DENOM;
    let low_free_pages =
        nr_pages.wrapping_mul(THRESHOLD_LOW_NUM) / THRESHOLD_LOW_DENOM;
    let high_free_pages =
        nr_pages.wrapping_mul(THRESHOLD_HIGH_NUM) / THRESHOLD_HIGH_DENOM;

    unsafe {
        (*seg).min_free_pages = min_free_pages.max(THRESHOLD_MIN);
        (*seg).low_free_pages = low_free_pages.max(THRESHOLD_LOW);
        (*seg).high_free_pages = high_free_pages.max(THRESHOLD_HIGH);
    }
}

/// Initializes `seg`, the segment at `index`, over `start..end`, with its page
/// descriptors at `pages`.
///
/// # Safety
///
/// `seg` must be a live segment, `pages` must point at a table of
/// `atop(end - start)` writable descriptors, and no other thread may be
/// using either.
pub unsafe fn init(
    seg: *mut Seg,
    index: u16,
    start: VmOffset,
    end: VmOffset,
    pages: *mut Page<()>,
) {
    unsafe {
        (*seg).start = start;
        (*seg).end = end;
    }
    let pool_size = unsafe { compute_pool_size(seg) };

    let mut i = 0;
    while i < MAX_NCPUS {
        // SAFETY: `i` is below `MAX_NCPUS`, so the pool is live.
        cpu_pool_init(unsafe { &mut *cpu_pool_get(seg, i) }, pool_size);
        i += 1;
    }

    unsafe {
        (*seg).pages = pages;
        (*seg).pages_end = pages.add(atop(size(seg)));
        (*seg).lock.init();
    }

    let mut i = 0;
    while i < NR_FREE_LISTS {
        // SAFETY: `i` indexes the segment's free lists, which live.
        let free_list = unsafe { &mut (*seg).free_lists[i] };
        free_list.size = 0;
        free_list.blocks = NodeList::new();
        i += 1;
    }

    unsafe {
        (*seg).nr_free_pages = 0;
    }
    unsafe { compute_pageout_thresholds(seg) };

    let mut pa = start;
    while pa < end {
        // SAFETY: `pa` runs over the segment's pages.
        let page = unsafe { (*seg).pages.add(atop(pa - start)) };
        // SAFETY: the descriptor is inside the freshly reserved table.
        unsafe { init_pa(page, index, pa) };
        pa = pa.wrapping_add(PAGE_SIZE);
    }
}

/// Takes a block of `1 << order` pages from the buddy lists of `seg`,
/// splitting a larger block when needed, or null.  A `limited` caller gets
/// nothing while allocation is paused or the segment is at its minimum.
///
/// # Safety
///
/// `seg` must be a live segment, the caller must serialize allocation and
/// hold the segment lock.
pub unsafe fn alloc_from_buddy(
    seg: *mut Seg,
    order: c_uint,
    limited: bool,
) -> *mut Page<()> {
    if unsafe { (*state()).alloc_paused } && limited {
        return null_mut();
    } else if unsafe { (*seg).nr_free_pages <= (*seg).low_free_pages } {
        // SAFETY: the caller serializes allocation, which guards the flag.
        unsafe { (*state()).pageout_wanted = true };

        if unsafe { (*seg).nr_free_pages <= (*seg).min_free_pages } && limited
        {
            // SAFETY: the caller serializes allocation, which guards the
            // flag.
            unsafe { (*state()).alloc_paused = true };
            return null_mut();
        }
    }

    let mut i = order as usize;
    while i < NR_FREE_LISTS {
        if unsafe { (*seg).free_lists[i].size } != 0 {
            break;
        }
        i += 1;
    }

    if i == NR_FREE_LISTS {
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
    unsafe { (*page).set_order(ORDER_UNLISTED) };

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

/// Returns the block at `page` to the buddy lists of `seg`, merging it with
/// its free buddies.
///
/// # Safety
///
/// `seg` must be a live segment, the caller must hold its lock, and `page`
/// must be the first of `1 << order` free descriptors inside it.
pub unsafe fn free_to_buddy(
    seg: *mut Seg,
    mut page: *mut Page<()>,
    order: c_uint,
) {
    let mut order = order;
    let nr_pages = 1usize << order;
    let mut pa = unsafe { (*page).phys_addr };

    while order < (NR_FREE_LISTS as c_uint - 1) {
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
        unsafe { (*buddy).set_order(ORDER_UNLISTED) };
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

/// Allocates a block of `1 << order` pages of type `type_` from `seg` for a
/// thread on CPU `cpu`, through the CPU pool for a single page, or null.
///
/// # Safety
///
/// `seg` must be a live segment, `cpu` below `MAX_NCPUS`, and the caller must
/// serialize allocation.
pub unsafe fn alloc(
    seg: *mut Seg,
    order: c_uint,
    type_: u16,
    cpu: usize,
    limited: bool,
) -> *mut Page<()> {
    let page;

    if order == 0 {
        // SAFETY: the caller serializes allocation, which guards the flag.
        if unsafe { (*state()).alloc_paused } && limited {
            return null_mut();
        }

        let cpu_pool = unsafe { cpu_pool_get(seg, cpu) };
        // SAFETY: the pool lock serializes the pool.
        unsafe { (*cpu_pool).lock.lock() };

        // SAFETY: `cpu_pool` points at a live pool of the segment.
        if unsafe { (*cpu_pool).nr_pages } == 0 {
            // SAFETY: the pool lock is held and allocation is serialized.
            let filled = unsafe { cpu_pool_fill(cpu_pool, seg, limited) };

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
        page = unsafe { alloc_from_buddy(seg, order, limited) };
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

/// Frees a block of `1 << order` pages to `seg` from CPU `cpu`, through the
/// CPU pool for a single page.
///
/// # Safety
///
/// `seg` must be a live segment, `cpu` below `MAX_NCPUS`, `page` the first
/// of a block `seg` handed out, and the caller must serialize allocation.
pub unsafe fn free(
    seg: *mut Seg,
    page: *mut Page<()>,
    order: c_uint,
    cpu: usize,
) {
    unsafe { set_type(NonNull::new_unchecked(page), order, PT_FREE) };

    if order == 0 {
        let cpu_pool = unsafe { cpu_pool_get(seg, cpu) };
        // SAFETY: the pool lock serializes the pool.
        unsafe { (*cpu_pool).lock.lock() };

        // SAFETY: `cpu_pool` points at a live pool of the segment.
        if unsafe { (*cpu_pool).nr_pages == (*cpu_pool).size } {
            // SAFETY: the pool is full, the pool lock is held, and
            // allocation is serialized.
            unsafe { cpu_pool_drain(cpu_pool, seg) };
        }

        // SAFETY: the pool lock is held and the page is off every list.
        cpu_pool_push(unsafe { &mut *cpu_pool }, page);
        // SAFETY: the pool lock was taken above.
        unsafe { (*cpu_pool).lock.unlock() };
    } else {
        unsafe { (*seg).lock.lock() };
        // SAFETY: the segment lock is held and allocation is serialized.
        unsafe { free_to_buddy(seg, page, order) };
        // SAFETY: the segment lock was taken above.
        unsafe { (*seg).lock.unlock() };
    }
}
