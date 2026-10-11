// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The segment table: the segments the boot loader reported, the boot heap
//! carved from them before the page table exists, and the page table the
//! allocator serves pages from.
//!
//! The caller serializes allocation and freeing with one lock of its own
//! (VM's free-page lock); a segment's own lock guards its buddy lists, and
//! a pool's lock its pool.

use crate::cell::SyncCell;
use crate::page::{PT_FREE, Page, set_type};
use crate::param::{VmOffset, VmSize, atop, round_page};
use crate::seg::{self, Seg};
use crate::simple_lock::SimpleLock;
use crate::types::{BootSeg, SegInfo};
use core::cell::UnsafeCell;
use core::cmp::min;
use core::ffi::{CStr, c_uint};
use core::ptr::{NonNull, addr_of_mut};

/// The segment ISA DMA reaches.
pub const SEG_DMA: c_uint = 0;
/// The segment the kernel maps directly.
pub const SEG_DIRECTMAP: c_uint = 1;
/// The segment 32-bit DMA reaches.
pub const SEG_DMA32: c_uint = 2;
/// The segment above the direct map.
pub const SEG_HIGHMEM: c_uint = 3;

/// The number of physical segments.
pub const MAX_SEGS: usize = 4;

/// The selector of memory ISA DMA reaches, for [`alloc`] through
/// [`select_seg`].
pub const SEL_DMA: c_uint = 0;
/// The selector of directly mapped memory.
pub const SEL_DIRECTMAP: c_uint = 1;
/// The selector of memory 32-bit DMA reaches.
pub const SEL_DMA32: c_uint = 2;
/// The selector of any memory.
pub const SEL_HIGHMEM: c_uint = 3;

/// The name of a physical segment index.
#[must_use]
pub const fn seg_name(seg_index: c_uint) -> Option<&'static CStr> {
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

/// The crate's `static` state: the segment table, the boot table, and the
/// flags allocation raises for its caller.
pub(crate) struct State {
    segs: [Seg; MAX_SEGS],
    boot_segs: [BootSeg; MAX_SEGS],
    segs_size: u32,
    is_ready: bool,
    pub(crate) alloc_paused: bool,
    pub(crate) pageout_wanted: bool,
}

impl State {
    const fn new() -> Self {
        Self {
            segs: [const { Seg::new() }; MAX_SEGS],
            boot_segs: [const { BootSeg::new() }; MAX_SEGS],
            segs_size: 0,
            is_ready: false,
            alloc_paused: false,
            pageout_wanted: false,
        }
    }
}

static STATE: SyncCell<State> = SyncCell(UnsafeCell::new(State::new()));

pub(crate) fn state() -> *mut State {
    STATE.0.get()
}

/// Halts the kernel with `message`, under the `func` tag.
pub(crate) fn die(func: &'static str, message: &'static str) -> ! {
    panic!("{func}: {message}")
}

/// The segment at `index`, which every caller keeps below `MAX_SEGS`, as the
/// C's unguarded array indexing assumed.
fn seg_ptr(index: usize) -> *mut Seg {
    debug_assert!(index < MAX_SEGS);
    // SAFETY: the caller promises `index` is in range; the array is static
    // storage that never moves.
    unsafe { addr_of_mut!((*state()).segs).cast::<Seg>().add(index) }
}

/// The number of segments the boot loader reported.
#[must_use]
pub fn seg_count() -> usize {
    // SAFETY: the state is live for the kernel's lifetime.
    unsafe { (*state()).segs_size as usize }
}

/// The boot segment at `index`.
///
/// # Safety
///
/// `index` must be below `MAX_SEGS`.
unsafe fn boot_seg(index: usize) -> *mut BootSeg {
    if index >= MAX_SEGS {
        die("vm_page_load", "vm_page: invalid segment index");
    }
    // SAFETY: the check above bounds the index.
    unsafe {
        addr_of_mut!((*state()).boot_segs)
            .cast::<BootSeg>()
            .add(index)
    }
}

/// Records the physical range `start..end` of segment `seg_index`, from the
/// boot loader.
pub fn load(seg_index: c_uint, start: VmOffset, end: VmOffset) {
    let index = seg_index as usize;
    // SAFETY: the architecture loader passes the segment index the C
    // declared, below `MAX_SEGS`.
    let seg = unsafe { boot_seg(index) };

    // SAFETY: the state is live and the boot loader runs single-threaded.
    unsafe {
        (*seg).start = start;
        (*seg).end = end;
        (*seg).heap_present = false;
        (*state()).segs_size += 1;
    }
}

/// Records the part `start..end` of segment `seg_index` the boot heap may use.
pub fn load_heap(seg_index: c_uint, start: VmOffset, end: VmOffset) {
    let index = seg_index as usize;
    // SAFETY: the architecture loader passes the segment index the C
    // declared, below `MAX_SEGS`.
    let seg = unsafe { boot_seg(index) };

    // SAFETY: the state is live and the boot loader runs single-threaded.
    unsafe {
        (*seg).avail_start = start;
        (*seg).avail_end = end;
        (*seg).heap_present = true;
    }
}

/// Whether the page table is set up.
#[must_use]
pub fn is_ready() -> bool {
    // SAFETY: the state is live for the kernel's lifetime.
    unsafe { (*state()).is_ready }
}

/// The segment an allocation with `selector` starts from: the selector's
/// segment, or the last one loaded.  [`alloc`] falls back from it to the
/// segments below.
#[must_use]
pub fn select_seg(selector: c_uint) -> usize {
    let seg_index = match selector {
        SEL_DMA => SEG_DMA,
        SEL_DMA32 => SEG_DMA32,
        SEL_DIRECTMAP => SEG_DIRECTMAP,
        SEL_HIGHMEM => SEG_HIGHMEM,
        _ => die("vm_page_select_alloc_seg", "vm_page: invalid selector"),
    };

    // An empty table wraps `segs_size - 1` to all ones, so the selector wins.
    // SAFETY: the state is live for the kernel's lifetime.
    min(unsafe { (*state()).segs_size }.wrapping_sub(1), seg_index) as usize
}

/// Checks that the loaded segments are exactly the first `segs_size` ones,
/// halting the kernel when they are not.
fn check_boot_segs() {
    if seg_count() == 0 {
        die(
            "vm_page_check_boot_segs",
            "vm_page: no physical memory loaded",
        );
    }

    let mut i = 0;
    while i < MAX_SEGS {
        let expect_loaded = i < seg_count();
        // SAFETY: `i` is inside the boot table.
        let seg = unsafe { boot_seg(i) };

        // SAFETY: the descriptor is live.
        if unsafe { (*seg).end != 0 } == expect_loaded {
            i += 1;
            continue;
        }

        die(
            "vm_page_check_boot_segs",
            "vm_page: invalid boot segment table",
        );
    }
}

/// Allocates `size` bytes of physical memory from the boot heap, before the
/// page table exists.  Running out halts the kernel.
#[must_use]
pub fn bootalloc(size: VmSize) -> VmOffset {
    let mut i = select_seg(SEL_DIRECTMAP);

    while i < seg_count() {
        // SAFETY: `i` is inside the boot table.
        let seg = unsafe { boot_seg(i) };

        // SAFETY: the descriptor is live.
        if size <= unsafe { (*seg).avail_end - (*seg).avail_start } {
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

/// The number of pages the boot segments cover: the descriptors the page
/// table [`setup`] takes needs.
#[must_use]
pub fn boot_table_size() -> usize {
    let mut nr_pages = 0;
    let mut i = 0;
    while i < seg_count() {
        // SAFETY: `i` is inside the boot table.
        let seg = unsafe { boot_seg(i) };
        // SAFETY: the descriptor is live.
        nr_pages += atop(unsafe { (*seg).end - (*seg).start });
        i += 1;
    }

    nr_pages
}

/// Builds the page table at `table`, which holds [`boot_table_size`]
/// descriptors, and hands the boot heap's unused pages to the buddy lists.
///
/// # Safety
///
/// `table` must point at writable storage for that many descriptors, which
/// stays mapped for the kernel's lifetime; setup runs once, single-threaded.
pub unsafe fn setup(table: *mut Page<()>) {
    check_boot_segs();

    let mut table = table;
    let mut i = 0;
    while i < seg_count() {
        let seg = seg_ptr(i);
        // SAFETY: `i` is inside the boot table, so the descriptor is live.
        let boot = unsafe { boot_seg(i) };

        // SAFETY: the page table has room for every segment's descriptors,
        // and setup is single-threaded.
        unsafe {
            seg::init(seg, i as u16, (*boot).start, (*boot).end, table);

            if (*boot).heap_present {
                let mut page = (*seg)
                    .pages
                    .add(atop((*boot).avail_start - (*boot).start));
                let end =
                    (*seg).pages.add(atop((*boot).avail_end - (*boot).start));

                while page < end {
                    (*page).set_page_type(PT_FREE);
                    seg::free_to_buddy(seg, page, 0);
                    page = page.add(1);
                }
            }

            table = table.add(atop(seg::size(seg)));
        }

        i += 1;
    }

    // SAFETY: the state is live and setup runs once.
    unsafe { (*state()).is_ready = true };
}

/// Hands the reserved page `page` to its segment's buddy lists as a free page.
///
/// # Safety
///
/// `page` must be a live descriptor the kernel is handing to the allocator,
/// not yet on any list.
pub unsafe fn manage<O>(page: *mut Page<O>) {
    let page = page.cast::<Page<()>>();
    unsafe {
        set_type(NonNull::new_unchecked(page), 0, PT_FREE);
        let seg = seg_ptr((*page).seg_index() as usize);
        seg::free_to_buddy(seg, page, 0);
    }
}

/// The descriptor of the physical page at `pa`, when a segment holds it.
#[must_use]
pub fn lookup_pa<O>(pa: VmOffset) -> Option<NonNull<Page<O>>> {
    let index = seg_of(pa)?;
    let seg = seg_ptr(index);
    // SAFETY: the physical address is inside the segment.
    let page = unsafe { (*seg).pages.add(atop(pa - (*seg).start)) };
    NonNull::new(page.cast::<Page<O>>())
}

/// The index of the segment holding the physical address `pa`.
#[must_use]
pub fn seg_of(pa: VmOffset) -> Option<usize> {
    let mut i = 0;
    while i < seg_count() {
        let seg = seg_ptr(i);
        // SAFETY: `i` is inside the segment table.
        let (start, end) = unsafe { ((*seg).start, (*seg).end) };

        if start <= pa && pa < end {
            return Some(i);
        }

        i += 1;
    }

    None
}

/// The number of page descriptors the page table holds, or will.
#[must_use]
pub fn table_size() -> usize {
    if !is_ready() {
        return boot_table_size();
    }

    let mut nr_pages = 0;
    let mut i = 0;
    while i < seg_count() {
        // SAFETY: the segment is live.
        nr_pages += atop(unsafe { seg::size(seg_ptr(i)) });
        i += 1;
    }

    nr_pages
}

/// The index of the physical page at `pa` in the page table; an address
/// outside every segment halts the kernel.
#[must_use]
pub fn table_index(pa: VmOffset) -> usize {
    let mut index = 0;
    let mut i = 0;

    while i < seg_count() {
        let seg = seg_ptr(i);
        // SAFETY: the segment is live.
        let (start, end) = unsafe { ((*seg).start, (*seg).end) };

        if start <= pa && pa < end {
            return index + atop(pa - start);
        }

        // SAFETY: the segment is live, as the loop's walk established.
        index += atop(unsafe { seg::size(seg) });
        i += 1;
    }

    die("vm_page_table_index", "vm_page: invalid physical address")
}

/// The size of the physical memory the segments cover.
#[must_use]
pub fn mem_size() -> VmOffset {
    let mut total = 0;
    let mut i = 0;

    while i < seg_count() {
        // SAFETY: the segment is live.
        total += unsafe { seg::size(seg_ptr(i)) };
        i += 1;
    }

    total
}

/// The number of free pages in every segment.
#[must_use]
pub fn mem_free() -> usize {
    let mut total = 0;
    let mut i = 0;

    while i < seg_count() {
        // SAFETY: the segment is live.
        total += unsafe { (*seg_ptr(i)).nr_free_pages };
        i += 1;
    }

    total
}

/// The page and free-page counts and the thresholds of segment `index`.
///
/// # Panics
///
/// When `index` is not a loaded segment.
#[must_use]
pub fn seg_info(index: usize) -> SegInfo {
    assert!(index < seg_count(), "vm_page: invalid segment index");
    let seg = seg_ptr(index);
    // SAFETY: `index` is inside the segment table, so the segment is live.
    unsafe {
        SegInfo {
            pages: (*seg).pages_end.offset_from((*seg).pages) as usize,
            free: (*seg).nr_free_pages,
            min_free: (*seg).min_free_pages,
            low_free: (*seg).low_free_pages,
            high_free: (*seg).high_free_pages,
        }
    }
}

/// The lock of segment `index`, which guards its buddy lists and counts, and
/// which VM also takes for its page queues of the segment.
///
/// # Panics
///
/// When `index` is not a loaded segment.
#[must_use]
pub fn seg_lock(index: usize) -> &'static SimpleLock {
    assert!(index < seg_count(), "vm_page: invalid segment index");
    // SAFETY: `index` is inside the segment table, so the segment is static
    // storage that never moves, and the lock is only ever used through
    // shared references.
    unsafe { &(*seg_ptr(index)).lock }
}

/// Allocates a block of `1 << order` pages of type `type_` from segment
/// `seg_index`, or null.
///
/// A single page comes through the pool of CPU `cpu`.  A `limited` thread
/// gets nothing while allocation is paused, or from a segment at its
/// minimum.
///
/// A segment at or below its low threshold raises the flag
/// [`take_pageout_wanted`] reports.
///
/// # Safety
///
/// `seg_index` must be a loaded segment and `cpu` below `MAX_NCPUS`; the
/// caller must serialize allocation and freeing.
#[must_use]
pub unsafe fn alloc<O>(
    seg_index: usize,
    order: c_uint,
    type_: u16,
    cpu: usize,
    limited: bool,
) -> *mut Page<O> {
    // SAFETY: the caller's promises are the segment's.
    unsafe { seg::alloc(seg_ptr(seg_index), order, type_, cpu, limited) }
        .cast()
}

/// Frees the block of `1 << order` pages at `page` from CPU `cpu`.
///
/// # Safety
///
/// `page` must be the first of `1 << order` descriptors [`alloc`] handed out,
/// `cpu` below `MAX_NCPUS`, and the caller must serialize allocation and
/// freeing.
pub unsafe fn free<O>(page: *mut Page<O>, order: c_uint, cpu: usize) {
    let page = page.cast::<Page<()>>();
    let seg = seg_ptr(unsafe { (*page).seg_index() } as usize);
    // SAFETY: the caller's promises are the segment's.
    unsafe { seg::free(seg, page, order, cpu) };
}

/// Takes a single page from the buddy lists of segment `seg_index`, as
/// [`alloc`] would but bypassing the CPU pools, or null.
///
/// # Safety
///
/// `seg_index` must be a loaded segment; the caller must serialize allocation
/// and hold the segment's lock.
#[must_use]
pub unsafe fn alloc_locked<O>(
    seg_index: usize,
    limited: bool,
) -> *mut Page<O> {
    // SAFETY: the caller's promises are the segment's.
    unsafe { seg::alloc_from_buddy(seg_ptr(seg_index), 0, limited) }.cast()
}

/// Returns the single page `page`, of type free, to the buddy lists of its
/// segment.
///
/// # Safety
///
/// `page` must be a live descriptor off every list, and the caller must
/// serialize allocation and hold the segment's lock.
pub unsafe fn free_locked<O>(page: *mut Page<O>) {
    let page = page.cast::<Page<()>>();
    unsafe {
        set_type(NonNull::new_unchecked(page), 0, PT_FREE);
        let seg = seg_ptr((*page).seg_index() as usize);
        seg::free_to_buddy(seg, page, 0);
    }
}

/// Whether allocation is paused for limited threads.
///
/// The caller must serialize allocation.
#[must_use]
pub fn alloc_paused() -> bool {
    // SAFETY: the caller's lock guards the flag.
    unsafe { (*state()).alloc_paused }
}

/// Resumes allocation for limited threads.
///
/// The caller must serialize allocation.
pub fn resume_alloc() {
    // SAFETY: the caller's lock guards the flag.
    unsafe { (*state()).alloc_paused = false };
}

/// Whether an allocation since the last call found a segment at or below its
/// low threshold; the caller then starts its pageout.
///
/// The caller must serialize allocation.
#[must_use]
pub fn take_pageout_wanted() -> bool {
    // SAFETY: the caller's lock guards the flag.
    unsafe { core::mem::replace(&mut (*state()).pageout_wanted, false) }
}
