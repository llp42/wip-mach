// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! VM's half of the physical pages: the page queues, the balancing of pages
//! between segments, eviction, and the wait for allocation to resume.
//!
//! The descriptor, the segments and their allocator are `mach_page`'s; VM
//! names the descriptor with its object as the owner, serializes allocation
//! with `VM_PAGE_QUEUE_FREE_LOCK`, and starts the pageout daemon when an
//! allocation finds a segment low.

use crate::cell::SyncCell;
use crate::cstr::CStrArg;
use crate::memory_object::default_manager;
use crate::param::{PAGE_SHIFT, PAGE_SIZE, VmOffset};
use crate::platform::{Continuation, Platform, THREAD_AWAKENED, TaskEvent};
use crate::types::{VmObject, VmProt};
use crate::vm_object;
use crate::vm_pageout::{self, vm_pageout_page};
use crate::vm_resident;
use crate::vm_resident::VM_PAGE_FICTITIOUS_ADDR;
use crate::vm_resident::VM_PAGE_QUEUE_FREE_LOCK;
use crate::vm_resident::VM_PAGE_QUEUE_LOCK;
use crate::vm_user::VM_STAT;
use collections::tail_queue::{self, TailQueue};
use core::cell::UnsafeCell;
use core::ffi::{CStr, c_int, c_uint, c_void};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::{NonNull, addr_of_mut, null_mut};
use core::sync::atomic::{AtomicBool, Ordering};
use mach_page::page::{ORDER_UNLISTED, PT_FREE, PT_TABLE};
use mach_page::table::{self, MAX_SEGS, seg_count, seg_lock};

pub use mach_page::page::set_type;
pub use mach_page::param::{atop, ptoa, round_page};
pub use mach_page::table::{
    SEG_DIRECTMAP, SEG_DMA, SEG_DMA32, SEG_HIGHMEM, SEL_DIRECTMAP, SEL_DMA,
    SEL_DMA32, SEL_HIGHMEM, bootalloc, is_ready, load, load_heap, manage,
    mem_free, mem_size, seg_name, table_index, table_size,
};

/// A physical page descriptor, owned by a VM object.
pub type VmPage = mach_page::Page<VmObject>;

/// The descriptor of the physical page at `pa`, when a segment holds it.
#[must_use]
pub fn lookup_pa(pa: VmOffset) -> Option<NonNull<VmPage>> {
    table::lookup_pa(pa)
}

tail_queue::adapter!(
    /// The adapter for a page's `node` in the page queues.
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

/// A segment page queue, on the pages' `node`, which they share with the
/// allocator's free lists: a queued page is never free.
pub type NodeList = TailQueue<'static, VmPageNodeAdapter>;

/// A global LRU queue, on the pages' `node_lru`.
pub type LruList = TailQueue<'static, VmPageLruAdapter>;

/// An object's resident pages, on their `listq`.
pub type ListqList = TailQueue<'static, VmPageListqAdapter>;

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

/// Marks the page wired down by yet another map, removing it from the paging
/// queues when it was unwired.
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

const VM_PAGE_HIGH_ACTIVE_PAGE_NUM: usize = 1;
const VM_PAGE_HIGH_ACTIVE_PAGE_DENOM: usize = 3;

const VM_PAGE_MAX_LAUNDRY: c_int = 5;
const VM_PAGE_MAX_EVICTIONS: usize = 5;

/// Halts the kernel with `message`, under the `func` tag.
fn die(func: &'static str, message: &'static str) -> ! {
    panic!("{func}: {message}")
}

/// A list of pages and its length.
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

/// The internal and external page lists of one queue.
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

/// The internal and external least-recently-used page lists.
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

/// The page queues of one segment, which its segment lock guards.
struct SegQueues {
    active: PageQueue,
    high_active: usize,
    inactive: PageQueue,
}

impl SegQueues {
    const fn new() -> Self {
        Self {
            active: PageQueue::new(),
            high_active: 0,
            inactive: PageQueue::new(),
        }
    }

    /// How many pages the segment's queues hold.
    const fn queued(&self) -> usize {
        self.active.internal.nr_pages
            + self.active.external.nr_pages
            + self.inactive.internal.nr_pages
            + self.inactive.external.nr_pages
    }
}

/// The module's `static` state: each segment's page queues, and the two LRU
/// queues the C kept at file scope.  The C locks serialize it.
struct QueueState {
    segs: [SegQueues; MAX_SEGS],
    active_lru: LruQueue,
    inactive_lru: LruQueue,
}

impl QueueState {
    const fn new() -> Self {
        Self {
            segs: [const { SegQueues::new() }; MAX_SEGS],
            active_lru: LruQueue::new(),
            inactive_lru: LruQueue::new(),
        }
    }
}

static STATE: SyncCell<QueueState> =
    SyncCell(UnsafeCell::new(QueueState::new()));

/// The event a thread waits on while allocation is paused.
static ALLOC_RESUMED: SyncCell<u8> = SyncCell(UnsafeCell::new(0));

/// Whether [`evict`] already warned that it could not recycle any page.
static WARNED: AtomicBool = AtomicBool::new(false);

fn state() -> *mut QueueState {
    STATE.0.get()
}

/// The page queues of segment `index`, which every caller keeps below
/// `MAX_SEGS`, as the C's unguarded array indexing assumed.
fn queues(index: usize) -> *mut SegQueues {
    debug_assert!(index < MAX_SEGS);
    // SAFETY: the caller promises `index` is in range; the array is static
    // storage that never moves.
    unsafe { addr_of_mut!((*state()).segs).cast::<SegQueues>().add(index) }
}

/// Whether the running thread may not dip into the free-page reserve: a
/// thread runs and it is not VM-privileged.  An early-boot call with no
/// thread is not limited.
fn limited<P: Platform>() -> bool {
    // SAFETY: the thread check short-circuits, so a thread runs.
    P::has_thread() && unsafe { P::vm_privilege() } == 0
}

/// Starts the pageout daemon when an allocation since the last check found a
/// segment low.  The caller holds `VM_PAGE_QUEUE_FREE_LOCK`, as
/// [`vm_pageout::start`] asks.
fn start_pageout_if_wanted<P: Platform>() {
    if table::take_pageout_wanted() {
        vm_pageout::start::<P>();
    }
}

/// Whether the page belongs to an object, is not wired, and sits on a page
/// queue.
///
/// # Safety
///
/// `page` must be a live descriptor.
unsafe fn pageable(page: *const VmPage) -> bool {
    unsafe {
        !(*page).object.is_null()
            && (*page).wire_count() == 0
            && ((*page).is_active() || (*page).is_inactive())
    }
}

/// Whether the page may move to another segment: it is idle and its object
/// alive.
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

/// Marks the page busy, removes every mapping of it, and records whether a
/// mapping dirtied it.
///
/// # Safety
///
/// `page` must be a live descriptor.
unsafe fn remove_mappings<P: Platform>(page: *mut VmPage) {
    unsafe {
        (*page).set_busy(true);
        P::pmap_page_protect((*page).phys_addr, VmProt::empty());
        if !(*page).is_dirty() {
            (*page).set_dirty(P::pmap_is_modified((*page).phys_addr));
        }
    }
}

/// Adds `page` to `queue`, on its internal or external list.
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

/// Removes `page` from `queue`.
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

/// Adds `page` to the LRU `queue`, on its internal or external list.
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

/// Removes `page` from the LRU `queue`.
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

/// Puts `page` on the active queue of segment `seg`.
///
/// # Safety
///
/// The segment and page-queues locks must be held, and `page` must be a live
/// descriptor of the segment, not already queued.
unsafe fn seg_add_active_page(seg: usize, page: *mut VmPage) {
    unsafe {
        (*page).set_active(true);
        (*page).set_reference(true);
        page_queue_push(addr_of_mut!((*queues(seg)).active), page);
        lru_queue_push(addr_of_mut!((*state()).active_lru), page);
    }
    vm_resident::VM_PAGE_ACTIVE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Takes `page` off the active queue of segment `seg`.
///
/// # Safety
///
/// The segment and page-queues locks must be held, and `page` must be queued
/// active.
unsafe fn seg_remove_active_page(seg: usize, page: *mut VmPage) {
    unsafe {
        (*page).set_active(false);
        page_queue_remove(addr_of_mut!((*queues(seg)).active), page);
        lru_queue_remove(addr_of_mut!((*state()).active_lru), page);
    }
    vm_resident::VM_PAGE_ACTIVE_COUNT.fetch_sub(1, Ordering::Relaxed);
}

/// Puts `page` on the inactive queue of segment `seg`.
///
/// # Safety
///
/// The segment and page-queues locks must be held, and `page` must be a live
/// descriptor of the segment, not already queued.
unsafe fn seg_add_inactive_page(seg: usize, page: *mut VmPage) {
    unsafe {
        (*page).set_inactive(true);
        page_queue_push(addr_of_mut!((*queues(seg)).inactive), page);
        lru_queue_push(addr_of_mut!((*state()).inactive_lru), page);
    }
    vm_resident::VM_PAGE_INACTIVE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Takes `page` off the inactive queue of segment `seg`.
///
/// # Safety
///
/// The segment and page-queues locks must be held, and `page` must be queued
/// inactive.
unsafe fn seg_remove_inactive_page(seg: usize, page: *mut VmPage) {
    unsafe {
        (*page).set_inactive(false);
        page_queue_remove(addr_of_mut!((*queues(seg)).inactive), page);
        lru_queue_remove(addr_of_mut!((*state()).inactive_lru), page);
    }
    vm_resident::VM_PAGE_INACTIVE_COUNT.fetch_sub(1, Ordering::Relaxed);
}

/// Takes a movable page off the internal or external active queue of segment
/// `seg`, or null.
///
/// # Safety
///
/// The segment and page-queues locks must be held.  On success the object
/// lock is held and the page is off the queues; the caller keeps the segment
/// lock.
unsafe fn seg_pull_active_page(seg: usize, external: bool) -> *mut VmPage {
    let page_list = if external {
        unsafe { addr_of_mut!((*queues(seg)).active.external.pages) }
    } else {
        unsafe { addr_of_mut!((*queues(seg)).active.internal.pages) }
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

/// Takes a movable page off the internal or external inactive queue of
/// segment `seg`, or null.
///
/// # Safety
///
/// Same contract as [`seg_pull_active_page()`].
unsafe fn seg_pull_inactive_page(seg: usize, external: bool) -> *mut VmPage {
    let page_list = if external {
        unsafe { addr_of_mut!((*queues(seg)).inactive.external.pages) }
    } else {
        unsafe { addr_of_mut!((*queues(seg)).inactive.internal.pages) }
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

/// Takes a pageable page off the internal or external active LRU list, or
/// null.
///
/// # Safety
///
/// The page-queues lock must be held.  On success the segment and object
/// locks are held and the page is off the queues.
unsafe fn pull_active_page(external: bool) -> *mut VmPage {
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
        let seg = unsafe { (*page).seg_index() } as usize;
        // The C takes the segment lock here.
        seg_lock(seg).lock();

        // SAFETY: the segment lock and page-queues lock are held.
        unsafe { seg_remove_active_page(seg, page) };
        // SAFETY: the page is live and was queued active above.
        let object = unsafe { (*page).object };
        // SAFETY: a queued page has a live object.
        let locked = unsafe { (*object).lock.try_lock() };

        if !locked {
            // SAFETY: the page was removed above.
            unsafe { seg_add_active_page(seg, page) };
            seg_lock(seg).unlock();
            continue;
        }

        // SAFETY: the object lock is held.
        if !unsafe { can_move(page) } {
            unsafe { seg_add_active_page(seg, page) };
            // SAFETY: the object lock was taken above.
            unsafe { (*object).lock.unlock() };
            seg_lock(seg).unlock();
            continue;
        }

        return page;
    }

    null_mut()
}

/// Takes a pageable page off the internal or external inactive LRU list, or
/// null.
///
/// # Safety
///
/// Same contract as [`pull_active_page()`].
unsafe fn pull_inactive_page(external: bool) -> *mut VmPage {
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
        let seg = unsafe { (*page).seg_index() } as usize;
        // The C takes the segment lock here.
        seg_lock(seg).lock();

        // SAFETY: the segment lock and page-queues lock are held.
        unsafe { seg_remove_inactive_page(seg, page) };
        // SAFETY: the page is live and was queued inactive above.
        let object = unsafe { (*page).object };
        // SAFETY: a queued page has a live object.
        let locked = unsafe { (*object).lock.try_lock() };

        if !locked {
            // SAFETY: the page was removed above.
            unsafe { seg_add_inactive_page(seg, page) };
            seg_lock(seg).unlock();
            continue;
        }

        // SAFETY: the object lock is held.
        if !unsafe { can_move(page) } {
            unsafe { seg_add_inactive_page(seg, page) };
            // SAFETY: the object lock was taken above.
            unsafe { (*object).lock.unlock() };
            seg_lock(seg).unlock();
            continue;
        }

        return page;
    }

    null_mut()
}

/// Whether segment `seg` has more free pages than its high threshold.
///
/// The segment lock must be held.
fn seg_page_available(seg: usize) -> bool {
    let info = table::seg_info(seg);
    info.free > info.high_free
}

/// Whether segment `seg` may serve allocations: it has no queued pages, or
/// enough free ones.
///
/// # Safety
///
/// The segment lock must be held.
unsafe fn seg_usable(seg: usize) -> bool {
    let queued = unsafe { (*queues(seg)).queued() };
    let info = table::seg_info(seg);

    queued == 0 || info.free >= info.high_free
}

/// Locks two segments in address order, so two balancers cannot deadlock.
///
/// `seg1` and `seg2` must be distinct segments, unlocked.
fn seg_double_lock(seg1: usize, seg2: usize) {
    let (lock1, lock2) = (seg_lock(seg1), seg_lock(seg2));
    if core::ptr::from_ref(lock1) < core::ptr::from_ref(lock2) {
        lock1.lock();
        lock2.lock();
    } else {
        lock2.lock();
        lock1.lock();
    }
}

/// Unlocks two segments [`seg_double_lock`] locked.
///
/// Both locks must be held.
fn seg_double_unlock(seg1: usize, seg2: usize) {
    seg_lock(seg1).unlock();
    seg_lock(seg2).unlock();
}

/// Moves one page out of segment `seg`, when it is short of free pages, into
/// `remote_seg`, when that one has pages to spare.
///
/// # Safety
///
/// Both segments must be unlocked; the page-queues and free locks must not
/// be held.  Returns with every lock released.
unsafe fn seg_balance_page<P: Platform>(
    seg: usize,
    remote_seg: usize,
    priv_alloc: bool,
) -> bool {
    VM_PAGE_QUEUE_LOCK.lock();
    VM_PAGE_QUEUE_FREE_LOCK.lock();
    seg_double_lock(seg, remote_seg);

    // SAFETY: the segment lock is held.
    let unusable = unsafe { !seg_usable(seg) };
    let remote_full = if priv_alloc {
        table::seg_info(remote_seg).free == 0
    } else {
        !seg_page_available(remote_seg)
    };

    if !unusable || remote_full {
        seg_double_unlock(seg, remote_seg);
        VM_PAGE_QUEUE_FREE_LOCK.unlock();
        VM_PAGE_QUEUE_LOCK.unlock();
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
        seg_double_unlock(seg, remote_seg);
        VM_PAGE_QUEUE_FREE_LOCK.unlock();
        VM_PAGE_QUEUE_LOCK.unlock();
        return false;
    }

    // SAFETY: the remote segment lock and the free lock are held, and the
    // remote segment has free pages, as the check above established.
    let dest: *mut VmPage =
        unsafe { table::alloc_locked(remote_seg, limited::<P>()) };

    seg_double_unlock(seg, remote_seg);
    start_pageout_if_wanted::<P>();
    VM_PAGE_QUEUE_FREE_LOCK.unlock();

    if dest.is_null() {
        die("vm_page_seg_balance_page", "vm_page: no dest page");
    }

    // SAFETY: the source object lock is held.
    if !was_active
        // SAFETY: the source page is live and its object lock is held.
        && !unsafe { (*src).is_reference() }
        && unsafe { P::pmap_is_referenced((*src).phys_addr) }
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
    unsafe { remove_mappings::<P>(src) };

    // SAFETY: both pages are live; the body copy carries the object, offset
    // and flags.
    unsafe {
        set_type(NonNull::new_unchecked(dest), 0, (*src).page_type());
        (*dest).copy_body_from(&*src);
    }
    // SAFETY: both pages are live and their object locks are held.
    unsafe {
        vm_resident::copy::<P>(
            NonNull::new_unchecked(src),
            NonNull::new_unchecked(dest),
        );
    };

    // SAFETY: the destination page is live.
    if !unsafe { (*src).is_dirty() } {
        // SAFETY: the destination page is live and its address is real.
        unsafe { P::pmap_clear_modify((*dest).phys_addr) };
    }
    // SAFETY: the destination page is live and off every queue.
    unsafe { (*dest).set_busy(false) };

    // SAFETY: the free lock and the segment lock are taken in the C's
    // order, and the source page is live.
    unsafe {
        VM_PAGE_QUEUE_FREE_LOCK.lock();
        vm_resident::init(&mut *src);
        (*src).set_free(true);
        seg_lock(seg).lock();
        table::free_locked(src);
        seg_lock(seg).unlock();
        VM_PAGE_QUEUE_FREE_LOCK.unlock();
    }

    // SAFETY: the destination page is live, the object lock and the
    // page-queues lock are held, and the destination is not queued.
    unsafe {
        vm_resident::insert::<P>(
            NonNull::new_unchecked(dest),
            NonNull::new_unchecked(object),
            offset,
        );
        (*object).lock.unlock();

        if was_active {
            activate(dest);
        } else {
            deactivate::<P>(dest);
        }

        VM_PAGE_QUEUE_LOCK.unlock();
    }

    true
}

/// Moves one page out of segment `seg` into another segment, trying the
/// segments from the last.
///
/// # Safety
///
/// The C's caller holds no page lock around it.
unsafe fn seg_balance<P: Platform>(seg: usize, priv_alloc: bool) -> bool {
    let mut i = seg_count().wrapping_sub(1);

    while i < seg_count() {
        if i != seg
            // SAFETY: both segments are unlocked, as required.
            && unsafe { seg_balance_page::<P>(seg, i, priv_alloc) }
        {
            return true;
        }

        i = i.wrapping_sub(1);
    }

    false
}

/// Sets the active-page limit of segment `seg` from its queued page count.
///
/// # Safety
///
/// The segment lock must be held.
unsafe fn seg_compute_high_active_page(seg: usize) {
    let queues = queues(seg);
    unsafe {
        (*queues).high_active = (*queues)
            .queued()
            .wrapping_mul(VM_PAGE_HIGH_ACTIVE_PAGE_NUM)
            / VM_PAGE_HIGH_ACTIVE_PAGE_DENOM;
    }
}

/// Moves pages of segment `seg` from its active to its inactive queues until
/// the active ones are under the limit.
///
/// # Safety
///
/// The segment lock must not be held; the page-queues lock must be held.
unsafe fn seg_refill_inactive<P: Platform>(seg: usize) {
    seg_lock(seg).lock();

    // SAFETY: the segment and page-queues locks are held.
    unsafe { seg_compute_high_active_page(seg) };

    loop {
        let queues = queues(seg);
        // SAFETY: the segment lock is held.
        let actives = unsafe {
            (*queues).active.internal.nr_pages
                + (*queues).active.external.nr_pages
        };
        // SAFETY: the segment lock is held.
        if actives <= unsafe { (*queues).high_active } {
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
            P::pmap_clear_reference((*page).phys_addr);
            seg_add_inactive_page(seg, page);
            (*(*page).object).lock.unlock();
        }
    }

    seg_lock(seg).unlock();
}

/// Builds the page table and releases the segments.
pub(crate) fn setup<P: Platform>() {
    let nr_pages = table::boot_table_size();
    let table_size = round_page(nr_pages.wrapping_mul(size_of::<VmPage>()));
    P::print(format_args!(
        "vm_page: page table size: {} entries ({}k)\n",
        nr_pages,
        table_size >> 10,
    ));

    // The boot allocator panics if the kernel address space is exhausted,
    // as the C did.
    let table = match vm_resident::pmap_steal_memory::<P>(table_size) {
        Ok(addr) => addr,
        Err(size) => panic!(
            "not enough kernel virtual space for {}MB virtual allocation!",
            size >> 20
        ),
    };

    // SAFETY: the stolen memory is mapped, holds `nr_pages` descriptors, and
    // setup runs once, single-threaded.
    unsafe { table::setup(table as *mut mach_page::Page<()>) };

    let mut va = table;
    while va < table + nr_pages * size_of::<VmPage>() {
        // SAFETY: `P::pmap_extract()` reads the boot pmap for a mapped address.
        let pa = unsafe { P::pmap_extract(P::kernel_pmap(), va) };
        // SAFETY: the address was just mapped by the pmap over the page
        // table, so it has a descriptor.
        let Some(page) = lookup_pa(pa) else {
            die("vm_page_setup", "vm_page: page table not in any segment");
        };

        // SAFETY: the descriptor is live and setup is single-threaded.
        unsafe { (*page.as_ptr()).set_page_type(PT_TABLE) };
        va = va.wrapping_add(PAGE_SIZE);
    }
}

/// Checks the descriptor `page` for inconsistent flags, halting the kernel
/// when it finds one.
///
/// # Safety
///
/// `page` must be a live descriptor whose fields no one changes during the
/// check.
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

    let Some(index) = table::seg_of(unsafe { (*page).phys_addr }) else {
        if !unsafe { (*page).is_private() } {
            die(
                "vm_page_check",
                "vm_page: page claims it's managed but not in any segment",
            );
        }
        return;
    };

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

        if unsafe { real_page.as_ref().page_type() } == PT_FREE
            || unsafe { real_page.as_ref().order() } != ORDER_UNLISTED
        {
            die(
                "vm_page_check",
                "vm_page: page underlying private pagei is free",
            );
        }
        return;
    }

    if index != unsafe { (*page).seg_index() } as usize {
        die("vm_page_check", "vm_page: page segment mismatch");
    }
}

/// Allocates a block of `1 << order` pages with `selector` and `type`, or
/// null.  Returns with `VM_PAGE_QUEUE_FREE_LOCK` held.
///
/// # Safety
///
/// The caller must not hold `VM_PAGE_QUEUE_FREE_LOCK` and must be ready to
/// release it.
pub(crate) unsafe fn alloc_pa<P: Platform>(
    order: c_uint,
    selector: c_uint,
    type_: u16,
) -> *mut VmPage {
    let seg_index = table::select_seg(selector);

    loop {
        VM_PAGE_QUEUE_FREE_LOCK.lock();

        let limited = limited::<P>();
        let mut i = seg_index;
        while i < seg_count() {
            // SAFETY: the free lock serializes allocation, `i` is a loaded
            // segment, and the running CPU's index is below `MAX_NCPUS`.
            let page =
                unsafe { table::alloc(i, order, type_, P::cpu_id(), limited) };
            start_pageout_if_wanted::<P>();

            if !page.is_null() {
                return page;
            }

            i = i.wrapping_sub(1);
        }

        if !limited {
            VM_PAGE_QUEUE_FREE_LOCK.unlock();

            let mut i = seg_index;
            while i < seg_count() {
                // SAFETY: the C's balancing caller holds no page lock.
                if unsafe { seg_balance::<P>(i, true) } {
                    break;
                }

                i = i.wrapping_sub(1);
            }

            if i < seg_count() {
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

/// Frees the block of `1 << order` pages at `page`.
///
/// # Safety
///
/// `page` must be the first of `1 << order` descriptors the module handed out,
/// and the caller must hold `VM_PAGE_QUEUE_FREE_LOCK`.
pub(crate) unsafe fn free_pa<P: Platform>(page: *mut VmPage, order: c_uint) {
    // SAFETY: the free lock serializes freeing, and the running CPU's index
    // is below `MAX_NCPUS`.
    unsafe { table::free(page, order, P::cpu_id()) };
}

/// The name of segment `seg_index` as a C string; an unknown index halts the
/// kernel.
fn name_ptr(seg_index: c_uint) -> *const core::ffi::c_char {
    seg_name(seg_index).map_or_else(
        || die("vm_page_seg_name", "vm_page: invalid segment index"),
        CStr::as_ptr,
    )
}

/// Prints each segment's page and free-page counts.
pub(crate) fn info_all<P: Platform>() {
    let mut i = 0;
    while i < seg_count() {
        let info = table::seg_info(i);
        let name = name_ptr(i as c_uint);

        // SAFETY: `name_ptr()` returned a segment's NUL-terminated name.
        let name = unsafe { CStrArg::from_ptr(name) };
        P::print(format_args!(
            "vm_page: {}: pages: {} ({}M), free: {} ({}M)\n",
            name,
            info.pages,
            info.pages >> (20 - PAGE_SHIFT),
            info.free,
            info.free >> (20 - PAGE_SHIFT),
        ));
        P::print(format_args!(
            "vm_page: {name}: min:{} low:{} high:{}\n",
            info.min_free, info.low_free, info.high_free,
        ));

        i += 1;
    }
}

/// Drops a wiring of `page`, putting it back on the active queue when it was
/// the last.
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

    let seg = unsafe { (*page).seg_index() } as usize;
    // The C takes the segment lock under the page-queues lock.
    seg_lock(seg).lock();
    // SAFETY: the segment and page-queues locks are held.
    unsafe { seg_add_active_page(seg, page) };
    seg_lock(seg).unlock();
    vm_resident::VM_PAGE_WIRE_COUNT.fetch_sub(1, Ordering::Relaxed);
}

/// Moves `page` to the inactive queue.
///
/// # Safety
///
/// `page` must be a live page and the caller must hold the page-queues lock.
pub(crate) unsafe fn deactivate<P: Platform>(page: *mut VmPage) {
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
            unsafe { P::pmap_clear_reference((*page).phys_addr) };
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
        let seg = unsafe { (*page).seg_index() } as usize;
        // The C takes the segment lock under the page-queues lock.
        seg_lock(seg).lock();
        // SAFETY: the segment and page-queues locks are held.
        unsafe { seg_add_inactive_page(seg, page) };
        seg_lock(seg).unlock();
    }
}

/// Moves `page` to the active queue; activating an active page halts the
/// kernel.
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
        let seg = unsafe { (*page).seg_index() } as usize;

        if unsafe { (*page).is_active() } {
            die("vm_page_activate", "vm_page_activate: already active");
        }

        // The C takes the segment lock under the page-queues lock.
        seg_lock(seg).lock();
        // SAFETY: the segment and page-queues locks are held.
        unsafe { seg_add_active_page(seg, page) };
        seg_lock(seg).unlock();
    }
}

/// Takes `page` off the active or inactive queue.
///
/// # Safety
///
/// `page` must be a live page and the caller must hold the page-queues lock
/// and, when the page is queued, its object lock, as the C required.
pub(crate) unsafe fn queues_remove(page: *mut VmPage) {
    if !unsafe { (*page).is_active() } && !unsafe { (*page).is_inactive() } {
        return;
    }

    let seg = unsafe { (*page).seg_index() } as usize;
    // The C takes the segment lock under the page-queues lock.
    seg_lock(seg).lock();

    // SAFETY: the segment and page-queues locks are held, and the page is
    // queued as its flags say.
    unsafe {
        if (*page).is_active() {
            seg_remove_active_page(seg, page);
        } else {
            seg_remove_inactive_page(seg, page);
        }
    }

    seg_lock(seg).unlock();
}

/// Whether every segment may serve allocations.  Returns with
/// `VM_PAGE_QUEUE_FREE_LOCK` held.
///
/// # Safety
///
/// The caller must hold no page lock: neither the free lock nor the
/// page-queues lock.
unsafe fn check_usable<P: Platform>() -> bool {
    VM_PAGE_QUEUE_FREE_LOCK.lock();

    let mut i = 0;
    while i < seg_count() {
        // The C takes the segment lock under the free lock.
        seg_lock(i).lock();
        // SAFETY: the segment lock is held.
        let usable = unsafe { seg_usable(i) };
        seg_lock(i).unlock();

        if !usable {
            return false;
        }

        i += 1;
    }

    vm_resident::VM_PAGE_EXTERNAL_LAUNDRY_COUNT.store(-1, Ordering::Relaxed);

    // The free lock serializes allocation, as resuming it requires.
    table::resume_alloc();
    P::thread_wakeup_prim(
        ALLOC_RESUMED.0.get().cast::<c_void>(),
        0,
        THREAD_AWAKENED,
    );

    true
}

/// Whether some segment has pages to spare for balancing.
///
/// The caller must hold no page lock; the function takes and releases each
/// segment's lock in turn to probe it.
fn may_balance() -> bool {
    let mut i = 0;
    while i < seg_count() {
        // The C takes the segment lock for the probe.
        seg_lock(i).lock();
        let available = seg_page_available(i);
        seg_lock(i).unlock();

        if available {
            return true;
        }

        i += 1;
    }

    false
}

/// Moves one page between segments, when one has pages to spare.
///
/// # Safety
///
/// The caller must hold no page lock, as [`seg_balance`] requires.
unsafe fn balance_once<P: Platform>() -> bool {
    let mut i = 0;
    while i < seg_count() {
        // SAFETY: no page lock is held.
        if unsafe { seg_balance::<P>(i, false) } {
            return true;
        }

        i += 1;
    }

    false
}

/// Balances the segments until none can spare a page.  Returns with
/// `VM_PAGE_QUEUE_FREE_LOCK` held.
///
/// # Safety
///
/// The caller must hold no page lock.
pub(crate) unsafe fn balance<P: Platform>() -> bool {
    while may_balance() {
        if !unsafe { balance_once::<P>() } {
            break;
        }
    }

    // SAFETY: the C's balancing caller holds no page lock.
    unsafe { check_usable::<P>() }
}

/// Evicts one page from the internal or external, active or inactive queues,
/// returning whether it did.
///
/// # Safety
///
/// No page lock may be held; the C's caller is the pageout path.
unsafe fn evict_one<P: Platform>(
    external: bool,
    active: bool,
    alloc_paused: bool,
) -> bool {
    if !external && !default_manager::is_set::<P>() {
        return false;
    }

    let mut seg: Option<usize> = None;
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
            seg = Some(unsafe { (*page).seg_index() } as usize);
        } else {
            // The second pass re-takes the locks the C did.
            if let Some(seg) = seg {
                seg_lock(seg).lock();
            }
            // SAFETY: the page is live and its object outlives the pass.
            unsafe { (*(*page).object).lock.lock() };
        }

        // SAFETY: the page is live and its object lock is held.
        object = unsafe { (*page).object };

        if !active
            // SAFETY: the page is live and its object lock is held.
            && (unsafe { (*page).is_reference() }
                || unsafe { P::pmap_is_referenced((*page).phys_addr) })
        {
            let Some(index) = seg else {
                die("vm_page_seg_evict", "vm_page: referenced page lost");
            };
            // SAFETY: the segment, object and page-queues locks are held.
            unsafe { evict_reactivate::<P>(index, page, object) };

            seg = None;
            page = null_mut();
            continue;
        }

        // SAFETY: the page is live.
        unsafe { remove_mappings::<P>(page) };

        // SAFETY: the page is live.
        reclaim = !unsafe { (*page).is_dirty() }
            && !unsafe { (*page).is_precious() };

        // SAFETY: the object lock is held.
        if !reclaim {
            // SAFETY: the object lock is held.
            if unsafe { (*object).is_internal() }
                || !alloc_paused
                || !default_manager::is_set::<P>()
                // SAFETY: the object lock is held, and its pager is live.
                || unsafe { default_manager::port::<P>((*object).pager) }
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
        if let Some(seg) = seg {
            seg_lock(seg).unlock();
        }

        if reclaim {
            // SAFETY: the page-queues lock is held, as `vm_resident::free`
            // requires.
            unsafe {
                vm_resident::free::<P>(NonNull::new_unchecked(page));
                VM_PAGE_QUEUE_LOCK.unlock();

                if (*object).ref_count == 0
                    && (*object).resident_page_count == 0
                {
                    vm_object::collect::<P>(object);
                } else {
                    (*object).lock.unlock();
                }
            }

            return true;
        }

        VM_PAGE_QUEUE_LOCK.unlock();

        if default_manager::is_set::<P>() {
            // SAFETY: the object lock is held and the C calls the object's
            // pager entries.
            unsafe {
                if !(*object).is_pager_initialized() {
                    vm_object::collapse::<P>(object);
                }
                if !(*object).is_pager_initialized() {
                    vm_object::pager_create::<P>(object);
                }
            }

            // SAFETY: the object lock is held.
            if !unsafe { (*object).is_pager_initialized() } {
                die("vm_page_seg_evict", "vm_page_seg_evict");
            }
        }

        // SAFETY: the object lock is held, as the C's flush had it.
        unsafe {
            vm_pageout_page::<P>(page, 0, 1);
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
/// and `object` must be the segment, live page and object the walk holds.
unsafe fn evict_reactivate<P: Platform>(
    seg: usize,
    page: *mut VmPage,
    object: *mut VmObject,
) {
    // SAFETY: the segment, object and page-queues locks are held.
    unsafe {
        seg_add_active_page(seg, page);
        seg_lock(seg).unlock();
        (*object).lock.unlock();
        VM_STAT.reactivations.fetch_add(1, Ordering::Relaxed);
        P::count(TaskEvent::Reactivation);
        VM_PAGE_QUEUE_LOCK.unlock();
    }
}

/// Evicts one page, trying the external inactive, internal inactive, external
/// active and internal active queues in turn.
///
/// # Safety
///
/// The caller must hold no page lock, as [`evict_one`] requires.
unsafe fn evict_once<P: Platform>(alloc_paused: bool) -> bool {
    // SAFETY: the C tries the four combinations in order, short-circuiting.
    unsafe {
        evict_one::<P>(true, false, alloc_paused)
            || evict_one::<P>(false, false, alloc_paused)
            || evict_one::<P>(true, true, alloc_paused)
            || evict_one::<P>(false, true, alloc_paused)
    }
}

/// Evicts a batch of pages, unless too many are already being cleaned.
/// Returns with `VM_PAGE_QUEUE_FREE_LOCK` held.
///
/// # Safety
///
/// `should_wait` must be writable, and no page lock may be held.
pub(crate) unsafe fn evict<P: Platform>(should_wait: *mut c_int) -> bool {
    unsafe { *should_wait = c_int::from(true) };

    VM_PAGE_QUEUE_FREE_LOCK.lock();
    vm_resident::VM_PAGE_EXTERNAL_LAUNDRY_COUNT.store(0, Ordering::Relaxed);
    let alloc_paused = table::alloc_paused();
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
        evicted = unsafe { evict_once::<P>(alloc_paused) };

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
            P::print(format_args!(
                "vm_page warning: unable to recycle any page\n"
            ));
        }
    }

    VM_PAGE_QUEUE_FREE_LOCK.unlock();

    // SAFETY: the C's eviction caller holds no page lock.
    unsafe { check_usable::<P>() }
}

/// Refills the inactive queues of every segment from their active ones.
pub(crate) fn refill_inactive<P: Platform>() {
    VM_PAGE_QUEUE_LOCK.lock();

    let mut i = 0;
    while i < seg_count() {
        // SAFETY: the page-queues lock is held.
        unsafe { seg_refill_inactive::<P>(i) };
        i += 1;
    }

    VM_PAGE_QUEUE_LOCK.unlock();
}

/// Waits for page allocation to resume, when it is paused, continuing with
/// `continuation`.
///
/// # Safety
///
/// The caller must not hold `VM_PAGE_QUEUE_FREE_LOCK` and must be ready to
/// block.
pub unsafe fn wait<P: Platform>(continuation: Continuation) {
    VM_PAGE_QUEUE_FREE_LOCK.lock();

    if !table::alloc_paused() {
        VM_PAGE_QUEUE_FREE_LOCK.unlock();
        return;
    }

    // SAFETY: the C waits on a static's address under the free lock.
    unsafe {
        P::assert_wait(NonNull::new(ALLOC_RESUMED.0.get().cast()), 0);
        VM_PAGE_QUEUE_FREE_LOCK.unlock();
        P::thread_block(continuation);
    }
}
