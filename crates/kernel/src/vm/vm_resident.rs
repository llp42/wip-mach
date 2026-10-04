// SPDX-License-Identifier: CMU-Mach
// Derived from vm/vm_resident.c:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Resident memory management, which `vm/vm_resident.c` used to define.

use crate::arch::types::{AtomicVmOffset, VmOffset, VmSize};
use crate::arch::vm_param::{PAGE_SHIFT, PAGE_SIZE};
use crate::arch::x86_64::phys;
use crate::arch::x86_64::pmap::kernel_pmap_ptr;
use crate::arch::x86_64::pmap::pmap_enter;
use crate::arch::x86_64::pmap::pmap_virtual_space;
use crate::ipc::HashInfoBucket;
use crate::kern::console::kprint;
use crate::kern::debug::kpanic;
use crate::kern::lock::SimpleLock;
use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::utils::cell::SyncCell;
use crate::vm::types::{VmObject, VmPage, VmProt};
use crate::vm::vm_map::{round_page, trunc_page};
use crate::vm::vm_page::{self, NodeList};
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_uint, c_ushort};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::{NonNull, addr_of_mut, null_mut};
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// `VM_PAGE_HIGHMEM` of <`vm/vm_page.h>`: the page may come from high physical
/// memory.
const VM_PAGE_HIGHMEM: c_uint = 0x08;

/// `VM_PAGE_DMA32` and `VM_PAGE_DIRECTMAP` of <`vm/vm_page.h>`: the flags that
/// ask for those segments.
pub(crate) const VM_PAGE_DMA32: c_uint = 0x04;
pub(crate) const VM_PAGE_DIRECTMAP: c_uint = 0x02;

/// `VM_PAGE_SEL_*` of <`vm/vm_page.h>`: the segment selectors
/// `vm_page_alloc_pa()` takes, ordered by physical reach.
const VM_PAGE_SEL_DMA: c_uint = 0;
const VM_PAGE_SEL_DIRECTMAP: c_uint = 1;
const VM_PAGE_SEL_DMA32: c_uint = 2;
const VM_PAGE_SEL_HIGHMEM: c_uint = 3;

/// `VM_PT_KERNEL` of <`vm/vm_page.h>`: the type for generic kernel
/// allocations.
const VM_PT_KERNEL: c_ushort = 3;

/// `vm_page_fictitious_quantum` of `vm/vm_resident.c`.
const VM_PAGE_FICTITIOUS_QUANTUM: c_int = 5;

/// `virtual_space_start` of `vm/vm_resident.c`: the first kernel virtual
/// address `pmap_steal_memory()` hands out.
static VIRTUAL_SPACE_START: AtomicVmOffset = AtomicVmOffset::new(0);

/// `virtual_space_end` of `vm/vm_resident.c`: the end of the range
/// `pmap_steal_memory()` hands out.
static VIRTUAL_SPACE_END: AtomicVmOffset = AtomicVmOffset::new(0);

/// `vm_page_queue_free_lock` of `vm/vm_resident.c`: the lock on the free page
/// queue and the fictitious-page list.
pub(crate) static VM_PAGE_QUEUE_FREE_LOCK: SimpleLock = SimpleLock::new();

/// `vm_page_queue_lock` of `vm/vm_resident.c`: the lock on the active and
/// inactive page queues.
pub(crate) static VM_PAGE_QUEUE_LOCK: SimpleLock = SimpleLock::new();

/// `vm_page_fictitious_addr` of `vm/vm_resident.c`: the fake physical address
/// of a fictitious page.
pub(crate) const VM_PAGE_FICTITIOUS_ADDR: VmOffset = VmOffset::MAX;

/// `vm_page_fictitious_count` of `vm/vm_resident.c`: how many fictitious pages
/// are free.  `vm_page_queue_free_lock` serializes every access, so the
/// atomic only has to make each one indivisible.
pub(crate) static VM_PAGE_FICTITIOUS_COUNT: AtomicI32 = AtomicI32::new(0);

/// `vm_object_external_count` of `vm/vm_object.h`: how many objects are paged
/// externally.  Locked like `VM_PAGE_ACTIVE_COUNT`.
pub(crate) static VM_OBJECT_EXTERNAL_COUNT: AtomicI32 = AtomicI32::new(0);

/// `vm_object_external_pages` of `vm/vm_object.h`: how many resident pages of
/// external objects there are.  Locked like `VM_PAGE_ACTIVE_COUNT`.
pub(crate) static VM_OBJECT_EXTERNAL_PAGES: AtomicI32 = AtomicI32::new(0);

/// `vm_page_active_count` of `vm/vm_resident.c`: how many pages are active.
/// Every update holds `vm_page_queue_lock`, so the atomic only has to make
/// each access indivisible.
pub(crate) static VM_PAGE_ACTIVE_COUNT: AtomicI32 = AtomicI32::new(0);

/// `vm_page_inactive_count` of `vm/vm_resident.c`: how many pages are
/// inactive.
pub(crate) static VM_PAGE_INACTIVE_COUNT: AtomicI32 = AtomicI32::new(0);

/// `vm_page_wire_count` of `vm/vm_resident.c`: how many pages are wired.
pub(crate) static VM_PAGE_WIRE_COUNT: AtomicI32 = AtomicI32::new(0);

/// `vm_page_laundry_count` of `vm/vm_resident.c`: how many pages are being
/// cleaned.  `vm_page_queue_lock` serializes every access.
pub(crate) static VM_PAGE_LAUNDRY_COUNT: AtomicI32 = AtomicI32::new(0);

/// `vm_page_external_laundry_count` of `vm/vm_resident.c`: the same for
/// external pagers.
pub(crate) static VM_PAGE_EXTERNAL_LAUNDRY_COUNT: AtomicI32 =
    AtomicI32::new(0);

/// `vm_page_deactivate_behind` of `vm/vm_resident.c`: whether a page inserted
/// right after the last allocation deactivates that last page.
pub(crate) static VM_PAGE_DEACTIVATE_BEHIND: AtomicBool =
    AtomicBool::new(true);

/// `vm_page_deactivate_hint` of `vm/vm_resident.c`: whether a clean request
/// deactivates the cleaned pages.
pub(crate) static VM_PAGE_DEACTIVATE_HINT: AtomicBool = AtomicBool::new(true);

/// `vm_page_cache` of `vm/vm_resident.c`: the `struct vm_page` slab cache.
static mut VM_PAGE_CACHE: KmemCache = KmemCache::zeroed();

/// `vm_page_bucket_t` of `vm/vm_resident.c`: one head of the
/// object/offset-to-page hash table.  File-private after this port.
struct PageBucket {
    lock: SimpleLock,
    pages: *mut VmPage,
}

/// The hash table and the fictitious-page list, the file-private state of
/// `vm/vm_resident.c`.  The bucket locks and `vm_page_queue_free_lock` serialize
/// access, as in the C.
struct ResidentState {
    buckets: *mut PageBucket,
    bucket_count: usize,
    hash_mask: usize,
    fictitious: NodeList,
}

impl ResidentState {
    const fn new() -> Self {
        Self {
            buckets: null_mut(),
            bucket_count: 0,
            hash_mask: 0,
            fictitious: NodeList::new(),
        }
    }
}

static RESIDENT_STATE: SyncCell<ResidentState> =
    SyncCell(UnsafeCell::new(ResidentState::new()));

fn state() -> *mut ResidentState {
    RESIDENT_STATE.0.get()
}

/// `panic()` of `vm/vm_resident.c`.
fn die(func: &'static str, message: &'static str) -> ! {
    kpanic!(func, "{}", message)
}

/// `vm_page_hash()` of `vm/vm_resident.c` at the given key.
///
/// # Safety
///
/// The bootstrap must have sized the table, as the C's callers had.
unsafe fn bucket_index(object: *mut VmObject, offset: VmOffset) -> usize {
    // The C truncated both terms to `unsigned int` before the mask, so on a
    // 64-bit machine the pointer contributes only its low 32 bits.
    let mask = unsafe { (*state()).hash_mask } as u32;
    let hash =
        (object as usize as u32).wrapping_add((offset >> PAGE_SHIFT) as u32);
    (hash & mask) as usize
}

/// The bucket head for `object`/`offset`.
///
/// # Safety
///
/// The bootstrap must have allocated the table.
unsafe fn bucket_ptr(
    object: *mut VmObject,
    offset: VmOffset,
) -> *mut PageBucket {
    unsafe { (*state()).buckets.add(bucket_index(object, offset)) }
}

/// `pmap_steal_memory()` in C: reserve `size` of kernel virtual space and map
/// fresh physical pages into it.
///
/// On failure the error is the page-rounded size the C passed to its
/// exhaustion panic, in bytes.
pub(crate) fn pmap_steal_memory(size: VmSize) -> Result<VmOffset, VmSize> {
    let size = round_page(size);

    let mut start = VIRTUAL_SPACE_START.load(Ordering::Relaxed);
    let mut end = VIRTUAL_SPACE_END.load(Ordering::Relaxed);
    if start == end {
        // SAFETY: the pair is empty, so the pmap has yet to report a range.
        unsafe { pmap_virtual_space(&raw mut start, &raw mut end) };
        start = round_page(start);
        end = trunc_page(end);
        VIRTUAL_SPACE_START.store(start, Ordering::Relaxed);
        VIRTUAL_SPACE_END.store(end, Ordering::Relaxed);
    }

    let addr = start;
    let new_start = start.wrapping_add(size);
    if new_start < start {
        return Err(size);
    }
    VIRTUAL_SPACE_START.store(new_start, Ordering::Relaxed);

    let limit = addr.wrapping_add(size);
    let mut vaddr = round_page(addr);
    while vaddr < limit {
        let paddr = vm_page::bootalloc(PAGE_SIZE);
        // SAFETY: `kernel_pmap` is the boot pmap and `vaddr` is inside the
        // range just reserved; the C maps the page without wiring it.
        unsafe {
            pmap_enter(
                NonNull::new(kernel_pmap_ptr()),
                vaddr,
                paddr,
                (VmProt::READ | VmProt::WRITE).bits(),
                c_int::from(false),
            );
        };
        vaddr = vaddr.wrapping_add(PAGE_SIZE);
    }

    Ok(addr)
}

/// `vm_page_bootstrap()` in C: initialize the page queues and the
/// object/offset hash table, then report the kernel virtual range.
pub(crate) fn bootstrap() -> (VmOffset, VmOffset) {
    // SAFETY: the bootstrap runs once, before any other user of the two
    // locks, and the fictitious list is not yet linked.
    unsafe {
        VM_PAGE_QUEUE_FREE_LOCK.init();
        VM_PAGE_QUEUE_LOCK.init();
        (*state()).fictitious = NodeList::new();
    }

    // SAFETY: the bootstrap owns the state until the table is up.
    let mut bucket_count = unsafe { (*state()).bucket_count };
    if bucket_count == 0 {
        let npages = vm_page::table_size();
        bucket_count = 1;
        while bucket_count < npages {
            bucket_count <<= 1;
        }
        // SAFETY: the bootstrap owns the state until the table is up.
        unsafe { (*state()).bucket_count = bucket_count };
    }

    let hash_mask = bucket_count - 1;
    // SAFETY: the bootstrap owns the state until the table is up.
    unsafe { (*state()).hash_mask = hash_mask };

    if hash_mask & bucket_count != 0 {
        kprint!("vm_page_bootstrap: WARNING -- strange page hash\n");
    }

    let size = bucket_count.wrapping_mul(size_of::<PageBucket>());
    let buckets = match pmap_steal_memory(size) {
        Ok(addr) => addr,
        Err(size) => {
            kpanic!(
                "pmap_steal_memory",
                "not enough kernel virtual space for {}MB virtual allocation!\n",
                size >> 20
            )
        }
    };
    // `vm_offset_t` and a pointer are the same width.
    let buckets = buckets as *mut PageBucket;

    // SAFETY: the fresh table is the module's own storage and no other
    // thread can see it yet.
    unsafe { (*state()).buckets = buckets };

    let mut i = 0;
    while i < bucket_count {
        // SAFETY: `i` is inside the table just allocated.
        let bucket = unsafe { buckets.add(i) };
        // SAFETY: `i` is inside the table just allocated; the bucket is fresh
        // storage.
        unsafe {
            (*bucket).pages = null_mut();
            (*bucket).lock.init();
        }
        i += 1;
    }

    vm_page::setup();

    let start = round_page(VIRTUAL_SPACE_START.load(Ordering::Relaxed));
    let end = trunc_page(VIRTUAL_SPACE_END.load(Ordering::Relaxed));
    VIRTUAL_SPACE_START.store(start, Ordering::Relaxed);
    VIRTUAL_SPACE_END.store(end, Ordering::Relaxed);

    (start, end)
}

/// `vm_page_insert()` in C: put `mem` in the object/offset hash table and the
/// object's page list.
///
/// # Safety
///
/// `mem` must be a live page and `object` a live, locked object, and the
/// caller must hold `vm_page_queue_lock`, as the C required.
pub(crate) unsafe fn insert(
    mem: NonNull<VmPage>,
    object: NonNull<VmObject>,
    offset: VmOffset,
) {
    let page = mem.as_ptr();
    let object = object.as_ptr();

    unsafe { vm_page::check(page) };

    unsafe {
        if !(*object).is_internal() {
            (*page).set_external(true);
            VM_OBJECT_EXTERNAL_PAGES.fetch_add(1, Ordering::Relaxed);
        }

        if (*page).is_tabled() {
            die("vm_page_insert", "vm_page_insert");
        }

        (*page).object = object;
        (*page).offset = offset;
    }

    // SAFETY: the bootstrap built the table; the object lock serializes the
    // field, and the bucket lock serializes the chain.
    unsafe {
        let bucket = bucket_ptr(object, offset);
        (*bucket).lock.lock();
        (*page).next = (*bucket).pages;
        (*bucket).pages = page;
        (*bucket).lock.unlock();

        VmObject::memq_pinned(object)
            .push_back_ptr(NonNull::new_unchecked(page));
        (*page).set_tabled(true);
        (*object).resident_page_count += 1;
    }

    let deactivate_behind = VM_PAGE_DEACTIVATE_BEHIND.load(Ordering::Relaxed);
    // SAFETY: the page is live and the object locked, as `lookup` needs.
    let behind = unsafe {
        if deactivate_behind
            && offset == (*object).last_alloc.wrapping_add(PAGE_SIZE)
        {
            lookup(NonNull::new_unchecked(object), (*object).last_alloc)
        } else {
            None
        }
    };
    if let Some(behind) = behind {
        // SAFETY: the page came out of the table and the page-queues lock is
        // held, as `deactivate` needs.
        unsafe {
            if !(*behind.as_ptr()).is_busy() {
                vm_page::deactivate(behind.as_ptr());
            }
            (*object).last_alloc = offset;
        }
    } else {
        unsafe { (*object).last_alloc = offset };
    }
}

/// `vm_page_replace()` in C: insert `mem`, first removing any page already at
/// the key.
///
/// # Safety
///
/// `mem` must be a live page and `object` a live, locked object, and the
/// caller must hold `vm_page_queue_lock`, as the C required.
pub(crate) unsafe fn replace(
    mem: NonNull<VmPage>,
    object: NonNull<VmObject>,
    offset: VmOffset,
) {
    let page = mem.as_ptr();
    let object = object.as_ptr();

    unsafe { vm_page::check(page) };

    unsafe {
        if !(*object).is_internal() {
            (*page).set_external(true);
            VM_OBJECT_EXTERNAL_PAGES.fetch_add(1, Ordering::Relaxed);
        }

        if (*page).is_tabled() {
            die("vm_page_replace", "vm_page_replace");
        }

        (*page).object = object;
        (*page).offset = offset;
    }

    // SAFETY: the bootstrap built the table; the object lock serializes the
    // fields, and the bucket lock serializes the chain.
    unsafe {
        let bucket = bucket_ptr(object, offset);
        (*bucket).lock.lock();

        if (*bucket).pages.is_null() {
            (*page).next = null_mut();
        } else {
            let mut link = addr_of_mut!((*bucket).pages);
            loop {
                let old = *link;
                if old.is_null() {
                    break;
                }
                if (*old).object == object && (*old).offset == offset {
                    *link = (*old).next;
                    VmObject::memq_pinned(object)
                        .remove_ptr(NonNull::new_unchecked(old));
                    (*old).set_tabled(false);
                    (*object).resident_page_count -= 1;
                    vm_page::queues_remove(old);

                    if (*old).is_external() {
                        (*old).set_external(false);
                        VM_OBJECT_EXTERNAL_PAGES
                            .fetch_sub(1, Ordering::Relaxed);
                    }

                    free(NonNull::new_unchecked(old));
                    break;
                }
                link = addr_of_mut!((*old).next);
            }
            (*page).next = (*bucket).pages;
        }

        (*bucket).pages = page;
        (*bucket).lock.unlock();
    }

    // SAFETY: the page is live and the caller holds the object lock.
    unsafe {
        VmObject::memq_pinned(object)
            .push_back_ptr(NonNull::new_unchecked(page));
        (*page).set_tabled(true);
        (*object).resident_page_count += 1;
    }
}

/// `vm_page_remove()` in C: unlink `mem` from the hash table, its object's
/// page list and the page queues.
///
/// # Safety
///
/// `mem` must be a live, tabled page whose object lock and page-queues lock
/// the caller holds, as the C required.
pub(crate) unsafe fn remove(mem: NonNull<VmPage>) {
    let page = mem.as_ptr();

    unsafe { vm_page::check(page) };

    unsafe {
        let object = (*page).object;
        let bucket = bucket_ptr(object, (*page).offset);

        (*bucket).lock.lock();
        if (*bucket).pages == page {
            (*bucket).pages = (*page).next;
        } else {
            let mut link = addr_of_mut!((*bucket).pages);
            loop {
                let this = *link;
                if this == page {
                    *link = (*this).next;
                    break;
                }
                link = addr_of_mut!((*this).next);
            }
        }
        (*bucket).lock.unlock();

        VmObject::memq_pinned(object).remove_ptr(NonNull::new_unchecked(page));
        (*object).resident_page_count -= 1;
        (*page).set_tabled(false);
        vm_page::queues_remove(page);

        if (*page).is_external() {
            (*page).set_external(false);
            VM_OBJECT_EXTERNAL_PAGES.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// `vm_page_lookup()` in C: the page at `object`/`offset`, when tabled.
///
/// # Safety
///
/// `object` must be a live, locked object.
pub(crate) unsafe fn lookup(
    object: NonNull<VmObject>,
    offset: VmOffset,
) -> Option<NonNull<VmPage>> {
    unsafe {
        let bucket = bucket_ptr(object.as_ptr(), offset);
        (*bucket).lock.lock();

        let mut page = (*bucket).pages;
        while !page.is_null() {
            vm_page::check(page);
            if (*page).object == object.as_ptr() && (*page).offset == offset {
                break;
            }
            page = (*page).next;
        }

        (*bucket).lock.unlock();
        NonNull::new(page)
    }
}

/// The fictitious-page list.
///
/// # Safety
///
/// The caller must hold `vm_page_queue_free_lock` for as long as it uses the
/// list.
unsafe fn fictitious_list() -> Pin<&'static mut NodeList> {
    // SAFETY: `RESIDENT_STATE` is a static, so the list never moves, and the
    // lock the caller holds keeps anything else from reaching it.
    unsafe { Pin::new_unchecked(&mut (*state()).fictitious) }
}

/// `vm_page_grab_fictitious()` in C: take a fictitious page off the free
/// list.
///
/// # Safety
///
/// The caller must not hold `vm_page_queue_free_lock`.
pub(crate) unsafe fn grab_fictitious() -> Option<NonNull<VmPage>> {
    VM_PAGE_QUEUE_FREE_LOCK.lock();

    let page = {
        // SAFETY: the free lock is held.
        let popped = unsafe { fictitious_list() }
            .cursor_front_mut()
            .remove_current();
        popped.map(|page| {
            page.set_free(false);
            VM_PAGE_FICTITIOUS_COUNT.fetch_sub(1, Ordering::Relaxed);
            NonNull::from(page)
        })
    };

    VM_PAGE_QUEUE_FREE_LOCK.unlock();

    page
}

/// `vm_page_release_fictitious()` in C: return a fictitious page to the free
/// list.
///
/// # Safety
///
/// `mem` must be a live fictitious page the caller owns, and the caller must
/// not hold `vm_page_queue_free_lock`.
unsafe fn release_fictitious(mem: NonNull<VmPage>) {
    let page = mem.as_ptr();

    VM_PAGE_QUEUE_FREE_LOCK.lock();

    // SAFETY: the free lock is held and the page is live.
    unsafe {
        if (*page).is_free() {
            die("vm_page_release_fictitious", "vm_page_release_fictitious");
        }

        (*page).set_free(true);
        // SAFETY: the free lock is held and the page is live and unlinked.
        fictitious_list().push_front_ptr(mem);
    }
    VM_PAGE_FICTITIOUS_COUNT.fetch_add(1, Ordering::Relaxed);

    VM_PAGE_QUEUE_FREE_LOCK.unlock();
}

/// `vm_page_more_fictitious()` in C: allocate more fictitious pages into the
/// free list.
///
/// # Safety
///
/// The slab package must be up and the caller must be allowed to block, as
/// the C required.
pub(crate) unsafe fn more_fictitious() {
    let mut i = 0;
    while i < VM_PAGE_FICTITIOUS_QUANTUM {
        let page = unsafe { (*addr_of_mut!(VM_PAGE_CACHE)).alloc() }
            .map_or_else(
                || die("vm_page_more_fictitious", "vm_page_more_fictitious"),
                NonNull::cast::<VmPage>,
            );

        // SAFETY: the fresh page is writable storage that nothing sees yet.
        unsafe {
            init(&mut *page.as_ptr());
            (*page.as_ptr()).phys_addr = VM_PAGE_FICTITIOUS_ADDR;
            (*page.as_ptr()).set_fictitious(true);
        }
        // SAFETY: the fresh page is owned by this call and the free lock is
        // not held.
        unsafe { release_fictitious(page) };

        i += 1;
    }
}

/// `vm_page_convert()` in C: turn a fictitious page into a real one, or
/// report that no page was available.
///
/// # Safety
///
/// `fict` must be a live fictitious page whose object lock the caller holds,
/// as the C required.
pub(crate) unsafe fn convert(
    fict: NonNull<VmPage>,
) -> Option<NonNull<VmPage>> {
    let real = unsafe { grab(VM_PAGE_HIGHMEM) }?;
    let page = fict.as_ptr();

    let (object, offset) = unsafe { ((*page).object, (*page).offset) };

    unsafe {
        VM_PAGE_QUEUE_LOCK.lock();
        remove(fict);

        (*real.as_ptr()).copy_body_from(&*page);
        (*real.as_ptr()).set_fictitious(false);

        insert(real, NonNull::new_unchecked(object), offset);
        VM_PAGE_QUEUE_LOCK.unlock();
    }

    // SAFETY: the page is the fictitious one just unlinked from every list.
    unsafe { release_fictitious(fict) };

    Some(real)
}

/// `vm_page_order()` of <`vm/vm_page.h>`: the power of two that holds `size`
/// bytes.
pub(crate) const fn page_order(size: VmSize) -> c_uint {
    let pages = round_page(size) >> PAGE_SHIFT;
    if pages == 1 {
        return 0;
    }
    // The C's `iorder2()`: the bit length of `pages - 1`, which wraps to the
    // word width for a zero size, as the C's unsigned shift did.
    usize::BITS - pages.wrapping_sub(1).leading_zeros()
}

/// The number of pages `size` rounds up to, or zero for the wrapped
/// `usize::BITS` order the C computed.
const fn contig_pages(size: VmSize) -> u32 {
    1u32.wrapping_shl(page_order(size))
}

/// `vm_page_grab_contig()` in C: remove a block of contiguous pages from the
/// free list.
///
/// # Safety
///
/// The caller must not hold `vm_page_queue_free_lock` and must be in a
/// context where the allocator may spin, as the C required.
pub(crate) unsafe fn grab_contig(
    size: VmSize,
    selector: c_uint,
) -> Option<NonNull<VmPage>> {
    let order = page_order(size);
    let nr_pages = contig_pages(size);

    let page = unsafe { vm_page::alloc_pa(order, selector, VM_PT_KERNEL) };
    let Some(page) = NonNull::new(page) else {
        // The allocator returned with the free lock held.
        VM_PAGE_QUEUE_FREE_LOCK.unlock();
        return None;
    };

    let mut i = 0;
    while i < nr_pages {
        // SAFETY: `i` is inside the block the allocator just returned.
        unsafe { (*page.as_ptr().add(i as usize)).set_free(false) };
        i += 1;
    }

    // The lock was taken by the allocator.
    VM_PAGE_QUEUE_FREE_LOCK.unlock();

    Some(page)
}

/// `vm_page_free()` in C: return a page to the free list, disassociating it
/// from any object.
///
/// # Safety
///
/// `mem` must be a live page the caller owns, and the caller must hold the
/// page-queues lock and the object lock, as the C required.
pub(crate) unsafe fn free(mem: NonNull<VmPage>) {
    let page = mem.as_ptr();

    unsafe {
        if (*page).is_free() {
            die("vm_page_free", "vm_page_free");
        }

        if (*page).is_tabled() {
            remove(mem);
        }

        if (*page).wire_count() != 0 {
            if !(*page).is_private() && !(*page).is_fictitious() {
                VM_PAGE_WIRE_COUNT.fetch_sub(1, Ordering::Relaxed);
            }
            (*page).set_wire_count(0);
        }
    }

    // SAFETY: the page is live and its object lock is held.
    unsafe { crate::vm::vm_object::page_wakeup_done(page) };

    // SAFETY: the page is live; an absent page belongs to a live object.
    unsafe {
        if (*page).is_absent() {
            crate::vm::vm_object::absent_release((*page).object);
        }
    }

    let recycled = unsafe { (*page).is_private() || (*page).is_fictitious() };
    if recycled {
        // SAFETY: the page is live and no other holder exists.
        unsafe {
            init(&mut *page);
            (*page).phys_addr = VM_PAGE_FICTITIOUS_ADDR;
            (*page).set_fictitious(true);
        }
        unsafe { release_fictitious(mem) };
    } else {
        // SAFETY: the page is live and its flags are the C's inputs.
        let (laundry, external_laundry) =
            unsafe { ((*page).is_laundry(), (*page).is_external_laundry()) };
        // SAFETY: the page is live and the caller's locks serialized it.
        unsafe { init(&mut *page) };
        unsafe { release(mem, laundry, external_laundry) };
    }
}

/// `vm_page_info()` in C: fill `info` with the counts of the first `count`
/// hash buckets.
///
/// # Safety
///
/// `info` must be writable for `count` `hash_info_bucket_t` records, and the
/// caller must hold no lock, as the C required.
pub(crate) unsafe fn info(info: *mut HashInfoBucket, count: c_uint) -> c_uint {
    let mut count = count as usize;
    // SAFETY: the resident state lives in a static and the bucket count is
    // fixed once bootstrap completes.
    let bucket_count = unsafe { (*state()).bucket_count };
    if bucket_count < count {
        count = bucket_count;
    }

    let mut i = 0;
    while i < count {
        // SAFETY: `i` is inside the table.
        let bucket = unsafe { (*state()).buckets.add(i) };
        let mut page_count = 0;

        // SAFETY: the bucket lock serializes the chain.
        unsafe {
            (*bucket).lock.lock();
            let mut page = (*bucket).pages;
            while !page.is_null() {
                page_count += 1;
                page = (*page).next;
            }
            (*bucket).lock.unlock();
        }

        // The C writes the record after dropping the bucket lock so that no
        // lock is held while touching pageable memory.
        unsafe { (*info.add(i)).hib_count = page_count };
        i += 1;
    }

    // The C returned the `unsigned long` count through an `unsigned int`
    // result; the bucket count is a power of two below the page count.
    bucket_count as c_uint
}

/// `vm_page_rename()` in C: move a page to another object and offset.
///
/// # Safety
///
/// `page` must be a live page and `object` a live object; the object must be
/// locked, as the C requires.
pub(crate) unsafe fn rename(
    page: NonNull<VmPage>,
    object: NonNull<VmObject>,
    offset: VmOffset,
) {
    // SAFETY: the page-queue lock is the live lock the pageout daemon also
    // takes, and the caller holds the object's lock.
    unsafe {
        VM_PAGE_QUEUE_LOCK.lock();
        remove(page);
        insert(page, object, offset);
        VM_PAGE_QUEUE_LOCK.unlock();
    }
}

/// `vm_page_alloc_flags()` in C: grab a free page and table it in `object`.
///
/// # Safety
///
/// `object` must be a live, locked object.
pub(crate) unsafe fn alloc_flags(
    object: NonNull<VmObject>,
    offset: VmOffset,
    flags: c_uint,
) -> Option<NonNull<VmPage>> {
    // SAFETY: `grab()` is the real allocator, and `flags` is its documented
    // selector set.
    let page = unsafe { grab(flags) }?;

    // SAFETY: the page-queue lock is the live lock, and the caller holds the
    // object's lock.
    unsafe {
        VM_PAGE_QUEUE_LOCK.lock();
        insert(page, object, offset);
        VM_PAGE_QUEUE_LOCK.unlock();
    }

    Some(page)
}

/// `vm_page_alloc()` in C: `vm_page_alloc_flags()` with `VM_PAGE_HIGHMEM`.
///
/// # Safety
///
/// `object` must be a live, locked object.
pub(crate) unsafe fn alloc(
    object: NonNull<VmObject>,
    offset: VmOffset,
) -> Option<NonNull<VmPage>> {
    unsafe { alloc_flags(object, offset, VM_PAGE_HIGHMEM) }
}

/// `vm_page_init()` in C: initialize the fields of a page whose storage holds
/// random values.  The C kept the body in a `vm_page_init_template()` static
/// with this one caller.
pub(crate) const fn init(page: &mut VmPage) {
    page.object = null_mut();
    page.offset = 0;
    page.set_wire_count(0);
    page.set_inactive(false);
    page.set_active(false);
    page.set_laundry(false);
    page.set_external_laundry(false);
    page.set_free(false);
    page.set_external(false);
    page.set_busy(true);
    page.set_wanted(false);
    page.set_tabled(false);
    page.set_fictitious(false);
    page.set_private(false);
    page.set_absent(false);
    page.set_error(false);
    page.set_dirty(false);
    page.set_precious(false);
    page.set_reference(false);
    page.set_page_lock(VmProt::NONE);
    page.set_unlock_request(VmProt::NONE);
}

/// `vm_page_module_init()` in C: create the `vm_page` slab cache.
///
/// # Safety
///
/// Must run once, in the bootstrap sequence, after the slab package is up.
pub(crate) unsafe fn module_init() {
    unsafe {
        (*addr_of_mut!(VM_PAGE_CACHE)).init(
            b"vm_page",
            size_of::<VmPage>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
    };
}

/// The selector `vm_page_grab()` computes from its flags, the widest
/// requested segment first.
const fn alloc_selector(flags: c_uint) -> c_uint {
    if flags & VM_PAGE_HIGHMEM != 0 {
        VM_PAGE_SEL_HIGHMEM
    } else if flags & VM_PAGE_DMA32 != 0 {
        VM_PAGE_SEL_DMA32
    } else if flags & VM_PAGE_DIRECTMAP != 0 {
        VM_PAGE_SEL_DIRECTMAP
    } else {
        VM_PAGE_SEL_DMA
    }
}

/// `vm_page_grab()` in C: take a page out of the free list.
///
/// # Safety
///
/// The caller must not hold `vm_page_queue_free_lock`, and must be in a
/// context where the allocator's spinning is allowed.
pub(crate) unsafe fn grab(flags: c_uint) -> Option<NonNull<VmPage>> {
    let page =
        unsafe { vm_page::alloc_pa(0, alloc_selector(flags), VM_PT_KERNEL) };
    let page = NonNull::new(page);

    if let Some(page) = page {
        // SAFETY: `page` is the live page just allocated, and the free lock,
        // still held, guards its free flag.
        unsafe { (*page.as_ptr()).set_free(false) };
    }

    // `vm_page_alloc_pa()` returns with the free lock held, on both
    // the found and the exhausted path.
    VM_PAGE_QUEUE_FREE_LOCK.unlock();

    page
}

/// `vm_page_release()` in C: return a page to the free list, resuming the
/// pageout daemon when the last laundered page is gone.
///
/// # Safety
///
/// `page` must be a live page that no one else holds, and the caller must
/// not hold `vm_page_queue_free_lock`.
pub(crate) unsafe fn release(
    page: NonNull<VmPage>,
    laundry: bool,
    external_laundry: bool,
) {
    let ptr = page.as_ptr();

    VM_PAGE_QUEUE_FREE_LOCK.lock();

    // SAFETY: the free lock serializes the flag, and the page is live.
    if unsafe { (*ptr).is_free() } {
        kpanic!("vm_page_release", "vm_page_release");
    }

    // SAFETY: the free lock is held and guards the flag.
    unsafe { (*ptr).set_free(true) };
    // SAFETY: the free lock is held; `vm_page_free_pa()` is the real backend
    // and order zero is the C's.
    unsafe { vm_page::free_pa(ptr, 0) };

    if laundry {
        let count = VM_PAGE_LAUNDRY_COUNT.fetch_sub(1, Ordering::Relaxed);
        if count == 1 {
            unsafe { crate::vm::vm_pageout::resume() };
        }
    }

    if external_laundry {
        // SAFETY: the free lock guards the counter.
        let count = VM_PAGE_EXTERNAL_LAUNDRY_COUNT.load(Ordering::Relaxed);
        if 0 < count {
            let count = count.wrapping_sub(1);
            VM_PAGE_EXTERNAL_LAUNDRY_COUNT.store(count, Ordering::Relaxed);
            if count == 0 {
                unsafe { crate::vm::vm_pageout::resume() };
            }
        }
    }

    VM_PAGE_QUEUE_FREE_LOCK.unlock();
}

/// `vm_page_zero_fill()` in C: zero the page's physical memory.
///
/// # Safety
///
/// `page` must be a live page.
pub(crate) unsafe fn zero_fill(page: NonNull<VmPage>) {
    unsafe { vm_page::check(page.as_ptr()) };
    // SAFETY: the page is live, so its physical address names real memory.
    unsafe { phys::zero_page((*page.as_ptr()).phys_addr) };
}

/// `vm_page_copy()` in C: copy one page's physical memory to another.
///
/// # Safety
///
/// `src` and `dest` must be live pages.
pub(crate) unsafe fn copy(src: NonNull<VmPage>, dest: NonNull<VmPage>) {
    unsafe {
        vm_page::check(src.as_ptr());
        vm_page::check(dest.as_ptr());
    }
    // SAFETY: both pages are live, so their physical addresses name real
    // memory.
    unsafe {
        phys::copy_page((*src.as_ptr()).phys_addr, (*dest.as_ptr()).phys_addr);
    };
}
