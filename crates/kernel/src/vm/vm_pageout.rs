// SPDX-License-Identifier: CMU-Mach
// Derived from vm/vm_pageout.c and vm/vm_pageout.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and
//   the Computer Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The pageout daemon.

use crate::arch::types::VmOffset;
use crate::arch::vm_param::PAGE_SIZE;
use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::pmap::pmap_clear_modify;
use crate::kern::machine::CLOCK_HZ;
use crate::kern::sched_prim::{
    THREAD_AWAKENED, assert_wait, thread_block, thread_set_timeout,
    thread_sleep, thread_wakeup_prim,
};
use crate::kern::slab::slab_collect;
use crate::kern::task;
use crate::kern::thread::Thread;
use crate::mig::{memory_object_data_initialize, memory_object_data_return};
use crate::utils::cell::SyncCell;
use crate::vm::memory_object::default_manager;
use crate::vm::types::{VmObject, VmPage, VmProt};
use crate::vm::vm_external::{
    VM_EXTERNAL_STATE_EXISTS, vm_external_state_set,
};
use crate::vm::vm_map::VmMapCopy;
use crate::vm::vm_object::{self, allocate};
use crate::vm::vm_resident::VM_PAGE_QUEUE_FREE_LOCK;
use crate::vm::vm_resident::VM_PAGE_QUEUE_LOCK;
use crate::vm::vm_resident::{
    VM_PAGE_EXTERNAL_LAUNDRY_COUNT, VM_PAGE_LAUNDRY_COUNT,
};
use crate::vm::vm_user::VM_STAT;
use crate::vm::{vm_page, vm_resident};
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_uint, c_void};
use core::ptr::{self, NonNull};
use core::sync::atomic::Ordering;

/// How long a throttled daemon waits before it retries, in milliseconds.
const VM_PAGEOUT_TIMEOUT: c_int = 50;

/// The event the daemon sleeps on when there is nothing to do.
static VM_PAGEOUT_REQUESTED: SyncCell<c_int> = SyncCell(UnsafeCell::new(0));

/// The event a throttled daemon sleeps on.
static VM_PAGEOUT_CONTINUE: SyncCell<c_int> = SyncCell(UnsafeCell::new(0));

/// Moves or copies a busy page into `new_object` for its memory manager.
///
/// # Safety
///
/// `m` must be a live, busy page that is on no pageout queue, its object must
/// be unlocked and hold a paging reference, and `new_object` must be an
/// unlocked object.
pub(crate) unsafe fn setup(
    m: NonNull<VmPage>,
    paging_offset: VmOffset,
    new_object: NonNull<VmObject>,
    new_offset: VmOffset,
    flush: bool,
) -> Option<NonNull<VmPage>> {
    let page = m.as_ptr();
    let old_object = unsafe { (*page).object };

    let mut result = m;
    let holding_page = if flush {
        let holding_page = loop {
            // SAFETY: the allocator owns the fictitious supply.
            if let Some(holding_page) =
                // SAFETY: the allocator owns the fictitious supply.
                unsafe { vm_resident::grab_fictitious() }
            {
                break holding_page;
            }
            unsafe { vm_resident::more_fictitious() };
        };

        unsafe { (*old_object).lock.lock() };
        // SAFETY: the page-queues lock is the live lock and the object lock
        // is held.
        unsafe {
            VM_PAGE_QUEUE_LOCK.lock();
            vm_resident::remove(m);
            VM_PAGE_QUEUE_LOCK.unlock();
        }
        // SAFETY: the object lock is held and the page is live.
        unsafe { vm_object::page_wakeup_done(page) };

        // SAFETY: the holding page replaces the page at the same offset.
        unsafe {
            VM_PAGE_QUEUE_LOCK.lock();
            vm_resident::insert(
                holding_page,
                NonNull::new_unchecked(old_object),
                (*page).offset,
            );
            VM_PAGE_QUEUE_LOCK.unlock();
        }

        // SAFETY: `existence_info` is the object's external state map, and
        // the page has been written out.
        unsafe {
            vm_external_state_set(
                (*old_object).existence_info.cast(),
                paging_offset,
                VM_EXTERNAL_STATE_EXISTS,
            );
        };

        // SAFETY: the old object's lock was taken above.
        unsafe { (*old_object).lock.unlock() };

        unsafe { (*new_object.as_ptr()).lock.lock() };
        // SAFETY: the object lock and the page-queues lock guard the move.
        unsafe {
            VM_PAGE_QUEUE_LOCK.lock();
            vm_resident::insert(m, new_object, new_offset);
            VM_PAGE_QUEUE_LOCK.unlock();

            (*page).set_dirty(true);
            (*page).set_precious(false);
            (*page).set_page_lock(VmProt::NONE);
            (*page).set_unlock_request(VmProt::NONE);
        }

        Some(holding_page)
    } else {
        let new_page = loop {
            let allocated = unsafe {
                (*new_object.as_ptr()).lock.lock();
                let allocated = vm_resident::alloc(new_object, new_offset);
                (*new_object.as_ptr()).lock.unlock();
                allocated
            };
            if let Some(new_page) = allocated {
                break new_page;
            }
            // SAFETY: the C waits for a page with no lock held.
            unsafe { vm_page::wait(None) };
        };
        // SAFETY: both pages are live and the new one is busy.
        unsafe { vm_resident::copy(m, new_page) };

        unsafe { (*old_object).lock.lock() };
        // SAFETY: the object lock guards the page's dirty state.
        unsafe { (*page).set_dirty(false) };
        // SAFETY: the object lock is held and the page's physical address is
        // live.
        unsafe { pmap_clear_modify((*page).phys_addr) };

        // SAFETY: the page-queues lock is the live lock.
        unsafe {
            VM_PAGE_QUEUE_LOCK.lock();
            vm_page::deactivate(page);
            VM_PAGE_QUEUE_LOCK.unlock();
        }

        // SAFETY: the object lock is held and the page is live.
        unsafe { vm_object::page_wakeup_done(page) };

        // SAFETY: `existence_info` is the object's external state map, and
        // the page has been written out.
        unsafe {
            vm_external_state_set(
                (*old_object).existence_info.cast(),
                paging_offset,
                VM_EXTERNAL_STATE_EXISTS,
            );
        };

        // SAFETY: the old object's lock was taken above.
        unsafe { (*old_object).lock.unlock() };

        unsafe { (*new_object.as_ptr()).lock.lock() };
        result = new_page;
        // SAFETY: the new page is busy and owned by the new object.
        unsafe {
            (*new_page.as_ptr()).set_dirty(true);
        }
        // SAFETY: the object lock is held and the page is live.
        unsafe { vm_object::page_wakeup_done(new_page.as_ptr()) };

        None
    };

    // SAFETY: the new object is live and locked, and `result` is the busy
    // page the setup produced.
    unsafe { finish_pageout(result, old_object, new_object) };

    holding_page
}

/// Account the moved or copied page in the page queues, as the C's shared
/// tail of `vm_pageout_setup()` did.
///
/// # Safety
///
/// The new object must be live and locked, `result` the live busy page the
/// setup produced, and `old_object` the live former object of that page.
unsafe fn finish_pageout(
    result: NonNull<VmPage>,
    old_object: *mut VmObject,
    new_object: NonNull<VmObject>,
) {
    // SAFETY: the page-queues lock is the live lock, and the old object is
    // unlocked while the new one is locked.
    unsafe {
        VM_PAGE_QUEUE_LOCK.lock();
        VM_STAT.pageouts += 1;
        if (*result.as_ptr()).is_laundry() {
            (*result.as_ptr()).set_laundry(false);
        } else if (*old_object).is_internal()
            || default_manager::port((*old_object).pager)
        {
            (*result.as_ptr()).set_laundry(true);
            // The page-queues lock serializes the count; the atomic only
            // makes the update indivisible.
            VM_PAGE_LAUNDRY_COUNT.fetch_add(1, Ordering::Relaxed);
            vm_page::wire(result);
        } else {
            (*result.as_ptr()).set_external_laundry(true);
            // A negative count tells the daemon not to be notified.
            if VM_PAGE_EXTERNAL_LAUNDRY_COUNT.load(Ordering::Relaxed) >= 0 {
                VM_PAGE_EXTERNAL_LAUNDRY_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            vm_page::activate(result.as_ptr());
        }
        VM_PAGE_QUEUE_LOCK.unlock();

        // SAFETY: the new object's lock was taken above.
        (*new_object.as_ptr()).lock.unlock();
    }
}

/// Writes a busy page back to its memory object.
///
/// # Safety
///
/// `m` must be a live, busy page that is on no pageout queue, and its object
/// must be locked.
pub(crate) unsafe fn page(m: NonNull<VmPage>, initial: bool, flush: bool) {
    let page_ptr = m.as_ptr();

    let precious_clean =
        unsafe { !(*page_ptr).is_dirty() && (*page_ptr).is_precious() };
    if precious_clean && !flush {
        unsafe { vm_object::page_wakeup_done(page_ptr) };
        return;
    }

    // SAFETY: the page's flags are stable under the caller's lock.
    if unsafe {
        (*page_ptr).is_absent()
            || (*page_ptr).is_error()
            || (!(*page_ptr).is_dirty() && !(*page_ptr).is_precious())
    } {
        // SAFETY: the page-queues lock is the live lock and the object lock is
        // held, as `vm_resident::free` requires.
        unsafe {
            VM_PAGE_QUEUE_LOCK.lock();
            vm_resident::free(m);
            VM_PAGE_QUEUE_LOCK.unlock();
        }
        return;
    }

    let old_object = unsafe { (*page_ptr).object };
    // SAFETY: the object lock is held and its paging offset is set.
    let paging_offset = unsafe {
        (*page_ptr).offset.wrapping_add((*old_object).paging_offset)
    };
    unsafe {
        vm_object::paging_begin(old_object);
        (*old_object).lock.unlock();
    }

    // SAFETY: the object allocator halts the kernel rather than fail, and
    // the new object owns the reference it returns.
    let new_object = unsafe { allocate(PAGE_SIZE) };
    // SAFETY: the fresh object is unshared.
    unsafe { (*new_object.as_ptr()).set_used_for_pageout(true) };

    // SAFETY: the page is busy and off the queues, and the caller's object is
    // unlocked, as `vm_pageout_setup` requires.
    let holding_page =
        unsafe { setup(m, paging_offset, new_object, 0, flush) };

    // SAFETY: the copy cache is initialized and the new object is live.
    let copy =
        unsafe { VmMapCopy::copyin_object(new_object.as_ptr(), 0, PAGE_SIZE) };

    // SAFETY: the old object was unlocked above and its pager fields are
    // stable while the paging reference is held.
    let pager = unsafe { (*old_object).pager };
    let pager_request = unsafe { (*old_object).pager_request };
    let sent = if initial {
        // SAFETY: the pager ports are the live ones the object holds, and the
        // copy stands in for the page's data.
        unsafe {
            memory_object_data_initialize(
                pager,
                pager_request,
                paging_offset,
                copy.as_ptr().addr(),
                // `PAGE_SIZE` is 4096 on both supported targets, so the
                // conversion cannot truncate.
                PAGE_SIZE as c_uint,
            )
        }
    } else {
        unsafe {
            memory_object_data_return(
                pager,
                pager_request,
                paging_offset,
                copy.as_ptr().addr(),
                // `PAGE_SIZE` is 4096 on both supported targets, so the
                // conversion cannot truncate.
                PAGE_SIZE as c_uint,
                c_int::from(!precious_clean),
                c_int::from(!flush),
            )
        }
    };

    if sent.is_err() {
        unsafe { VmMapCopy::discard(copy) };
    }

    // SAFETY: the old object is live and its lock guards the paging count and
    // the placeholder page.
    unsafe {
        (*old_object).lock.lock();
        if let Some(holding_page) = holding_page {
            VM_PAGE_QUEUE_LOCK.lock();
            vm_resident::free(holding_page);
            VM_PAGE_QUEUE_LOCK.unlock();
        }
        vm_object::paging_end(old_object);
    }
}

/// Balances the free lists, shrinks the caches and evicts pages.
///
/// # Safety
///
/// Must run on the pageout daemon thread with no page lock held; `should_wait`
/// must be writable.  Returns with `VM_PAGE_QUEUE_FREE_LOCK` held.
unsafe fn scan(should_wait: *mut c_int) -> bool {
    // SAFETY: `balance` takes the free lock and returns with it held.
    if unsafe { vm_page::balance() } {
        return true;
    }
    // The lock was taken by `balance`.
    VM_PAGE_QUEUE_FREE_LOCK.unlock();

    // SAFETY: the collectors require no page lock.
    unsafe {
        Thread::stack_collect();
        crate::device::net_io::kmsg_collect();
        task::consider_collect();
        slab_collect();
    }

    vm_page::refill_inactive();

    unsafe { vm_page::evict(should_wait) }
}

/// Becomes the pageout daemon.
///
/// # Safety
///
/// Must be called on the kernel thread that becomes the daemon; the call never
/// returns.
pub(crate) unsafe fn pageout() -> ! {
    let thread = per_cpu::thread();
    unsafe {
        (*thread).vm_privilege = 1;
        (*thread).stack_privilege();
    }
    unsafe { Thread::set_own_priority(0) };

    loop {
        let mut should_wait: c_int = 0;
        // SAFETY: the loop body starts with the free lock released, and
        // `scan` returns holding it.
        let done = unsafe { scan(&raw mut should_wait) };

        if done {
            // SAFETY: the free lock is held, and `thread_sleep` releases it.
            unsafe {
                thread_sleep(
                    VM_PAGEOUT_REQUESTED.0.get().cast::<c_void>(),
                    ptr::from_ref(&VM_PAGE_QUEUE_FREE_LOCK).cast_mut(),
                    0,
                );
            };
        } else if should_wait != 0 {
            // SAFETY: the free lock is held; the wait and timeout are the
            // C's, and the block releases nothing else.
            unsafe {
                assert_wait(
                    NonNull::new(VM_PAGEOUT_CONTINUE.0.get().cast::<c_void>()),
                    0,
                );
                thread_set_timeout(
                    VM_PAGEOUT_TIMEOUT.wrapping_mul(CLOCK_HZ) / 1000,
                );
                VM_PAGE_QUEUE_FREE_LOCK.unlock();
                thread_block(None);
            }
        } else {
            VM_PAGE_QUEUE_FREE_LOCK.unlock();
        }
    }
}

/// Wakes the daemon.
///
/// # Safety
///
/// The caller must hold `VM_PAGE_QUEUE_FREE_LOCK`.
pub(crate) unsafe fn start() {
    // SAFETY: `per_cpu::thread()` is the running thread, or null early in
    // boot, and the C only wakes a daemon that exists.
    if !per_cpu::thread().is_null() {
        // SAFETY: the wakeup takes its own locks, and the caller holds the
        // free lock as the C required.
        let _ = unsafe {
            thread_wakeup_prim(
                VM_PAGEOUT_REQUESTED.0.get().cast::<c_void>(),
                1,
                THREAD_AWAKENED,
            )
        };
    }
}

/// Wakes a throttled daemon.
///
/// # Safety
///
/// The caller must hold `VM_PAGE_QUEUE_FREE_LOCK`.
pub(crate) unsafe fn resume() {
    // SAFETY: the wakeup takes its own locks, and the caller holds the free
    // lock as the C required.
    let _ = unsafe {
        thread_wakeup_prim(
            VM_PAGEOUT_CONTINUE.0.get().cast::<c_void>(),
            1,
            THREAD_AWAKENED,
        )
    };
}
/// [`setup`] over raw pointers: the page moved or copied for the memory
/// manager, or null.
///
/// # Safety
///
/// `m` must be a live, busy page that is on no pageout queue, its object must
/// be unlocked and hold a paging reference, and `new_object` must be an
/// unlocked object.
pub(crate) unsafe fn vm_pageout_setup(
    m: *mut VmPage,
    paging_offset: VmOffset,
    new_object: *mut VmObject,
    new_offset: VmOffset,
    flush: c_int,
) -> *mut VmPage {
    let (m, new_object) = unsafe {
        (
            NonNull::new_unchecked(m),
            NonNull::new_unchecked(new_object),
        )
    };
    unsafe { setup(m, paging_offset, new_object, new_offset, flush != 0) }
        .map_or(ptr::null_mut(), NonNull::as_ptr)
}

/// [`page`] over a raw pointer and integer flags.
///
/// # Safety
///
/// `m` must be a live, busy page that is on no pageout queue, and its object
/// must be locked.
pub(crate) unsafe fn vm_pageout_page(
    m: *mut VmPage,
    initial: c_int,
    flush: c_int,
) {
    unsafe { page(NonNull::new_unchecked(m), initial != 0, flush != 0) };
}

/// Wakes the daemon.
///
/// # Safety
///
/// The caller must hold `VM_PAGE_QUEUE_FREE_LOCK`.
pub(crate) unsafe fn vm_pageout_start() {
    unsafe { start() };
}
