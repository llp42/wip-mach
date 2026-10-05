// SPDX-License-Identifier: CMU-Mach
// Derived from vm/vm_fault.c and vm/vm_fault.h:
//   Copyright (c) 1994,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and
//   the Computer Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The page-fault module:
//!
//! finding the resident page for an object/offset, handling a map fault and
//! its continuation, wiring a map entry, unwiring it, cleaning up an
//! object/page pair, and copying pages between objects.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::PAGE_SIZE;
use crate::arch::x86_64::mp_desc::simple_lock_pause;
use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::pmap::{
    pmap_change_wiring, pmap_clear_modify, pmap_enter, pmap_page_protect,
    pmap_pageable,
};
use crate::ipc::error::SendError;
use crate::kern::console::kprint;
use crate::kern::debug::kpanic;
use crate::kern::sched_prim::{
    THREAD_AWAKENED, THREAD_RESTART, assert_wait, thread_block,
    thread_wakeup_prim,
};
use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::kern::task::current_task;
use crate::kern::thread::Continuation;
use crate::mig::{memory_object_data_request, memory_object_data_unlock};
use crate::vm::error::Error;
use crate::vm::types::{VmObject, VmPage, VmProt};
use crate::vm::vm_external::{self, ExternalState};
use crate::vm::vm_map::{VmMap, VmMapEntry, VmMapVersion};
use crate::vm::vm_object::{
    self, deallocate, page_free, page_wakeup_done, paging_begin, paging_end,
};
use crate::vm::vm_pageout::vm_pageout_page;
use crate::vm::vm_resident::VM_PAGE_QUEUE_LOCK;
use crate::vm::vm_user::VM_STAT;
use crate::vm::{vm_page, vm_resident};
use core::ffi::{c_int, c_uint, c_void};
use core::mem::{align_of, size_of};
use core::ptr::{self, NonNull, addr_of_mut};

/// The allocation flag that lets the page come from high physical memory.
const VM_PAGE_HIGHMEM: c_uint = 0x08;

/// Why [`fault_page`] produced no page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FaultError {
    /// The page changed under the fault; run it again.
    Retry,
    /// A wait the fault had to make was interrupted.
    Interrupted,
    /// No free page could be had; wait for one and run the fault again.
    MemoryShortage,
    /// No fictitious page could be had; add some and run the fault again.
    FictitiousShortage,
    /// The page is in error, or its pager could not supply it.
    MemoryError,
}

/// The state [`fault`] saves on the current thread for a continuation.
#[repr(C)]
#[allow(missing_docs)]
struct VmFaultState {
    vmf_map: *mut VmMap,
    vmf_vaddr: VmOffset,
    vmf_fault_type: VmProt,
    vmf_change_wiring: c_int,
    /// The continuation a blocked fault resumes through.
    ///
    /// [`fault_lookup`] and [`fault_step`] save it here before the thread
    /// sleeps, and [`fault`] calls it with the final result once the state
    /// above it has been freed; like [`fault`]'s own `continuation`
    /// parameter, it must not return.
    vmf_continuation: Option<unsafe fn(Result<(), Error>)>,
    vmf_version: VmMapVersion,
    vmf_wired: c_int,
    vmf_object: *mut VmObject,
    vmf_offset: VmOffset,
    vmf_prot: VmProt,
    vmfp_backoff: c_int,
    vmfp_object: *mut VmObject,
    vmfp_offset: VmOffset,
    vmfp_first_m: *mut VmPage,
    vmfp_access: VmProt,
}

const _: () = {
    assert!(size_of::<VmFaultState>() == 96);
    assert!(align_of::<VmFaultState>() == 8);
    assert!(core::mem::offset_of!(VmFaultState, vmf_map) == 0);
    assert!(core::mem::offset_of!(VmFaultState, vmf_vaddr) == 8);
    assert!(core::mem::offset_of!(VmFaultState, vmf_fault_type) == 16);
    assert!(core::mem::offset_of!(VmFaultState, vmf_change_wiring) == 20);
    assert!(core::mem::offset_of!(VmFaultState, vmf_continuation) == 24);
    assert!(core::mem::offset_of!(VmFaultState, vmf_version) == 32);
    assert!(core::mem::offset_of!(VmFaultState, vmf_wired) == 36);
    assert!(core::mem::offset_of!(VmFaultState, vmf_object) == 40);
    assert!(core::mem::offset_of!(VmFaultState, vmf_offset) == 48);
    assert!(core::mem::offset_of!(VmFaultState, vmf_prot) == 56);
    assert!(core::mem::offset_of!(VmFaultState, vmfp_backoff) == 60);
    assert!(core::mem::offset_of!(VmFaultState, vmfp_object) == 64);
    assert!(core::mem::offset_of!(VmFaultState, vmfp_offset) == 72);
    assert!(core::mem::offset_of!(VmFaultState, vmfp_first_m) == 80);
    assert!(core::mem::offset_of!(VmFaultState, vmfp_access) == 88);
};

/// The outstanding page-request count past which the fault waits for the
/// object's absent count to drop.
static VM_OBJECT_ABSENT_MAX: c_int = 50;

/// Whether a write fault marks the page dirty.
static VM_FAULT_DIRTY_HANDLING: c_int = 0;
/// Whether a fault may be interrupted.
static VM_FAULT_INTERRUPTIBLE: c_int = 1;
/// Whether the hardware reference bits are emulated.
static SOFTWARE_REFERENCE_BITS: c_int = 1;

/// The slab cache of fault state records.
static mut VM_FAULT_STATE_CACHE: KmemCache = KmemCache::zeroed();

/// Allocates a fault state record, or `None` when the cache is out of memory.
fn cache_alloc() -> Option<NonNull<VmFaultState>> {
    // SAFETY: the caller runs after `init_module()`, so the cache is live,
    // and the cache's lock serializes the call.
    let buf = unsafe { (*addr_of_mut!(VM_FAULT_STATE_CACHE)).alloc() }?;
    Some(buf.cast::<VmFaultState>())
}

/// Returns `state` to the cache.
///
/// # Safety
///
/// `state` must be a dead record that came from [`cache_alloc()`] and has no
/// other holder.
unsafe fn cache_free(state: NonNull<VmFaultState>) {
    unsafe { (*addr_of_mut!(VM_FAULT_STATE_CACHE)).free(state.cast::<u8>()) };
}

/// Initializes the state cache.
pub(crate) fn init_module() {
    // SAFETY: the call runs once in the bootstrap sequence, after the slab
    // package is up and before any fault state is allocated.
    unsafe {
        (*addr_of_mut!(VM_FAULT_STATE_CACHE)).init(
            b"vm_fault_state",
            size_of::<VmFaultState>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
    }
}

/// What [`fault_page`] produced: whether it found the page, and the outputs
/// the C signature carried in pointers.
pub(crate) struct Fault {
    /// Whether the fault found the page, or why it did not.
    pub(crate) result: Result<(), FaultError>,
    /// The protection for the mapping, modified in place as the C did.
    pub(crate) protection: VmProt,
    /// The busy result page, or null when the fault failed.
    pub(crate) result_page: *mut VmPage,
    /// The busy page left in the top object, or null.
    pub(crate) top_page: *mut VmPage,
}

impl Fault {
    /// A failure result, which carries no pages.
    const fn error(error: FaultError, protection: VmProt) -> Self {
        Self {
            result: Err(error),
            protection,
            result_page: ptr::null_mut(),
            top_page: ptr::null_mut(),
        }
    }
}

/// The fault state [`fault`] saved on the current thread for a continuation.
///
/// # Safety
///
/// The current thread's saved `other` slot must hold the state [`fault`] saved
/// before calling with a continuation.
unsafe fn fault_state() -> *mut VmFaultState {
    unsafe { (*per_cpu::thread()).saved.other.cast::<VmFaultState>() }
}

/// The `after_block_and_backoff` code of the C: the wait result decides retry
/// or interruption.
///
/// # Safety
///
/// The current thread must have just returned from `thread_block()`.
unsafe fn after_block_and_backoff() -> FaultError {
    // SAFETY: the block returned on the current thread.
    if unsafe { (*per_cpu::thread()).wait_result } == THREAD_AWAKENED {
        FaultError::Retry
    } else {
        FaultError::Interrupted
    }
}

/// Takes the object lock back after a wait and reports a failed wait, or
/// `None` to continue the search.
///
/// # Safety
///
/// `object` must be the object the fault unlocked for the wait, `first_m` the
/// top page it left busy, and the current thread must have just returned from
/// `thread_block()`.
unsafe fn after_wait(
    object: *mut VmObject,
    first_m: *mut VmPage,
    protection: VmProt,
) -> Option<Fault> {
    // SAFETY: the block returned on the current thread.
    let wait_result = unsafe { (*per_cpu::thread()).wait_result };
    unsafe { (*object).lock.lock() };
    if wait_result == THREAD_AWAKENED {
        return None;
    }

    unsafe { cleanup(object, NonNull::new(first_m)) };
    Some(Fault::error(
        if wait_result == THREAD_RESTART {
            FaultError::Retry
        } else {
            FaultError::Interrupted
        },
        protection,
    ))
}

/// The `block_and_backoff` epilogue of the C: clean up the fault's object and
/// top page, block, and report the wait result.
///
/// # Safety
///
/// `object` must be live and locked with its paging reference held, and
/// `first_m` the busy top page the search left.  With a continuation, the
/// current thread's saved `other` slot must hold the state [`fault`] saved.
unsafe fn block_and_backoff(
    object: *mut VmObject,
    first_m: *mut VmPage,
    protection: VmProt,
    continuation: Continuation,
) -> Fault {
    unsafe { cleanup(object, NonNull::new(first_m)) };

    match continuation {
        Some(continuation) => {
            let state = unsafe { fault_state() };
            // SAFETY: the state is the live allocation `fault` made for
            // this continuation.
            unsafe {
                (*state).vmfp_backoff = 1;
                (*state).vmf_prot = protection;
                thread_block(Some(continuation));
            }
        }
        None => {
            // SAFETY: the block takes no continuation.
            unsafe { thread_block(None) };
        }
    }

    // SAFETY: the block returned on the current thread.
    Fault::error(unsafe { after_block_and_backoff() }, protection)
}

/// Releases the busy page `m` and puts it back on the active queue when it is
/// on no queue.
///
/// # Safety
///
/// `m` must be a live busy page whose object lock the caller holds, and the
/// page-queues lock must not be held.
unsafe fn release_page(m: *mut VmPage) {
    unsafe {
        page_wakeup_done(m);
        VM_PAGE_QUEUE_LOCK.lock();
        if !(*m).is_active() && !(*m).is_inactive() {
            vm_page::activate(m);
        }
        VM_PAGE_QUEUE_LOCK.unlock();
    }
}

/// Wires down every page of `entry` in `map`.
///
/// # Safety
///
/// `entry` must be a live entry of `map`, and `map` must be referenced and
/// read-locked (or otherwise stable) for the whole call, as the C requires.
pub(crate) unsafe fn wire(map: &VmMap, entry: NonNull<VmMapEntry>) {
    let (start, end) = unsafe {
        let links = &(*entry.as_ptr()).links;
        (links.start, links.end)
    };

    pmap_pageable(map.pmap, start, end, c_int::from(false));

    let map = ptr::from_ref(map).cast_mut();
    let mut va = start;
    while va < end {
        // SAFETY: `map` and `entry` are live and read-locked by the caller,
        // and `va` is an address the entry covers.
        if !unsafe { wire_fast(&*map, va, entry.as_ptr()) } {
            // The C ignored the wiring fault's result.
            let _ = unsafe { fault(map, va, VmProt::NONE, true, false, None) };
        }
        va = va.wrapping_add(PAGE_SIZE);
    }
}

/// Whether the page was resident and usable, so the fast path could wire it
/// without a fault.
///
/// # Safety
///
/// `map` must be the referenced, read-locked map `entry` belongs to, `entry`
/// must be a live entry of it, and `va` must be a page address the entry
/// covers.
pub(crate) unsafe fn wire_fast(
    map: &VmMap,
    va: VmOffset,
    entry: *mut VmMapEntry,
) -> bool {
    unsafe {
        VM_STAT.faults += 1;
        (*current_task()).faults += 1;
    }

    if unsafe { (*entry).is_sub_map() } {
        return false;
    }

    let (object, offset, prot) = unsafe {
        (
            (*entry).object.vm_object,
            va.wrapping_sub((*entry).links.start)
                .wrapping_add((*entry).offset),
            (*entry).protection,
        )
    };

    // SAFETY: the object is live, and the C takes its lock to keep it from
    // being disposed while the page is wired.
    unsafe {
        (*object).lock.lock();
        (*object).ref_count += 1;
        (*object).set_paging_in_progress((*object).paging_in_progress() + 1);
    }

    // SAFETY: the object is live and locked.
    let m =
        unsafe { vm_resident::lookup(NonNull::new_unchecked(object), offset) };
    let Some(m) = m else {
        // SAFETY: the object is live and locked, holding the paging
        // reference taken above.
        return unsafe { give_up(object) };
    };

    // SAFETY: the lookup returned a live, locked page.
    let unusable = unsafe {
        (*m.as_ptr()).is_error()
            || (*m.as_ptr()).is_busy()
            || (*m.as_ptr()).is_absent()
            || (prot & (*m.as_ptr()).page_lock()) != VmProt::NONE
    };
    if unusable {
        // SAFETY: the object is live and locked, holding the paging
        // reference taken above.
        return unsafe { give_up(object) };
    }

    // SAFETY: the page is live; the C wires it under the page-queues lock.
    unsafe {
        VM_PAGE_QUEUE_LOCK.lock();
        vm_page::wire(m);
        VM_PAGE_QUEUE_LOCK.unlock();
        (*m.as_ptr()).set_busy(true);
    }

    // SAFETY: the object is live and locked; the page is live and busy, as
    // `release_page` assumes.
    if !unsafe { (*object).copy.is_null() }
        && (prot & VmProt::WRITE) != VmProt::NONE
    {
        unsafe {
            page_wakeup_done(m.as_ptr());
            VM_PAGE_QUEUE_LOCK.lock();
            vm_page::unwire(m.as_ptr());
            VM_PAGE_QUEUE_LOCK.unlock();
            return give_up(object);
        }
    }

    // SAFETY: the object is live and locked.
    unsafe { (*object).lock.unlock() };

    unsafe {
        pmap_enter(
            NonNull::new(map.pmap),
            va,
            (*m.as_ptr()).phys_addr,
            (prot & !(*m.as_ptr()).page_lock()).bits(),
            1,
        );
    }

    // SAFETY: the object is live; the C relocks it to clear the paging
    // reference and hands back the reference it took.
    unsafe {
        (*object).lock.lock();
        page_wakeup_done(m.as_ptr());
        (*object).set_paging_in_progress((*object).paging_in_progress() - 1);
        (*object).lock.unlock();
        deallocate(object);
    }

    true
}

/// Gives up the fast path for [`wire_fast`]: drops the object's paging
/// reference and lock, then the object reference.
///
/// # Safety
///
/// `object` must be live, its lock held, and its paging reference taken by
/// [`wire_fast`].
unsafe fn give_up(object: *mut VmObject) -> bool {
    unsafe {
        (*object).set_paging_in_progress((*object).paging_in_progress() - 1);
        (*object).lock.unlock();
        deallocate(object);
    }
    false
}

/// Drops the paging reference and lock of `object`, then frees the busy top
/// page and its own object's paging reference.
///
/// # Safety
///
/// `object` must be live, its lock held, and its paging reference held;
/// `top_page` must be the busy page the fault left in the top object, whose
/// own object the call then cleans up.
pub(crate) unsafe fn cleanup(
    object: *mut VmObject,
    top_page: Option<NonNull<VmPage>>,
) {
    unsafe {
        paging_end(object);
        (*object).lock.unlock();

        if let Some(top_page) = top_page {
            let top_object = (*top_page.as_ptr()).object;
            (*top_object).lock.lock();
            page_free(top_page.as_ptr());
            paging_end(top_object);
            (*top_object).lock.unlock();
        }
    }
}

/// The mutable state [`fault_page()`] threads through its search.
struct FaultState {
    first_object: *mut VmObject,
    first_offset: VmOffset,
    fault_type: VmProt,
    must_be_resident: bool,
    interruptible: bool,
    protection: VmProt,
    continuation: Continuation,
    object: *mut VmObject,
    offset: VmOffset,
    first_m: *mut VmPage,
    access_required: VmProt,
    m: *mut VmPage,
}

/// What one step of [`fault_page()`]'s search loop leaves it to do.
enum SearchStep {
    /// Continue the search loop.
    Retry,
    /// The result page is busy; leave the loop.
    Done,
    /// Return this fault to the caller.
    Return(Fault),
}

/// What a step of [`FaultState::copy_object()`] leaves it to do.
enum CopyStep {
    /// Re-run the copy loop.
    Retry,
    /// Leave the copy loop.
    Done,
    /// Return this fault to the caller.
    Return(Fault),
}

impl FaultState {
    /// Wait for the busy page the lookup found, as the C's busy path
    /// did.
    ///
    /// # Safety
    ///
    /// The lookup must have returned the live, locked page `m`.
    unsafe fn found_busy(&mut self) -> SearchStep {
        // SAFETY: the page is live and locked.
        unsafe {
            (*self.m).set_wanted(true);
            assert_wait(
                NonNull::new(self.m.cast::<c_void>()),
                c_int::from(self.interruptible),
            );
        }
        // SAFETY: the object is live and locked.
        unsafe { (*self.object).lock.unlock() };

        match self.continuation {
            Some(continuation) => {
                let state = unsafe { fault_state() };
                // SAFETY: the state is the live allocation the C
                // made for this continuation.
                unsafe {
                    (*state).vmfp_backoff = 0;
                    (*state).vmfp_object = self.object;
                    (*state).vmfp_offset = self.offset;
                    (*state).vmfp_first_m = self.first_m;
                    (*state).vmfp_access = self.access_required;
                    (*state).vmf_prot = self.protection;
                    thread_block(Some(continuation));
                }
            }
            None => {
                // SAFETY: the block takes no continuation.
                unsafe { thread_block(None) };
            }
        }

        // SAFETY: the object and top page are the ones the block
        // saved.
        if let Some(fault) =
            // SAFETY: the thread just returned from the block that
            // saved this object and top page.
            unsafe {
                after_wait(self.object, self.first_m, self.protection)
            }
        {
            return SearchStep::Return(fault);
        }
        SearchStep::Retry
    }

    /// Handle the page the lookup found, as the C's found path did.
    ///
    /// # Safety
    ///
    /// The lookup must have returned the live, locked page `m`.
    unsafe fn found_page(&mut self) -> SearchStep {
        // SAFETY: the lookup returned the live, locked page.
        if unsafe { (*self.m).is_busy() } {
            // SAFETY: the lookup returned the live, busy page.
            return unsafe { self.found_busy() };
        }

        // SAFETY: the page is live and locked.
        if unsafe { (*self.m).is_error() } {
            // SAFETY: the page is live and locked.
            unsafe {
                page_free(self.m);
                cleanup(self.object, NonNull::new(self.first_m));
            }
            return SearchStep::Return(Fault::error(
                FaultError::MemoryError,
                self.protection,
            ));
        }

        // SAFETY: the page is live and locked.
        if unsafe { (*self.m).is_absent() } {
            // SAFETY: the lookup returned the live, absent page.
            return unsafe { self.found_absent() };
        }

        // SAFETY: the page is live and locked.
        if (self.access_required & unsafe { (*self.m).page_lock() })
            != VmProt::NONE
        {
            // SAFETY: the lookup returned the live, page-locked page.
            return unsafe { self.found_locked() };
        }

        if SOFTWARE_REFERENCE_BITS == 0 {
            // SAFETY: the queue lock guards the page queues.
            unsafe {
                VM_PAGE_QUEUE_LOCK.lock();
                if (*self.m).is_inactive() {
                    VM_STAT.reactivations += 1;
                    (*current_task()).reactivations += 1;
                }
                vm_page::queues_remove(self.m);
                VM_PAGE_QUEUE_LOCK.unlock();
            }
        }

        // SAFETY: the page is live and locked.
        unsafe { (*self.m).set_busy(true) };
        SearchStep::Done
    }

    /// Walk the shadow chain of the absent page the lookup found, as
    /// the C's absent path did.
    ///
    /// # Safety
    ///
    /// The lookup must have returned the live, locked page `m`,
    /// absent in the live, locked object.
    unsafe fn found_absent(&mut self) -> SearchStep {
        self.offset =
    // SAFETY: the object is live and locked.
    self.offset.wrapping_add(unsafe { (*self.object).shadow_offset });
        self.access_required = VmProt::READ;
        // SAFETY: the object is live and locked.
        let next_object = unsafe { (*self.object).shadow };
        if next_object.is_null() {
            // SAFETY: the allocator may spin while the object lock
            // is held.
            let Some(real_m) = (unsafe { vm_resident::grab(VM_PAGE_HIGHMEM) })
            else {
                // SAFETY: the object and top page are the fault's.
                unsafe { cleanup(self.object, NonNull::new(self.first_m)) };
                return SearchStep::Return(Fault::error(
                    FaultError::MemoryShortage,
                    self.protection,
                ));
            };

            if self.object != self.first_object {
                // SAFETY: the bottom absent page is the fault's,
                // and the object lock is held.
                unsafe {
                    page_free(self.m);
                    paging_end(self.object);
                    (*self.object).lock.unlock();
                }
                self.object = self.first_object;
                self.offset = self.first_offset;
                self.m = self.first_m;
                self.first_m = ptr::null_mut();
                // SAFETY: the top object is live.
                unsafe { (*self.object).lock.lock() };
            }

            // SAFETY: the top absent page is the fault's and the
            // queue lock guards the page table.
            unsafe {
                page_free(self.m);
                VM_PAGE_QUEUE_LOCK.lock();
                vm_resident::insert(
                    real_m,
                    NonNull::new_unchecked(self.object),
                    self.offset,
                );
                VM_PAGE_QUEUE_LOCK.unlock();
            }
            self.m = real_m.as_ptr();

            // SAFETY: the page is tabled in the locked object; the
            // lock is dropped for the zero fill as the C did.
            unsafe {
                (*self.object).lock.unlock();
                vm_resident::zero_fill(real_m);
                VM_STAT.zero_fill_count += 1;
                (*current_task()).zero_fills += 1;
                (*self.object).lock.lock();
                pmap_clear_modify((*self.m).phys_addr);
            }
            return SearchStep::Done;
        }

        if self.must_be_resident {
            // SAFETY: the object is live and locked.
            unsafe { paging_end(self.object) };
        } else if self.object != self.first_object {
            // SAFETY: the object is live and locked; the absent
            // page is the fault's.
            unsafe {
                paging_end(self.object);
                page_free(self.m);
            }
        } else {
            // SAFETY: the page is live and locked; the queue lock
            // guards the page queues.
            unsafe {
                self.first_m = self.m;
                (*self.m).set_absent(false);
                vm_object::absent_release(self.object);
                (*self.m).set_busy(true);

                VM_PAGE_QUEUE_LOCK.lock();
                vm_page::queues_remove(self.m);
                VM_PAGE_QUEUE_LOCK.unlock();
            }
        }

        // SAFETY: the next object is live; the C locks it before
        // unlocking the current one.
        unsafe {
            (*next_object).lock.lock();
            (*self.object).lock.unlock();
        }
        self.object = next_object;
        // SAFETY: the object is live and locked.
        unsafe { paging_begin(self.object) };
        SearchStep::Retry
    }

    /// Service the page-lock request of the page the lookup found, as
    /// the C's page-lock path did.
    ///
    /// # Safety
    ///
    /// The lookup must have returned the live, locked page `m`, and
    /// the object must be live, locked, and pager ready.
    unsafe fn found_locked(&mut self) -> SearchStep {
        // SAFETY: the page is live and locked.
        if (self.access_required & unsafe { (*self.m).unlock_request() })
            != self.access_required
        {
            // SAFETY: the object is live and locked.
            if !unsafe { (*self.object).is_pager_ready() } {
                // SAFETY: the object is live and locked.
                unsafe {
                    vm_object::assert_wait_event(
                        self.object,
                        vm_object::EVENT_PAGER_READY,
                        self.interruptible,
                    );
                };
                return SearchStep::Return(unsafe {
                    block_and_backoff(
                        self.object,
                        self.first_m,
                        self.protection,
                        self.continuation,
                    )
                });
            }

            // SAFETY: the page is live and locked.
            let new_unlock_request =
                self.access_required | unsafe { (*self.m).unlock_request() };
            // SAFETY: the page is live and locked.
            unsafe { (*self.m).set_unlock_request(new_unlock_request) };
            // SAFETY: the object is live and locked.
            unsafe { (*self.object).lock.unlock() };

            // SAFETY: the pager port and its request are live, and
            // the busy page holds the object's paging reference.
            let sent = unsafe {
                memory_object_data_unlock(
                    (*self.object).pager,
                    (*self.object).pager_request,
                    self.offset.wrapping_add((*self.object).paging_offset),
                    PAGE_SIZE,
                    new_unlock_request,
                )
            };
            if let Err(error) = sent {
                kprint!("vm_fault: memory_object_data_unlock failed\n");
                // SAFETY: the object is live; its lock is taken
                // back for the cleanup.
                unsafe {
                    (*self.object).lock.lock();
                    cleanup(self.object, NonNull::new(self.first_m));
                }
                return SearchStep::Return(Fault::error(
                    if error == SendError::Interrupted {
                        FaultError::Interrupted
                    } else {
                        FaultError::MemoryError
                    },
                    self.protection,
                ));
            }

            unsafe { (*self.object).lock.lock() };
            return SearchStep::Retry;
        }

        // SAFETY: the page is live and locked.
        unsafe {
            (*self.m).set_wanted(true);
            assert_wait(
                NonNull::new(self.m.cast::<c_void>()),
                c_int::from(self.interruptible),
            );
        }
        SearchStep::Return(unsafe {
            block_and_backoff(
                self.object,
                self.first_m,
                self.protection,
                self.continuation,
            )
        })
    }

    /// Handle the case the search found no page, as the C's
    /// fall-through path did.
    ///
    /// # Safety
    ///
    /// The object must be live and locked, with its paging reference
    /// held.
    unsafe fn missing_page(&mut self) -> SearchStep {
        // SAFETY: the object is live and locked, and its existence map is
        // live for the object's lifetime.
        let look_for_page = unsafe {
            (*self.object).is_pager_created()
                && vm_external::state_get(
                    (*self.object).existence_info.cast(),
                    self.offset.wrapping_add((*self.object).paging_offset),
                ) != ExternalState::Absent
        };

        if (look_for_page || self.object == self.first_object)
            && !self.must_be_resident
        {
            // SAFETY: the fictitious list is up.
            let Some(fictitious) = (unsafe { vm_resident::grab_fictitious() })
            else {
                // SAFETY: the object and top page are the fault's.
                unsafe { cleanup(self.object, NonNull::new(self.first_m)) };
                return SearchStep::Return(Fault::error(
                    FaultError::FictitiousShortage,
                    self.protection,
                ));
            };
            self.m = fictitious.as_ptr();
            // SAFETY: the queue lock guards the page table.
            unsafe {
                VM_PAGE_QUEUE_LOCK.lock();
                vm_resident::insert(
                    fictitious,
                    NonNull::new_unchecked(self.object),
                    self.offset,
                );
                VM_PAGE_QUEUE_LOCK.unlock();
            }
        }

        if look_for_page && !self.must_be_resident {
            // SAFETY: the object is live and locked.
            if !unsafe { (*self.object).is_pager_ready() } {
                // SAFETY: the object is live and locked, and `m` is the
                // fictitious page just tabled.
                unsafe {
                    vm_object::assert_wait_event(
                        self.object,
                        vm_object::EVENT_PAGER_READY,
                        self.interruptible,
                    );
                    page_free(self.m);
                }
                return SearchStep::Return(unsafe {
                    block_and_backoff(
                        self.object,
                        self.first_m,
                        self.protection,
                        self.continuation,
                    )
                });
            }

            // SAFETY: the object is live and locked.
            return unsafe { self.missing_request() };
        }

        // SAFETY: the object is live and locked.
        unsafe { self.missing_shadow() }
    }

    /// Deliver the fault's page request to the object's pager, as the
    /// C's `memory_object_data_request()` path did.
    ///
    /// # Safety
    ///
    /// The object must be live, locked, and pager ready, and `m` the
    /// live page just tabled.
    unsafe fn missing_request(&mut self) -> SearchStep {
        // SAFETY: the object is live and locked.
        if unsafe { (*self.object).is_internal() } {
            // SAFETY: the page is live and locked.
            if unsafe { (*self.m).is_fictitious() } {
                // SAFETY: the object is live and locked, and `m` is the
                // fictitious page just tabled.
                let Some(real) = (unsafe {
                    vm_resident::convert(NonNull::new_unchecked(self.m))
                }) else {
                    // SAFETY: the page is the fault's, and the object
                    // and top page are the fault's.
                    unsafe {
                        page_free(self.m);
                        cleanup(self.object, NonNull::new(self.first_m));
                    }
                    return SearchStep::Return(Fault::error(
                        FaultError::MemoryShortage,
                        self.protection,
                    ));
                };
                self.m = real.as_ptr();
            }
        } else {
            let absent_max =
                u32::try_from(VM_OBJECT_ABSENT_MAX).unwrap_or(u32::MAX);
            // SAFETY: the object is live and locked.
            if unsafe { (*self.object).absent_count } > absent_max {
                // SAFETY: the object is live and locked, and `m` is the
                // page just tabled.
                unsafe {
                    vm_object::absent_assert_wait(
                        self.object,
                        self.interruptible,
                    );
                    page_free(self.m);
                }
                return SearchStep::Return(unsafe {
                    block_and_backoff(
                        self.object,
                        self.first_m,
                        self.protection,
                        self.continuation,
                    )
                });
            }
        }

        // SAFETY: the page is live and locked.
        unsafe {
            (*self.m).set_absent(true);
            (*self.object).absent_count += 1;
            (*self.object).lock.unlock();
        }

        unsafe {
            VM_STAT.pageins += 1;
            (*current_task()).pageins += 1;
        }
        // SAFETY: the pager port and its request are live, and the busy
        // page holds the object's paging reference.
        let sent = unsafe {
            memory_object_data_request(
                (*self.object).pager,
                (*self.object).pager_request,
                (*self.m).offset.wrapping_add((*self.object).paging_offset),
                PAGE_SIZE,
                self.access_required,
            )
        };
        if let Err(error) = sent {
            // SAFETY: the object is live and referenced by the busy
            // page.
            if !unsafe { (*self.object).pager }.is_null()
                && error != SendError::Interrupted
            {
                // SAFETY: the pager and its request are read as the C's
                // diagnostic did.
                kprint!(
                    "memory_object_data_request({:p}, {:p}, 0x{:x}, \
                         0x{:x}, 0x{:x}) failed, {:?}\n",
                    // SAFETY: the object is live and referenced by the
                    // busy page.
                    unsafe { (*self.object).pager },
                    // SAFETY: the object is live and referenced by the
                    // busy page.
                    unsafe { (*self.object).pager_request },
                    // SAFETY: the page is live and busy.
                    unsafe { (*self.m).offset }
                        // SAFETY: the object is live and referenced by the
                        // busy page.
                        .wrapping_add(unsafe { (*self.object).paging_offset }),
                    PAGE_SIZE,
                    self.access_required.bits(),
                    error
                );
            }
            // SAFETY: the object is live; its lock is taken back for
            // the cleanup.
            unsafe {
                (*self.object).lock.lock();
                let still = vm_resident::lookup(
                    NonNull::new_unchecked(self.object),
                    self.offset,
                );
                if still == NonNull::new(self.m)
                    && (*self.m).is_absent()
                    && (*self.m).is_busy()
                {
                    page_free(self.m);
                }
                cleanup(self.object, NonNull::new(self.first_m));
            }
            return SearchStep::Return(Fault::error(
                if error == SendError::Interrupted {
                    FaultError::Interrupted
                } else {
                    FaultError::MemoryError
                },
                self.protection,
            ));
        }

        unsafe { (*self.object).lock.lock() };
        SearchStep::Retry
    }

    /// Descend the shadow chain for the missing page, as the C's
    /// shadow path did.
    ///
    /// # Safety
    ///
    /// The object must be live and locked, with its paging reference
    /// held.
    unsafe fn missing_shadow(&mut self) -> SearchStep {
        if self.object == self.first_object {
            self.first_m = self.m;
        }

        // SAFETY: the object is live and locked.
        self.access_required = VmProt::READ;
        // SAFETY: the object is live and locked.
        self.offset = self
            .offset
            .wrapping_add(unsafe { (*self.object).shadow_offset });
        // SAFETY: the object is live and locked.
        let next_object = unsafe { (*self.object).shadow };
        if next_object.is_null() {
            if self.object != self.first_object {
                // SAFETY: the bottom object is live and locked.
                unsafe {
                    paging_end(self.object);
                    (*self.object).lock.unlock();
                }
                self.object = self.first_object;
                // The C also reset `offset` here; this path only zero-fills
                // the page it already holds, so the dead store is dropped.
                unsafe { (*self.object).lock.lock() };
            }

            self.m = self.first_m;
            self.first_m = ptr::null_mut();
            // SAFETY: the page is live and locked.
            if unsafe { (*self.m).is_fictitious() } {
                // SAFETY: the object is live and locked, and `m` is the
                // top page just taken.
                let Some(real) = (unsafe {
                    vm_resident::convert(NonNull::new_unchecked(self.m))
                }) else {
                    // SAFETY: the page is the fault's, and the object is
                    // the fault's.
                    unsafe {
                        page_free(self.m);
                        cleanup(self.object, None);
                    }
                    return SearchStep::Return(Fault::error(
                        FaultError::MemoryShortage,
                        self.protection,
                    ));
                };
                self.m = real.as_ptr();
            }

            // SAFETY: the page is tabled in the locked object; the lock is
            // dropped for the zero fill as the C did.
            unsafe {
                (*self.object).lock.unlock();
                vm_resident::zero_fill(NonNull::new_unchecked(self.m));
                VM_STAT.zero_fill_count += 1;
                (*current_task()).zero_fills += 1;
                (*self.object).lock.lock();
                pmap_clear_modify((*self.m).phys_addr);
            }
            return SearchStep::Done;
        }

        // SAFETY: the next object is live; the C locks it before unlocking
        // the current one.
        unsafe {
            (*next_object).lock.lock();
            if (self.object != self.first_object) || self.must_be_resident {
                paging_end(self.object);
            }
            (*self.object).lock.unlock();
        }
        self.object = next_object;
        // SAFETY: the object is live and locked.
        unsafe { paging_begin(self.object) };
        SearchStep::Retry
    }

    /// Copy the bottom page up for a write fault, as the C's
    /// copy-on-write path did.
    ///
    /// # Safety
    ///
    /// The bottom object must be live and locked with its page in `m`,
    /// and the top object live and locked.
    unsafe fn cow(&mut self) -> Option<Fault> {
        if self.fault_type.contains(VmProt::WRITE) {
            // SAFETY: the allocator may spin while the bottom object is
            // locked.
            let Some(copy_m) = (unsafe { vm_resident::grab(VM_PAGE_HIGHMEM) })
            else {
                // SAFETY: the result page is the fault's busy page, and
                // the object and top page are the fault's.
                unsafe {
                    release_page(self.m);
                    cleanup(self.object, NonNull::new(self.first_m));
                }
                return Some(Fault::error(
                    FaultError::MemoryShortage,
                    self.protection,
                ));
            };
            let copy_m = copy_m.as_ptr();

            // SAFETY: the source page is live and busy in the bottom
            // object, and the copy is a fresh real page.
            unsafe {
                (*self.object).lock.unlock();
                vm_resident::copy(
                    NonNull::new_unchecked(self.m),
                    NonNull::new_unchecked(copy_m),
                );
                (*self.object).lock.lock();

                VM_PAGE_QUEUE_LOCK.lock();
                vm_page::deactivate(self.m);
                pmap_page_protect((*self.m).phys_addr, VmProt::NONE.bits());
                VM_PAGE_QUEUE_LOCK.unlock();

                page_wakeup_done(self.m);
                paging_end(self.object);
                (*self.object).lock.unlock();
            }

            unsafe {
                VM_STAT.cow_faults += 1;
                (*current_task()).cow_faults += 1;
            }
            self.object = self.first_object;
            self.offset = self.first_offset;

            // SAFETY: the top object is live and gets the copy; the top
            // page is the fault's.
            unsafe {
                (*self.object).lock.lock();
                page_free(self.first_m);
                self.first_m = ptr::null_mut();
                VM_PAGE_QUEUE_LOCK.lock();
                vm_resident::insert(
                    NonNull::new_unchecked(copy_m),
                    NonNull::new_unchecked(self.object),
                    self.offset,
                );
                VM_PAGE_QUEUE_LOCK.unlock();
            }
            self.m = copy_m;

            // SAFETY: the object is live and locked, and the top object
            // must not be collapsed while its page is busy.
            unsafe {
                paging_end(self.object);
                vm_object::collapse(self.object);
                paging_begin(self.object);
            }
        } else {
            self.protection &= !VmProt::WRITE;
        }
        None
    }

    /// Grow the copy object's page for the source page, as the C's
    /// null-copy path did.
    ///
    /// # Safety
    ///
    /// The copy object must be live and locked, and the source page
    /// `m` live and busy with the top object locked.
    unsafe fn copy_alloc(
        &mut self,
        copy_object: *mut VmObject,
        copy_offset: VmOffset,
    ) -> CopyStep {
        // SAFETY: the allocator may spin and the copy object is
        // locked.
        let Some(allocated) = (unsafe {
            vm_resident::alloc(
                NonNull::new_unchecked(copy_object),
                copy_offset,
            )
        }) else {
            // SAFETY: the result page and the copy object are the
            // fault's.
            unsafe {
                release_page(self.m);
                (*copy_object).ref_count -= 1;
                (*copy_object).lock.unlock();
                cleanup(self.object, NonNull::new(self.first_m));
            }
            return CopyStep::Return(Fault::error(
                FaultError::MemoryShortage,
                self.protection,
            ));
        };
        let copy_m = allocated.as_ptr();

        // SAFETY: the source page is busy and the copy is a fresh real
        // page; the queue lock guards the pmap flush.
        unsafe {
            vm_resident::copy(NonNull::new_unchecked(self.m), allocated);
            VM_PAGE_QUEUE_LOCK.lock();
            pmap_page_protect((*self.m).phys_addr, VmProt::NONE.bits());
            (*copy_m).set_dirty(true);
            VM_PAGE_QUEUE_LOCK.unlock();
        }

        // SAFETY: the copy object is live and locked.
        if unsafe { (*copy_object).is_pager_created() } {
            // SAFETY: the object lock is dropped around the pageout,
            // as the C did.
            unsafe { (*self.object).lock.unlock() };
            // SAFETY: the copy page is busy and off the pageout
            // queues, and the copy object is locked.
            unsafe { vm_pageout_page(copy_m, 1, 1) };

            // SAFETY: the copy object may have been deallocated for us
            // while the pageout dropped its lock.
            if unsafe { (*copy_object).shadow != self.object }
        // SAFETY: the copy object may have been deallocated
        // for us while the pageout dropped its lock.
        || unsafe { (*copy_object).ref_count == 1 }
            {
                // SAFETY: the copy object lock is held here and the
                // object reference is the fault's.
                unsafe {
                    (*copy_object).lock.unlock();
                    deallocate(copy_object);
                    (*self.object).lock.lock();
                }
                return CopyStep::Retry;
            }

            // SAFETY: the object is live; the C takes the lock back.
            unsafe { (*self.object).lock.lock() };
        } else {
            // SAFETY: the queue lock guards the page queues; the page
            // is live and busy.
            unsafe {
                VM_PAGE_QUEUE_LOCK.lock();
                vm_page::activate(copy_m);
                VM_PAGE_QUEUE_LOCK.unlock();
                page_wakeup_done(copy_m);
            }
        }

        // SAFETY: the source page is live and its object is locked.
        if unsafe { (*self.m).is_wanted() } {
            // SAFETY: the page is live and its object is locked.
            unsafe {
                (*self.m).set_wanted(false);
                thread_wakeup_prim(self.m.cast::<c_void>(), 0, THREAD_RESTART);
            }
        }
        CopyStep::Done
    }

    /// Handle the copy object page for the source page, as the
    /// C's copy loop did.
    ///
    /// # Safety
    ///
    /// The top object lock and reference must be the fault's, and
    /// the source page live and busy.
    unsafe fn copy_object(&mut self) -> Option<Fault> {
        loop {
            // Read the copy object with a volatile load: the retry after a
            // busy pageout or a failed try_lock must re-test it, and a plain
            // reload lets the optimizer carry the non-null it proved for the
            // previous iteration's dereference across those calls, which is
            // the miscompile MIGRATE records.
            //
            // SAFETY: `first_object` is live and referenced for the whole
            // call.
            let copy_object = unsafe {
                ptr::read_volatile(ptr::addr_of!((*self.first_object).copy))
            };
            if copy_object.is_null() {
                break;
            }

            if !self.fault_type.contains(VmProt::WRITE) {
                self.protection &= !VmProt::WRITE;
                break;
            }

            if self.must_be_resident {
                break;
            }

            // SAFETY: the copy object is live; the C tries its lock here.
            if unsafe { !(*copy_object).lock.try_lock() } {
                unsafe { (*self.object).lock.unlock() };
                simple_lock_pause();
                // SAFETY: the object is live and is locked again.
                unsafe { (*self.object).lock.lock() };
                continue;
            }

            // SAFETY: the copy object is live and locked.
            unsafe { (*copy_object).ref_count += 1 };

            let copy_offset =
    // SAFETY: the copy object is live and locked.
    self.first_offset.wrapping_sub(unsafe { (*copy_object).shadow_offset });
            // SAFETY: the copy object is live and locked.
            let copy_m = unsafe {
                vm_resident::lookup(
                    NonNull::new_unchecked(copy_object),
                    copy_offset,
                )
            }
            .map_or(ptr::null_mut(), NonNull::as_ptr);

            if copy_m.is_null() {
                // SAFETY: the copy object is live and locked, and the
                // source page is live and busy.
                match unsafe { self.copy_alloc(copy_object, copy_offset) } {
                    CopyStep::Retry => continue,
                    CopyStep::Done => {}
                    CopyStep::Return(fault) => return Some(fault),
                }
            } else if unsafe { (*copy_m).is_busy() } {
                // SAFETY: the page is live and locked.
                unsafe {
                    (*copy_m).set_wanted(true);
                    assert_wait(
                        NonNull::new(copy_m.cast::<c_void>()),
                        c_int::from(self.interruptible),
                    );
                    release_page(self.m);
                    (*copy_object).ref_count -= 1;
                    (*copy_object).lock.unlock();
                }
                return Some(unsafe {
                    block_and_backoff(
                        self.object,
                        self.first_m,
                        self.protection,
                        self.continuation,
                    )
                });
            }

            // SAFETY: the copy object is live and locked.
            unsafe {
                (*copy_object).ref_count -= 1;
                (*copy_object).lock.unlock();
            }
            break;
        }
        None
    }

    /// Build the success result, marking the page dirty as the C did.
    ///
    /// # Safety
    ///
    /// The search's result page must be live and busy in `m`.
    unsafe fn finish(&mut self) -> Fault {
        if VM_FAULT_DIRTY_HANDLING != 0
            && self.protection.contains(VmProt::WRITE)
        {
            // SAFETY: the result page is live and busy.
            unsafe { (*self.m).set_dirty(true) };
        }

        Fault {
            result: Ok(()),
            protection: self.protection,
            result_page: self.m,
            top_page: self.first_m,
        }
    }
}

/// Finds the resident page for the object/offset pair, following the shadow
/// chain and requesting the data from the pager when it is absent.
///
/// # Safety
///
/// `first_object` must be live, locked and referenced and must donate one
/// paging reference; the call consumes the lock and the reference.  When
/// `resume` is set, the current thread's saved `other` slot must hold the
/// state [`fault`] saved, and `continuation` must be the continuation that
/// state names.
#[expect(clippy::too_many_arguments)]
pub(crate) unsafe fn fault_page(
    first_object: *mut VmObject,
    first_offset: VmOffset,
    fault_type: VmProt,
    must_be_resident: bool,
    mut interruptible: bool,
    protection: VmProt,
    resume: bool,
    continuation: Continuation,
) -> Fault {
    let mut protection = protection;
    let object: *mut VmObject;
    let offset: VmOffset;
    let first_m: *mut VmPage;
    let access_required: VmProt;
    let m: *mut VmPage = ptr::null_mut();

    let mut resume_after_thread_block = if resume {
        // SAFETY: with `resume`, the caller saved the state on the current
        // thread before blocking.
        let state = unsafe { fault_state() };
        // SAFETY: `state` is the live state the caller saved.
        if unsafe { (*state).vmfp_backoff } != 0 {
            // SAFETY: the backoff already cleaned up before it blocked.
            return Fault::error(
                unsafe { after_block_and_backoff() },
                protection,
            );
        }
        // SAFETY: `state` is the live state the caller saved.
        unsafe {
            object = (*state).vmfp_object;
            offset = (*state).vmfp_offset;
            first_m = (*state).vmfp_first_m;
            access_required = (*state).vmfp_access;
        }
        true
    } else {
        unsafe {
            VM_STAT.faults += 1;
            (*current_task()).faults += 1;
        }

        if VM_FAULT_DIRTY_HANDLING != 0 && !fault_type.contains(VmProt::WRITE)
        {
            protection &= !VmProt::WRITE;
        }

        if VM_FAULT_INTERRUPTIBLE == 0 {
            interruptible = false;
        }

        object = first_object;
        offset = first_offset;
        first_m = ptr::null_mut();
        access_required = fault_type;
        false
    };

    let mut state = FaultState {
        first_object,
        first_offset,
        fault_type,
        must_be_resident,
        interruptible,
        protection,
        continuation,
        object,
        offset,
        first_m,
        access_required,
        m,
    };

    'search: loop {
        if resume_after_thread_block {
            resume_after_thread_block = false;
            // SAFETY: the thread just returned from the block that
            // saved this object and top page.
            if let Some(fault) = unsafe {
                after_wait(state.object, state.first_m, state.protection)
            } {
                return fault;
            }
            continue 'search;
        }

        // SAFETY: the object is live and locked.
        let found = unsafe {
            vm_resident::lookup(
                NonNull::new_unchecked(state.object),
                state.offset,
            )
        };
        state.m = found.map_or(ptr::null_mut(), NonNull::as_ptr);

        let step = if state.m.is_null() {
            // SAFETY: the object is live and locked.
            unsafe { state.missing_page() }
        } else {
            // SAFETY: the lookup returned the live, locked page.
            unsafe { state.found_page() }
        };

        match step {
            SearchStep::Retry => {}
            SearchStep::Done => break 'search,
            SearchStep::Return(fault) => return fault,
        }
    }

    if state.object != state.first_object {
        // SAFETY: the bottom object is live and locked.
        if let Some(fault) = unsafe { state.cow() } {
            return fault;
        }
    }

    // SAFETY: the search left the object and its page for the copy
    // loop.
    if let Some(fault) = unsafe { state.copy_object() } {
        return fault;
    }
    // SAFETY: the search left the live, busy result page in `m`.
    unsafe { state.finish() }
}

/// The continuation the fault computation resumes through after its stack may
/// have been discarded.
///
/// # Safety
///
/// The scheduling code calls this only with the current thread's saved `other`
/// slot holding the state [`fault`] saved.
unsafe extern "C" fn vm_fault_continue() {
    let state = unsafe { fault_state() };
    // SAFETY: the state is live until `fault` frees it at its end.
    let (map, vaddr, fault_type, change_wiring, continuation) = unsafe {
        (
            (*state).vmf_map,
            (*state).vmf_vaddr,
            (*state).vmf_fault_type,
            (*state).vmf_change_wiring != 0,
            (*state).vmf_continuation,
        )
    };
    // SAFETY: the state named this map and continuation, which receives
    // the result.
    let _ = unsafe {
        fault(map, vaddr, fault_type, change_wiring, true, continuation)
    };
}

/// The saved state a resumed [`fault()`] continues from.
type ResumeFault = (*mut VmObject, VmOffset, VmProt, VmMapVersion, bool);

/// Produce one fault for [`fault_run()`]: resume a saved state or look up
/// and fault the page, and service the non-success results.
///
/// # Safety
///
/// `map` must be a live map covering `vaddr`, `fault_type` a live mutable
/// protection, and any `resumed` state the one [`vm_fault_continue`] saved.
unsafe fn fault_step(
    map: &mut NonNull<VmMap>,
    fault_type: &mut VmProt,
    resumed: &mut Option<ResumeFault>,
    vaddr: VmOffset,
    change_wiring: bool,
    continuation: Option<unsafe fn(Result<(), Error>)>,
) -> FaultStep {
    let (object, offset, version, wired, fault) =
        if let Some((object, offset, prot, version, wired)) = resumed.take() {
            // SAFETY: the resume state names a live object, and the
            // state's continuation names this computation.
            let fault = unsafe {
                fault_page(
                    object,
                    offset,
                    *fault_type,
                    change_wiring && !wired,
                    !change_wiring,
                    prot,
                    true,
                    Some(vm_fault_continue),
                )
            };
            (object, offset, version, wired, fault)
        } else {
            // SAFETY: the live map and the caller's continuation.
            match unsafe {
                fault_lookup(
                    map,
                    vaddr,
                    fault_type,
                    change_wiring,
                    continuation,
                )
            } {
                Ok(found) => found,
                Err(error) => return FaultStep::Break(Err(error)),
            }
        };

    let result = fault.result;
    if result.is_err() {
        // SAFETY: the lookup's reference is the caller's, and no lock is
        // held here.
        unsafe { deallocate(object) };
    }

    match result {
        Err(FaultError::Retry) => FaultStep::Retry,
        Err(FaultError::Interrupted) => FaultStep::Break(Ok(())),
        Err(FaultError::MemoryShortage) => {
            if continuation.is_some() {
                // SAFETY: the state was allocated above.
                let state = unsafe { fault_state() };
                // SAFETY: the state is live and this is the only writer.
                unsafe {
                    (*state).vmf_map = map.as_ptr();
                    (*state).vmf_vaddr = vaddr;
                    (*state).vmf_fault_type = *fault_type;
                    (*state).vmf_change_wiring = c_int::from(change_wiring);
                    (*state).vmf_continuation = continuation;
                    (*state).vmf_object = ptr::null_mut();
                }
                // SAFETY: the wait resumes through the state.
                unsafe { vm_page::wait(Some(vm_fault_continue)) };
            } else {
                // SAFETY: the wait takes no continuation.
                unsafe { vm_page::wait(None) };
            }
            FaultStep::Retry
        }
        Err(FaultError::FictitiousShortage) => {
            // SAFETY: the slab package is up in this path.
            unsafe { vm_resident::more_fictitious() };
            FaultStep::Retry
        }
        Err(FaultError::MemoryError) => {
            FaultStep::Break(Err(Error::MemoryError))
        }
        Ok(()) => FaultStep::Page(FaultPage {
            object,
            offset,
            version,
            wired,
            result_page: fault.result_page,
            top_page: fault.top_page,
            protection: fault.protection,
        }),
    }
}

/// Run [`fault()`]'s retry loop until a fault succeeds or fails.
///
/// # Safety
///
/// As [`fault()`]: `map` must cover `vaddr`, and a `resumed` state must be
/// the one [`vm_fault_continue`] saved.
unsafe fn fault_run(
    map: &mut NonNull<VmMap>,
    fault_type: &mut VmProt,
    resumed: &mut Option<ResumeFault>,
    vaddr: VmOffset,
    change_wiring: bool,
    continuation: Option<unsafe fn(Result<(), Error>)>,
) -> Result<(), Error> {
    loop {
        match unsafe {
            fault_step(
                map,
                fault_type,
                resumed,
                vaddr,
                change_wiring,
                continuation,
            )
        } {
            FaultStep::Retry => {}
            FaultStep::Break(result) => return result,
            FaultStep::Page(page) => {
                // SAFETY: the fault returned the live, busy result page.
                match unsafe {
                    fault_success(map, vaddr, *fault_type, change_wiring, page)
                } {
                    SuccessStep::Retry => {}
                    SuccessStep::Break(result) => return result,
                }
            }
        }
    }
}

/// The result a [`fault_lookup()`] produces: the object, offset, version,
/// wiring flag, and the page fault it
type FaultLookup = (*mut VmObject, VmOffset, VmMapVersion, bool, Fault);

/// Look the fault's entry up in `map` and fault its page, as the C's lookup
/// arm did.
///
/// # Safety
///
/// `map` must be a live map covering `vaddr`, `fault_type` a live mutable
/// protection, and `continuation` the caller's continuation.
unsafe fn fault_lookup(
    map: &mut NonNull<VmMap>,
    vaddr: VmOffset,
    fault_type: &mut VmProt,
    change_wiring: bool,
    continuation: Option<unsafe fn(Result<(), Error>)>,
) -> Result<FaultLookup, Error> {
    match VmMap::lookup(map, vaddr, *fault_type, false) {
        Ok(found) => {
            let object = found.object;
            if found.wired {
                *fault_type = found.protection;
            }
            // SAFETY: the lookup returned the object locked.
            unsafe {
                (*object).ref_count += 1;
                paging_begin(object);
            }
            if continuation.is_some() {
                // SAFETY: the state was allocated above and nothing else
                // holds it.
                let state = unsafe { fault_state() };
                // SAFETY: the state is live and this is the only writer.
                unsafe {
                    (*state).vmf_map = map.as_ptr();
                    (*state).vmf_vaddr = vaddr;
                    (*state).vmf_fault_type = *fault_type;
                    (*state).vmf_change_wiring = c_int::from(change_wiring);
                    (*state).vmf_continuation = continuation;
                    (*state).vmf_version = VmMapVersion {
                        main_timestamp: found.timestamp,
                    };
                    (*state).vmf_wired = c_int::from(found.wired);
                    (*state).vmf_object = object;
                    (*state).vmf_offset = found.offset;
                    (*state).vmf_prot = found.protection;
                }
            }
            // SAFETY: the lookup's object lock and reference are the
            // fault's, and the continuation resumes through the state when
            // one is asked for.
            let fault = unsafe {
                fault_page(
                    object,
                    found.offset,
                    *fault_type,
                    change_wiring && !found.wired,
                    !change_wiring,
                    found.protection,
                    false,
                    if continuation.is_some() {
                        Some(vm_fault_continue)
                    } else {
                        None
                    },
                )
            };
            Ok((
                object,
                found.offset,
                VmMapVersion {
                    main_timestamp: found.timestamp,
                },
                found.wired,
                fault,
            ))
        }
        Err(error) => Err(error),
    }
}

/// The successful fault [`fault_success()`] installs in the map.
struct FaultPage {
    object: *mut VmObject,
    offset: VmOffset,
    version: VmMapVersion,
    wired: bool,
    result_page: *mut VmPage,
    top_page: *mut VmPage,
    protection: VmProt,
}

/// What one iteration of [`fault_step()`] produces for [`fault_run()`].
enum FaultStep {
    /// Run the lookup and fault again.
    Retry,
    /// Leave the loop with this result.
    Break(Result<(), Error>),
    /// Install this successful fault.
    Page(FaultPage),
}

/// What [`fault_success()`] leaves for [`fault_run()`].
enum SuccessStep {
    /// Run the lookup and fault again.
    Retry,
    /// Leave the loop with this result.
    Break(Result<(), Error>),
}

/// Re-check the map and install the fault's result page, as the C's success
/// path did.
///
/// # Safety
///
/// `map` must be a live map covering `vaddr`, `page` the live result of
/// [`fault_page()`] with its object locked, and `fault_type` the fault's
/// current protection.
unsafe fn fault_success(
    map: &mut NonNull<VmMap>,
    vaddr: VmOffset,
    fault_type: VmProt,
    change_wiring: bool,
    page: FaultPage,
) -> SuccessStep {
    let mut version = page.version;
    let mut wired = page.wired;
    let mut prot = page.protection;
    let result_page = page.result_page;
    let top_page = page.top_page;
    let object = page.object;
    let offset = page.offset;

    // SAFETY: the fault returned the live, busy result page with its
    // object locked.
    let old_copy_object = unsafe { (*(*result_page).object).copy };
    unsafe { (*(*result_page).object).lock.unlock() };

    while !VmMap::verify(*map, &version) {
        // The C clears the write bit so the retry cannot write-lock the
        // map.
        let retry =
            VmMap::lookup(map, vaddr, fault_type & !VmProt::WRITE, false);
        let (retry_object, retry_offset, retry_prot) = match retry {
            Ok(found) => {
                version = VmMapVersion {
                    main_timestamp: found.timestamp,
                };
                wired = found.wired;
                (found.object, found.offset, found.protection)
            }
            Err(error) => {
                unsafe {
                    (*(*result_page).object).lock.lock();
                    release_page(result_page);
                    cleanup((*result_page).object, NonNull::new(top_page));
                    deallocate(object);
                }
                return SuccessStep::Break(Err(error));
            }
        };

        // SAFETY: the retry lookup returned its object locked.
        unsafe { (*retry_object).lock.unlock() };
        unsafe { (*(*result_page).object).lock.lock() };

        if retry_object != object || retry_offset != offset {
            unsafe {
                release_page(result_page);
                cleanup((*result_page).object, NonNull::new(top_page));
                deallocate(object);
            }
            return SuccessStep::Retry;
        }

        prot &= retry_prot;
        unsafe { (*(*result_page).object).lock.unlock() };
    }

    // SAFETY: `verify` left the map read-locked, and the result page's
    // object is live.
    unsafe { (*(*result_page).object).lock.lock() };
    // SAFETY: the result page's object is live and locked.
    if unsafe { (*(*result_page).object).copy } != old_copy_object {
        prot &= !VmProt::WRITE;
    }
    if wired && prot != fault_type {
        // SAFETY: `verify` left the map read-locked.
        unsafe { map.as_ref().lock.done() };
        unsafe {
            release_page(result_page);
            cleanup((*result_page).object, NonNull::new(top_page));
            deallocate(object);
        }
        return SuccessStep::Retry;
    }

    // SAFETY: the result page's object is live and locked.
    unsafe { (*(*result_page).object).lock.unlock() };

    // SAFETY: the map is live, and the page is the live, busy result of
    // the fault.
    unsafe {
        pmap_enter(
            NonNull::new((*map.as_ptr()).pmap),
            vaddr,
            (*result_page).phys_addr,
            (prot & !(*result_page).page_lock()).bits(),
            c_int::from(wired),
        );
    }

    // SAFETY: the result page's object and the page-queues lock serialize
    // the page's state.
    unsafe {
        (*(*result_page).object).lock.lock();
        VM_PAGE_QUEUE_LOCK.lock();
        if change_wiring {
            if wired {
                vm_page::wire(NonNull::new_unchecked(result_page));
            } else {
                vm_page::unwire(result_page);
            }
        } else if SOFTWARE_REFERENCE_BITS != 0 {
            if !(*result_page).is_active() && !(*result_page).is_inactive() {
                vm_page::activate(result_page);
            }
            (*result_page).set_reference(true);
        } else {
            vm_page::activate(result_page);
        }
        VM_PAGE_QUEUE_LOCK.unlock();
    }

    // SAFETY: `verify` left the map read-locked, and the page is the live,
    // busy result of the fault.
    unsafe {
        map.as_ref().lock.done();
        page_wakeup_done(result_page);
    }

    unsafe {
        cleanup((*result_page).object, NonNull::new(top_page));
        deallocate(object);
    }
    SuccessStep::Break(Ok(()))
}

/// Handles a page fault, including the pseudo-faults that change a mapping's
/// wiring.
///
/// # Safety
///
/// `map` must be a live map covering `vaddr`.  With a continuation the call
/// does not return to its caller: it invokes the continuation at its end, and
/// with `resume` the current thread's saved `other` slot must hold the state
/// [`vm_fault_continue`] saved.
///
/// # Panics
///
/// Halts through the kernel panic path when the state cache cannot allocate
/// for a continuation, which the C's unchecked `kmem_cache_alloc` left to
/// fault later.
pub(crate) unsafe fn fault(
    map: *mut VmMap,
    vaddr: VmOffset,
    fault_type: VmProt,
    change_wiring: bool,
    resume: bool,
    continuation: Option<unsafe fn(Result<(), Error>)>,
) -> Result<(), Error> {
    let mut fault_type = fault_type;
    let mut map = unsafe { NonNull::new_unchecked(map) };

    // The state a resumed call continues from, when one was saved.
    let mut resumed = None;
    if resume {
        let state = unsafe { fault_state() };
        // SAFETY: the state is live for the whole call.
        unsafe {
            let object = (*state).vmf_object;
            if !object.is_null() {
                resumed = Some((
                    object,
                    (*state).vmf_offset,
                    (*state).vmf_prot,
                    VmMapVersion {
                        main_timestamp: (*state).vmf_version.main_timestamp,
                    },
                    (*state).vmf_wired != 0,
                ));
            }
        }
    } else if continuation.is_some() {
        let Some(state) = cache_alloc() else {
            kpanic!("vm_fault", "vm_fault: vm_fault_state allocation failed");
        };
        // SAFETY: the current thread is live, and this is its only writer
        // for the call.
        unsafe {
            (*per_cpu::thread()).saved.other = state.as_ptr().cast::<c_void>();
        }
    }

    let result = unsafe {
        fault_run(
            &mut map,
            &mut fault_type,
            &mut resumed,
            vaddr,
            change_wiring,
            continuation,
        )
    };

    if let Some(continuation) = continuation {
        // SAFETY: the state was allocated for this continuation, and
        // nothing else holds it.
        let state = unsafe { fault_state() };
        // SAFETY: the state is the dead allocation.
        unsafe { cache_free(NonNull::new_unchecked(state)) };
        unsafe { continuation(result) };
    }
    result
}

/// Unwires every page of `entry` in `map`.
///
/// # Safety
///
/// `map` must be a live, referenced map and `entry` a live entry of it whose
/// pages are wired down.
pub(crate) unsafe fn unwire(map: &VmMap, entry: NonNull<VmMapEntry>) {
    let (start, end_addr, object) = unsafe {
        (
            (*entry.as_ptr()).links.start,
            (*entry.as_ptr()).links.end,
            if (*entry.as_ptr()).is_sub_map() {
                ptr::null_mut()
            } else {
                (*entry.as_ptr()).object.vm_object
            },
        )
    };

    let pmap = map.pmap;
    let map_ptr = ptr::from_ref(map).cast_mut();
    let mut va = start;
    while va < end_addr {
        unsafe { pmap_change_wiring(pmap, va, 0) };

        if object.is_null() {
            unsafe {
                map.lock.set_recursive();
                // The C ignored the unwiring fault's result.
                let _ = fault(map_ptr, va, VmProt::NONE, true, false, None);
                map.lock.clear_recursive();
            }
        } else {
            let fault = loop {
                // SAFETY: the object is live; each attempt takes the lock
                // and paging reference the fault consumes, exactly as the C
                // do/while does.
                let fault = unsafe {
                    (*object).lock.lock();
                    paging_begin(object);
                    fault_page(
                        object,
                        (*entry.as_ptr())
                            .offset
                            .wrapping_add(va.wrapping_sub(start)),
                        VmProt::NONE,
                        true,
                        false,
                        VmProt::NONE,
                        false,
                        None,
                    )
                };
                if fault.result != Err(FaultError::Retry) {
                    break fault;
                }
            };
            if fault.result.is_err() {
                kpanic!("vm_fault_unwire", "vm_fault_unwire: failure");
            }

            let result_page = fault.result_page;
            // SAFETY: the fault returned the live, busy page and holds its
            // object lock.
            unsafe {
                VM_PAGE_QUEUE_LOCK.lock();
                vm_page::unwire(result_page);
                VM_PAGE_QUEUE_LOCK.unlock();
                page_wakeup_done(result_page);
                cleanup((*result_page).object, NonNull::new(fault.top_page));
            }
        }
        va = va.wrapping_add(PAGE_SIZE);
    }

    pmap_pageable(pmap, start, end_addr, 1);
}

/// Fault the source page for [`copy()`], retrying as the C's source loop
/// did.
///
/// # Safety
///
/// `src_object` must be live with a reference held, and the caller must
/// hold no locks.
unsafe fn copy_source(
    src_object: *mut VmObject,
    src_offset: VmOffset,
    interruptible: bool,
) -> Result<(*mut VmPage, *mut VmPage), Error> {
    let (page, top) = loop {
        // SAFETY: each attempt takes the source object's lock and paging
        // reference, which `fault_page()` consumes.
        let fault = unsafe {
            (*src_object).lock.lock();
            paging_begin(src_object);
            fault_page(
                src_object,
                src_offset,
                VmProt::READ,
                false,
                interruptible,
                VmProt::READ,
                false,
                None,
            )
        };
        match fault.result {
            Ok(()) => break (fault.result_page, fault.top_page),
            Err(FaultError::Retry) => (),
            Err(FaultError::Interrupted) => return Err(Error::Interrupted),
            Err(FaultError::MemoryShortage) => {
                // SAFETY: the page wait takes no continuation.
                unsafe { vm_page::wait(None) };
            }
            Err(FaultError::FictitiousShortage) => {
                // SAFETY: the slab package is up in this path.
                unsafe { vm_resident::more_fictitious() };
            }
            Err(FaultError::MemoryError) => return Err(Error::MemoryError),
        }
    };
    // SAFETY: the fault left the result page's object locked.
    unsafe { (*(*page).object).lock.unlock() };
    Ok((page, top))
}

/// Fault the destination page for [`copy()`], retrying as the C's
/// destination loop did and releasing the source fault's pages on failure.
///
/// # Safety
///
/// `dst_object` must be live with a reference held, `src_page` and
/// `src_top_page` the source fault's live pages (or null), and the caller
/// must hold no locks.
unsafe fn copy_dest(
    dst_object: *mut VmObject,
    dst_offset: VmOffset,
    src_page: *mut VmPage,
    src_top_page: *mut VmPage,
    src_size: &mut VmSize,
    amount_done: VmSize,
) -> Result<(*mut VmPage, *mut VmPage), Error> {
    let (page, top) = loop {
        // SAFETY: each attempt takes the destination object's lock and
        // paging reference, which `fault_page()` consumes.
        let fault = unsafe {
            (*dst_object).lock.lock();
            paging_begin(dst_object);
            fault_page(
                dst_object,
                dst_offset,
                VmProt::WRITE,
                false,
                false,
                VmProt::WRITE,
                false,
                None,
            )
        };
        match fault.result {
            Ok(()) => break (fault.result_page, fault.top_page),
            Err(FaultError::Retry) => (),
            Err(FaultError::Interrupted) => {
                if !src_page.is_null() {
                    // SAFETY: the source fault left the page and its
                    // top page for this call to release.
                    unsafe { copy_cleanup(src_page, src_top_page) };
                }
                *src_size = amount_done;
                return Err(Error::Interrupted);
            }
            Err(FaultError::MemoryShortage) => {
                // SAFETY: the page wait takes no continuation.
                unsafe { vm_page::wait(None) };
            }
            Err(FaultError::FictitiousShortage) => {
                // SAFETY: the slab package is up in this path.
                unsafe { vm_resident::more_fictitious() };
            }
            Err(FaultError::MemoryError) => {
                if !src_page.is_null() {
                    unsafe { copy_cleanup(src_page, src_top_page) };
                }
                return Err(Error::MemoryError);
            }
        }
    };
    Ok((page, top))
}

/// Copies pages from `src_object` into `dst_object`, advancing through the
/// destination map's `dst_version`.
///
/// # Safety
///
/// The caller must hold a reference, but not a lock, to each object and to
/// `dst_map`; `src_size` must be writable and name the bytes to copy.
///
/// # Panics
///
/// Halts through the kernel panic path when [`fault_page`] cannot produce the
/// page.
#[expect(clippy::too_many_arguments)]
pub(crate) unsafe fn copy(
    src_object: Option<NonNull<VmObject>>,
    mut src_offset: VmOffset,
    src_size: &mut VmSize,
    dst_object: *mut VmObject,
    mut dst_offset: VmOffset,
    dst_map: NonNull<VmMap>,
    dst_version: &VmMapVersion,
    interruptible: bool,
) -> Result<(), Error> {
    let mut amount_done: VmSize = 0;

    loop {
        let (src_page, src_top_page) = match src_object {
            None => (ptr::null_mut(), ptr::null_mut()),
            Some(src_object) => {
                // SAFETY: the source object is live with a reference
                // held.
                match unsafe {
                    copy_source(src_object.as_ptr(), src_offset, interruptible)
                } {
                    Ok(pages) => pages,
                    Err(error) => {
                        if error == Error::Interrupted {
                            *src_size = amount_done;
                        }
                        return Err(error);
                    }
                }
            }
        };

        // SAFETY: the destination object is live and the source pages
        // are the source fault's.
        let (dst_page, dst_top_page) = unsafe {
            copy_dest(
                dst_object,
                dst_offset,
                src_page,
                src_top_page,
                src_size,
                amount_done,
            )
        }?;

        // SAFETY: the destination object is live and was left locked.
        let old_copy_object = unsafe { (*(*dst_page).object).copy };
        // SAFETY: the fault left the page's object locked.
        unsafe { (*(*dst_page).object).lock.unlock() };

        if !VmMap::verify(dst_map, dst_version) {
            // SAFETY: both faults left their page and top page to release.
            unsafe {
                if !src_page.is_null() {
                    copy_cleanup(src_page, src_top_page);
                }
                copy_cleanup(dst_page, dst_top_page);
            }
            break;
        }

        // SAFETY: the destination object is live; the C relocks it to
        // recheck the copy object.
        unsafe {
            (*(*dst_page).object).lock.lock();
            if (*(*dst_page).object).copy != old_copy_object {
                (*(*dst_page).object).lock.unlock();
                // SAFETY: `verify` left the read lock held; the failed
                // recheck releases it.
                (*dst_map.as_ptr()).lock.done();
                if !src_page.is_null() {
                    copy_cleanup(src_page, src_top_page);
                }
                copy_cleanup(dst_page, dst_top_page);
                break;
            }
            (*(*dst_page).object).lock.unlock();
        }

        if src_page.is_null() {
            // SAFETY: the destination page is live and busy.
            unsafe {
                vm_resident::zero_fill(NonNull::new_unchecked(dst_page));
            };
        } else {
            // SAFETY: both pages are live and busy.
            unsafe {
                vm_resident::copy(
                    NonNull::new_unchecked(src_page),
                    NonNull::new_unchecked(dst_page),
                );
            };
        }
        // SAFETY: the destination page is live.
        unsafe { (*dst_page).set_dirty(true) };
        // SAFETY: `verify` left the read lock held.
        unsafe { (*dst_map.as_ptr()).lock.done() };

        // SAFETY: both faults left their page and top page to release.
        unsafe {
            if !src_page.is_null() {
                copy_cleanup(src_page, src_top_page);
            }
            copy_cleanup(dst_page, dst_top_page);
        }

        amount_done = amount_done.wrapping_add(PAGE_SIZE);
        src_offset = src_offset.wrapping_add(PAGE_SIZE);
        dst_offset = dst_offset.wrapping_add(PAGE_SIZE);

        if amount_done == *src_size {
            break;
        }
    }

    *src_size = amount_done;
    Ok(())
}

/// Releases the busy page a [`copy`] fault returned, then its object through
/// [`cleanup`].
///
/// # Safety
///
/// `page` must be the busy page the fault returned with its object locked,
/// and `top_page` that fault's top page.
unsafe fn copy_cleanup(page: *mut VmPage, top_page: *mut VmPage) {
    // SAFETY: the fault left the page's object locked.
    let object = unsafe { (*page).object };
    unsafe {
        (*object).lock.lock();
        page_wakeup_done(page);
        VM_PAGE_QUEUE_LOCK.lock();
        if !(*page).is_active() && !(*page).is_inactive() {
            vm_page::activate(page);
        }
        VM_PAGE_QUEUE_LOCK.unlock();
        cleanup(object, NonNull::new(top_page));
    }
}
