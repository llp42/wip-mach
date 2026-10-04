// SPDX-License-Identifier: CMU-Mach
// Derived from vm/memory_object.c and vm/memory_object.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The external memory management interface, which `vm/memory_object.c` used
//! to define and `vm/memory_object.h` declares.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::{PAGE_SHIFT, PAGE_SIZE};
use crate::arch::x86_64::pmap::pmap_clear_modify;
use crate::arch::x86_64::pmap::pmap_is_modified;
use crate::arch::x86_64::pmap::pmap_page_protect;
use crate::glue::{
    memory_object_change_completed, memory_object_data_return,
    memory_object_lock_completed, memory_object_supply_completed,
};
use crate::ipc::{IpcPort, ipc_port};
use crate::kern::debug::kpanic;
use crate::kern::host::Host;
use crate::kern::sched_prim::{assert_wait, thread_block};
use crate::vm::error::{Error, error_from_kern_return};
use crate::vm::types::{VmObject, VmPage, VmProt};
use crate::vm::vm_map::{VmMapCopy, round_page};
use crate::vm::vm_pageout::vm_pageout_setup;
use crate::vm::vm_resident::VM_PAGE_QUEUE_LOCK;
use crate::vm::{vm_external, vm_object, vm_page, vm_resident};
use core::ffi::{c_int, c_uint, c_void};
use core::ptr::{NonNull, addr_of_mut, null_mut};
use core::sync::atomic::Ordering;

/// `MEMORY_OBJECT_RETURN_*` of <`mach/memory_object.h>`: what a lock request
/// asks the kernel to return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Return {
    /// `MEMORY_OBJECT_RETURN_NONE`.
    None,
    /// `MEMORY_OBJECT_RETURN_DIRTY`.
    Dirty,
    /// `MEMORY_OBJECT_RETURN_ALL`.
    All,
}

impl Return {
    /// The value a C `memory_object_return_t` names; anything outside the
    /// three behaves as `DIRTY` did in the C's two comparisons.
    pub(crate) const fn from_c(code: c_int) -> Self {
        match code {
            0 => Self::None,
            2 => Self::All,
            _ => Self::Dirty,
        }
    }
}

/// `MEMORY_OBJECT_COPY_*` of <`mach/memory_object.h>`: the strategies a memory
/// manager may ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CopyStrategy {
    /// `MEMORY_OBJECT_COPY_NONE`.
    None,
    /// `MEMORY_OBJECT_COPY_CALL`.
    Call,
    /// `MEMORY_OBJECT_COPY_DELAY`.
    Delay,
    /// `MEMORY_OBJECT_COPY_TEMPORARY`.
    Temporary,
}

impl CopyStrategy {
    /// The strategy a C `memory_object_copy_strategy_t` names, or `None`
    /// when the value is not one of the four.
    pub(crate) const fn from_c(code: c_int) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::Call),
            2 => Some(Self::Delay),
            3 => Some(Self::Temporary),
            _ => None,
        }
    }

    /// The C `memory_object_copy_strategy_t` this strategy names.
    pub(crate) const fn as_c(self) -> c_int {
        match self {
            Self::None => 0,
            Self::Call => 1,
            Self::Delay => 2,
            Self::Temporary => 3,
        }
    }
}

/// `MEMORY_OBJECT_LOCK_RESULT_*` of `vm/memory_object.c`: what a page lock
/// did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LockResult {
    Done,
    MustBlock,
    MustClean,
    MustReturn,
}

/// `VM_EXTERNAL_SMALL_SIZE` and `VM_EXTERNAL_LARGE_SIZE` of
/// <`vm/vm_external.h`>.
const VM_EXTERNAL_SMALL_SIZE: VmSize = 128;
const VM_EXTERNAL_LARGE_SIZE: VmSize = 8192;

/// `DATA_WRITE_MAX` of `vm/memory_object.c`: how many holding pages one
/// data-return message may carry.
const DATA_WRITE_MAX: usize = 32;

/// One `memory_object_lock_request()` in Rust terms.
#[derive(Clone, Copy)]
pub(crate) struct LockRequest {
    pub(crate) offset: VmOffset,
    pub(crate) size: VmSize,
    pub(crate) should_return: Return,
    pub(crate) should_flush: bool,
    pub(crate) prot: VmProt,
    pub(crate) reply_to: *mut c_void,
    pub(crate) reply_to_type: c_uint,
}

/// One `memory_object_data_supply()` in Rust terms.
#[derive(Clone, Copy)]
pub(crate) struct SupplyRequest {
    pub(crate) offset: VmOffset,
    pub(crate) data: VmOffset,
    pub(crate) data_cnt: c_uint,
    pub(crate) lock_value: VmProt,
    pub(crate) precious: bool,
    pub(crate) reply_to: *mut c_void,
    pub(crate) reply_to_type: c_uint,
}

/// `atop()` of <`vm/vm_page.h`>.
const fn atop(address: VmOffset) -> usize {
    address >> PAGE_SHIFT
}

/// `panic()` of `vm/memory_object.c`.
fn die(func: &'static str, message: &'static str) -> ! {
    kpanic!(func, "{}", message)
}

/// `VM_PAGE_FREE()` of <`vm/vm_page.h`>.
///
/// # Safety
///
/// `page` must be a live page that the caller owns, and the page-queues lock
/// must not be held.
unsafe fn page_free(page: *mut VmPage) {
    unsafe {
        VM_PAGE_QUEUE_LOCK.lock();
        vm_resident::free(NonNull::new_unchecked(page));
        VM_PAGE_QUEUE_LOCK.unlock();
    }
}

/// `PAGE_WAKEUP()` of <`vm/vm_page.h`>.
///
/// # Safety
///
/// `page` must be a live page whose object lock the caller holds.
unsafe fn page_wakeup(page: *mut VmPage) {
    unsafe { vm_object::page_wakeup(page) };
}

/// `memory_object_lock_page()` in C: apply the lock request to one page.
///
/// # Safety
///
/// `page` must be a live page whose object lock the caller holds.
unsafe fn lock_page(
    page: *mut VmPage,
    should_return: Return,
    should_flush: bool,
    mut prot: VmProt,
) -> LockResult {
    if unsafe { (*page).is_absent() } {
        return LockResult::Done;
    }

    if unsafe { (*page).is_busy() } {
        return LockResult::MustBlock;
    }

    if unsafe { (*page).wire_count() } != 0 {
        let unchanged = !should_flush
            && ((unsafe { (*page).page_lock() } == prot)
                || prot == VmProt::NO_CHANGE)
            && (should_return == Return::None
                || (!unsafe { (*page).is_dirty() }
                    && unsafe { pmap_is_modified((*page).phys_addr) } == 0
                    && (!unsafe { (*page).is_precious() }
                        || should_return != Return::All)));
        if unchanged {
            unsafe {
                (*page).set_unlock_request(VmProt::NONE);
            }
            unsafe { page_wakeup(page) };

            return LockResult::Done;
        }

        return LockResult::MustBlock;
    }

    if should_flush {
        prot = VmProt::ALL;
    }

    if prot != VmProt::NO_CHANGE {
        let decreases = unsafe {
            (((*page).page_lock().bits() ^ prot.bits()) & prot.bits()) != 0
        };
        if decreases {
            // SAFETY: the page is live, so its physical address names real
            // memory.
            unsafe {
                pmap_page_protect(
                    (*page).phys_addr,
                    (VmProt::ALL & !prot).bits(),
                );
            };
        }
        unsafe {
            (*page).set_page_lock(prot);
            (*page).set_unlock_request(VmProt::NONE);
        }
        unsafe { page_wakeup(page) };
    }

    if should_return != Return::None {
        unsafe {
            if !(*page).is_dirty() {
                (*page).set_dirty(pmap_is_modified((*page).phys_addr) != 0);
            }
        }

        let clean = unsafe {
            (*page).is_dirty()
                || ((*page).is_precious() && should_return == Return::All)
        };
        if clean {
            // SAFETY: the page-queues lock is the C macro's, and the page is
            // live.
            unsafe {
                VM_PAGE_QUEUE_LOCK.lock();
                vm_page::queues_remove(page);
                VM_PAGE_QUEUE_LOCK.unlock();
            }

            if !should_flush {
                // SAFETY: the page is live, so its physical address names
                // real memory.
                unsafe {
                    pmap_page_protect((*page).phys_addr, VmProt::NONE.bits());
                };
            }

            // SAFETY: the page is live and its dirty flag was just read.
            return if unsafe { (*page).is_dirty() } {
                LockResult::MustClean
            } else {
                LockResult::MustReturn
            };
        }
    }

    if should_flush {
        unsafe { page_free(page) };
    } else if vm_resident::VM_PAGE_DEACTIVATE_HINT.load(Ordering::Relaxed)
        && should_return != Return::None
    {
        // SAFETY: the page-queues lock is the C's, and the page is live.
        unsafe {
            VM_PAGE_QUEUE_LOCK.lock();
            vm_page::deactivate(page);
            VM_PAGE_QUEUE_LOCK.unlock();
        }
    }

    LockResult::Done
}

/// One run of pages collected for a `memory_object_data_return()` message;
/// the state the C's `PAGEOUT_PAGES` macro carried between iterations.
struct PageoutBatch {
    new_object: *mut VmObject,
    new_offset: VmOffset,
    paging_offset: VmOffset,
    action: LockResult,
    holding: [*mut VmPage; DATA_WRITE_MAX],
}

impl PageoutBatch {
    const fn new() -> Self {
        Self {
            new_object: null_mut(),
            new_offset: 0,
            paging_offset: 0,
            action: LockResult::Done,
            holding: [null_mut(); DATA_WRITE_MAX],
        }
    }

    /// `PAGEOUT_PAGES` of `vm/memory_object.c`.
    ///
    /// # Safety
    ///
    /// The caller must hold `object`'s lock and a paging reference; the
    /// batch's `new_object` must be a live object.
    unsafe fn flush(&mut self, object: *mut VmObject, should_flush: bool) {
        unsafe { (*object).lock.unlock() };

        // SAFETY: the batch's object is live and held by the paging
        // reference, and the copy cache is initialized.
        let copy = unsafe {
            VmMapCopy::copyin_object(self.new_object, 0, self.new_offset)
        };

        // SAFETY: the object is live, and its pager fields are valid under
        // the paging reference the caller holds; the copy is the live
        // page-list copy just made.
        unsafe {
            memory_object_data_return(
                (*object).pager,
                (*object).pager_request,
                self.paging_offset,
                // `pointer_t` is a `vm_offset_t`, and a pointer is the same
                // width on both targets.
                copy.as_ptr() as VmOffset,
                // The copy holds at most `DATA_WRITE_MAX` pages, so the
                // byte count fits the C's `mach_msg_type_number_t`.
                self.new_offset as c_uint,
                c_int::from(self.action == LockResult::MustClean),
                c_int::from(!should_flush),
            );
            (*object).lock.lock();
        }

        let mut i = 0;
        while i < atop(self.new_offset) {
            let page = self.holding[i];
            if !page.is_null() {
                // SAFETY: the batch owns the holding page, and the object
                // lock is held as the macro's call site had it.
                unsafe { page_free(page) };
            }
            i += 1;
        }

        self.new_object = null_mut();
    }
}

/// Flush the pending batch and block on a page the lock request must wait
/// for, as the C's `PAGE_ASSERT_WAIT` arm did.
///
/// # Safety
///
/// The object must be live and locked, and `page` the live page the lookup
/// returned with that lock held.
unsafe fn lock_page_block(
    batch: &mut PageoutBatch,
    page: *mut VmPage,
    object: *mut VmObject,
    should_flush: bool,
) {
    if !batch.new_object.is_null() {
        // SAFETY: the batch is live and the object lock is held.
        unsafe { batch.flush(object, should_flush) };
        return;
    }

    // SAFETY: the page is live and the object lock is held, as
    // `PAGE_ASSERT_WAIT` requires.
    unsafe {
        (*page).set_wanted(true);
        assert_wait(NonNull::new(page.cast()), 0);
        (*object).lock.unlock();
        thread_block(None);
        (*object).lock.lock();
    }
}

/// Move a page the lock request must clean or return into the pageout
/// batch, allocating the batch's object for its first page.
///
/// # Safety
///
/// The object must be live and locked with the paging reference held,
/// the page must be the live, busy page the lookup returned, and `state`
/// must hold the request's current offset, last offset, and last action.
unsafe fn lock_pageout(
    batch: &mut PageoutBatch,
    page: *mut VmPage,
    object: *mut VmObject,
    result: LockResult,
    state: &mut (VmOffset, VmOffset, LockResult),
    original_size: VmSize,
    should_flush: bool,
) {
    unsafe { (*page).set_busy(true) };

    if !batch.new_object.is_null() && (state.1 != state.0 || state.2 != result)
    {
        // SAFETY: the batch is live and the object lock is
        // held.
        unsafe { batch.flush(object, should_flush) };
    }

    // SAFETY: the page is live, and `vm_object_allocate()`
    // and `vm_pageout_setup()` run unlocked, as the C did.
    unsafe {
        (*object).lock.unlock();
    }

    if batch.new_object.is_null() {
        // SAFETY: the slab allocator and the IPC space are up.
        let new_object = unsafe { vm_object::allocate(original_size) };
        batch.new_object = new_object.as_ptr();
        batch.new_offset = 0;
        // The paging reference keeps the object alive, so
        // these unlock without the lock as the C did.
        // SAFETY: the page is busy and the object live.
        batch.paging_offset =
            unsafe { (*page).offset + (*object).paging_offset };
        state.2 = result;
    }

    let new_page = unsafe {
        vm_pageout_setup(
            page,
            (*page).offset + (*object).paging_offset,
            batch.new_object,
            batch.new_offset,
            c_int::from(should_flush),
        )
    };

    // The offset is below `DATA_WRITE_MAX` pages, which the
    // flush above the lookup loop enforced.
    batch.holding[atop(batch.new_offset)] = new_page;
    batch.new_offset = batch.new_offset.wrapping_add(PAGE_SIZE);
    state.1 = state.0.wrapping_add(PAGE_SIZE);

    // SAFETY: the object is live and held by the paging
    // reference.
    unsafe { (*object).lock.lock() };
}

/// `memory_object_lock_request()` in C: apply a lock request to every page of
/// the object's range.
///
/// # Safety
///
/// A non-null `object` must be a live object, and the call consumes the
/// caller's reference to it; `reply_to` must be `IP_NULL` or a live port.
pub(crate) unsafe fn lock_request(
    object: *mut VmObject,
    request: &LockRequest,
) -> Result<(), Error> {
    let LockRequest {
        offset,
        size,
        should_return,
        should_flush,
        prot,
        reply_to,
        reply_to_type,
    } = *request;

    let Some(object) = NonNull::new(object) else {
        return Err(Error::InvalidArgument);
    };
    if (prot.bits() & !VmProt::ALL.bits()) != 0 && prot != VmProt::NO_CHANGE {
        return Err(Error::InvalidArgument);
    }

    let object = object.as_ptr();
    let original_offset = offset;
    let original_size = size;
    let mut size = round_page(size);
    let mut batch = PageoutBatch::new();

    unsafe {
        (*object).lock.lock();
        vm_object::paging_begin(object);
    }
    // SAFETY: the object is live and its lock is held.
    let mut offset = offset.wrapping_sub(unsafe { (*object).paging_offset });
    // The cross-arm state of the pageout loop: the current offset, the
    // last offset, and the last action taken.
    let mut pageout_state = (offset, original_offset, LockResult::Done);

    while size != 0 {
        pageout_state.0 = offset;
        if !batch.new_object.is_null()
            && batch.new_offset >= PAGE_SIZE * DATA_WRITE_MAX
        {
            // SAFETY: the batch is live and the object lock is held.
            unsafe { batch.flush(object, should_flush) };
        }

        // SAFETY: the object is live and locked, as `lookup` requires.
        while let Some(page) = unsafe {
            vm_resident::lookup(NonNull::new_unchecked(object), offset)
        } {
            let page = page.as_ptr();
            // SAFETY: the page is live and the object lock is held.
            let result =
                unsafe { lock_page(page, should_return, should_flush, prot) };

            match result {
                LockResult::Done => {
                    if !batch.new_object.is_null() {
                        // SAFETY: the batch is live and the object lock is
                        // held.
                        unsafe { batch.flush(object, should_flush) };
                        continue;
                    }
                }
                LockResult::MustBlock => {
                    // SAFETY: the page is live and the object lock is held.
                    unsafe {
                        lock_page_block(
                            &mut batch,
                            page,
                            object,
                            should_flush,
                        );
                    }
                    continue;
                }
                LockResult::MustClean | LockResult::MustReturn => {
                    unsafe {
                        lock_pageout(
                            &mut batch,
                            page,
                            object,
                            result,
                            &mut pageout_state,
                            original_size,
                            should_flush,
                        );
                    };
                }
            }
            break;
        }

        size -= PAGE_SIZE;
        offset = offset.wrapping_add(PAGE_SIZE);
    }

    if !batch.new_object.is_null() {
        // SAFETY: the batch is live and the object lock is held.
        unsafe { batch.flush(object, should_flush) };
    }

    // SAFETY: the object is live and locked, and the reply right is live
    // when there is one.
    unsafe {
        lock_request_reply(
            object,
            reply_to,
            reply_to_type,
            original_offset,
            original_size,
        );
    }

    // SAFETY: the object is live and locked; the call consumes the caller's
    // reference.
    unsafe {
        vm_object::paging_end(object);
        (*object).lock.unlock();
        vm_object::deallocate(object);
    }

    Ok(())
}

/// Send the completion a lock request with a reply right owes, as the C's
/// unlocked `memory_object_lock_completed()` call did.
///
/// # Safety
///
/// The object must be live and locked, and `reply_to` must be `IP_NULL` or
/// a live port the call consumes.
unsafe fn lock_request_reply(
    object: *mut VmObject,
    reply_to: *mut c_void,
    reply_to_type: c_uint,
    original_offset: VmOffset,
    original_size: VmSize,
) {
    if IpcPort::valid(reply_to).is_some() {
        // SAFETY: the object is live and locked; the reply routine consumes
        // the reply right, and the C re-locks around it.
        unsafe {
            (*object).lock.unlock();
            memory_object_lock_completed(
                reply_to,
                reply_to_type,
                (*object).pager_request,
                original_offset,
                original_size,
            );
            (*object).lock.lock();
        }
    }
}

/// Take one page of the copy into the object, waiting for the target
/// first, as one iteration of the C's `while` loop did.
///
/// # Safety
///
/// The object must be live and locked with the paging reference held,
/// `page_list` must be the copy's live cursor, and the page-queues lock
/// must be free.  Returns `true` when the caller must stop its loop.
unsafe fn supply_one_page(
    object: NonNull<VmObject>,
    offset: VmOffset,
    page_list: &mut *mut *mut VmPage,
    result: &mut Result<(), Error>,
    error_offset: &mut VmOffset,
    lock_value: VmProt,
    precious: bool,
) -> bool {
    let data_m = unsafe { **page_list };

    // SAFETY: the entry is a live page of the copy.
    let bad = unsafe {
        data_m.is_null()
            || (*data_m).is_tabled()
            || (*data_m).is_error()
            || (*data_m).is_absent()
            || (*data_m).is_fictitious()
    };
    if bad {
        die("memory_object_data_supply", "Data_supply: bad page");
    }

    // SAFETY: the object is live and locked, and the paging
    // reference is held.
    let target =
        unsafe { supply_target(object, offset, result, error_offset) };

    let was_absent = match target {
        None => {
            if result.is_err() {
                return true;
            }
            false
        }
        Some(was_absent) => was_absent,
    };

    // SAFETY: the entry is a live page of the copy, the object is
    // live and locked, and the queue lock is free.
    unsafe {
        supply_install(
            data_m, object, offset, lock_value, precious, was_absent,
            page_list,
        );
    }
    false
}

/// Wait for or clear the target page at `offset`, as the C's target
/// loop did.
///
/// # Safety
///
/// The object must be live and locked with the paging reference held,
/// and `offset` must be a valid offset in it.
unsafe fn supply_target(
    object: NonNull<VmObject>,
    offset: VmOffset,
    result: &mut Result<(), Error>,
    error_offset: &mut VmOffset,
) -> Option<bool> {
    loop {
        let page = (unsafe { vm_resident::lookup(object, offset) })?;
        let page = page.as_ptr();

        // SAFETY: the target page is live and the object lock is held.
        let absent_busy = unsafe { (*page).is_absent() && (*page).is_busy() };
        if absent_busy {
            // SAFETY: the page is live; `VM_PAGE_FREE` takes the queue
            // lock and keeps the object lock the caller holds.
            unsafe { page_free(page) };
            return Some(true);
        }

        // SAFETY: the page is live and the object lock is held.
        if unsafe { (*page).is_busy() } {
            // SAFETY: the page is live and the object lock is held, as
            // `PAGE_ASSERT_WAIT` requires.
            unsafe {
                (*page).set_wanted(true);
                assert_wait(NonNull::new(page.cast()), 0);
                (*object.as_ptr()).lock.unlock();
                thread_block(None);
                (*object.as_ptr()).lock.lock();
            }
            continue;
        }

        *result = Err(Error::MemoryPresent);
        *error_offset = offset
            // SAFETY: the object is live and locked.
            .wrapping_add(unsafe { (*object.as_ptr()).paging_offset });
        return None;
    }
}

/// Publish one supplied page in the object: clear its state, table it,
/// and advance the page-list cursor.
///
/// # Safety
///
/// The object must be live and locked, with the page-queues lock free;
/// `data_m` must be the live page of the copy, and `page_list` the
/// cursor into its live page list.
unsafe fn supply_install(
    data_m: *mut VmPage,
    object: NonNull<VmObject>,
    offset: VmOffset,
    lock_value: VmProt,
    precious: bool,
    was_absent: bool,
    page_list: &mut *mut *mut VmPage,
) {
    // SAFETY: the entry is a live page of the copy, and the object lock
    // is held.
    unsafe {
        (*data_m).set_busy(false);
        (*data_m).set_dirty(false);
        pmap_clear_modify((*data_m).phys_addr);
        (*data_m).set_page_lock(lock_value);
        (*data_m).set_unlock_request(VmProt::NONE);
        (*data_m).set_precious(precious);

        VM_PAGE_QUEUE_LOCK.lock();
        vm_resident::insert(NonNull::new_unchecked(data_m), object, offset);
        if was_absent {
            vm_page::activate(data_m);
        } else {
            vm_page::deactivate(data_m);
        }
        VM_PAGE_QUEUE_LOCK.unlock();

        **page_list = null_mut();
        *page_list = (*page_list).add(1);
    }
}

/// Hand a finished page-list copy to its continuation, as the C's
/// `memory_object_data_supply()` continuation block did.
///
/// # Safety
///
/// The object must be live and locked with the paging reference held,
/// and `copy` the live page-list copy the call owns; `page_list` must
/// be its cursor.  Returns `true` when the caller must stop its loop.
unsafe fn supply_continuation(
    copy: &mut NonNull<VmMapCopy>,
    orig_copy: NonNull<VmMapCopy>,
    page_list: &mut *mut *mut VmPage,
    object: NonNull<VmObject>,
    offset: VmOffset,
    result: &mut Result<(), Error>,
    error_offset: &mut VmOffset,
) -> bool {
    // SAFETY: the object lock is held, and the continuation runs
    // with it released, as the C did.
    unsafe { (*object.as_ptr()).lock.unlock() };

    // SAFETY: the copy is live and owned by this call.
    let (code, new_copy) = unsafe { VmMapCopy::invoke_cont(*copy) };

    match error_from_kern_return(code) {
        Ok(()) => {
            if *copy != orig_copy {
                // SAFETY: the copy is live and was replaced.
                unsafe { VmMapCopy::discard(*copy) };
            }

            let Some(new_copy) = NonNull::new(new_copy) else {
                // The C's continuation never returns a null copy
                // together with success; stop rather than follow a
                // freed list.
                *error_offset = offset.wrapping_add(PAGE_SIZE).wrapping_add(
                    // SAFETY: the object is live and held by the
                    // paging reference.
                    unsafe { (*object.as_ptr()).paging_offset },
                );
                *result = Err(Error::Failure);
                return true;
            };
            *copy = new_copy;
            // SAFETY: the new copy is a live page-list copy.
            *page_list = unsafe {
                addr_of_mut!((*VmMapCopy::page_list(*copy)).page_list)
            }
            .cast::<*mut VmPage>();

            // SAFETY: the object is live and held by the paging
            // reference.
            unsafe { (*object.as_ptr()).lock.lock() };
        }
        Err(error) => {
            // SAFETY: the object is live and held by the paging
            // reference.
            unsafe { (*object.as_ptr()).lock.lock() };
            *error_offset =
                        // SAFETY: the object is live and held by the
                        // paging reference.
                        offset.wrapping_add(PAGE_SIZE).wrapping_add(unsafe {
                            (*object.as_ptr()).paging_offset
                        });
            *result = Err(error);
            return true;
        }
    }
    false
}

/// `memory_object_data_supply()` in C: take the pages of a page-list copy
/// into the object.
///
/// # Safety
///
/// A non-null `object` must be a live object the call may deallocate;
/// `vm_data_copy` must name a live page-list copy of `data_cnt` bytes;
/// `reply_to` must be `IP_NULL` or a live port.
pub(crate) unsafe fn data_supply(
    object: *mut VmObject,
    request: &SupplyRequest,
) -> Result<(), Error> {
    let SupplyRequest {
        offset,
        data,
        data_cnt,
        lock_value,
        precious,
        ..
    } = *request;

    let Some(object) = NonNull::new(object) else {
        return Err(Error::InvalidArgument);
    };
    if (lock_value.bits() & !VmProt::ALL.bits()) != 0 {
        unsafe { vm_object::deallocate(object.as_ptr()) };
        return Err(Error::InvalidArgument);
    }
    if !data_cnt.is_multiple_of(PAGE_SIZE as c_uint) {
        unsafe { vm_object::deallocate(object.as_ptr()) };
        return Err(Error::InvalidArgument);
    }

    // `vm_offset_t` and a pointer are the same width on both targets.
    let mut copy = unsafe { NonNull::new_unchecked(data as *mut VmMapCopy) };
    let orig_copy = copy;
    let mut page_list =
        unsafe { addr_of_mut!((*VmMapCopy::page_list(copy)).page_list) }
            .cast::<*mut VmPage>();

    unsafe {
        (*object.as_ptr()).lock.lock();
        vm_object::paging_begin(object.as_ptr());
    }
    // SAFETY: the object is live and locked.
    let mut offset =
        offset.wrapping_sub(unsafe { (*object.as_ptr()).paging_offset });
    let mut data_cnt = data_cnt;
    let mut result: Result<(), Error> = Ok(());
    let mut error_offset: VmOffset = 0;

    while data_cnt != 0 {
        // SAFETY: the copy's page list holds this entry, the object is
        // live and locked, and the queue lock is free.
        if unsafe {
            supply_one_page(
                object,
                offset,
                &mut page_list,
                &mut result,
                &mut error_offset,
                lock_value,
                precious,
            )
        } {
            break;
        }

        // SAFETY: the copy is live and holds the page list.
        let pages = unsafe { VmMapCopy::page_list(copy) };
        // SAFETY: `pages` names the live page-list variant.
        unsafe { (*pages).npages -= 1 };
        let exhausted = unsafe { (*pages).npages == 0 };
        // SAFETY: the copy may hold a continuation.
        let has_cont = unsafe { VmMapCopy::has_cont(copy) };

        if exhausted && has_cont {
            // SAFETY: the copy is live and owned by this call, the
            // object is live and locked, and the continuation runs
            // with its lock released.
            unsafe {
                if supply_continuation(
                    &mut copy,
                    orig_copy,
                    &mut page_list,
                    object,
                    offset,
                    &mut result,
                    &mut error_offset,
                ) {
                    break;
                }
            }
        }

        data_cnt -= PAGE_SIZE as c_uint;
        offset = offset.wrapping_add(PAGE_SIZE);
    }

    // SAFETY: the object is live and locked; the paging reference is the
    // caller's.
    unsafe {
        supply_finish(object, request, copy, orig_copy, result, error_offset)
    }
}

/// End a `data_supply()` call: drop the paging reference, abort a left-over
/// continuation, send the completion, and release the copies.
///
/// # Safety
///
/// The object must be live and locked by the caller's reference, `copy` and
/// `orig_copy` must be the call's live copies, and `request` the request the
/// call was entered with.
unsafe fn supply_finish(
    object: NonNull<VmObject>,
    request: &SupplyRequest,
    copy: NonNull<VmMapCopy>,
    orig_copy: NonNull<VmMapCopy>,
    result: Result<(), Error>,
    error_offset: VmOffset,
) -> Result<(), Error> {
    // SAFETY: the object is live and locked; the paging reference is the
    // caller's.
    unsafe {
        vm_object::paging_end(object.as_ptr());
        (*object.as_ptr()).lock.unlock();
    }

    // SAFETY: a page-list copy may hold a continuation.
    if unsafe { VmMapCopy::has_cont(copy) } {
        // SAFETY: the copy is live and owned by this call.
        unsafe { VmMapCopy::abort_cont(copy) };
    }

    if IpcPort::valid(request.reply_to).is_some() {
        // SAFETY: the object is live under the caller's reference, and the
        // C sends the reply before releasing it.
        unsafe {
            memory_object_supply_completed(
                request.reply_to,
                request.reply_to_type,
                (*object.as_ptr()).pager_request,
                request.offset,
                // `data_cnt` is a `mach_msg_type_number_t` byte count;
                // `vm_size_t` holds every value it can name.
                request.data_cnt as VmSize,
                match result {
                    Ok(()) => 0,
                    Err(error) => error.as_kern_return(),
                },
                error_offset,
            );
        }
    }

    // SAFETY: the call consumes the caller's reference.
    unsafe { vm_object::deallocate(object.as_ptr()) };

    if copy != orig_copy {
        // SAFETY: the copy is live and was replaced.
        unsafe { VmMapCopy::discard(copy) };
    }
    if result.is_ok() {
        // SAFETY: the original copy is live and owned by this call.
        unsafe { VmMapCopy::discard(orig_copy) };
    }

    result
}

/// `memory_object_data_error()` in C: mark the waiting absent pages of a
/// range as failed.
///
/// # Safety
///
/// A non-null `object` must be a live object the call may deallocate.
pub(crate) unsafe fn data_error(
    object: *mut VmObject,
    offset: VmOffset,
    size: VmSize,
) -> Result<(), Error> {
    let Some(object) = NonNull::new(object) else {
        return Err(Error::InvalidArgument);
    };
    if size != round_page(size) {
        return Err(Error::InvalidArgument);
    }

    unsafe { (*object.as_ptr()).lock.lock() };
    // SAFETY: the object is live and locked.
    let mut offset =
        offset.wrapping_sub(unsafe { (*object.as_ptr()).paging_offset });
    let mut size = size;

    while size != 0 {
        // SAFETY: the object is live and locked.
        if let Some(page) = unsafe { vm_resident::lookup(object, offset) } {
            let page = page.as_ptr();
            // SAFETY: the page is live and the object lock is held.
            let waiting = unsafe { (*page).is_busy() && (*page).is_absent() };
            if waiting {
                // SAFETY: the page is live and the object lock is held.
                unsafe {
                    (*page).set_error(true);
                    (*page).set_absent(false);
                    vm_object::absent_release(object.as_ptr());
                    vm_object::page_wakeup_done(page);

                    VM_PAGE_QUEUE_LOCK.lock();
                    vm_page::activate(page);
                    VM_PAGE_QUEUE_LOCK.unlock();
                }
            }
        }

        size -= PAGE_SIZE;
        offset = offset.wrapping_add(PAGE_SIZE);
    }

    // SAFETY: the object is live and locked; the call consumes the caller's
    // reference.
    unsafe {
        (*object.as_ptr()).lock.unlock();
        vm_object::deallocate(object.as_ptr());
    }

    Ok(())
}

/// `memory_object_data_unavailable()` in C: clear the waiting absent pages of
/// a range without providing data.
///
/// # Safety
///
/// A non-null `object` must be a live object the call may deallocate.
pub(crate) unsafe fn data_unavailable(
    object: *mut VmObject,
    offset: VmOffset,
    size: VmSize,
) -> Result<(), Error> {
    let Some(object) = NonNull::new(object) else {
        return Err(Error::InvalidArgument);
    };
    if size != round_page(size) {
        return Err(Error::InvalidArgument);
    }

    let mut existence_info: *mut c_void = null_mut();
    // SAFETY: the object is live under the caller's reference.
    let needs_map = offset == 0
        && size > VM_EXTERNAL_LARGE_SIZE
        && unsafe { (*object.as_ptr()).existence_info }.is_null();
    if needs_map {
        // SAFETY: the external module's caches are initialized before any
        // object exists.
        existence_info =
            unsafe { vm_external::vm_external_create(VM_EXTERNAL_SMALL_SIZE) }
                .cast::<c_void>();
    }

    unsafe { (*object.as_ptr()).lock.lock() };
    if !existence_info.is_null() {
        // SAFETY: the object is live and locked.
        unsafe { (*object.as_ptr()).existence_info = existence_info };
    }
    if offset == 0 && size > VM_EXTERNAL_LARGE_SIZE {
        // SAFETY: the object is live and locked; the call consumes the
        // caller's reference.
        unsafe {
            (*object.as_ptr()).lock.unlock();
            vm_object::deallocate(object.as_ptr());
        }
        return Ok(());
    }
    // SAFETY: the object is live and locked.
    let mut offset =
        offset.wrapping_sub(unsafe { (*object.as_ptr()).paging_offset });
    let mut size = size;

    while size != 0 {
        // SAFETY: the object is live and locked.
        if let Some(page) = unsafe { vm_resident::lookup(object, offset) } {
            let page = page.as_ptr();
            // SAFETY: the page is live and the object lock is held.
            let waiting = unsafe { (*page).is_busy() && (*page).is_absent() };
            if waiting {
                // SAFETY: the page is live and the object lock is held.
                unsafe {
                    vm_object::page_wakeup_done(page);

                    VM_PAGE_QUEUE_LOCK.lock();
                    vm_page::activate(page);
                    VM_PAGE_QUEUE_LOCK.unlock();
                }
            }
        }

        size -= PAGE_SIZE;
        offset = offset.wrapping_add(PAGE_SIZE);
    }

    // SAFETY: the object is live and locked; the call consumes the caller's
    // reference.
    unsafe {
        (*object.as_ptr()).lock.unlock();
        vm_object::deallocate(object.as_ptr());
    }

    Ok(())
}

/// Types and functions for the default memory manager.
///
/// `memory_manager_default` of `vm/memory_object.h` lives in an [`Rcu`]:
/// the pageout path reads it for every page it considers, and only the
/// default pager's `vm_set_default_memory_manager()` changes it, about once
/// per boot. Readers take no lock; the C's `memory_manager_default_lock`
/// is gone.
///
/// # Safety
///
/// See each function.
pub(crate) mod default_manager {
    use super::{Error, Host, IpcPort, c_void, ipc_port, null_mut};
    use crate::arch::x86_64::per_cpu;
    use crate::kern::debug::kpanic;
    use crate::kern::kheap::Kalloc;
    use crate::kern::rcu::Rcu;
    use crate::kern::sched_prim::{
        THREAD_AWAKENED, assert_wait, clear_wait, thread_block,
        thread_wakeup_prim,
    };
    use core::ptr::{self, NonNull};
    use core::sync::atomic::{AtomicPtr, Ordering};
    use kmem::KBox;

    /// A published default-manager port, `IP_NULL` before the default
    /// pager registers.
    ///
    /// Beyond the send right the kernel keeps for the manager, each value
    /// holds an object reference of its own, dropped with the value. So a
    /// port stays live for readers that saw it until a grace period after
    /// it is replaced, even when the send right handed back to
    /// `vm_set_default_memory_manager()`'s caller goes at once.
    struct ManagerPort(*mut c_void);

    // SAFETY: the value is a port pointer plus a reference; ports are
    // shared between CPUs, and the reference may be dropped on any thread.
    unsafe impl Send for ManagerPort {}
    // SAFETY: the value is a port pointer plus a reference; ports are shared
    // between CPUs, and the reference may be dropped on any thread;
    // readers only read the pointer.
    unsafe impl Sync for ManagerPort {}

    impl ManagerPort {
        /// Publishable `port`, taking the value's reference on it.
        ///
        /// # Safety
        ///
        /// `port` must be `IP_NULL`, `IP_DEAD`, or a live port.
        unsafe fn new(port: *mut c_void) -> Self {
            if let Some(live) = IpcPort::valid(port) {
                unsafe { live.reference() };
            }
            Self(port)
        }

        /// Whether the port is neither `IP_NULL` nor `IP_DEAD`.
        fn is_valid(&self) -> bool {
            IpcPort::valid(self.0).is_some()
        }
    }

    impl Drop for ManagerPort {
        fn drop(&mut self) {
            if let Some(live) = IpcPort::valid(self.0) {
                // SAFETY: `new()` took this reference.
                unsafe { live.release() };
            }
        }
    }

    /// The published default-manager port: null until `init()` stores a
    /// leaked box, which is never freed.
    static DEFAULT_MANAGER: AtomicPtr<Rcu<ManagerPort>> =
        AtomicPtr::new(null_mut());

    /// The `Rcu`, or `None` before `init()`.
    fn manager() -> Option<&'static Rcu<ManagerPort>> {
        let manager = DEFAULT_MANAGER.load(Ordering::Acquire);
        // SAFETY: a non-null pointer is the leaked box `init()` stored with
        // release, never freed.
        unsafe { manager.as_ref() }
    }

    /// The event `reference()` sleeps on until a manager registers.
    fn registered_event() -> *mut c_void {
        ptr::from_ref(&DEFAULT_MANAGER).cast_mut().cast()
    }

    /// `vm_set_default_memory_manager()` in C: replace or fetch the default
    /// memory manager's port.
    ///
    /// # Safety
    ///
    /// A non-null `host` must be a live host, and `default_manager` must be
    /// writable for one port.
    pub unsafe fn set(
        host: *mut Host,
        default_manager: *mut *mut c_void,
    ) -> Result<(), Error> {
        if host.is_null() {
            return Err(Error::InvalidHost);
        }
        let Some(manager) = manager() else {
            return Err(Error::ResourceShortage);
        };

        let new_manager = unsafe { *default_manager };

        let returned = if new_manager.is_null() {
            let current = manager.read();
            // SAFETY: the value's reference keeps the port live while the
            // read section is open, and `copy_send()` does not block.
            unsafe { ipc_port::copy_send(current.0) }
        } else {
            // The kernel takes over the caller's send right for the new
            // manager and hands back its right for the old one, as the C
            // did; the old value keeps the port live for readers.
            let mut old = null_mut();
            let new = unsafe { ManagerPort::new(new_manager) };
            let result = manager.try_update(|current| {
                old = current.0;
                new
            });
            if result.is_err() {
                return Err(Error::ResourceShortage);
            }

            // SAFETY: the event is a static's address, used only as a key.
            unsafe {
                thread_wakeup_prim(registered_event(), 0, THREAD_AWAKENED);
            }
            old
        };

        unsafe { *default_manager = returned };
        Ok(())
    }

    /// `memory_manager_default_reference()` in C: a naked send right for the
    /// default memory manager, waiting until one exists.
    ///
    /// # Safety
    ///
    /// Thread context with no lock held: the routine may block.
    pub unsafe fn reference() -> IpcPort {
        let event = NonNull::new(registered_event());
        loop {
            // Asserted before the check, so a registration between the
            // check and the block still wakes this thread.
            // SAFETY: thread context; the wait is cleared or blocked on.
            unsafe { assert_wait(event, 0) };

            let right = manager().map_or(null_mut(), |manager| {
                let current = manager.read();
                unsafe { ipc_port::copy_send(current.0) }
            });
            if let Some(port) = IpcPort::valid(right) {
                // SAFETY: the current thread is live.
                unsafe { clear_wait(per_cpu::thread(), THREAD_AWAKENED, 0) };
                return port;
            }

            unsafe { thread_block(None) };
        }
    }

    /// `memory_manager_default_port()` in C: whether `port` receives for the
    /// default memory manager.
    ///
    /// # Safety
    ///
    /// `port` must be `IP_NULL` or a live port.
    pub unsafe fn port(port: *mut c_void) -> bool {
        let Some(manager) = manager() else {
            return false;
        };
        let current = manager.read();
        match (IpcPort::valid(port), IpcPort::valid(current.0)) {
            (Some(port), Some(current)) => unsafe {
                port.receiver() == current.receiver()
            },
            _ => false,
        }
    }

    /// `IP_VALID(memory_manager_default)`: whether a default memory manager
    /// has registered.
    pub fn is_set() -> bool {
        manager().is_some_and(|manager| manager.read().is_valid())
    }

    /// `memory_manager_default_init()` in C.  Runs once, during boot.
    ///
    /// # Panics
    ///
    /// If the kernel heap cannot hold the published port.
    pub fn init() {
        // SAFETY: `IP_NULL` is a valid argument.
        let null = unsafe { ManagerPort::new(null_mut()) };
        let Some(manager) = Rcu::try_new(null)
            .ok()
            .and_then(|manager| KBox::try_new(manager, Kalloc).ok())
        else {
            kpanic!("default_manager::init", "out of memory\n")
        };
        DEFAULT_MANAGER
            .store(ptr::from_mut(KBox::leak(manager)), Ordering::Release);
    }
}

/// `memory_object_set_attributes_common()` in C: apply a manager's attribute
/// change.
///
/// # Safety
///
/// A non-null `object` must be a live object; the call consumes the caller's
/// reference.
pub(crate) unsafe fn set_attributes(
    object: *mut VmObject,
    may_cache: bool,
    copy_strategy: CopyStrategy,
) -> Result<(), Error> {
    let Some(object) = NonNull::new(object) else {
        return Err(Error::InvalidArgument);
    };

    unsafe { (*object.as_ptr()).lock.lock() };

    // SAFETY: the object is live and locked.
    unsafe {
        if !(*object.as_ptr()).is_pager_ready() {
            vm_object::wakeup_pager_ready(object.as_ptr());
        }

        (*object.as_ptr()).set_can_persist(may_cache);
        (*object.as_ptr()).set_pager_ready(true);
        if copy_strategy == CopyStrategy::Temporary {
            (*object.as_ptr()).set_temporary(true);
        } else {
            (*object.as_ptr()).copy_strategy = copy_strategy.as_c();
        }

        (*object.as_ptr()).lock.unlock();
        vm_object::deallocate(object.as_ptr());
    }

    Ok(())
}

/// `memory_object_change_attributes()` in C: apply the change and acknowledge
/// it.
///
/// # Safety
///
/// A non-null `object` must be a live object the call may deallocate;
/// `reply_to` must be `IP_NULL` or a live port.
pub(crate) unsafe fn change_attributes(
    object: *mut VmObject,
    may_cache: bool,
    copy_strategy: c_int,
    reply_to: *mut c_void,
    reply_to_type: c_uint,
) -> Result<(), Error> {
    let result =
        match (NonNull::new(object), CopyStrategy::from_c(copy_strategy)) {
            (None, _) => Err(Error::InvalidArgument),
            (Some(object), Some(strategy)) => unsafe {
                set_attributes(object.as_ptr(), may_cache, strategy)
            },
            (Some(object), None) => {
                // SAFETY: the C's invalid-strategy path released the reference.
                unsafe { vm_object::deallocate(object.as_ptr()) };
                Err(Error::InvalidArgument)
            }
        };

    if IpcPort::valid(reply_to).is_some() {
        // SAFETY: `reply_to` is a live port and the C sends the raw request
        // values back.
        unsafe {
            memory_object_change_completed(
                reply_to,
                reply_to_type,
                c_int::from(may_cache),
                copy_strategy,
            );
        }
    }

    result
}

/// `memory_object_ready()` in C: apply the manager's ready attributes.
///
/// # Safety
///
/// A non-null `object` must be a live object the call may deallocate.
pub(crate) unsafe fn ready(
    object: *mut VmObject,
    may_cache: bool,
    copy_strategy: c_int,
) -> Result<(), Error> {
    match (NonNull::new(object), CopyStrategy::from_c(copy_strategy)) {
        (None, _) => Err(Error::InvalidArgument),
        (Some(object), Some(strategy)) => unsafe {
            set_attributes(object.as_ptr(), may_cache, strategy)
        },
        (Some(object), None) => {
            // SAFETY: the C's invalid-strategy path released the reference.
            unsafe { vm_object::deallocate(object.as_ptr()) };
            Err(Error::InvalidArgument)
        }
    }
}

/// `memory_object_get_attributes()` in C: read the object's pager state.
pub(crate) struct Attributes {
    /// `object_ready`: whether the manager has set the attributes.
    pub ready: bool,
    /// `may_cache`: whether the object may be cached.
    pub may_cache: bool,
    /// `copy_strategy`: the raw `memory_object_copy_strategy_t`.
    pub copy_strategy: c_int,
}

/// `memory_object_get_attributes()` in C: read the object's pager state.
///
/// # Safety
///
/// A non-null `object` must be a live object; the call consumes the caller's
/// reference.
pub(crate) unsafe fn get_attributes(
    object: *mut VmObject,
) -> Result<Attributes, Error> {
    let Some(object) = NonNull::new(object) else {
        return Err(Error::InvalidArgument);
    };

    unsafe { (*object.as_ptr()).lock.lock() };
    // SAFETY: the object is live and locked.
    let attributes = unsafe {
        Attributes {
            ready: (*object.as_ptr()).is_pager_ready(),
            may_cache: (*object.as_ptr()).can_persist(),
            copy_strategy: (*object.as_ptr()).copy_strategy,
        }
    };
    // SAFETY: the object is live and locked; the call consumes the caller's
    // reference.
    unsafe {
        (*object.as_ptr()).lock.unlock();
        vm_object::deallocate(object.as_ptr());
    }

    Ok(attributes)
}
