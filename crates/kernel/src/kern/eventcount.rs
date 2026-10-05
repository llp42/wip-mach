// SPDX-License-Identifier: CMU-Mach
// Derived from kern/eventcount.c and kern/eventcount.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Eventcounters.

use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::spl;
use crate::kern::error::Error;
use crate::kern::lock::SimpleLock;
use crate::kern::sched_prim::{assert_wait, thread_block};
use crate::kern::thread::Thread;
use crate::mig::code::{KERN_SUCCESS, kern_return};
use crate::utils::cell::SyncCell;
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_uint};
use core::mem::offset_of;
use core::ptr::{self, NonNull};

/// The eventcounter table's length.
const MAX_EVCS: usize = 10;

/// One eventcounter.
#[repr(C)]
#[allow(missing_docs)]
pub struct EventCounter {
    /// `count`: pending events, or `-1` while a waiter blocks.
    pub count: c_int,
    pub waiting_thread: *mut Thread,
    /// `ev_id`: the table index.
    pub ev_id: c_uint,
    /// `sanity`: the counter's own address, or null once destroyed.
    pub sanity: *mut Self,
    pub lock: SimpleLock,
}

const _: () = {
    assert!(size_of::<EventCounter>() == 40);
    assert!(align_of::<EventCounter>() == align_of::<*mut EventCounter>());
    assert!(offset_of!(EventCounter, count) == 0);
    assert!(offset_of!(EventCounter, waiting_thread) == 8);
    assert!(offset_of!(EventCounter, ev_id) == 16);
    assert!(offset_of!(EventCounter, sanity) == 24);
    assert!(offset_of!(EventCounter, lock) == 32);
};

/// The registered eventcounters, by id.
static ALL_EVENTCOUNTERS: SyncCell<[*mut EventCounter; MAX_EVCS]> =
    SyncCell(UnsafeCell::new([ptr::null_mut(); MAX_EVCS]));

/// The table index `id` names, or `None` when it is out of range.
fn slot_of(id: c_uint) -> Option<usize> {
    usize::try_from(id).ok().filter(|index| *index < MAX_EVCS)
}

/// The live counter `ev_id` names, or `None` when it is not registered.
fn counter(ev_id: c_uint) -> Option<NonNull<EventCounter>> {
    let index = slot_of(ev_id)?;
    // SAFETY: the table is written by the boot's single-threaded init path
    // and by `destroy()`, which clears the slot before the counter goes away.
    let ev = unsafe { (*ALL_EVENTCOUNTERS.0.get())[index] };
    let ev = NonNull::new(ev)?;
    // SAFETY: the slot is non-null, and `init()` stored both words before the
    // counter became reachable.
    if unsafe { (*ev.as_ptr()).ev_id } != ev_id
        // SAFETY: the slot is non-null, and `init()` stored both words before
        // the counter became reachable; the same live counter supplies
        // the field.
        || unsafe { (*ev.as_ptr()).sanity } != ev.as_ptr()
    {
        return None;
    }
    Some(ev)
}

/// Gives the blocked waiter the stack back with success as the syscall answer.
unsafe extern "C" fn evc_continue() {
    // SAFETY: `thread_syscall_return()` never returns.
    unsafe {
        crate::arch::x86_64::locore::thread_syscall_return(KERN_SUCCESS);
    }
}

/// Lets go of a dying waiter.
///
/// # Safety
///
/// `thread` must be the live thread the C thread-termination path is about to
/// take off the wait queues.
pub(crate) unsafe fn notify_abort(thread: *mut Thread) {
    unsafe {
        let s = spl::splsched();
        let table = ALL_EVENTCOUNTERS.0.get();

        for i in 0..MAX_EVCS {
            let ev = (*table)[i];
            if ev.is_null() {
                continue;
            }

            (*ev).lock.lock();
            if (*ev).waiting_thread == thread {
                (*ev).waiting_thread = ptr::null_mut();
                // Removing a waiting thread has to bump the count by one.
                (*ev).count = (*ev).count.wrapping_add(1);
            }
            (*ev).lock.unlock();
        }

        spl::splx(s);
    }
}

/// Waits for the eventcounter `ev_id` to count, consuming one count.
pub(crate) fn wait(ev_id: c_uint) -> Result<(), Error> {
    let Some(ev) = counter(ev_id) else {
        return Err(Error::InvalidArgument);
    };

    // SAFETY: `counter()` returned a registered counter; the C took the
    // counter lock at splsched.
    unsafe {
        let s = spl::splsched();
        (*ev.as_ptr()).lock.lock();

        if (*ev.as_ptr()).count > 0 {
            (*ev.as_ptr()).count = (*ev.as_ptr()).count.wrapping_sub(1);
            (*ev.as_ptr()).lock.unlock();
            spl::splx(s);
            return Ok(());
        }

        if (*ev.as_ptr()).waiting_thread.is_null() {
            (*ev.as_ptr()).count = (*ev.as_ptr()).count.wrapping_sub(1);
            (*ev.as_ptr()).waiting_thread = per_cpu::thread();
            assert_wait(None, 1);
            (*ev.as_ptr()).lock.unlock();
            thread_block(Some(evc_continue));
            return Ok(());
        }

        (*ev.as_ptr()).lock.unlock();
        spl::splx(s);
        Err(Error::NoSpace)
    }
}

/// Clears the count before blocking.
pub(crate) fn wait_clear(ev_id: c_uint) -> Result<(), Error> {
    let Some(ev) = counter(ev_id) else {
        return Err(Error::InvalidArgument);
    };

    // SAFETY: `counter()` returned a registered counter; the C took the
    // counter lock at splsched.
    unsafe {
        let s = spl::splsched();
        (*ev.as_ptr()).lock.lock();

        if (*ev.as_ptr()).waiting_thread.is_null() {
            (*ev.as_ptr()).count = -1;
            (*ev.as_ptr()).waiting_thread = per_cpu::thread();
            assert_wait(None, 1);
            (*ev.as_ptr()).lock.unlock();
            thread_block(Some(evc_continue));
            return Ok(());
        }

        (*ev.as_ptr()).lock.unlock();
        spl::splx(s);
        Err(Error::NoSpace)
    }
}

/// The `evc_wait` trap entry.
///
/// # Safety
///
/// The caller is the system-call entry, which passes the id in the trap's
/// first argument slot.
pub(crate) unsafe extern "C" fn evc_wait(ev_id: c_uint) -> c_int {
    kern_return(wait(ev_id))
}

/// The `evc_wait_clear` trap entry.
///
/// # Safety
///
/// The caller is the system-call entry, which passes the id in the trap's
/// first argument slot.
pub(crate) unsafe extern "C" fn evc_wait_clear(ev_id: c_uint) -> c_int {
    kern_return(wait_clear(ev_id))
}
