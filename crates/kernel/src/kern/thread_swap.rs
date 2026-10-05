// SPDX-License-Identifier: CMU-Mach
// Derived from kern/thread_swap.c:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The thread swapper.

use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::spl;
use crate::kern::debug::kpanic;
use crate::kern::lock::SimpleLock;
use crate::kern::sched_prim::{
    THREAD_AWAKENED, assert_wait, thread_block, thread_continue,
    thread_setrun, thread_wakeup_prim,
};
use crate::kern::thread::{
    TH_RUN, TH_SW_COMING_IN, TH_SWAP_STATE, TH_SWAPPED, Thread, ThreadQueue,
};
use crate::utils::cell::SyncCell;
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};
use core::pin::Pin;
use core::ptr::{self, NonNull};

/// Guards `SWAPIN_QUEUE`.
static SWAPPER_LOCK: SimpleLock = SimpleLock::new();

/// The threads waiting for a stack, and the event the swapin thread sleeps on.
static SWAPIN_QUEUE: SyncCell<ThreadQueue> =
    SyncCell(UnsafeCell::new(ThreadQueue::new()));

/// The live swapin queue head.
///
/// # Safety
///
/// The caller must hold `SWAPPER_LOCK` for as long as it uses the queue.
unsafe fn swapin_queue() -> Pin<&'static mut ThreadQueue> {
    // SAFETY: the static never moves, and the lock the caller holds keeps
    // anything else from reaching the queue.
    unsafe { Pin::new_unchecked(&mut *SWAPIN_QUEUE.0.get()) }
}

/// The swapin queue's address, which doubles as the wakeup event.
fn swapin_event() -> *mut c_void {
    SWAPIN_QUEUE.0.get().cast()
}

/// Initializes the swapper lock and queue.
///
/// # Safety
///
/// Must be called once during boot, before any thread is queued for swapin;
/// `setup_main()` is the only caller.
pub(crate) unsafe fn swapper_init() {
    SWAPPER_LOCK.init();
}

/// Queues `thread`, which lost its stack, for the swapin thread.
///
/// # Safety
///
/// `thread` must be a live thread whose lock the caller holds, at splsched, as
/// the scheduler's swap path is.
pub(crate) unsafe fn thread_swapin(thread: *mut Thread) {
    let state = unsafe { (*thread).state() };
    match state & TH_SWAP_STATE {
        TH_SWAPPED => {
            unsafe {
                (*thread)
                    .set_state((state & !TH_SWAP_STATE) | TH_SW_COMING_IN);
            }
            // SAFETY: the swapper lock serializes the queue, and the thread's
            // `links` field is free while the thread is swapped out.
            unsafe {
                SWAPPER_LOCK.lock();
                swapin_queue().push_back_ptr(NonNull::new_unchecked(thread));
                SWAPPER_LOCK.unlock();
            }
            // SAFETY: the event is the queue head's fixed address, the key the
            // swapin thread registers with `assert_wait()`.
            unsafe {
                thread_wakeup_prim(swapin_event(), 0, THREAD_AWAKENED);
            }
        }
        TH_SW_COMING_IN => (),
        _ => kpanic!("thread_swapin", "thread_swapin"),
    }
}

/// Gives the thread a stack and makes it runnable again.
///
/// # Safety
///
/// `thread` must be a live thread with `TH_SWAP_STATE` set that no lock
/// protects, because the stack allocation can block; the caller must hold no
/// spin lock.
pub(crate) unsafe fn doswapin(thread: *mut Thread) {
    unsafe { (*thread).stack_alloc(Some(thread_continue)) };

    // SAFETY: `thread` is live and not locked; the spl level and the thread
    // lock guard the state and the run queue, in the C order.
    unsafe {
        let s = spl::splsched();
        (*thread).lock.lock();
        (*thread).set_state((*thread).state() & !TH_SWAP_STATE);
        if (*thread).state() & TH_RUN != 0 {
            thread_setrun(thread, c_int::from(true));
        }
        (*thread).lock.unlock();
        spl::splx(s);
    }
}

/// The swapin thread's loop: gives each queued thread a stack.
///
/// # Safety
///
/// Runs as the swapin kernel thread.
unsafe fn swapin_thread_continue() -> ! {
    loop {
        // SAFETY: the continuation runs in thread context; the swapper lock
        // and the spl level guard the queue, and `doswapin()` blocks only with
        // both released.
        unsafe {
            let mut s = spl::splsched();
            SWAPPER_LOCK.lock();

            while let Some(elt) =
                swapin_queue().cursor_front_mut().remove_current()
            {
                SWAPPER_LOCK.unlock();
                spl::splx(s);

                // SAFETY: `links` is the first field of `struct thread`, so a
                // popped link is its thread; every entry on this queue was
                // pushed that way.
                let thread = ptr::from_mut(elt);
                doswapin(thread);

                s = spl::splsched();
                SWAPPER_LOCK.lock();
            }

            // SAFETY: the event is the queue head's fixed address, and the
            // lock is released before blocking, as in C.
            assert_wait(NonNull::new(swapin_event()), 0);
            SWAPPER_LOCK.unlock();
            spl::splx(s);
            thread_block(Some(swapin_thread_continuation));
        }
    }
}

/// The `void (*)(void)` continuation `thread_block()` resumes.
///
/// # Safety
///
/// Runs as the swapin kernel thread's continuation after a block; it never
/// returns.
unsafe extern "C" fn swapin_thread_continuation() {
    // SAFETY: the swapin thread's own loop, which never returns.
    unsafe { swapin_thread_continue() }
}

/// Becomes the swapin thread.
///
/// # Safety
///
/// Started by `kernel_thread()` as the "swapin" thread; it reserves its stack
/// and never returns.
pub(crate) unsafe fn swapin_thread() -> ! {
    // SAFETY: the kernel thread starts here with `per_cpu::thread()` pointing
    // at itself, and `stack_privilege()` reserves the stack it already runs
    // on.
    unsafe {
        let thread = per_cpu::thread();
        (*thread).vm_privilege = 1;
        (*thread).stack_privilege();
        swapin_thread_continue()
    }
}
