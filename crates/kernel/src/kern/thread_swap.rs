// SPDX-License-Identifier: CMU-Mach
// Derived from kern/thread_swap.c:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The thread swapper.

use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::spl;
use crate::kern::debug::kpanic;
use crate::kern::sched_prim::{
    THREAD_AWAKENED, assert_wait, thread_block, thread_continue,
    thread_setrun, thread_wakeup_prim,
};
use crate::kern::thread::{
    TH_RUN, TH_SW_COMING_IN, TH_SWAP_STATE, TH_SWAPPED, Thread, ThreadQueue,
};
use core::ffi::{c_int, c_void};
use core::pin::Pin;
use core::ptr::{self, NonNull};
use lock::IrqSpinLock;

/// The threads waiting for a stack.
struct SwapinQueue(ThreadQueue);

// SAFETY: the queue links thread records, which every CPU shares.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "the linked threads are shared between CPUs, which their type \
              does not say"
)]
unsafe impl Send for SwapinQueue {}

impl SwapinQueue {
    /// The queue, pinned.
    const fn pinned(&mut self) -> Pin<&mut ThreadQueue> {
        // SAFETY: the one `SwapinQueue` is in `SWAPIN_QUEUE`, a static, which
        // never moves.
        unsafe { Pin::new_unchecked(&mut self.0) }
    }
}

/// The threads waiting for a stack, and the event the swapin thread sleeps
/// on.  Under an irq spin lock, since the scheduler queues threads at
/// splsched.
static SWAPIN_QUEUE: IrqSpinLock<SwapinQueue, MachPlatform> =
    IrqSpinLock::new(SwapinQueue(ThreadQueue::new()));

/// The swapin queue's address, which doubles as the wakeup event.
fn swapin_event() -> *mut c_void {
    ptr::from_ref(&SWAPIN_QUEUE).cast_mut().cast()
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
            // SAFETY: the thread's `links` field is free while the thread is
            // swapped out.
            unsafe {
                SWAPIN_QUEUE
                    .lock()
                    .pinned()
                    .push_back_ptr(NonNull::new_unchecked(thread));
            }
            // SAFETY: the event is the queue's fixed address, the key the
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
        let mut queue = SWAPIN_QUEUE.lock();
        while let Some(thread) =
            queue.pinned().cursor_front_mut().remove_current()
        {
            let thread = ptr::from_mut(thread);
            // SAFETY: every thread on the queue is a live, swapped-out
            // thread that no lock protects, and the queue's lock is
            // released for the stack allocation, which can block.
            queue.unlocked(|| unsafe { doswapin(thread) });
        }

        // SAFETY: the wait is asserted before the queue's lock is released,
        // so a thread queued after the check still wakes this one, and the
        // block holds no lock.
        unsafe {
            assert_wait(NonNull::new(swapin_event()), 0);
            drop(queue);
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
