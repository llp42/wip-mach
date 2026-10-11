// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The thread swapper.

use crate::platform::Platform;
use crate::sched_prim::{
    THREAD_AWAKENED, assert_wait, thread_block, thread_continue,
    thread_setrun, thread_wakeup_prim,
};
use crate::thread::{Thread, ThreadQueue};
use crate::types::ThreadState;
use core::ffi::{c_int, c_void};
use core::pin::Pin;
use core::ptr;
use core::ptr::NonNull;
use lock::MutexGuard;

/// The threads waiting for a stack.
pub(crate) struct SwapinQueue<P: Platform>(ThreadQueue<P>);

// SAFETY: the queue links thread records, which every CPU shares.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "the linked threads are shared between CPUs, which their type \
              does not say"
)]
unsafe impl<P: Platform> Send for SwapinQueue<P> {}

impl<P: Platform> SwapinQueue<P> {
    /// An empty queue.
    pub(crate) const fn new() -> Self {
        Self(ThreadQueue::new())
    }

    /// The queue, pinned.
    const fn pinned(&mut self) -> Pin<&mut ThreadQueue<P>> {
        // SAFETY: the one `SwapinQueue` is in the platform's task state, a
        // static, which never moves.
        unsafe { Pin::new_unchecked(&mut self.0) }
    }
}

/// The swapin queue's address, which doubles as the wakeup event.
fn swapin_event<P: Platform>() -> *mut c_void {
    ptr::from_ref(&P::task_state().swapin_queue)
        .cast_mut()
        .cast()
}

/// Queues `thread`, which lost its stack, for the swapin thread.
///
/// # Safety
///
/// `thread` must be a live thread whose lock the caller holds, at splsched, as
/// the scheduler's swap path is.
pub(crate) unsafe fn thread_swapin<P: Platform>(thread: *mut Thread<P>) {
    let state = unsafe { (*thread).state() };
    match state & ThreadState::SWAP_STATE {
        ThreadState::SWAPPED => {
            unsafe {
                (*thread).set_state(
                    (state & !ThreadState::SWAP_STATE)
                        | ThreadState::SW_COMING_IN,
                );
            }
            // SAFETY: the thread's `links` field is free while the thread is
            // swapped out.
            unsafe {
                P::task_state()
                    .swapin_queue
                    .lock()
                    .pinned()
                    .push_back_ptr(NonNull::new_unchecked(thread));
            }
            // The event is the queue's fixed address, the key the swapin
            // thread registers with `assert_wait()`.
            thread_wakeup_prim::<P>(swapin_event::<P>(), 0, THREAD_AWAKENED);
        }
        ThreadState::SW_COMING_IN => (),
        _ => panic!("thread_swapin"),
    }
}

/// Gives the thread a stack and makes it runnable again.
///
/// # Safety
///
/// `thread` must be a live thread with a `ThreadState::SWAP_STATE` bit set
/// that no lock protects, because the stack allocation can block; the caller
/// must hold no spin lock.
pub unsafe fn doswapin<P: Platform>(thread: *mut Thread<P>) {
    unsafe { (*thread).stack_alloc(Some(thread_continue)) };

    // SAFETY: `thread` is live and not locked; the spl level and the thread
    // lock guard the state and the run queue, in the C order.
    unsafe {
        let s = P::splsched();
        (*thread).lock.lock();
        (*thread).set_state((*thread).state() & !ThreadState::SWAP_STATE);
        if (*thread).state().intersects(ThreadState::RUN) {
            thread_setrun(thread, c_int::from(true));
        }
        (*thread).lock.unlock();
        P::splx(s);
    }
}

/// The swapin thread's loop: gives each queued thread a stack.
///
/// # Safety
///
/// Runs as the swapin kernel thread.
unsafe fn swapin_thread_continue<P: Platform>() -> ! {
    loop {
        let mut queue = P::task_state().swapin_queue.lock();
        while let Some(thread) =
            queue.pinned().cursor_front_mut().remove_current()
        {
            let thread = ptr::from_mut(thread);
            // SAFETY: every thread on the queue is a live, swapped-out
            // thread that no lock protects, and the queue's lock is
            // released for the stack allocation, which can block.
            MutexGuard::unlocked(&mut queue, || unsafe { doswapin(thread) });
        }

        // SAFETY: the wait is asserted before the queue's lock is released,
        // so a thread queued after the check still wakes this one, and the
        // block holds no lock.
        unsafe {
            assert_wait::<P>(NonNull::new(swapin_event::<P>()), 0);
            drop(queue);
            thread_block::<P>(Some(swapin_thread_continuation::<P>));
        }
    }
}

/// The `void (*)(void)` continuation `thread_block()` resumes.
///
/// # Safety
///
/// Runs as the swapin kernel thread's continuation after a block; it never
/// returns.
unsafe extern "C" fn swapin_thread_continuation<P: Platform>() {
    // SAFETY: the swapin thread's own loop, which never returns.
    unsafe { swapin_thread_continue::<P>() }
}

/// Becomes the swapin thread.
///
/// # Safety
///
/// Started by `kernel_thread()` as the "swapin" thread; it reserves its stack
/// and never returns.
pub unsafe fn swapin_thread<P: Platform>() -> ! {
    // SAFETY: the kernel thread starts here with `P::cpu_thread()` pointing
    // at itself, and `stack_privilege()` reserves the stack it already runs
    // on.
    unsafe {
        let thread = P::cpu_thread();
        (*thread).vm_privilege = 1;
        (*thread).stack_privilege();
        swapin_thread_continue::<P>()
    }
}
