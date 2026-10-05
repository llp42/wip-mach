// SPDX-License-Identifier: CMU-Mach
// Derived from kern/ipc_sched.c:
//   Copyright (c) 1993, 1992,1991,1990 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The thread scheduling entries of the IPC paths.

use crate::arch::x86_64::pcb::stack_handoff;
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::spl;
use crate::kern::ast;
use crate::kern::debug::kpanic;
use crate::kern::machine;
use crate::kern::sched_prim::{
    TH_RUN_WAIT, TH_RUN_WAIT_SUSP, TH_RUN_WAIT_SUSP_UNINT, TH_RUN_WAIT_UNINT,
    TH_WAIT_SUSP, TH_WAIT_SUSP_UNINT, TH_WAIT_UNINT, THREAD_AWAKENED,
    thread_setrun, thread_wakeup_prim,
};
use crate::kern::thread::{
    Continuation, TH_RUN, TH_SCHED_STATE, TH_SUSP, TH_SWAPPED, TH_WAIT, Thread,
};
use core::ffi::c_uint;

/// Rounds a millisecond timeout up to whole ticks.
pub(crate) const fn ipc_timeout_to_ticks(msecs: c_uint) -> c_uint {
    let hz = machine::CLOCK_HZ;
    // The C expression is unsigned arithmetic over the `int` rate converted to
    // unsigned.
    msecs.wrapping_mul(hz as c_uint).wrapping_add(999) / 1000
}

/// Makes a waiting thread runnable with a successful wait result.
///
/// # Safety
///
/// `thread` must point at a live thread; IPC locks may be held, as the C
/// documented.
pub(crate) unsafe fn thread_go(thread: *mut Thread) {
    // SAFETY: `splsched()` is the real asm routine.
    let s = unsafe { spl::splsched() };
    unsafe {
        (*thread).lock.lock();
        // ADR 0028: the waker does not touch the sleeper's timeout; the
        // sleeper stops its own callout on the way out of `thread_block`.

        let state = (*thread).state();
        match state & TH_SCHED_STATE {
            TH_WAIT | TH_WAIT_UNINT | TH_WAIT_SUSP_UNINT => {
                (*thread).set_state((state & !TH_WAIT) | TH_RUN);
                (*thread).wait_result = THREAD_AWAKENED;
                thread_setrun(thread, 1);
            }
            TH_WAIT_SUSP
            | TH_RUN_WAIT
            | TH_RUN_WAIT_SUSP
            | TH_RUN_WAIT_UNINT
            | TH_RUN_WAIT_SUSP_UNINT => {
                (*thread).set_state(state & !TH_WAIT);
                (*thread).wait_result = THREAD_AWAKENED;
            }
            _ => (),
        }

        (*thread).lock.unlock();
        spl::splx(s);
    }
}

/// Marks `thread` as about to wait uninterruptibly.
///
/// # Safety
///
/// `thread` must point at a live thread; the routine takes the thread lock
/// itself.
pub(crate) unsafe fn thread_will_wait(thread: *mut Thread) {
    // SAFETY: `splsched()` is the real asm routine.
    let s = unsafe { spl::splsched() };
    unsafe {
        (*thread).lock.lock();
        (*thread).wait_result = -1;
        (*thread).set_state((*thread).state() | TH_WAIT);
        (*thread).lock.unlock();
        spl::splx(s);
    }
}

/// Marks `thread` as about to wait, with a timeout of `timeout` ticks.
///
/// # Safety
///
/// `thread` must point at a live thread; the routine takes the thread lock
/// itself.
pub(crate) unsafe fn thread_will_wait_with_timeout(
    thread: *mut Thread,
    msecs: c_uint,
) {
    // The 32-bit `msecs * HZ / 1000` used to wrap above ~11.9 hours
    // (DEBT); `from_milliseconds_ceil` widens first.
    let ticks = clock::Ticks::from_milliseconds_ceil(u64::from(msecs));
    // SAFETY: `splsched()` is the real asm routine.
    let s = unsafe { spl::splsched() };
    unsafe {
        (*thread).lock.lock();
        (*thread).wait_result = -1;
        (*thread).set_state((*thread).state() | TH_WAIT);
        // SAFETY: `thread` is live and will not move.
        Thread::start_timer(thread, ticks);
        (*thread).lock.unlock();
        spl::splx(s);
    }
}

/// Whether `thread` may run on the current processor's set.
///
/// # Safety
///
/// `thread` must be a live thread.
unsafe fn check_processor_set(thread: *mut Thread) -> bool {
    per_cpu::processor().processor_set() == unsafe { (*thread).processor_set }
}

/// Whether `thread` is bound to no processor, or to the current one.
///
/// # Safety
///
/// `thread` must be a live thread.
unsafe fn check_bound_processor(thread: *mut Thread) -> bool {
    let bound = unsafe { (*thread).bound_processor };
    bound.is_null() || bound == per_cpu::processor().as_ptr()
}

/// Switches to `new`, leaving `old` blocked with `continuation` as its resume
/// point.
///
/// # Safety
///
/// `old` must be the running thread, `new` a live thread the caller has
/// validated to be wait-and-swapped with the continuation its queue expects,
/// and the caller must hold no thread lock.
pub(crate) unsafe fn thread_handoff(
    old: *mut Thread,
    continuation: Continuation,
    new: *mut Thread,
) -> bool {
    // SAFETY: `splsched()` is the real asm routine.
    let s = unsafe { spl::splsched() };
    unsafe {
        (*new).lock.lock();

        let can_handoff = (*old).stack_privilege != per_cpu::stack()
            && (*new).state() == (TH_WAIT | TH_SWAPPED)
            && check_processor_set(new)
            && check_bound_processor(new);
        if !can_handoff {
            (*new).lock.unlock();
            spl::splx(s);
            return false;
        }

        // ADR 0028: the waker never touches the sleeper's timeout.
        (*new).set_state(TH_RUN);
        (*new).lock.unlock();

        (*new).last_processor = per_cpu::processor().as_ptr();
        ast::context(new, cpu_id());

        stack_handoff(old, new);

        (*old).lock.lock();
        (*old).swap_func = continuation;
        (*old).wait_result = -1;
        match (*old).state() {
            TH_RUN => (*old).set_state(TH_WAIT | TH_SWAPPED),
            state if state == TH_RUN | TH_SUSP => {
                (*old).set_state(TH_WAIT | TH_SUSP | TH_SWAPPED);
                if (*old).wake_active() {
                    (*old).set_wake_active(false);
                    (*old).lock.unlock();
                    thread_wakeup_prim(
                        (*old).wake_active_event(),
                        0,
                        THREAD_AWAKENED,
                    );
                    spl::splx(s);
                    return true;
                }
            }
            _ => kpanic!("thread_handoff", "thread_handoff"),
        }
        (*old).lock.unlock();
        spl::splx(s);
        true
    }
}
