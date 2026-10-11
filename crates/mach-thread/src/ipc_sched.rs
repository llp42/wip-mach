// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The thread scheduling entries of the IPC paths.

use crate::ast;
use crate::platform::Platform;
use crate::sched_prim::{THREAD_AWAKENED, thread_setrun, thread_wakeup_prim};
use crate::thread::{Continuation, Thread};
use crate::types::ThreadState;
use core::ffi::c_uint;
use mach_sched::sched::CLOCK_HZ;

/// Rounds a millisecond timeout up to whole ticks.
pub(crate) const fn ipc_timeout_to_ticks(msecs: c_uint) -> c_uint {
    let hz = CLOCK_HZ;
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
pub unsafe fn thread_go<P: Platform>(thread: *mut Thread<P>) {
    let s = P::splsched();
    unsafe {
        (*thread).lock.lock();
        // The waker does not touch the sleeper's timeout; the sleeper
        // stops its own callout on the way out of `thread_block`.

        let state = (*thread).state();
        match state & ThreadState::SCHED_STATE {
            ThreadState::WAIT
            | ThreadState::WAIT_UNINT
            | ThreadState::WAIT_SUSP_UNINT => {
                (*thread).set_state(
                    (state & !ThreadState::WAIT) | ThreadState::RUN,
                );
                (*thread).wait_result = THREAD_AWAKENED;
                thread_setrun(thread, 1);
            }
            ThreadState::WAIT_SUSP
            | ThreadState::RUN_WAIT
            | ThreadState::RUN_WAIT_SUSP
            | ThreadState::RUN_WAIT_UNINT
            | ThreadState::RUN_WAIT_SUSP_UNINT => {
                (*thread).set_state(state & !ThreadState::WAIT);
                (*thread).wait_result = THREAD_AWAKENED;
            }
            _ => (),
        }

        (*thread).lock.unlock();
        P::splx(s);
    }
}

/// Marks `thread` as about to wait uninterruptibly.
///
/// # Safety
///
/// `thread` must point at a live thread; the routine takes the thread lock
/// itself.
pub unsafe fn thread_will_wait<P: Platform>(thread: *mut Thread<P>) {
    let s = P::splsched();
    unsafe {
        (*thread).lock.lock();
        (*thread).wait_result = -1;
        (*thread).set_state((*thread).state() | ThreadState::WAIT);
        (*thread).lock.unlock();
        P::splx(s);
    }
}

/// Marks `thread` as about to wait, with a timeout of `timeout` ticks.
///
/// # Safety
///
/// `thread` must point at a live thread; the routine takes the thread lock
/// itself.
pub unsafe fn thread_will_wait_with_timeout<P: Platform>(
    thread: *mut Thread<P>,
    msecs: c_uint,
) {
    // The 32-bit `msecs * HZ / 1000` used to wrap above ~11.9 hours
    // (DEBT); `from_milliseconds_ceil` widens first.
    let ticks = clock::Ticks::from_milliseconds_ceil(u64::from(msecs));
    let s = P::splsched();
    unsafe {
        (*thread).lock.lock();
        (*thread).wait_result = -1;
        (*thread).set_state((*thread).state() | ThreadState::WAIT);
        // SAFETY: `thread` is live and will not move.
        Thread::<P>::start_timer(thread, ticks);
        (*thread).lock.unlock();
        P::splx(s);
    }
}

/// Switches to `new`, leaving `old` blocked with `continuation` as its resume
/// point.
///
/// # Panics
///
/// If `old` is in a state a running thread cannot be in.
///
/// # Safety
///
/// `old` must be the running thread, `new` a live thread the caller has
/// validated to be wait-and-swapped with the continuation its queue expects,
/// and the caller must hold no thread lock.
pub unsafe fn thread_handoff<P: Platform>(
    old: *mut Thread<P>,
    continuation: Continuation,
    new: *mut Thread<P>,
) -> bool {
    let s = P::splsched();
    unsafe {
        (*new).lock.lock();

        let can_handoff = (*old).stack_privilege != P::cpu_stack()
            && (*new).state() == (ThreadState::WAIT | ThreadState::SWAPPED)
            && P::cpu_processor().processor_set() == (*new).processor_set
            && ((*new).bound_processor.is_null()
                || (*new).bound_processor == P::cpu_processor().as_ptr());
        if !can_handoff {
            (*new).lock.unlock();
            P::splx(s);
            return false;
        }

        // The waker never touches the sleeper's timeout.
        (*new).set_state(ThreadState::RUN);
        (*new).lock.unlock();

        (*new).last_processor = P::cpu_processor().as_ptr();
        ast::context(new, P::current_cpu());

        P::stack_handoff(old, new);

        (*old).lock.lock();
        (*old).swap_func = continuation;
        (*old).wait_result = -1;
        match (*old).state() {
            ThreadState::RUN => {
                (*old).set_state(ThreadState::WAIT | ThreadState::SWAPPED);
            }
            ThreadState::RUN_SUSP => {
                (*old).set_state(
                    ThreadState::WAIT
                        | ThreadState::SUSP
                        | ThreadState::SWAPPED,
                );
                if (*old).wake_active() {
                    (*old).set_wake_active(false);
                    (*old).lock.unlock();
                    thread_wakeup_prim::<P>(
                        (*old).wake_active_event(),
                        0,
                        THREAD_AWAKENED,
                    );
                    P::splx(s);
                    return true;
                }
            }
            _ => panic!("thread_handoff"),
        }
        (*old).lock.unlock();
        P::splx(s);
        true
    }
}
