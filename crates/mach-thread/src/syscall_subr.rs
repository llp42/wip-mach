// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The console-print trap and the scheduling traps.

use crate::error::Error;
use crate::ipc_sched::{ipc_timeout_to_ticks, thread_will_wait_with_timeout};
use crate::ipc_tt::IKOT_THREAD;
use crate::platform::Platform;
use crate::sched_prim::{
    compute_priority, rem_runq, thread_block, thread_run,
};
use crate::thread::Thread;
use core::ffi::{c_int, c_uint, c_void};
use mach_ipc::{IpcPort, IpcSpace, ipc_object};
use mach_sched::policy::POLICY_FIXEDPRI;
use mach_sched::sched::NRQS;
use mach_sched::sched::min_quantum;

/// `KERN_SUCCESS`: a trap that succeeded.
const KERN_SUCCESS: c_int = 0;

/// The thread-switch option that leaves the priority alone.
const SWITCH_OPTION_NONE: c_int = 0;
/// The thread-switch option that depresses the caller's priority.
const SWITCH_OPTION_DEPRESS: c_int = 1;
/// The thread-switch option that waits for the timeout.
const SWITCH_OPTION_WAIT: c_int = 2;

/// The send right [`thread_switch`] translates its hint name to.
const MACH_PORT_RIGHT_SEND: c_uint = 0;

/// Depresses `thread`'s priority to the lowest, for `depress_time`
/// milliseconds.
///
/// # Safety
///
/// `thread` must be a live thread; the routine takes splsched and the thread
/// lock itself.
pub(crate) unsafe fn depress_priority<P: Platform>(
    thread: *mut Thread<P>,
    depress_time: c_uint,
) {
    let ticks = ipc_timeout_to_ticks(depress_time);
    let s = P::splsched();
    unsafe {
        (*thread).lock.lock();

        // SAFETY: `thread` is live.
        Thread::<P>::stop_depress_timer(thread);

        (*thread).sched.depress_priority = (*thread).sched.priority;
        (*thread).sched.priority = NRQS as c_int - 1;
        (*thread).sched.sched_pri = NRQS as c_int - 1;
        if ticks != 0 {
            // SAFETY: `thread` is live and will not move.
            Thread::<P>::start_depress_timer(
                thread,
                clock::Ticks::new(u64::from(ticks)),
            );
        }

        (*thread).lock.unlock();
        P::splx(s);
    }
}

/// Restores the depressed priority of the thread `param` names, from the timer
/// callback.
///
/// # Safety
///
/// `param` must be the live thread the timer was armed for.
pub(crate) unsafe fn depress_timeout<P: Platform>(param: *mut c_void) {
    let thread = param.cast::<Thread<P>>();
    let s = P::splsched();
    unsafe {
        (*thread).lock.lock();

        if (*thread).sched.depress_priority >= 0 {
            (*thread).sched.priority = (*thread).sched.depress_priority;
            (*thread).sched.depress_priority = -1;
            compute_priority(thread, 0);
        }

        (*thread).lock.unlock();
        P::splx(s);
    }
}

/// Ends `thread`'s priority depression early.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] when `thread` is null.
///
/// # Safety
///
/// `thread` must be null or a live thread; the routine takes splsched and the
/// thread lock itself.
pub unsafe fn depress_abort<P: Platform>(
    thread: *mut Thread<P>,
) -> Result<(), Error> {
    if thread.is_null() {
        return Err(Error::InvalidArgument);
    }

    let s = P::splsched();
    // SAFETY: the null check above; the thread lock protects the priority
    // fields and the timer element.
    unsafe {
        (*thread).lock.lock();

        if (*thread).sched.depress_priority >= 0 {
            // SAFETY: `thread` is live.
            Thread::<P>::stop_depress_timer(thread);
            (*thread).sched.priority = (*thread).sched.depress_priority;
            (*thread).sched.depress_priority = -1;
            compute_priority(thread, 0);
        }

        (*thread).lock.unlock();
        P::splx(s);
    }

    Ok(())
}

/// The continuation of [`swtch`]: returns whether another thread is runnable.
unsafe extern "C" fn swtch_continue<P: Platform>() {
    let runnable = P::cpu_processor().has_runnable();
    // SAFETY: the machine's syscall return never comes back, and the C
    // passed the boolean as an `int`.
    unsafe { P::syscall_return(c_int::from(runnable)) };
}

/// Yields the processor, and returns whether another thread is still runnable.
///
/// # Safety
///
/// Must run on the current thread with no lock held and no wait state set.
pub(crate) unsafe fn swtch<P: Platform>() -> bool {
    if !P::cpu_processor().has_runnable() {
        return false;
    }

    unsafe { thread_block::<P>(Some(swtch_continue::<P>)) };

    P::cpu_processor().has_runnable()
}

/// The `swtch` trap entry.
///
/// # Safety
///
/// Must run on the current thread with no lock held and no wait state set.
#[must_use]
pub unsafe extern "C" fn swtch_entry<P: Platform>() -> c_int {
    c_int::from(unsafe { swtch::<P>() })
}

/// The continuation of [`swtch_pri`]: ends the depression and returns whether
/// another thread is runnable.
unsafe extern "C" fn swtch_pri_continue<P: Platform>() {
    let thread = P::cpu_thread();
    // SAFETY: the continuation runs on its own thread, whose lock it takes.
    unsafe {
        if (*thread).sched.depress_priority >= 0 {
            let _ = depress_abort(thread);
        }
    }

    let runnable = P::cpu_processor().has_runnable();
    // SAFETY: the machine's syscall return never comes back.
    unsafe { P::syscall_return(c_int::from(runnable)) };
}

/// Yields the processor at a depressed priority, and returns whether another
/// thread is still runnable.  The priority argument is unused.
///
/// # Safety
///
/// Must run on the current thread with no lock held and no wait state set.
pub(crate) unsafe fn swtch_pri<P: Platform>() -> bool {
    let thread = P::cpu_thread();
    if !P::cpu_processor().has_runnable() {
        return false;
    }

    // The C converted the non-negative `min_quantum` to the depression time.
    let quantum = min_quantum() as c_uint;
    unsafe {
        depress_priority(thread, quantum);
        thread_block::<P>(Some(swtch_pri_continue::<P>));
        if (*thread).sched.depress_priority >= 0 {
            let _ = depress_abort(thread);
        }
    }

    P::cpu_processor().has_runnable()
}

/// The `swtch_pri` trap entry.
///
/// # Safety
///
/// Must run on the current thread with no lock held and no wait state set.
#[must_use]
pub unsafe extern "C" fn swtch_pri_entry<P: Platform>(_pri: c_int) -> c_int {
    c_int::from(unsafe { swtch_pri::<P>() })
}

/// The continuation of [`thread_switch`]: ends a pending depression and
/// returns success.
unsafe extern "C" fn thread_switch_continue<P: Platform>() {
    let cur_thread = P::cpu_thread();
    // SAFETY: the continuation runs on its own thread, whose lock it takes.
    unsafe {
        if (*cur_thread).sched.depress_priority >= 0 {
            let _ = depress_abort(cur_thread);
        }
    }
    // SAFETY: the machine's syscall return never comes back.
    unsafe {
        P::syscall_return(KERN_SUCCESS);
    }
}

/// Yields the processor, to the thread `thread_name` names when it can run,
/// with the priority change or wait `option` asks for.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] when `option` is not one of the switch
/// options.
///
/// # Safety
///
/// Must run on the current thread with no lock held and no wait state set.
pub unsafe fn thread_switch<P: Platform>(
    thread_name: c_uint,
    option: c_int,
    option_time: c_uint,
) -> Result<(), Error> {
    let cur_thread = P::cpu_thread();

    match option {
        SWITCH_OPTION_NONE => (),
        SWITCH_OPTION_DEPRESS => unsafe {
            depress_priority(cur_thread, option_time);
        },
        SWITCH_OPTION_WAIT => unsafe {
            thread_will_wait_with_timeout(cur_thread, option_time);
        },
        _ => return Err(Error::InvalidArgument),
    }

    if let Some(thread) = unsafe { hint_thread(cur_thread, thread_name) } {
        // SAFETY: `hint_thread` removed `thread` from its run queue under the
        // thread lock, which it left held.
        unsafe {
            if (*thread).sched.policy == POLICY_FIXEDPRI {
                let myprocessor = P::cpu_processor();
                myprocessor.set_quantum((*thread).sched.sched_data);
                myprocessor.set_first_quantum(true);
            }
            thread_run(Some(thread_switch_continue::<P>), thread);

            if (*cur_thread).sched.depress_priority >= 0 {
                let _ = depress_abort(cur_thread);
            }
        }
        return Ok(());
    }

    if P::cpu_processor().has_runnable() {
        unsafe { thread_block::<P>(Some(thread_switch_continue::<P>)) };
    }

    // SAFETY: the thread is the current one, whose lock the routine takes.
    unsafe {
        if (*cur_thread).sched.depress_priority >= 0 {
            let _ = depress_abort(cur_thread);
        }
    }

    Ok(())
}

/// The thread-hint arm of `thread_switch()`: translate `thread_name`, check
/// that it is an eligible thread of the current set still on its run queue,
/// and pull it off.
///
/// Returns the thread with its lock held and interrupts at `splsched` when
/// the hint is usable; the port, thread and run-queue lock are released
/// otherwise.
///
/// # Safety
///
/// `cur_thread` must be the current thread and nothing may be locked.
unsafe fn hint_thread<P: Platform>(
    cur_thread: *mut Thread<P>,
    thread_name: c_uint,
) -> Option<*mut Thread<P>> {
    if thread_name == 0 {
        return None;
    }

    // SAFETY: the current thread's task and space are live.
    let space = unsafe { IpcSpace::from_raw((*(*cur_thread).task).itk_space) };
    // SAFETY: the space is live and nothing is locked; the C looked the name
    // up as a send right.
    let object = unsafe {
        ipc_object::translate::<P>(space, thread_name, MACH_PORT_RIGHT_SEND)
    }
    .ok()?;
    // SAFETY: a successful translate returns a live, locked object.
    let port = unsafe { IpcPort::from_raw(object) };

    // SAFETY: the port is live and locked.
    let eligible = unsafe { port.is_active() && port.kotype() == IKOT_THREAD };
    if !eligible {
        // SAFETY: the port is live and locked.
        unsafe { port.unlock() };
        return None;
    }

    // SAFETY: an active port of type `IKOT_THREAD` names a live thread.
    let thread = unsafe { port.kobject().cast::<Thread<P>>() };
    let s = P::splsched();
    // SAFETY: `thread` is live and the thread lock protects its run-queue
    // link and processor set.
    unsafe {
        (*thread).lock.lock();
        let got_it = (*thread).processor_set == (*cur_thread).processor_set
            && !rem_runq(thread).is_null();
        if got_it {
            // SAFETY: the C released the lock and the interrupt level before
            // switching to the thread, and the port after.
            (*thread).lock.unlock();
            P::splx(s);
            port.unlock();
            return Some(thread);
        }
        (*thread).lock.unlock();
        P::splx(s);
    }

    // SAFETY: the port is live and locked.
    unsafe { port.unlock() };
    None
}
