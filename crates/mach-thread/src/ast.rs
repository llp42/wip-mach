// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The per-CPU AST reasons: what each CPU has to act on before it
//! returns to user mode.

use crate::platform::Platform;
use crate::processor_ref::ProcessorRef;
use crate::sched_prim::thread_block;
use crate::smp::CpuId;
use crate::thread::Thread;
use crate::types::{ProcessorState, ThreadState};
use core::ffi::c_int;
use core::sync::atomic::Ordering;
use mach_sched::ast::{AST_ARRAY, AstReason, needed, on};
use mach_sched::policy::POLICY_FIXEDPRI;
use mach_sched::run_queue::SchedQueue;
use mach_sched::sched::NRQS;

/// Replaces the per-thread reasons of `cpu` with `thread`'s pending ones.
///
/// # Safety
///
/// `thread` must be a live thread.
pub unsafe fn context<P: Platform>(thread: *mut Thread<P>, cpu: CpuId) {
    // SAFETY: `thread` is live, so `(*thread).ast` is readable.
    unsafe {
        let word = &AST_ARRAY[cpu.as_usize()];
        let per_thread =
            AstReason::HALT | AstReason::TERMINATE | P::AST_PER_THREAD;
        word.fetch_and(!per_thread, Ordering::AcqRel);
        word.fetch_or((*thread).ast, Ordering::AcqRel);
    }
}

/// Acts on the reasons pending on the running CPU.
///
/// # Safety
///
/// Machine-dependent code calls this on return to user mode with interrupts
/// disabled; the CPU must have no AST action in progress.
pub unsafe fn taken<P: Platform>() {
    let self_ = P::cpu_thread();
    let cpu = P::current_cpu();
    let reasons =
        AST_ARRAY[cpu.as_usize()].swap(AstReason::empty(), Ordering::AcqRel);
    // SAFETY: this runs on the CPU's trap stack with interrupts still
    // disabled from the AST entry.
    unsafe { P::spl0() };

    if self_ == P::cpu_processor().idle_thread() {
        return;
    }

    unsafe {
        while (*self_).ast.intersects(AstReason::SHOULD_HALT) {
            Thread::<P>::halt_self(Some(P::EXCEPTION_RETURN));
        }

        // `halt_self()` may block, so the thread may be back on another CPU.
        if reasons.contains(AstReason::BLOCK)
            || csw_needed(self_, P::cpu_processor())
        {
            thread_block::<P>(Some(P::EXCEPTION_RETURN));
        }
    }
}

/// Checks the running processor for AST conditions at `splsched`.
///
/// The interrupt path enters here directly.
///
/// # Safety
///
/// The caller must be the running thread's CPU, able to take `splsched`, and
/// must not hold the run-queue lock.
pub unsafe extern "C" fn check<P: Platform>() {
    let mycpu = P::current_cpu();
    let thread = P::cpu_thread();
    let myprocessor = P::cpu_processor();
    let s = P::splsched();

    unsafe {
        match myprocessor.state() {
            ProcessorState::OffLine
            | ProcessorState::Idle
            | ProcessorState::Dispatching => (),
            ProcessorState::Assign | ProcessorState::Shutdown => {
                on(mycpu, AstReason::BLOCK);
            }
            ProcessorState::Running => {
                on(mycpu, (*thread).ast);
                if needed(mycpu).is_empty() {
                    check_running(mycpu, thread, myprocessor);
                }
            }
        }

        P::splx(s);
    }
}

/// The [`ProcessorState::Running`] arm of [`check()`], after the thread's
/// own reasons have been propagated.
///
/// # Safety
///
/// `myprocessor` must be the running CPU's processor, `thread` its current
/// thread, and the caller must hold `splsched` with the run-queue lock free.
unsafe fn check_running<P: Platform>(
    mycpu: CpuId,
    thread: *mut Thread<P>,
    myprocessor: ProcessorRef<P>,
) {
    unsafe {
        if (*thread).state().intersects(ThreadState::SUSP)
            || myprocessor.runq_count() > 0
        {
            on(mycpu, AstReason::BLOCK);
            return;
        }

        let pset = myprocessor.processor_set();
        if (*pset).policies & POLICY_FIXEDPRI != 0 {
            if csw_needed(thread, myprocessor) {
                on(mycpu, AstReason::BLOCK);
            } else if (*thread).sched.policy == POLICY_FIXEDPRI {
                myprocessor.set_first_quantum(true);
            }
            return;
        }

        let rq = &raw mut (*pset).runq;
        if myprocessor.first_quantum()
            || (*rq).count.load(Ordering::Relaxed) == 0
        {
            return;
        }

        let low = (*rq).low;
        if (*queue_at(rq, low)).is_empty() {
            (*rq).lock.lock();
            if (*rq).count.load(Ordering::Relaxed) > 0 {
                let mut i = (*rq).low;
                while i < NRQS as c_int {
                    if !(*queue_at(rq, i)).is_empty() {
                        break;
                    }
                    i += 1;
                }
                (*rq).low = i;
            }
            (*rq).lock.unlock();
        }

        if (*rq).low <= (*thread).sched.sched_pri {
            on(mycpu, AstReason::BLOCK);
        }
    }
}

/// A pointer to `runq[low]`, one step of the run-queue hint walk.
///
/// # Safety
///
/// `rq` must be a live run queue and `low` a valid queue index.
unsafe fn queue_at(
    rq: *mut mach_sched::RunQueue,
    low: c_int,
) -> *mut SchedQueue {
    unsafe { (&raw mut (*rq).runq).cast::<SchedQueue>().add(low as usize) }
}

/// Whether a context switch is needed for `thread` on `processor`.
///
/// # Safety
///
/// `thread` must be live.
///
/// # Panics
///
/// If `processor` is not the running CPU's; see
/// [`ProcessorRef::has_runnable()`].
unsafe fn csw_needed<P: Platform>(
    thread: *mut Thread<P>,
    processor: ProcessorRef<P>,
) -> bool {
    let suspended = unsafe { (*thread).state() }.intersects(ThreadState::SUSP);
    suspended || processor.has_runnable()
}
