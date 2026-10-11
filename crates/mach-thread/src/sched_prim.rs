// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The wait/wake and run-queue scheduler primitives.

use crate::mach_factor;
use crate::platform::Platform;
use crate::processor::Processor;
use crate::processor_ref::ProcessorRef;
use crate::processor_set::ProcessorSet;
use crate::sched::Callout;
use crate::smp::CpuId;
use crate::thread::{Thread, ThreadQueue};
use crate::thread_swap::thread_swapin;
use crate::types::{ProcessorState, ThreadState};
use crate::{ast, processor};
use core::ffi::{c_int, c_uint, c_void};
use core::pin::Pin;
use core::ptr;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicI32, Ordering};
use mach_sched::RunQueue;
use mach_sched::ast::AstReason;
use mach_sched::policy::{POLICY_FIXEDPRI, POLICY_TIMESHARE};
use mach_sched::run_queue::{self};
use mach_sched::sched::{CLOCK_HZ, NRQS, add_single_writer};
use mach_sched::sched::{min_quantum, sched_tick};
use mach_vm::simple_lock::SimpleLock;

/// The size of the event hash table.
pub const NUMQUEUES: usize = 1031;

/// A normal wakeup.
pub const THREAD_AWAKENED: c_int = 0;
/// `THREAD_TIMED_OUT`: the timeout expired.
pub const THREAD_TIMED_OUT: c_int = 1;
/// `THREAD_INTERRUPTED`: `clear_wait()` interrupted the wait.
pub const THREAD_INTERRUPTED: c_int = 2;
/// `THREAD_RESTART`: restart the operation entirely.
pub const THREAD_RESTART: c_int = 3;

/// The stuck-thread scan's array size.
pub(crate) const MAX_STUCK_THREADS: usize = 16;

/// The bucket locks.
static WAIT_LOCK: [SimpleLock; NUMQUEUES] =
    [const { SimpleLock::new() }; NUMQUEUES];

/// How many threads the stuck-thread array holds, with the same `Relaxed`
/// accesses.
static STUCK_COUNT: AtomicI32 = AtomicI32::new(0);

/// When set, the stuck-thread scan reports what it finds; read under the
/// run-queue lock, and never changed at run time.
static DO_THREAD_SCAN_DEBUG: AtomicI32 = AtomicI32::new(0);

/// How often an idle processor went non-idle without a dispatch.  Nothing
/// reads it.
static NO_DISPATCH_COUNT: AtomicI32 = AtomicI32::new(0);

/// The wait-queue bucket of `event`.
fn wait_hash(event: *mut c_void) -> usize {
    let bits = event as isize;
    let folded = if bits < 0 { !bits } else { bits };
    // The folded value is non-negative and the modulo is below `NUMQUEUES`, so
    // the cast cannot lose anything.
    (folded % NUMQUEUES as isize) as usize
}

/// The wait bucket `index` names.
fn wait_queue<P: Platform>(index: usize) -> *mut ThreadQueue<P> {
    // SAFETY: `index` is below `NUMQUEUES`, the array's length, and only a
    // pointer is handed out.
    unsafe {
        P::task_state()
            .wait_queue
            .0
            .get()
            .cast::<ThreadQueue<P>>()
            .add(index)
    }
}

/// Pins the thread queue at `q`, a run queue or a wait bucket, for one
/// operation.
///
/// # Safety
///
/// `q` must be a run queue or a wait bucket, which never move, and the caller
/// must hold the lock that guards it for as long as it uses the result.
const unsafe fn pin_queue<'a, P: Platform>(
    q: *mut ThreadQueue<P>,
) -> Pin<&'a mut ThreadQueue<P>> {
    // SAFETY: the queue never moves, and the lock the caller holds keeps
    // anything else from reaching it.
    unsafe { Pin::new_unchecked(&mut *q) }
}

/// The wait lock `index` names.
fn wait_lock(index: usize) -> &'static SimpleLock {
    &WAIT_LOCK[index]
}

/// Halts the kernel: the scheduler cannot classify `thread`'s state.
fn state_panic<P: Platform>(thread: *mut Thread<P>) -> ! {
    // SAFETY: the caller holds the thread lock and `thread` is live.
    let state = unsafe { (*thread).state() };
    let tag = |bit: ThreadState, on: &'static str| -> &'static str {
        if state.intersects(bit) { on } else { "" }
    };
    panic!(
        "state_panic: thread {:x} has unexpected state {:x} ({}{}{}{}{}{}{}{})",
        thread.expose_provenance(),
        state,
        tag(ThreadState::WAIT, "TH_WAIT|"),
        tag(ThreadState::SUSP, "TH_SUSP|"),
        tag(ThreadState::RUN, "TH_RUN|"),
        tag(ThreadState::UNINT, "TH_UNINT|"),
        tag(ThreadState::HALTED, "TH_HALTED|"),
        tag(ThreadState::IDLE, "TH_IDLE|"),
        tag(ThreadState::SWAPPED, "TH_SWAPPED|"),
        tag(ThreadState::SW_COMING_IN, "TH_SW_COMING_IN|"),
    )
}

/// Sets the quantum, bootstraps the processor sets, and initializes the AST
/// state.
///
/// # Safety
///
/// The boot path calls this once, before any other CPU or thread can reach the
/// scheduler.
pub unsafe fn sched_init<P: Platform>() {
    mach_sched::sched::init();

    // SAFETY: the processor module owns the processor sets, and this is the
    // boot step that builds them.
    unsafe { processor::bootstrap::<P>() };

    // No other CPU is running yet, so no AST can be pending.
    mach_sched::ast::init();
}

/// Puts `th` on `rq` at its priority.
///
/// # Safety
///
/// `rq` must be a live run queue and `th` a locked thread, at splsched; the
/// caller may hold the thread lock.
unsafe fn enqueue_run_queue<P: Platform>(
    rq: *mut RunQueue,
    th: *mut Thread<P>,
) {
    // SAFETY: the caller's promises are the run queue's.
    if unsafe { run_queue::enqueue(rq, &raw mut (*th).sched) } {
        P::print(format_args!(
            "thread_setrun: pri too high ({})\n",
            // SAFETY: the thread is live and locked.
            unsafe { (*th).sched.sched_pri }
        ));
    }
}

/// Whether `th` is already scheduled: on a run queue, chosen as some
/// processor's `next_thread`, or running on a CPU.
///
/// # Safety
///
/// `th` must be a live thread locked by the caller, and the caller must be at
/// splsched.
unsafe fn already_scheduled<P: Platform>(th: *mut Thread<P>) -> bool {
    if !unsafe { (*th).sched.runq }.is_null() {
        return true;
    }
    CpuId::online()
        .zip(processor::iter())
        .any(|(cpu, processor)| {
            processor.next_thread() == th || P::cpu_thread_at(cpu) == th
        })
}

/// Makes `th` runnable, dispatching it straight to an idle processor when one
/// waits, else enqueuing it.  A thread that is already scheduled is left
/// alone, so a duplicate call is harmless.
///
/// # Safety
///
/// `th` must be a live thread locked by the caller, and the caller must be at
/// splsched.
unsafe fn setrun<P: Platform>(th: *mut Thread<P>, may_preempt: bool) {
    // SAFETY: every field read is protected by the thread lock, and the
    // run queues by their own locks. A bound processor and an idle-queue
    // entry are both static processor records.
    unsafe {
        if already_scheduled(th) {
            return;
        }

        if (*th).sched.sched_stamp != sched_tick() {
            update_priority(th);
        }

        let mut processor = (*th).bound_processor;
        if processor.is_null() {
            let pset = (*th).processor_set;
            if (*pset).idle_count > 0 {
                (*pset).idle_lock.lock();
                if (*pset).idle_count > 0 {
                    processor = (*pset)
                        .idle_queue_pinned()
                        .pop_front()
                        .map_or(ptr::null_mut(), ptr::from_mut);
                    (*pset).idle_count -= 1;
                    (*processor).next_thread.store(th, Ordering::Release);
                    (*processor)
                        .state
                        .store(ProcessorState::Dispatching, Ordering::Release);
                    (*pset).idle_lock.unlock();
                    if processor != P::cpu_processor().as_ptr() {
                        ProcessorRef::<P>::from_static(processor).ast_check();
                    }
                    return;
                }
                (*pset).idle_lock.unlock();
            }
            let rq = &raw mut (*pset).runq;
            enqueue_run_queue(rq, th);
            if may_preempt
                && pset == P::cpu_processor().processor_set()
                && (*P::cpu_thread()).sched.sched_pri > (*th).sched.sched_pri
            {
                P::cpu_processor().set_first_quantum(false);
                mach_sched::ast::on(P::current_cpu(), AstReason::BLOCK);
            }
        } else {
            if !processor.is_null()
                && (*processor).state.load(Ordering::Acquire)
                    == ProcessorState::Idle
            {
                (*processor).lock.lock();
                let pset = (*processor).processor_set.load(Ordering::Acquire);
                (*pset).idle_lock.lock();
                if (*processor).state.load(Ordering::Acquire)
                    == ProcessorState::Idle
                {
                    let _ = (*pset)
                        .idle_queue_pinned()
                        .remove_ptr(processor.cast_const());
                    (*pset).idle_count -= 1;
                    (*processor).next_thread.store(th, Ordering::Release);
                    (*processor)
                        .state
                        .store(ProcessorState::Dispatching, Ordering::Release);
                    (*pset).idle_lock.unlock();
                    (*processor).lock.unlock();
                    if processor != P::cpu_processor().as_ptr() {
                        ProcessorRef::<P>::from_static(processor).ast_check();
                    }
                    return;
                }
                (*pset).idle_lock.unlock();
                (*processor).lock.unlock();
            }
            let rq = &raw mut (*processor).runq;
            enqueue_run_queue(rq, th);

            if processor == P::cpu_processor().as_ptr() {
                mach_sched::ast::on(P::current_cpu(), AstReason::BLOCK);
            } else if (*processor).state.load(Ordering::Acquire)
                != ProcessorState::OffLine
            {
                ProcessorRef::<P>::from_static(processor).ast_check();
            }
        }
    }
}

/// Sets up a new thread's timeouts: the callouts carry their actions in the
/// Declares that the current thread waits on `event`.
///
/// # Panics
///
/// If the current thread already waits on an event.
///
/// # Safety
///
/// Called from a thread context with interrupts at a level that prevents the
/// wakeup from being lost, and with the current thread not already waiting on
/// an event.
pub unsafe fn assert_wait<P: Platform>(
    event: Option<NonNull<c_void>>,
    interruptible: c_int,
) {
    let thread = P::cpu_thread();
    // SAFETY: `thread` is the current thread; the C tests the field before
    // raising splsched, so the order stays.
    let wait_event = unsafe { (*thread).wait_event };
    assert!(
        wait_event.is_null(),
        "assert_wait: already asserted event {:x}\n",
        wait_event.expose_provenance()
    );
    let s = P::splsched();
    let add = if interruptible != 0 {
        ThreadState::WAIT
    } else {
        ThreadState::WAIT | ThreadState::UNINT
    };
    if let Some(event) = event {
        let index = wait_hash(event.as_ptr());
        let q = wait_queue(index);
        let lock = wait_lock(index);
        // SAFETY: `index` is below `NUMQUEUES`; the buckets are static
        // storage, and the hash and thread locks are the C order: the bucket
        // first.
        unsafe {
            lock.lock();
            (*thread).lock.lock();
            pin_queue(q).push_back_ptr(NonNull::new_unchecked(thread));
            (*thread).wait_event = event.as_ptr();
            let state = (*thread).state();
            (*thread).set_state(state | add);
            (*thread).lock.unlock();
            lock.unlock();
        }
    } else {
        unsafe {
            (*thread).lock.lock();
            let state = (*thread).state();
            (*thread).set_state(state | add);
            (*thread).lock.unlock();
        }
    }
    // SAFETY: `s` is the level `splsched()` returned.
    unsafe { P::splx(s) };
}

/// Clears `thread`'s wait with `result`, waking it; with `interrupt_only`, an
/// uninterruptible wait is left alone.
///
/// # Safety
///
/// `thread` must be a live thread; the routine takes splsched and the thread
/// and hash locks itself, as the C does.
pub unsafe fn clear_wait<P: Platform>(
    thread: *mut Thread<P>,
    result: c_int,
    interrupt_only: c_int,
) {
    let s = P::splsched();
    // SAFETY: `thread` is live; the lock protects every field below.
    unsafe {
        (*thread).lock.lock();
        if interrupt_only != 0
            && (*thread).state().intersects(ThreadState::UNINT)
        {
            (*thread).lock.unlock();
            P::splx(s);
            return;
        }

        let mut event = (*thread).wait_event;
        if !event.is_null() {
            (*thread).lock.unlock();
            let index = wait_hash(event);
            let q = wait_queue(index);
            let lock = wait_lock(index);
            lock.lock();
            (*thread).lock.lock();
            if (*thread).wait_event == event {
                pin_queue(q).remove_ptr(NonNull::new_unchecked(thread));
                (*thread).wait_event = ptr::null_mut();
                event = ptr::null_mut(); // cause the wakeup below
            }
            lock.unlock();
        }

        if event.is_null() {
            let state = (*thread).state();
            // SAFETY: `thread` is live; the sleeper owns its timeout, but
            // `clear_wait` is the C's cancel point until the resume path
            // stops it.
            Thread::<P>::stop_timer(thread);
            match state & ThreadState::SCHED_STATE {
                ThreadState::WAIT
                | ThreadState::WAIT_UNINT
                | ThreadState::WAIT_SUSP_UNINT => {
                    (*thread).set_state(
                        (state & !ThreadState::WAIT) | ThreadState::RUN,
                    );
                    (*thread).wait_result = result;
                    setrun(thread, true);
                }
                ThreadState::WAIT_SUSP
                | ThreadState::RUN_WAIT
                | ThreadState::RUN_WAIT_SUSP
                | ThreadState::RUN_WAIT_UNINT
                | ThreadState::RUN_WAIT_SUSP_UNINT => {
                    (*thread).set_state(state & !ThreadState::WAIT);
                    (*thread).wait_result = result;
                }
                _ => (),
            }
        }
        (*thread).lock.unlock();
    }
    // SAFETY: `s` is the level `splsched()` returned.
    unsafe { P::splx(s) };
}

/// Wakes the threads waiting on `event`, only the first when `one_thread` is
/// nonzero, with `result`, and returns whether there was one.
///
/// `event` is an opaque key that is hashed and compared, never dereferenced,
/// and the routine takes the locks it needs itself, so any value is safe to
/// pass, before the scheduler starts too: the wait buckets are built empty.
pub fn thread_wakeup_prim<P: Platform>(
    event: *mut c_void,
    one_thread: c_int,
    result: c_int,
) -> bool {
    let index = wait_hash(event);
    let q = wait_queue(index);
    let s = P::splsched();
    let lock = wait_lock(index);
    // SAFETY: the bucket lock is held for the whole walk; the thread lock is
    // taken around each thread's fields.
    let mut woke = false;
    // SAFETY: the bucket lock is held for the whole walk; the thread lock is
    // taken around each thread's fields.
    unsafe {
        lock.lock();
        let mut thread = (*q).cursor_front().current_ptr();
        while let Some(current) = thread {
            let current = current.as_ptr();
            // Capture the successor before the removal.
            let next = {
                let mut cursor = pin_queue(q)
                    .cursor_mut_from_ptr(NonNull::new_unchecked(current));
                cursor.move_next();
                cursor.current_ptr()
            };

            if (*current).wait_event == event {
                (*current).lock.lock();
                pin_queue(q).remove_ptr(NonNull::new_unchecked(current));
                (*current).wait_event = ptr::null_mut();
                // SAFETY: `current` is the live current thread.
                Thread::<P>::stop_timer(current);

                let state = (*current).state();
                match state & ThreadState::SCHED_STATE {
                    ThreadState::WAIT
                    | ThreadState::WAIT_UNINT
                    | ThreadState::WAIT_SUSP_UNINT => {
                        (*current).set_state(
                            (state & !ThreadState::WAIT) | ThreadState::RUN,
                        );
                        (*current).wait_result = result;
                        setrun(current, true);
                    }
                    ThreadState::WAIT_SUSP
                    | ThreadState::RUN_WAIT
                    | ThreadState::RUN_WAIT_SUSP
                    | ThreadState::RUN_WAIT_UNINT
                    | ThreadState::RUN_WAIT_SUSP_UNINT => {
                        (*current).set_state(state & !ThreadState::WAIT);
                        (*current).wait_result = result;
                    }
                    _ => state_panic(current),
                }
                (*current).lock.unlock();
                woke = true;
                if one_thread != 0 {
                    break;
                }
            }
            thread = next;
        }
        lock.unlock();
    }
    // SAFETY: `s` is the level `splsched()` returned.
    unsafe { P::splx(s) };
    woke
}

/// Waits on `event`, releasing `lock` once the wait is declared.
///
/// # Safety
///
/// Same contract as `assert_wait()`, plus `lock` must be a live simple lock
/// held by the current thread, as the C requires.
pub unsafe fn thread_sleep<P: Platform>(
    event: *mut c_void,
    lock: *mut SimpleLock,
    interruptible: c_int,
) {
    unsafe {
        assert_wait::<P>(NonNull::new(event), interruptible);
        (*lock).unlock();
        thread_block::<P>(None);
    }
}

/// Finishes the switch away from `thread`: frees its stack when it resumes
/// through a continuation, and stops, requeues or parks it as its state says.
///
/// # Safety
///
/// `thread` must be a live thread that is not on a run queue, and the caller
/// must be at splsched; the `x86_64` context switch calls
/// [`thread_dispatch_entry`].
pub(crate) unsafe fn thread_dispatch<P: Platform>(thread: *mut Thread<P>) {
    unsafe {
        (*thread).lock.lock();

        if (*thread).swap_func.is_some() {
            (*thread).set_state((*thread).state() | ThreadState::SWAPPED);
            (*thread).stack_free();
        }

        match (*thread).state() & !ThreadState::SWAP_STATE {
            ThreadState::RUN_SUSP
            | ThreadState::RUN_SUSP_HALTED
            | ThreadState::RUN_WAIT_SUSP => {
                (*thread).set_state((*thread).state() & !ThreadState::RUN);
                if (*thread).wake_active() {
                    (*thread).set_wake_active(false);
                    (*thread).lock.unlock();
                    let event = (*thread).wake_active_event();
                    thread_wakeup_prim::<P>(event, 0, THREAD_AWAKENED);
                    return;
                }
            }
            ThreadState::RUN_SUSP_UNINT
            | ThreadState::RUN
            | ThreadState::RUN_UNINT => {
                setrun(thread, false);
            }
            ThreadState::RUN_WAIT_SUSP_UNINT
            | ThreadState::RUN_WAIT_UNINT
            | ThreadState::RUN_WAIT => {
                (*thread).set_state((*thread).state() & !ThreadState::RUN);
            }
            // The idle thread is already in `idle_thread_array`.
            ThreadState::RUN_IDLE => (),
            _ => state_panic(thread),
        }
        (*thread).lock.unlock();
    }
}

/// The entry the context switch calls.
///
/// # Safety
///
/// `thread` must be a live thread that is not on a run queue, and the caller
/// must be at splsched.
pub unsafe extern "C" fn thread_dispatch_entry<P: Platform>(
    thread: *mut Thread<P>,
) {
    unsafe { thread_dispatch(thread) };
}

/// [`setrun`] with an integer preemption flag.
///
/// # Safety
///
/// `thread` must be a live thread locked by the caller, and the caller must be
/// at splsched.
pub(crate) unsafe fn thread_setrun<P: Platform>(
    thread: *mut Thread<P>,
    may_preempt: c_int,
) {
    unsafe { setrun(thread, may_preempt != 0) };
}

/// Picks the thread this processor runs next, possibly the current one.
///
/// # Safety
///
/// The caller must be at splsched, hold no run-queue lock, and `myprocessor`
/// must be the current processor.
unsafe fn thread_select<P: Platform>(
    myprocessor: *mut Processor<P>,
) -> *mut Thread<P> {
    unsafe {
        (*myprocessor).first_quantum.store(1, Ordering::Relaxed);

        if (*myprocessor).runq.count.load(Ordering::Relaxed) > 0 {
            let thread = choose_thread(myprocessor);
            (*myprocessor)
                .quantum
                .store(min_quantum(), Ordering::Relaxed);
            return thread;
        }

        let pset = (*myprocessor).processor_set.load(Ordering::Acquire);
        let runq = &raw mut (*pset).runq;
        (*runq).lock.lock();

        let thread = if (*runq).count.load(Ordering::Relaxed) == 0 {
            let thread = P::cpu_thread();
            if (*thread).state() == ThreadState::RUN
                && (*thread).processor_set == pset
                && ((*thread).bound_processor.is_null()
                    || (*thread).bound_processor == myprocessor)
            {
                (*runq).lock.unlock();
                (*thread).lock.lock();
                if (*thread).sched.sched_stamp != sched_tick() {
                    update_priority(thread);
                }
                (*thread).lock.unlock();
                thread
            } else {
                pset_thread(myprocessor, pset)
            }
        } else {
            let mut low = (*runq).low;
            let mut q = &raw mut (*runq).runq[low as usize];
            if (*q).is_empty() {
                low += 1;
                (*runq).low = low;
                pset_thread(myprocessor, pset)
            } else {
                let thread = run_queue::pin_queue(q)
                    .cursor_front_mut()
                    .remove_current()
                    .map_or(ptr::null_mut(), |si| {
                        Thread::<P>::from_sched(ptr::from_mut(si))
                    });
                (*thread).sched.runq = ptr::null_mut();
                add_single_writer(&(*runq).count, -1);
                // The fixed-priority policy cannot lazily evaluate `runq.low`.
                if (*runq).count.load(Ordering::Relaxed) > 0
                    && (*pset).policies & POLICY_FIXEDPRI != 0
                {
                    while (*q).is_empty() {
                        low += 1;
                        // The count guarantees a non-empty queue above; the
                        // guard keeps a corrupt queue from walking off the
                        // array as the C would.
                        assert!(low < NRQS as c_int, "thread_select");
                        (*runq).low = low;
                        q = &raw mut (*runq).runq[low as usize];
                    }
                }
                (*runq).lock.unlock();
                thread
            }
        };

        if (*thread).sched.policy == POLICY_TIMESHARE {
            (*myprocessor)
                .quantum
                .store((*pset).set_quantum, Ordering::Relaxed);
        } else {
            (*myprocessor)
                .quantum
                .store((*thread).sched.sched_data, Ordering::Relaxed);
        }
        thread
    }
}

/// Hand `old_thread`'s stack to the swapped-out `new_thread` and resume
/// it, as the C's `TH_SWAPPED` arm of [`thread_invoke()`] did.
///
/// # Safety
///
/// Both threads must be live, `new_thread`'s lock must be held, and the
/// caller must be at splsched, as [`thread_invoke()`]'s contract
/// requires.
unsafe fn invoke_swapped<P: Platform>(
    old_thread: *mut Thread<P>,
    new_thread: *mut Thread<P>,
    continuation: crate::thread::Continuation,
) -> ! {
    unsafe {
        (*new_thread).set_state(
            (*new_thread).state()
                & !(ThreadState::SWAPPED | ThreadState::UNINT),
        );
        (*new_thread).lock.unlock();
        thread_wakeup_prim::<P>(
            (*new_thread).state_event(),
            0,
            THREAD_AWAKENED,
        );

        (*new_thread).last_processor = P::cpu_processor().as_ptr();
        ast::context(new_thread, P::current_cpu());
        P::stack_handoff(old_thread, new_thread);

        (*old_thread).lock.lock();
        (*old_thread).swap_func = continuation;
        match (*old_thread).state() {
            ThreadState::RUN_SUSP
            | ThreadState::RUN_SUSP_HALTED
            | ThreadState::RUN_WAIT_SUSP => {
                (*old_thread).set_state(
                    ((*old_thread).state() & !ThreadState::RUN)
                        | ThreadState::SWAPPED,
                );
                if (*old_thread).wake_active() {
                    (*old_thread).set_wake_active(false);
                    (*old_thread).lock.unlock();
                    thread_wakeup_prim::<P>(
                        (*old_thread).wake_active_event(),
                        0,
                        THREAD_AWAKENED,
                    );
                    P::spl0();
                    P::call_continuation((*new_thread).swap_func);
                }
            }
            ThreadState::RUN_SUSP_UNINT
            | ThreadState::RUN_UNINT
            | ThreadState::RUN => {
                (*old_thread)
                    .set_state((*old_thread).state() | ThreadState::SWAPPED);
                thread_setrun(old_thread, 0);
            }
            ThreadState::RUN_WAIT_SUSP_UNINT
            | ThreadState::RUN_WAIT_UNINT
            | ThreadState::RUN_WAIT => {
                (*old_thread).set_state(
                    ((*old_thread).state() & !ThreadState::RUN)
                        | ThreadState::SWAPPED,
                );
            }
            ThreadState::RUN_IDLE => {
                (*old_thread).set_state(
                    ThreadState::RUN
                        | ThreadState::IDLE
                        | ThreadState::SWAPPED,
                );
            }
            _ => state_panic(old_thread),
        }
        (*old_thread).lock.unlock();

        P::spl0();
        P::call_continuation((*new_thread).swap_func);
    }
}

/// Stops running `old_thread` and starts `new_thread`; `false` means a stack
/// is not ready yet and the caller must select again.
///
/// # Safety
///
/// The caller must be at splsched, hold no run-queue lock, and both threads
/// must be live.
pub(crate) unsafe fn thread_invoke<P: Platform>(
    old_thread: *mut Thread<P>,
    continuation: crate::thread::Continuation,
    new_thread: *mut Thread<P>,
) -> bool {
    if old_thread == new_thread {
        unsafe {
            (*new_thread).lock.lock();
            (*new_thread)
                .set_state((*new_thread).state() & !ThreadState::UNINT);
            (*new_thread).lock.unlock();
            thread_wakeup_prim::<P>(
                (*new_thread).state_event(),
                0,
                THREAD_AWAKENED,
            );
        }

        if continuation.is_some() {
            // SAFETY: `spl0()` and `call_continuation()` are the real asm
            // routines, and the continuation does not return into the caller.
            unsafe {
                P::spl0();
                P::call_continuation(continuation);
            }
        }
        return true;
    }

    let handoff = unsafe {
        (*new_thread).lock.lock();
        (*old_thread).stack_privilege != P::cpu_stack()
            && continuation.is_some()
    };

    if handoff {
        unsafe {
            match (*new_thread).state() & ThreadState::SWAP_STATE {
                ThreadState::SWAPPED => {
                    invoke_swapped(old_thread, new_thread, continuation);
                }
                ThreadState::SW_COMING_IN => {
                    thread_swapin(new_thread);
                    (*new_thread).lock.unlock();
                    return false;
                }
                _ => (),
            }
        }
    } else {
        unsafe {
            if (*new_thread).state().intersects(ThreadState::SWAPPED)
                && ((*new_thread)
                    .state()
                    .intersects(ThreadState::SW_COMING_IN)
                    || !(*new_thread).stack_alloc_try(Some(thread_continue)))
            {
                thread_swapin(new_thread);
                (*new_thread).lock.unlock();
                return false;
            }
        }
    }

    unsafe {
        (*new_thread).set_state(
            (*new_thread).state()
                & !(ThreadState::SWAPPED | ThreadState::UNINT),
        );
        (*new_thread).lock.unlock();
        thread_wakeup_prim::<P>(
            (*new_thread).state_event(),
            0,
            THREAD_AWAKENED,
        );

        (*new_thread).last_processor = P::cpu_processor().as_ptr();
        ast::context(new_thread, P::current_cpu());

        let resuming = P::switch_context(old_thread, continuation, new_thread);
        thread_dispatch(resuming);
    }
    true
}

/// Blocks the current thread and runs the next one, resuming at `continuation`
/// when there is one.
///
/// # Safety
///
/// The caller must be the current thread, must not hold a spin lock, and must
/// have set its wait state first when it means to block.
pub unsafe fn thread_block<P: Platform>(
    continuation: crate::thread::Continuation,
) {
    let thread = P::cpu_thread();
    let myprocessor = P::cpu_processor().as_ptr();
    let s = P::splsched();

    mach_sched::ast::off(P::current_cpu(), AstReason::BLOCK);

    loop {
        // SAFETY: at splsched with no run-queue lock, as `thread_select()`
        // requires.
        let new_thread = unsafe { thread_select(myprocessor) };
        // SAFETY: at splsched with no run-queue lock, as `thread_invoke()`
        // requires.
        if unsafe { thread_invoke(thread, continuation, new_thread) } {
            break;
        }
    }

    // SAFETY: `s` is the level `splsched()` returned.
    unsafe { P::splx(s) };
}

/// Switches directly from the current thread to `new_thread`, both runnable.
///
/// # Safety
///
/// The caller must be the current thread, must not hold a spin lock, and
/// `new_thread` must be live and runnable.
pub(crate) unsafe fn thread_run<P: Platform>(
    continuation: crate::thread::Continuation,
    mut new_thread: *mut Thread<P>,
) {
    let thread = P::cpu_thread();
    let myprocessor = P::cpu_processor().as_ptr();
    let s = P::splsched();

    // SAFETY: at splsched with no run-queue lock, as `thread_invoke()`
    // requires.
    while !unsafe { thread_invoke(thread, continuation, new_thread) } {
        // SAFETY: at splsched with no run-queue lock, as `thread_select()`
        // requires.
        new_thread = unsafe { thread_select(myprocessor) };
    }

    // SAFETY: `s` is the level `splsched()` returned.
    unsafe { P::splx(s) };
}

/// The priority catch-up of a thread that has been asleep or suspended, with
/// the `(5/8)**n` decay of used CPU.
///
/// # Safety
///
/// `thread` must be a live thread whose lock the caller holds at splsched.
pub unsafe fn update_priority<P: Platform>(thread: *mut Thread<P>) {
    // SAFETY: the thread and its set are live, and the caller holds the
    // thread lock at splsched.
    unsafe {
        let load = (*(*thread).processor_set).sched_load;
        (*thread).sched.update_priority(load);
    }
}

/// Takes `th` off its run queue and returns that queue, or null
/// when it was not on one.
///
/// # Safety
///
/// `th` must be a live thread whose lock the caller holds.
pub(crate) unsafe fn rem_runq<P: Platform>(
    th: *mut Thread<P>,
) -> *mut RunQueue {
    // SAFETY: the caller's promises are the run queue's.
    unsafe { run_queue::remove(&raw mut (*th).sched) }
}

/// Takes the next thread off the processor's own run queue, or hands the
/// search to `pset_thread`.
///
/// # Panics
///
/// If the run queue counts threads that none of its queues holds.
///
/// # Safety
///
/// The caller must be at splsched and hold no run-queue lock; `myprocessor`
/// must be the current processor.
pub unsafe fn choose_thread<P: Platform>(
    myprocessor: *mut Processor<P>,
) -> *mut Thread<P> {
    unsafe {
        let si = run_queue::dequeue(&raw mut (*myprocessor).runq);
        if !si.is_null() {
            return Thread::<P>::from_sched(si);
        }

        let pset = (*myprocessor).processor_set.load(Ordering::Acquire);
        (*pset).runq.lock.lock();
        pset_thread(myprocessor, pset)
    }
}

/// The idle loop, which parks the processor until [`setrun`] dispatches a
/// thread to it.
///
/// # Safety
///
/// Runs as the processor's own idle thread, at spl0 except where the C raised
/// it.
unsafe extern "C" fn idle_thread_continue<P: Platform>() {
    let mycpu = P::current_cpu();
    let myprocessor = P::cpu_processor();

    loop {
        // The global idle count is the processor set's.
        while myprocessor.next_thread().is_null()
            && !myprocessor.has_runnable()
        {
            if mach_sched::ast::scheduling_pending(mycpu) {
                // SAFETY: `taken()` runs at splsched with no lock held, and
                // it lowers the level itself.
                unsafe {
                    P::splsched();
                    mach_sched::ast::clear_scheduling(mycpu);
                    ast::taken::<P>();
                }
            }
            P::machine_idle(mycpu);
        }

        // The idle thread raises the level before touching the
        // processor state and queues.
        let s = P::splsched();

        'retry: loop {
            // The idle lock protects the queue and the count below.
            match myprocessor.state() {
                ProcessorState::Dispatching => {
                    let new_thread = myprocessor.next_thread();
                    myprocessor.set_next_thread(ptr::null_mut());
                    myprocessor.set_state(ProcessorState::Running);
                    // SAFETY: the dispatch handed over a live runnable
                    // thread, whose set stays live while it holds the thread.
                    let quantum = unsafe {
                        if (*new_thread).sched.policy == POLICY_TIMESHARE {
                            (*(*new_thread).processor_set).set_quantum
                        } else {
                            (*new_thread).sched.sched_data
                        }
                    };
                    myprocessor.set_quantum(quantum);
                    myprocessor.set_first_quantum(true);
                    // SAFETY: the dispatch and the run-queue locks make
                    // `new_thread` the thread this processor must run.
                    unsafe {
                        thread_run(
                            Some(idle_thread_continue::<P>),
                            new_thread,
                        );
                    }
                    break;
                }
                ProcessorState::Idle => {
                    let pset = myprocessor.processor_set();
                    // SAFETY: `pset` is the live processor set of the
                    // running processor.
                    unsafe { (*pset).idle_lock.lock() };
                    if myprocessor.state() != ProcessorState::Idle {
                        // Something happened; try again.
                        // SAFETY: the state changed while the idle lock was
                        // held, so this path releases it.
                        unsafe { (*pset).idle_lock.unlock() };
                        continue 'retry;
                    }
                    let _ = NO_DISPATCH_COUNT.fetch_add(1, Ordering::Relaxed);
                    // SAFETY: the idle lock is held, and the state above
                    // confirms the processor is on the idle queue.
                    unsafe {
                        (*pset).idle_count =
                            (*pset).idle_count.wrapping_sub(1);
                        let _ = (*pset)
                            .idle_queue_pinned()
                            .remove_ptr(myprocessor.as_ptr().cast_const());
                        myprocessor.set_state(ProcessorState::Running);
                        (*pset).idle_lock.unlock();
                    }
                    // SAFETY: the idle lock is released and the processor is
                    // running, so blocking here parks it as the C did.
                    unsafe {
                        thread_block::<P>(Some(idle_thread_continue::<P>));
                    };
                    break;
                }
                ProcessorState::Assign | ProcessorState::Shutdown => {
                    let new_thread = myprocessor.next_thread();
                    if !new_thread.is_null() {
                        myprocessor.set_next_thread(ptr::null_mut());
                        // SAFETY: the dispatch set `next_thread`; the thread
                        // lock protects its run-queue link.
                        unsafe {
                            (*new_thread).lock.lock();
                            thread_setrun(new_thread, 0);
                            (*new_thread).lock.unlock();
                        }
                    }
                    // SAFETY: the processor is leaving its set, so blocking
                    // here parks it as the C did.
                    unsafe {
                        thread_block::<P>(Some(idle_thread_continue::<P>));
                    };
                    break;
                }
                state
                @ (ProcessorState::OffLine | ProcessorState::Running) => {
                    P::print(format_args!(
                        " Bad processor state {state:?} (Cpu {mycpu})\n"
                    ));
                    panic!("idle_thread")
                }
            }
        }
        // SAFETY: `s` is the level `splsched()` returned.
        unsafe { P::splx(s) };
    }
}

/// Starts the processor's idle thread.
///
/// # Safety
///
/// The boot path starts this as the processor's idle thread; it never returns.
pub(crate) unsafe fn idle_thread<P: Platform>() {
    unsafe {
        let me = P::cpu_thread();
        (*me).stack_privilege();
        let s = P::splsched();
        (*me).sched.priority = NRQS as c_int - 1;
        (*me).sched.sched_pri = NRQS as c_int - 1;

        (*me).lock.lock();
        (*me).set_state((*me).state() | ThreadState::IDLE);
        (*me).lock.unlock();
        P::cpu_processor().set_idle_thread(me);
        P::splx(s);

        thread_block::<P>(Some(idle_thread_continue::<P>));
        idle_thread_continue::<P>();
    }
}

/// The kernel-thread entry of `idle_thread`.
///
/// # Safety
///
/// The boot path starts this as the processor's idle thread; it never returns.
pub unsafe extern "C" fn idle_thread_entry<P: Platform>() {
    unsafe { idle_thread::<P>() };
}

/// The scheduler thread's loop: recomputes the mach factors, scans for stuck
/// threads every other tick, then waits for the next wakeup.
unsafe extern "C" fn sched_thread_continue<P: Platform>() {
    loop {
        // SAFETY: the scan runs at spl0 with no lock held, as the C did.
        unsafe {
            mach_factor::compute::<P>();
            if sched_tick() & 1 != 0 {
                do_thread_scan::<P>();
            }
            assert_wait::<P>(None, 0);
            thread_block::<P>(Some(sched_thread_continue::<P>));
        }
    }
}

/// The scheduler thread, woken by [`recompute_priorities_start`]'s timer once
/// a second.
///
/// # Safety
///
/// The boot path starts this as the "sched" kernel thread; it never returns.
pub(crate) unsafe fn sched_thread<P: Platform>() {
    unsafe {
        P::task_state()
            .sched_thread
            .store(P::cpu_thread(), Ordering::Release);
        assert_wait::<P>(None, 0);
        thread_block::<P>(Some(sched_thread_continue::<P>));
        sched_thread_continue::<P>();
    }
}

/// The kernel-thread entry of `sched_thread`.
///
/// # Safety
///
/// The boot path starts this as the "sched" kernel thread; it never returns.
pub unsafe extern "C" fn sched_thread_entry<P: Platform>() {
    unsafe { sched_thread::<P>() };
}

/// Passes one of the stuck-thread scan, moving the candidates off `runq`.
/// `true` means the array ran out of room.
///
/// # Safety
///
/// The caller must hold no run-queue lock, and `runq` must be live.
unsafe fn do_runq_scan<P: Platform>(runq: *mut RunQueue) -> bool {
    let s = P::splsched();
    unsafe {
        (*runq).lock.lock();
        let mut count = (*runq).count.load(Ordering::Relaxed);
        if count > 0 {
            let mut q = &raw mut (*runq).runq[(*runq).low as usize];
            while count > 0 {
                let mut record = (*q).cursor_front().current_ptr();
                while let Some(si) = record {
                    let si = si.as_ptr();
                    let current = Thread::<P>::from_sched(si);
                    // Capture the successor before the removal.
                    let next = {
                        let mut cursor = run_queue::pin_queue(q)
                            .cursor_mut_from_ptr(NonNull::new_unchecked(si));
                        cursor.move_next();
                        cursor.current_ptr()
                    };

                    if (*current).state() & ThreadState::SCHED_STATE
                        == ThreadState::RUN
                        && sched_tick()
                            .wrapping_sub((*current).sched.sched_stamp)
                            > 1
                    {
                        if STUCK_COUNT.load(Ordering::Relaxed)
                            == MAX_STUCK_THREADS as c_int
                        {
                            (*runq).lock.unlock();
                            P::splx(s);
                            return true;
                        }
                        // A RUN thread cannot be deallocated until it stops
                        // running, so taking it off the queue here makes the
                        // later unlocked update safe.
                        run_queue::pin_queue(q)
                            .remove_ptr(NonNull::new_unchecked(si));
                        add_single_writer(&(*runq).count, -1);
                        (*current).sched.runq = ptr::null_mut();
                        let index =
                            STUCK_COUNT.fetch_add(1, Ordering::Relaxed);
                        P::task_state().stuck_threads[index as usize]
                            .store(current, Ordering::Relaxed);
                        if DO_THREAD_SCAN_DEBUG.load(Ordering::Relaxed) != 0 {
                            P::print(format_args!(
                                "do_runq_scan: adding thread {:x}\n",
                                current.expose_provenance()
                            ));
                        }
                    }
                    count -= 1;
                    record = next;
                }
                q = q.add(1);
            }
        }
        (*runq).lock.unlock();
        P::splx(s);
    }
    false
}

/// Passes two of the stuck-thread scan, updating the priority of every thread
/// it found.
///
/// # Safety
///
/// Runs in thread context with no lock held; the scan takes the locks it
/// needs.
pub(crate) unsafe fn do_thread_scan<P: Platform>() {
    let mut restart_needed = false;
    loop {
        let all_psets = P::task_state().all_psets.lock();
        let mut cursor = all_psets.list().cursor_front();
        while let Some(pset) = cursor.current_ptr() {
            cursor.move_next();
            // SAFETY: the set is live while it is on the list, and each run
            // queue has its own lock taken by `do_runq_scan`.
            if unsafe { do_runq_scan::<P>(&raw mut (*pset.as_ptr()).runq) } {
                restart_needed = true;
                break;
            }
        }
        drop(all_psets);

        if !restart_needed {
            for processor in processor::iter::<P>() {
                // SAFETY: the processor record is static, and the
                // projection only computes the field's address.
                let runq = unsafe { &raw mut (*processor.as_ptr()).runq };
                // SAFETY: the run queue is the live one of the probed CPU.
                if unsafe { do_runq_scan::<P>(runq) } {
                    restart_needed = true;
                    break;
                }
            }
        }

        while STUCK_COUNT.load(Ordering::Relaxed) > 0 {
            // The array holds `STUCK_COUNT` live threads.
            let index =
                (STUCK_COUNT.fetch_sub(1, Ordering::Relaxed) - 1) as usize;
            let thread = P::task_state().stuck_threads[index]
                .swap(ptr::null_mut(), Ordering::Relaxed);
            let s = P::splsched();
            // SAFETY: the thread is live and off every run queue; its lock
            // protects the state and priority fields.
            unsafe {
                (*thread).lock.lock();
                if (*thread).state() & ThreadState::SCHED_STATE
                    == ThreadState::RUN
                {
                    update_priority(thread);
                    thread_setrun(thread, 1);
                }
                (*thread).lock.unlock();
                P::splx(s);
            }
        }

        if !restart_needed {
            break;
        }
    }
}

/// Recomputes `thread`'s priority from its base and its usage, rescheduling it
/// when `resched` is set.
///
/// # Safety
///
/// `thread` must be a live thread whose lock the caller holds.
unsafe fn recompute_priority<P: Platform>(
    thread: *mut Thread<P>,
    resched: bool,
) {
    unsafe {
        if (*thread).sched.policy == POLICY_TIMESHARE {
            let pri = (*thread).sched.priority_computation();
            if (*thread).sched.depress_priority < 0 {
                set_priority(thread, pri, resched);
            } else {
                (*thread).sched.depress_priority = pri;
            }
        } else {
            set_priority(thread, (*thread).sched.priority, resched);
        }
    }
}

/// Sets `th`'s scheduled priority to `pri`, moving it between run queues as
/// needed.
///
/// # Safety
///
/// `th` must be a live thread whose lock the caller holds, and the caller must
/// be at splsched.
pub(crate) unsafe fn set_priority<P: Platform>(
    th: *mut Thread<P>,
    pri: c_int,
    resched: bool,
) {
    unsafe {
        let rq = rem_runq(th);
        (*th).sched.sched_pri = pri;
        if !rq.is_null() {
            if resched {
                setrun(th, true);
            } else {
                enqueue_run_queue(rq, th);
            }
        }
    }
}

/// Takes the next thread off the processor set's run queue, or returns the
/// processor's idle thread.
///
/// # Safety
///
/// The caller must be at splsched, must hold `pset`'s run-queue lock, and
/// `myprocessor` must be the current processor with `pset` its processor set.
unsafe fn pset_thread<P: Platform>(
    myprocessor: *mut Processor<P>,
    pset: *mut ProcessorSet<P>,
) -> *mut Thread<P> {
    unsafe {
        let runq = &raw mut (*pset).runq;
        let mut i = (*runq).low;
        if (*runq).count.load(Ordering::Relaxed) > 0 {
            while i < NRQS as c_int {
                let mut q = &raw mut (*runq).runq[i as usize];
                if !(*q).is_empty() {
                    let th = run_queue::pin_queue(q)
                        .cursor_front_mut()
                        .remove_current()
                        .map_or(ptr::null_mut(), |si| {
                            Thread::<P>::from_sched(ptr::from_mut(si))
                        });
                    (*th).sched.runq = ptr::null_mut();
                    add_single_writer(&(*runq).count, -1);
                    if (*runq).count.load(Ordering::Relaxed) > 0
                        && (*pset).policies & POLICY_FIXEDPRI != 0
                    {
                        while (*q).is_empty() {
                            i += 1;
                            assert!(i < NRQS as c_int, "choose_pset_thread");
                            q = &raw mut (*runq).runq[i as usize];
                        }
                    }
                    (*runq).low = i;
                    (*runq).lock.unlock();
                    return th;
                }
                i += 1;
            }
            panic!("choose_pset_thread")
        }
        (*runq).lock.unlock();
    }

    unsafe {
        (*pset).idle_lock.lock();
        if (*myprocessor).state.load(Ordering::Acquire)
            == ProcessorState::Running
        {
            (*myprocessor)
                .state
                .store(ProcessorState::Idle, Ordering::Release);
            if myprocessor == processor::boot_processor() {
                (*pset)
                    .idle_queue_pinned()
                    .push_back_ptr(NonNull::new_unchecked(myprocessor));
            } else {
                (*pset)
                    .idle_queue_pinned()
                    .push_front_ptr(NonNull::new_unchecked(myprocessor));
            }
            (*pset).idle_count = (*pset).idle_count.wrapping_add(1);
        }
        (*pset).idle_lock.unlock();

        (*myprocessor).idle_thread.load(Ordering::Relaxed)
    }
}

/// Arms the current thread's timeout for `t` ticks.
///
/// # Safety
///
/// Must be called between `assert_wait()` and `thread_block()` for the current
/// thread, as the C documents.
pub unsafe fn thread_set_timeout<P: Platform>(t: c_int) {
    let thread = P::cpu_thread();
    let s = P::splsched();
    // SAFETY: `thread` is the current thread; its lock protects the state and
    // the timer element, as in C.
    unsafe {
        (*thread).lock.lock();
        if (*thread).state().intersects(ThreadState::WAIT) {
            // A negative interval is a long wait, as the C `unsigned` cast
            // spelled; `Ticks` is 64-bit so it does not wrap.
            let ticks = if t < 0 {
                clock::Ticks::new(u64::from(t as c_uint))
            } else {
                clock::Ticks::new(t as u64)
            };
            // SAFETY: `thread` is the current thread and will not move.
            Thread::<P>::start_timer(thread, ticks);
        }
        (*thread).lock.unlock();
        P::splx(s);
    }
}

/// Binds `thread` to `processor`, or unbinds it when `processor` is null.
///
/// # Safety
///
/// `thread` must be a live thread, and `processor` must be a live processor or
/// null.
pub unsafe fn thread_bind<P: Platform>(
    thread: *mut Thread<P>,
    processor: *mut Processor<P>,
) {
    let s = P::splsched();
    unsafe {
        (*thread).lock.lock();
        (*thread).bound_processor = processor;
        (*thread).lock.unlock();
        P::splx(s);
    }
}

/// The first code a resumed thread runs: finishes the switch away from
/// `old_thread`, lowers the level and calls the continuation.
///
/// # Safety
///
/// The caller runs this on the current thread, at splsched, after a stack
/// swap; `old_thread` must be a live thread the context switch left to
/// dispatch, or null when there is none.
pub(crate) unsafe extern "C" fn thread_continue<P: Platform>(
    old_thread: *mut Thread<P>,
) {
    let continuation = unsafe { (*P::cpu_thread()).swap_func };

    if !old_thread.is_null() {
        unsafe { thread_dispatch(old_thread) };
    }
    // SAFETY: a resumed thread lowers the level once the switch is finished.
    unsafe { P::spl0() };

    // SAFETY: the C calls the continuation unconditionally; a null `swap_func`
    // means the thread was resumed without one, which cannot happen, so the
    // halt spells out what the C null call did.
    unsafe {
        match continuation {
            Some(continuation) => continuation(),
            None => panic!("thread_continue: null continuation"),
        }
    }
}

/// [`recompute_priority`] with an integer reschedule flag.
///
/// # Safety
///
/// `thread` must be a live thread whose lock the caller holds.
pub(crate) unsafe fn compute_priority<P: Platform>(
    thread: *mut Thread<P>,
    resched: c_int,
) {
    unsafe { recompute_priority(thread, resched != 0) };
}

/// Recomputes `thread`'s scheduled priority, without moving it between run
/// queues.
///
/// # Safety
///
/// The caller must hold the thread lock and know the thread is timesharing and
/// not depressed, as the C documents.
pub(crate) unsafe fn compute_my_priority<P: Platform>(thread: *mut Thread<P>) {
    unsafe { (*thread).sched.compute_my_priority() };
}

/// The expiry of the priority recomputation callout, which re-arms itself.
pub(crate) fn recompute_priorities_action<P: Platform>(
    callout: Pin<&Callout<P>>,
) {
    mach_sched::sched::advance_sched_tick();
    // A periodic 1 Hz timer, which its own action re-arms.
    callout.start(clock::Ticks::new(CLOCK_HZ as u64));
    let thread = P::task_state().sched_thread.load(Ordering::Acquire);
    if !thread.is_null() {
        // SAFETY: `thread` is the live scheduler thread the scan armed.
        unsafe { clear_wait(thread, THREAD_AWAKENED, 0) };
    }
}

/// Arms the periodic scan.
pub fn recompute_priorities_start<P: Platform>() {
    Pin::static_ref(&P::task_state().recompute_priorities_timer)
        .start(clock::Ticks::new(CLOCK_HZ as u64));
}
