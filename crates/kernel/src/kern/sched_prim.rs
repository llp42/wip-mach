// SPDX-License-Identifier: CMU-Mach
// Derived from kern/sched_prim.c:
//   Copyright (c) 1993-1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The wait/wake and run-queue scheduler primitives, which `kern/sched_prim.c`
//! used to define and `kern/sched_prim.h` declares.

use crate::arch::x86_64::clock_platform::{MachCallout, wheel};
use crate::arch::x86_64::model_dep::machine_idle;
use crate::arch::x86_64::pcb::{stack_handoff, switch_context};
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::spl;
use crate::kern::ast::{self, AstReason};
use crate::kern::console::kprint;
use crate::kern::debug::kpanic;
use crate::kern::lock::SimpleLock;
use crate::kern::mach_factor;
use crate::kern::machine;
use crate::kern::policy::{POLICY_FIXEDPRI, POLICY_TIMESHARE};
use crate::kern::processor::{
    self, Processor, ProcessorRef, ProcessorSet, ProcessorState,
};
use crate::kern::sched::{
    NRQS, PRI_SHIFT, RUN_QUEUE_NULL, RunQueue, SCHED_SHIFT, add_single_writer,
};
use crate::kern::thread::{
    TH_HALTED, TH_IDLE, TH_RUN, TH_SCHED_STATE, TH_SUSP, TH_SW_COMING_IN,
    TH_SWAP_STATE, TH_SWAPPED, TH_UNINT, TH_WAIT, Thread, ThreadQueue,
};
use crate::kern::thread_swap::thread_swapin;
use crate::utils::cell::SyncCell;
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_uint, c_void};
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU32, Ordering};

/// `NUMQUEUES` in `kern/sched_prim.c`: the size of the event hash table.
pub const NUMQUEUES: usize = 1031;

/// `THREAD_AWAKENED` in <`kern/sched_prim.h>`: a normal wakeup.
pub const THREAD_AWAKENED: c_int = 0;
/// `THREAD_TIMED_OUT`: the timeout expired.
pub const THREAD_TIMED_OUT: c_int = 1;
/// `THREAD_INTERRUPTED`: `clear_wait()` interrupted the wait.
pub const THREAD_INTERRUPTED: c_int = 2;
/// `THREAD_RESTART`: restart the operation entirely.
pub const THREAD_RESTART: c_int = 3;

/// `TH_WAIT | TH_UNINT`: waiting, and not to be interrupted.
pub const TH_WAIT_UNINT: u32 = TH_WAIT | TH_UNINT;
/// `TH_WAIT | TH_SUSP`: waiting, and suspended.
pub const TH_WAIT_SUSP: u32 = TH_WAIT | TH_SUSP;
/// `TH_WAIT | TH_SUSP | TH_UNINT`: waiting and suspended, and not to be
/// interrupted.
pub const TH_WAIT_SUSP_UNINT: u32 = TH_WAIT | TH_SUSP | TH_UNINT;
/// `TH_RUN | TH_WAIT`: runnable, but waiting on an event.
pub const TH_RUN_WAIT: u32 = TH_RUN | TH_WAIT;
/// `TH_RUN | TH_WAIT | TH_SUSP`: runnable, waiting and suspended.
pub const TH_RUN_WAIT_SUSP: u32 = TH_RUN | TH_WAIT | TH_SUSP;
/// `TH_RUN | TH_WAIT | TH_UNINT`: runnable and waiting, and not to be
/// interrupted.
pub const TH_RUN_WAIT_UNINT: u32 = TH_RUN | TH_WAIT | TH_UNINT;
/// `TH_RUN | TH_WAIT | TH_SUSP | TH_UNINT`: runnable, waiting and
/// suspended, and not to be interrupted.
pub const TH_RUN_WAIT_SUSP_UNINT: u32 = TH_RUN | TH_WAIT | TH_SUSP | TH_UNINT;
/// `TH_RUN | TH_UNINT`: runnable, and not to be interrupted.
pub const TH_RUN_UNINT: u32 = TH_RUN | TH_UNINT;
/// `TH_RUN | TH_SUSP`: runnable, and suspended.
pub const TH_RUN_SUSP: u32 = TH_RUN | TH_SUSP;
/// `TH_RUN | TH_SUSP | TH_HALTED`: runnable, suspended and halted at a
/// clean point.
pub const TH_RUN_SUSP_HALTED: u32 = TH_RUN | TH_SUSP | TH_HALTED;
/// `TH_RUN | TH_SUSP | TH_UNINT`: runnable and suspended, and not to be
/// interrupted.
pub const TH_RUN_SUSP_UNINT: u32 = TH_RUN | TH_SUSP | TH_UNINT;
/// `TH_RUN | TH_IDLE`: the state of a processor's idle thread.
pub const TH_RUN_IDLE: u32 = TH_RUN | TH_IDLE;

/// `MAX_STUCK_THREADS` in `kern/sched_prim.c`: the stuck-thread scan's array
/// size.
const MAX_STUCK_THREADS: usize = 16;

/// `sched_tick` of `kern/sched_prim.c`: the seconds counter that ages
/// priorities.  `kern/priority.c` still reads the symbol, so it keeps the C
/// name and width; the accesses are `Relaxed` because no data rides on the
/// counter, the thread lock serializes the fields it compares.
static SCHED_TICK: AtomicU32 = AtomicU32::new(0);

/// `min_quantum` of `kern/sched_prim.c`: the shortest processor quantum, in
/// ticks.  `kern/priority.c` and `kern/syscall_subr.c` still read the symbol.
static MIN_QUANTUM_TICKS: AtomicI32 = AtomicI32::new(0);

/// `sched_thread_id` of `kern/sched_prim.c`: the scheduler thread
/// `recompute_priorities()` wakes.
static SCHED_THREAD_ID: AtomicPtr<Thread> = AtomicPtr::new(ptr::null_mut());

/// `recompute_priorities_timer` of `kern/sched_prim.c`: a leaked static
/// callout, never dropped.
static RECOMPUTE_PRIORITIES_TIMER: MachCallout =
    MachCallout::new(wheel(), recompute_priorities_action, ());

/// `wait_queue[NUMQUEUES]` of `kern/sched_prim.c`: one bucket per hash value.
static WAIT_QUEUE: SyncCell<[ThreadQueue; NUMQUEUES]> =
    SyncCell(UnsafeCell::new([const { ThreadQueue::new() }; NUMQUEUES]));

/// `wait_lock[NUMQUEUES]` of `kern/sched_prim.c`: the bucket locks.
static WAIT_LOCK: [SimpleLock; NUMQUEUES] =
    [const { SimpleLock::new() }; NUMQUEUES];

/// `stuck_threads[MAX_STUCK_THREADS]` of `kern/sched_prim.c`.  Only the
/// stuck-thread scan touches it, at splsched on one CPU at a time, so the
/// accesses are `Relaxed`.
static STUCK_THREADS: [AtomicPtr<Thread>; MAX_STUCK_THREADS] =
    [const { AtomicPtr::new(ptr::null_mut()) }; MAX_STUCK_THREADS];

/// `stuck_count` of `kern/sched_prim.c`, with the same `Relaxed` accesses as
/// [`STUCK_THREADS`].
static STUCK_COUNT: AtomicI32 = AtomicI32::new(0);

/// `do_thread_scan_debug` of `kern/sched_prim.c`, read by the scan under the
/// run-queue lock; the flag never changes at run time.
static DO_THREAD_SCAN_DEBUG: AtomicI32 = AtomicI32::new(0);

/// `no_dispatch_count` of `kern/sched_prim.c`: how often an idle processor went
/// non-idle without a dispatch.  The C incremented it and nothing read it.
static NO_DISPATCH_COUNT: AtomicI32 = AtomicI32::new(0);

/// `struct shift` of <kern/sched.h>: one `(5/8)**n` approximation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Shift {
    shift1: c_int,
    shift2: c_int,
}

/// `wait_shift[32]` of `kern/sched_prim.c`: the shift pairs.
const WAIT_SHIFT: [Shift; 32] = [
    Shift {
        shift1: 1,
        shift2: 1,
    },
    Shift {
        shift1: 1,
        shift2: 3,
    },
    Shift {
        shift1: 1,
        shift2: -3,
    },
    Shift {
        shift1: 2,
        shift2: -7,
    },
    Shift {
        shift1: 3,
        shift2: 5,
    },
    Shift {
        shift1: 3,
        shift2: -5,
    },
    Shift {
        shift1: 4,
        shift2: -8,
    },
    Shift {
        shift1: 5,
        shift2: 7,
    },
    Shift {
        shift1: 5,
        shift2: -7,
    },
    Shift {
        shift1: 6,
        shift2: -10,
    },
    Shift {
        shift1: 7,
        shift2: 10,
    },
    Shift {
        shift1: 7,
        shift2: -9,
    },
    Shift {
        shift1: 8,
        shift2: -11,
    },
    Shift {
        shift1: 9,
        shift2: 12,
    },
    Shift {
        shift1: 9,
        shift2: -11,
    },
    Shift {
        shift1: 10,
        shift2: -13,
    },
    Shift {
        shift1: 11,
        shift2: 14,
    },
    Shift {
        shift1: 11,
        shift2: -13,
    },
    Shift {
        shift1: 12,
        shift2: -15,
    },
    Shift {
        shift1: 13,
        shift2: 17,
    },
    Shift {
        shift1: 13,
        shift2: -15,
    },
    Shift {
        shift1: 14,
        shift2: -17,
    },
    Shift {
        shift1: 15,
        shift2: 19,
    },
    Shift {
        shift1: 16,
        shift2: 18,
    },
    Shift {
        shift1: 16,
        shift2: -19,
    },
    Shift {
        shift1: 17,
        shift2: 22,
    },
    Shift {
        shift1: 18,
        shift2: 20,
    },
    Shift {
        shift1: 18,
        shift2: -20,
    },
    Shift {
        shift1: 19,
        shift2: 26,
    },
    Shift {
        shift1: 20,
        shift2: 22,
    },
    Shift {
        shift1: 20,
        shift2: -22,
    },
    Shift {
        shift1: 21,
        shift2: -27,
    },
];

/// The `sched_tick` counter, as the C read it.
pub(crate) fn sched_tick() -> c_uint {
    SCHED_TICK.load(Ordering::Relaxed)
}

/// The `min_quantum` value, as the C read it.
pub(crate) fn min_quantum() -> c_int {
    MIN_QUANTUM_TICKS.load(Ordering::Relaxed)
}

/// The `wait_hash()` macro of `kern/sched_prim.c`.
fn wait_hash(event: *mut c_void) -> usize {
    let bits = event as isize;
    let folded = if bits < 0 { !bits } else { bits };
    // The folded value is non-negative and the modulo is below `NUMQUEUES`, so
    // the cast cannot lose anything.
    (folded % NUMQUEUES as isize) as usize
}

/// The wait bucket `index` names.
fn wait_queue(index: usize) -> *mut ThreadQueue {
    // SAFETY: `index` is below `NUMQUEUES`, the array's length, and only a
    // pointer is handed out.
    unsafe { WAIT_QUEUE.0.get().cast::<ThreadQueue>().add(index) }
}

/// Pins the thread queue at `q`, a run queue or a wait bucket, for one
/// operation.
///
/// # Safety
///
/// `q` must be a run queue or a wait bucket, which never move, and the caller
/// must hold the lock that guards it for as long as it uses the result.
const unsafe fn pin_queue<'a>(
    q: *mut ThreadQueue,
) -> Pin<&'a mut ThreadQueue> {
    // SAFETY: the queue never moves, and the lock the caller holds keeps
    // anything else from reaching it.
    unsafe { Pin::new_unchecked(&mut *q) }
}

/// The wait lock `index` names.
fn wait_lock(index: usize) -> &'static SimpleLock {
    &WAIT_LOCK[index]
}

/// The `state_panic()` macro of `kern/sched_prim.c`: a thread state the
/// scheduler cannot classify is fatal, with the C message.
fn state_panic(thread: *mut Thread) -> ! {
    // SAFETY: the caller holds the thread lock and `thread` is live.
    let state = unsafe { (*thread).state() };
    let tag = |bit: u32, on: &'static str| -> &'static str {
        if state & bit != 0 { on } else { "" }
    };
    kpanic!(
        "state_panic",
        "thread {:x} has unexpected state {:x} ({}{}{}{}{}{}{}{})",
        thread.expose_provenance(),
        state,
        tag(TH_WAIT, "TH_WAIT|"),
        tag(TH_SUSP, "TH_SUSP|"),
        tag(TH_RUN, "TH_RUN|"),
        tag(TH_UNINT, "TH_UNINT|"),
        tag(TH_HALTED, "TH_HALTED|"),
        tag(TH_IDLE, "TH_IDLE|"),
        tag(TH_SWAPPED, "TH_SWAPPED|"),
        tag(TH_SW_COMING_IN, "TH_SW_COMING_IN|"),
    )
}

/// `sched_init()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// `kern/startup.c` calls this once during the boot, before any other CPU or
/// thread can reach the scheduler.
pub(crate) unsafe fn sched_init() {
    MIN_QUANTUM_TICKS.store(machine::CLOCK_HZ / 33, Ordering::Relaxed);

    // SAFETY: the processor module owns the processor sets and the machine
    // module the action globals, and this is the boot step that builds them.
    unsafe {
        processor::bootstrap();
        (*machine::action_lock()).init();
    }

    SCHED_TICK.store(0, Ordering::Relaxed);
    // No other CPU is running yet, so no AST can be pending.
    ast::init();
}

/// The `run_queue_enqueue()` macro of `kern/sched_prim.c`, non-DEBUG branch.
///
/// # Safety
///
/// `rq` must be a live run queue and `th` a locked thread, at splsched; the
/// caller may hold the thread lock.
unsafe fn enqueue_run_queue(rq: *mut RunQueue, th: *mut Thread) {
    unsafe {
        // The C assigns the signed priority to an `unsigned int`, so a
        // negative value fails the bounds check below and is clamped.
        let mut whichq = (*th).sched_pri as c_uint;
        if whichq >= NRQS as c_uint {
            kprint!("thread_setrun: pri too high ({})\n", (*th).sched_pri);
            whichq = NRQS as c_uint - 1;
        }

        (*rq).lock.lock();
        pin_queue(&raw mut (*rq).runq[whichq as usize])
            .push_back_ptr(NonNull::new_unchecked(th));
        // The C compares the unsigned index against the signed `low`; `low` is
        // a queue index in `0..NRQS`.
        if whichq < (*rq).low as c_uint
            || (*rq).count.load(Ordering::Relaxed) == 0
        {
            (*rq).low = whichq as c_int;
        }
        add_single_writer(&(*rq).count, 1);
        (*th).runq = rq;
        (*rq).lock.unlock();
    }
}

/// Take the first processor off `pset`'s idle queue.
///
/// # Safety
///
/// The caller must hold `pset`'s `idle_lock` and have established that the
/// queue is non-empty.
unsafe fn idle_queue_pop(pset: *mut ProcessorSet) -> *mut Processor {
    unsafe {
        (*pset)
            .idle_queue_pinned()
            .pop_front()
            .map_or(ptr::null_mut(), ptr::from_mut)
    }
}

/// Whether `th` is already scheduled: on a run queue, chosen as some
/// processor's `next_thread`, or running on a CPU.
///
/// # Safety
///
/// `th` must be a live thread locked by the caller, and the caller must be at
/// splsched.
unsafe fn already_scheduled(th: *mut Thread) -> bool {
    if unsafe { (*th).runq } != RUN_QUEUE_NULL {
        return true;
    }
    per_cpu::iter()
        .zip(processor::iter())
        .any(|(block, processor)| {
            processor.next_thread() == th || block.thread() == th
        })
}

/// `thread_setrun()` of `kern/sched_prim.c`, the core: make `th` runnable,
/// dispatching it straight to an idle processor when one waits, else enqueuing
/// it.  A thread that is already scheduled is left alone, so a duplicate call
/// is harmless.
///
/// # Safety
///
/// `th` must be a live thread locked by the caller, and the caller must be at
/// splsched.
fn setrun(th: *mut Thread, may_preempt: bool) {
    // SAFETY: every field read is protected by the thread lock, and the
    // run queues by their own locks. A bound processor and an idle-queue
    // entry are both static processor records.
    unsafe {
        if already_scheduled(th) {
            return;
        }

        if (*th).sched_stamp != sched_tick() {
            update_priority(th);
        }

        let mut processor = (*th).bound_processor;
        if processor.is_null() {
            let pset = (*th).processor_set;
            if (*pset).idle_count > 0 {
                (*pset).idle_lock.lock();
                if (*pset).idle_count > 0 {
                    processor = idle_queue_pop(pset);
                    (*pset).idle_count -= 1;
                    (*processor).next_thread.store(th, Ordering::Release);
                    (*processor)
                        .state
                        .store(ProcessorState::Dispatching, Ordering::Release);
                    (*pset).idle_lock.unlock();
                    if processor != per_cpu::processor().as_ptr() {
                        ProcessorRef::from_static(processor).ast_check();
                    }
                    return;
                }
                (*pset).idle_lock.unlock();
            }
            let rq = &raw mut (*pset).runq;
            enqueue_run_queue(rq, th);
            if may_preempt
                && pset == per_cpu::processor().processor_set()
                && (*per_cpu::thread()).sched_pri > (*th).sched_pri
            {
                per_cpu::processor().set_first_quantum(false);
                ast::on(cpu_id(), AstReason::BLOCK);
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
                    if processor != per_cpu::processor().as_ptr() {
                        ProcessorRef::from_static(processor).ast_check();
                    }
                    return;
                }
                (*pset).idle_lock.unlock();
                (*processor).lock.unlock();
            }
            let rq = &raw mut (*processor).runq;
            enqueue_run_queue(rq, th);

            if processor == per_cpu::processor().as_ptr() {
                ast::on(cpu_id(), AstReason::BLOCK);
            } else if (*processor).state.load(Ordering::Acquire)
                != ProcessorState::OffLine
            {
                ProcessorRef::from_static(processor).ast_check();
            }
        }
    }
}

/// `thread_timeout_setup()` of `kern/sched_prim.c`: the callouts carry
/// their actions in the [`Thread::new`] image, so this is only the C
/// shape kept for the create path.
///
/// # Safety
///
/// `thread` must be a live, freshly created thread that no other CPU can see
/// yet, as in C.
pub(crate) const unsafe fn thread_timeout_setup(_thread: *mut Thread) {}

/// `assert_wait()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// Called from a thread context with interrupts at a level that prevents the
/// wakeup from being lost, and with the current thread not already waiting on
/// an event.
pub(crate) unsafe fn assert_wait(
    event: Option<NonNull<c_void>>,
    interruptible: c_int,
) {
    let thread = per_cpu::thread();
    // SAFETY: `thread` is the current thread; the C tests the field before
    // raising splsched, so the order stays.
    let wait_event = unsafe { (*thread).wait_event };
    if !wait_event.is_null() {
        kpanic!(
            "assert_wait",
            "assert_wait: already asserted event {:x}\n",
            wait_event.expose_provenance()
        )
    }
    // SAFETY: `splsched()` is the real asm routine of <machine/spl.h>;
    // the value is only handed back to the matching `splx()`.
    let s = unsafe { spl::splsched() };
    let add = if interruptible != 0 {
        TH_WAIT
    } else {
        TH_WAIT | TH_UNINT
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
    unsafe { spl::splx(s) };
}

/// `clear_wait()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// `thread` must be a live thread; the routine takes splsched and the thread
/// and hash locks itself, as the C does.
pub(crate) unsafe fn clear_wait(
    thread: *mut Thread,
    result: c_int,
    interrupt_only: c_int,
) {
    // SAFETY: `splsched()` is the real asm routine of <machine/spl.h>;
    // the value is only handed back to the matching `splx()`.
    let s = unsafe { spl::splsched() };
    // SAFETY: `thread` is live; the lock protects every field below.
    unsafe {
        (*thread).lock.lock();
        if interrupt_only != 0 && (*thread).state() & TH_UNINT != 0 {
            (*thread).lock.unlock();
            spl::splx(s);
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
            // SAFETY: `thread` is live; the sleeper owns its timeout
            // (ADR 0028) but `clear_wait` is the C's cancel point until
            // the resume path stops it.
            Thread::stop_timer(thread);
            match state & TH_SCHED_STATE {
                TH_WAIT | TH_WAIT_UNINT | TH_WAIT_SUSP_UNINT => {
                    (*thread).set_state((state & !TH_WAIT) | TH_RUN);
                    (*thread).wait_result = result;
                    setrun(thread, true);
                }
                TH_WAIT_SUSP
                | TH_RUN_WAIT
                | TH_RUN_WAIT_SUSP
                | TH_RUN_WAIT_UNINT
                | TH_RUN_WAIT_SUSP_UNINT => {
                    (*thread).set_state(state & !TH_WAIT);
                    (*thread).wait_result = result;
                }
                _ => (),
            }
        }
        (*thread).lock.unlock();
    }
    // SAFETY: `s` is the level `splsched()` returned.
    unsafe { spl::splx(s) };
}

/// `thread_wakeup_prim()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// `event` is an opaque key; the C signature passes a `boolean_t` for
/// `one_thread` and a wait result, and the routine takes the locks it needs
/// itself.
pub(crate) unsafe fn thread_wakeup_prim(
    event: *mut c_void,
    one_thread: c_int,
    result: c_int,
) -> c_int {
    let index = wait_hash(event);
    let q = wait_queue(index);
    // SAFETY: `splsched()` is the real asm routine of <machine/spl.h>;
    // the value is only handed back to the matching `splx()`.
    let s = unsafe { spl::splsched() };
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
                Thread::stop_timer(current);

                let state = (*current).state();
                match state & TH_SCHED_STATE {
                    TH_WAIT | TH_WAIT_UNINT | TH_WAIT_SUSP_UNINT => {
                        (*current).set_state((state & !TH_WAIT) | TH_RUN);
                        (*current).wait_result = result;
                        setrun(current, true);
                    }
                    TH_WAIT_SUSP
                    | TH_RUN_WAIT
                    | TH_RUN_WAIT_SUSP
                    | TH_RUN_WAIT_UNINT
                    | TH_RUN_WAIT_SUSP_UNINT => {
                        (*current).set_state(state & !TH_WAIT);
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
    unsafe { spl::splx(s) };
    c_int::from(woke)
}

/// `thread_sleep()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// Same contract as `assert_wait()`, plus `lock` must be a live simple lock
/// held by the current thread, as the C requires.
pub(crate) unsafe fn thread_sleep(
    event: *mut c_void,
    lock: *mut SimpleLock,
    interruptible: c_int,
) {
    unsafe {
        assert_wait(NonNull::new(event), interruptible);
        (*lock).unlock();
        thread_block(None);
    }
}

/// `thread_dispatch()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// `thread` must be a live thread that is not on a run queue, and the caller
/// must be at splsched; the `x86_64` context switch calls
/// [`thread_dispatch_entry`].
pub(crate) unsafe fn thread_dispatch(thread: *mut Thread) {
    unsafe {
        (*thread).lock.lock();

        if (*thread).swap_func.is_some() {
            (*thread).set_state((*thread).state() | TH_SWAPPED);
            (*thread).stack_free();
        }

        match (*thread).state() & !TH_SWAP_STATE {
            TH_RUN_SUSP | TH_RUN_SUSP_HALTED | TH_RUN_WAIT_SUSP => {
                (*thread).set_state((*thread).state() & !TH_RUN);
                if (*thread).wake_active() {
                    (*thread).set_wake_active(false);
                    (*thread).lock.unlock();
                    let event = (*thread).wake_active_event();
                    thread_wakeup_prim(event, 0, THREAD_AWAKENED);
                    return;
                }
            }
            TH_RUN_SUSP_UNINT | TH_RUN | TH_RUN_UNINT => {
                setrun(thread, false);
            }
            TH_RUN_WAIT_SUSP_UNINT | TH_RUN_WAIT_UNINT | TH_RUN_WAIT => {
                (*thread).set_state((*thread).state() & !TH_RUN);
            }
            // The idle thread is already in `idle_thread_array`.
            TH_RUN_IDLE => (),
            _ => state_panic(thread),
        }
        (*thread).lock.unlock();
    }
}

/// `thread_dispatch()` of <`kern/sched_prim.h>`: the entry the i386 context
/// switch calls.
///
/// # Safety
///
/// `thread` must be a live thread that is not on a run queue, and the caller
/// must be at splsched.
pub(crate) unsafe extern "C" fn thread_dispatch_entry(thread: *mut Thread) {
    unsafe { thread_dispatch(thread) };
}

/// `thread_setrun()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// `thread` must be a live thread locked by the caller, and the caller must be
/// at splsched.
pub(crate) unsafe fn thread_setrun(thread: *mut Thread, may_preempt: c_int) {
    setrun(thread, may_preempt != 0);
}

/// `thread_select()` of `kern/sched_prim.c`: pick the thread this processor runs
/// next, possibly the current one.
///
/// # Safety
///
/// The caller must be at splsched, hold no run-queue lock, and `myprocessor`
/// must be the current processor.
unsafe fn thread_select(myprocessor: *mut Processor) -> *mut Thread {
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
            let thread = per_cpu::thread();
            if (*thread).state() == TH_RUN
                && (*thread).processor_set == pset
                && ((*thread).bound_processor.is_null()
                    || (*thread).bound_processor == myprocessor)
            {
                (*runq).lock.unlock();
                (*thread).lock.lock();
                if (*thread).sched_stamp != sched_tick() {
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
                let thread = pin_queue(q)
                    .cursor_front_mut()
                    .remove_current()
                    .map_or(ptr::null_mut(), ptr::from_mut);
                (*thread).runq = RUN_QUEUE_NULL;
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
                        if low >= NRQS as c_int {
                            kpanic!("thread_select", "thread_select")
                        }
                        (*runq).low = low;
                        q = &raw mut (*runq).runq[low as usize];
                    }
                }
                (*runq).lock.unlock();
                thread
            }
        };

        if (*thread).policy == POLICY_TIMESHARE {
            (*myprocessor)
                .quantum
                .store((*pset).set_quantum, Ordering::Relaxed);
        } else {
            (*myprocessor)
                .quantum
                .store((*thread).sched_data, Ordering::Relaxed);
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
unsafe fn invoke_swapped(
    old_thread: *mut Thread,
    new_thread: *mut Thread,
    continuation: crate::kern::thread::Continuation,
) -> ! {
    unsafe {
        (*new_thread)
            .set_state((*new_thread).state() & !(TH_SWAPPED | TH_UNINT));
        (*new_thread).lock.unlock();
        thread_wakeup_prim((*new_thread).state_event(), 0, THREAD_AWAKENED);

        (*new_thread).last_processor = per_cpu::processor().as_ptr();
        ast::context(new_thread, cpu_id());
        stack_handoff(old_thread, new_thread);

        (*old_thread).lock.lock();
        (*old_thread).swap_func = continuation;
        match (*old_thread).state() {
            TH_RUN_SUSP | TH_RUN_SUSP_HALTED | TH_RUN_WAIT_SUSP => {
                (*old_thread)
                    .set_state(((*old_thread).state() & !TH_RUN) | TH_SWAPPED);
                if (*old_thread).wake_active() {
                    (*old_thread).set_wake_active(false);
                    (*old_thread).lock.unlock();
                    thread_wakeup_prim(
                        (*old_thread).wake_active_event(),
                        0,
                        THREAD_AWAKENED,
                    );
                    spl::spl0();
                    crate::arch::x86_64::locore::call_continuation(
                        (*new_thread).swap_func,
                    );
                }
            }
            TH_RUN_SUSP_UNINT | TH_RUN_UNINT | TH_RUN => {
                (*old_thread).set_state((*old_thread).state() | TH_SWAPPED);
                thread_setrun(old_thread, 0);
            }
            TH_RUN_WAIT_SUSP_UNINT | TH_RUN_WAIT_UNINT | TH_RUN_WAIT => {
                (*old_thread)
                    .set_state(((*old_thread).state() & !TH_RUN) | TH_SWAPPED);
            }
            TH_RUN_IDLE => {
                (*old_thread).set_state(TH_RUN | TH_IDLE | TH_SWAPPED);
            }
            _ => state_panic(old_thread),
        }
        (*old_thread).lock.unlock();

        spl::spl0();
        crate::arch::x86_64::locore::call_continuation(
            (*new_thread).swap_func,
        );
    }
}

/// `thread_invoke()` of `kern/sched_prim.c`: stop running `old_thread` and start
/// `new_thread`; `false` means a stack is not ready yet and the caller must
/// select again.
///
/// # Safety
///
/// The caller must be at splsched, hold no run-queue lock, and both threads
/// must be live.
pub(crate) unsafe fn thread_invoke(
    old_thread: *mut Thread,
    continuation: crate::kern::thread::Continuation,
    new_thread: *mut Thread,
) -> bool {
    // The old thread is giving up the CPU, which a non-preemptible kernel
    // does only outside RCU read sections.
    crate::kern::rcu::note_qs();

    if old_thread == new_thread {
        unsafe {
            (*new_thread).lock.lock();
            (*new_thread).set_state((*new_thread).state() & !TH_UNINT);
            (*new_thread).lock.unlock();
            thread_wakeup_prim(
                (*new_thread).state_event(),
                0,
                THREAD_AWAKENED,
            );
        }

        if continuation.is_some() {
            // SAFETY: `spl0()` and `call_continuation()` are the real asm
            // routines, and the continuation does not return into the caller.
            unsafe {
                spl::spl0();
                crate::arch::x86_64::locore::call_continuation(continuation);
            }
        }
        return true;
    }

    let handoff = unsafe {
        (*new_thread).lock.lock();
        (*old_thread).stack_privilege != per_cpu::stack()
            && continuation.is_some()
    };

    if handoff {
        unsafe {
            match (*new_thread).state() & TH_SWAP_STATE {
                TH_SWAPPED => {
                    invoke_swapped(old_thread, new_thread, continuation);
                }
                TH_SW_COMING_IN => {
                    thread_swapin(new_thread);
                    (*new_thread).lock.unlock();
                    return false;
                }
                _ => (),
            }
        }
    } else {
        unsafe {
            if (*new_thread).state() & TH_SWAPPED != 0
                && ((*new_thread).state() & TH_SW_COMING_IN != 0
                    || !(*new_thread).stack_alloc_try(Some(thread_continue)))
            {
                thread_swapin(new_thread);
                (*new_thread).lock.unlock();
                return false;
            }
        }
    }

    unsafe {
        (*new_thread)
            .set_state((*new_thread).state() & !(TH_SWAPPED | TH_UNINT));
        (*new_thread).lock.unlock();
        thread_wakeup_prim((*new_thread).state_event(), 0, THREAD_AWAKENED);

        (*new_thread).last_processor = per_cpu::processor().as_ptr();
        ast::context(new_thread, cpu_id());

        let resuming = switch_context(old_thread, continuation, new_thread);
        thread_dispatch(resuming);
    }
    true
}

/// `thread_block()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// The caller must be the current thread, must not hold a spin lock, and must
/// have set its wait state first when it means to block.
pub(crate) unsafe fn thread_block(
    continuation: crate::kern::thread::Continuation,
) {
    let thread = per_cpu::thread();
    let myprocessor = per_cpu::processor().as_ptr();
    let s = unsafe { spl::splsched() };

    ast::off(cpu_id(), AstReason::BLOCK);

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
    unsafe { spl::splx(s) };
}

/// `thread_run()` of `kern/sched_prim.c`: switch directly from the current
/// thread to `new_thread`, both runnable.
///
/// # Safety
///
/// The caller must be the current thread, must not hold a spin lock, and
/// `new_thread` must be live and runnable.
pub(crate) unsafe fn thread_run(
    continuation: crate::kern::thread::Continuation,
    mut new_thread: *mut Thread,
) {
    let thread = per_cpu::thread();
    let myprocessor = per_cpu::processor().as_ptr();
    let s = unsafe { spl::splsched() };

    // SAFETY: at splsched with no run-queue lock, as `thread_invoke()`
    // requires.
    while !unsafe { thread_invoke(thread, continuation, new_thread) } {
        // SAFETY: at splsched with no run-queue lock, as `thread_select()`
        // requires.
        new_thread = unsafe { thread_select(myprocessor) };
    }

    // SAFETY: `s` is the level `splsched()` returned.
    unsafe { spl::splx(s) };
}

/// `update_priority()` of `kern/sched_prim.c`: the priority catch-up of a thread
/// that has been asleep or suspended, with the `(5/8)**n` decay of used CPU.
///
/// # Safety
///
/// `thread` must be a live thread whose lock the caller holds at splsched.
pub(crate) unsafe fn update_priority(thread: *mut Thread) {
    unsafe {
        let ticks = sched_tick().wrapping_sub((*thread).sched_stamp);
        (*thread).sched_stamp = (*thread).sched_stamp.wrapping_add(ticks);
        Thread::timer_delta(thread);

        if ticks > 30 {
            (*thread).cpu_usage = 0;
            (*thread).sched_usage = 0;
        } else {
            (*thread).cpu_usage =
                (*thread).cpu_usage.wrapping_add((*thread).cpu_delta);
            (*thread).sched_usage =
                (*thread).sched_usage.wrapping_add((*thread).sched_delta);
            // The reset branch above keeps `ticks` at most 30.
            let shift = WAIT_SHIFT[ticks as usize];
            (*thread).cpu_usage = decay_usage((*thread).cpu_usage, shift);
            (*thread).sched_usage = decay_usage((*thread).sched_usage, shift);
        }
        (*thread).cpu_delta = 0;
        (*thread).sched_delta = 0;

        if (*thread).policy == POLICY_TIMESHARE
            && (*thread).depress_priority < 0
        {
            (*thread).sched_pri = priority_computation(thread);
        }
    }
}

/// One `(usage >> shift1) +/- (usage >> -shift2)` step of the C.
const fn decay_usage(usage: c_uint, shift: Shift) -> c_uint {
    if shift.shift2 > 0 {
        (usage >> (shift.shift1 as u32)) + (usage >> (shift.shift2 as u32))
    } else {
        (usage >> (shift.shift1 as u32)) - (usage >> ((-shift.shift2) as u32))
    }
}

/// The run-queue bucket a queued thread sits in, from the priority its
/// enqueue used.
///
/// Every writer of `sched_pri` holds the thread lock and changes it while the
/// thread is off every run queue: `set_priority()` removes the thread first,
/// and the depression, create and swap-in paths run on threads that are not
/// queued.  The key therefore always names the bucket the thread is in.
///
/// # Safety
///
/// `th` must be a live thread on a run queue.
fn runq_index(th: *mut Thread) -> usize {
    let whichq = unsafe { (*th).sched_pri } as c_uint;
    if whichq >= NRQS as c_uint {
        NRQS - 1
    } else {
        whichq as usize
    }
}

/// `rem_runq()` of `kern/sched_prim.c`: take `th` off its run queue and return
/// that queue, or `RUN_QUEUE_NULL` when it was not on one.
///
/// # Safety
///
/// `th` must be a live thread whose lock the caller holds.
pub(crate) unsafe fn rem_runq(th: *mut Thread) -> *mut RunQueue {
    unsafe {
        let mut rq = (*th).runq;
        if rq != RUN_QUEUE_NULL {
            (*rq).lock.lock();
            if rq == (*th).runq {
                pin_queue(&raw mut (*rq).runq[runq_index(th)])
                    .remove_ptr(NonNull::new_unchecked(th));
                add_single_writer(&(*rq).count, -1);
                (*th).runq = RUN_QUEUE_NULL;
                (*rq).lock.unlock();
            } else {
                // The thread left the queue before the lock; the caller's
                // thread lock keeps it from moving again.
                (*rq).lock.unlock();
                rq = RUN_QUEUE_NULL;
            }
        }
        rq
    }
}

/// `choose_thread()` of `kern/sched_prim.c`: take the next thread off the
/// processor's own run queue, or hand the search to `choose_pset_thread()`.
///
/// # Safety
///
/// The caller must be at splsched and hold no run-queue lock; `myprocessor`
/// must be the current processor.
pub(crate) unsafe fn choose_thread(
    myprocessor: *mut Processor,
) -> *mut Thread {
    unsafe {
        let runq = &raw mut (*myprocessor).runq;
        (*runq).lock.lock();
        if (*runq).count.load(Ordering::Relaxed) > 0 {
            let mut i = (*runq).low;
            while i < NRQS as c_int {
                let q = &raw mut (*runq).runq[i as usize];
                if !(*q).is_empty() {
                    let th = pin_queue(q)
                        .cursor_front_mut()
                        .remove_current()
                        .map_or(ptr::null_mut(), ptr::from_mut);
                    (*th).runq = RUN_QUEUE_NULL;
                    add_single_writer(&(*runq).count, -1);
                    (*runq).low = i;
                    (*runq).lock.unlock();
                    return th;
                }
                i += 1;
            }
            kpanic!("choose_thread", "choose_thread")
        }
        (*runq).lock.unlock();

        let pset = (*myprocessor).processor_set.load(Ordering::Acquire);
        (*pset).runq.lock.lock();
        pset_thread(myprocessor, pset)
    }
}

/// `idle_thread_continue()` of `kern/sched_prim.c`: the idle loop, which parks
/// the processor until `thread_setrun()` dispatches a thread to it.
///
/// # Safety
///
/// Runs as the processor's own idle thread, at spl0 except where the C raised
/// it.
unsafe extern "C" fn idle_thread_continue() {
    let mycpu = cpu_id();
    let myprocessor = per_cpu::processor();

    loop {
        // `MACH_HOST` is 1 in both configured builds, so the global count is
        // the processor set's.
        while myprocessor.next_thread().is_null()
            && !myprocessor.has_runnable()
        {
            if ast::scheduling_pending(mycpu) {
                // SAFETY: `taken()` runs at splsched with no lock held, and
                // it lowers the level itself.
                unsafe {
                    spl::splsched();
                    ast::clear_scheduling(mycpu);
                    ast::taken();
                }
            }
            // The idle thread holds no RCU references, and each clock tick
            // brings a halted CPU back here, so idle CPUs keep up.
            crate::kern::rcu::note_qs();
            machine_idle(mycpu.bits() as c_int);
        }

        // SAFETY: the idle thread raises the level before touching the
        // processor state and queues.
        let s = unsafe { spl::splsched() };

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
                        if (*new_thread).policy == POLICY_TIMESHARE {
                            (*(*new_thread).processor_set).set_quantum
                        } else {
                            (*new_thread).sched_data
                        }
                    };
                    myprocessor.set_quantum(quantum);
                    myprocessor.set_first_quantum(true);
                    // SAFETY: the dispatch and the run-queue locks make
                    // `new_thread` the thread this processor must run.
                    unsafe {
                        thread_run(Some(idle_thread_continue), new_thread);
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
                        // SAFETY: the state changed while the idle lock was held, so
                        // this path releases it.
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
                    unsafe { thread_block(Some(idle_thread_continue)) };
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
                    unsafe { thread_block(Some(idle_thread_continue)) };
                    break;
                }
                state
                @ (ProcessorState::OffLine | ProcessorState::Running) => {
                    kprint!(
                        " Bad processor state {:?} (Cpu {})\n",
                        state,
                        mycpu
                    );
                    kpanic!("idle_thread", "idle_thread")
                }
            }
        }
        // SAFETY: `s` is the level `splsched()` returned.
        unsafe { spl::splx(s) };
    }
}

/// `idle_thread()` of `kern/sched_prim.c`: the processor's idle thread start.
///
/// # Safety
///
/// `kern/startup.c` starts this as the processor's idle thread; it never
/// returns.
pub(crate) unsafe fn idle_thread() {
    unsafe {
        let me = per_cpu::thread();
        (*me).stack_privilege();
        let s = spl::splsched();
        (*me).priority = NRQS as c_int - 1;
        (*me).sched_pri = NRQS as c_int - 1;

        (*me).lock.lock();
        (*me).set_state((*me).state() | TH_IDLE);
        (*me).lock.unlock();
        per_cpu::processor().set_idle_thread(me);
        spl::splx(s);

        thread_block(Some(idle_thread_continue));
        idle_thread_continue();
    }
}

/// `idle_thread()` of <`kern/sched_prim.h>`: the `kernel_thread` entry.
///
/// # Safety
///
/// `kern/startup.c` starts this as the processor's idle thread; it never
/// returns.
pub(crate) unsafe extern "C" fn idle_thread_entry() {
    unsafe { idle_thread() };
}

/// `sched_thread_continue()` of `kern/sched_prim.c`.
unsafe extern "C" fn sched_thread_continue() {
    loop {
        // SAFETY: the scan runs at spl0 with no lock held, as the C did.
        unsafe {
            mach_factor::compute();
            if sched_tick() & 1 != 0 {
                do_thread_scan();
            }
            assert_wait(None, 0);
            thread_block(Some(sched_thread_continue));
        }
    }
}

/// `sched_thread()` of `kern/sched_prim.c`: the scheduler thread, woken by
/// `recompute_priorities()` once a second.
///
/// # Safety
///
/// `kern/startup.c` starts this as the "sched" kernel thread; it never
/// returns.
pub(crate) unsafe fn sched_thread() {
    unsafe {
        SCHED_THREAD_ID.store(per_cpu::thread(), Ordering::Release);
        assert_wait(None, 0);
        thread_block(Some(sched_thread_continue));
        sched_thread_continue();
    }
}

/// `sched_thread()` of <`kern/sched_prim.h>`: the `kernel_thread` entry.
///
/// # Safety
///
/// `kern/startup.c` starts this as the "sched" kernel thread; it never
/// returns.
pub(crate) unsafe extern "C" fn sched_thread_entry() {
    unsafe { sched_thread() };
}

/// `do_runq_scan()` of `kern/sched_prim.c`: pass one of the stuck-thread scan,
/// moving the candidates off `runq`.  `true` means the array ran out of room.
///
/// # Safety
///
/// The caller must hold no run-queue lock, and `runq` must be live.
unsafe fn do_runq_scan(runq: *mut RunQueue) -> bool {
    let s = unsafe { spl::splsched() };
    unsafe {
        (*runq).lock.lock();
        let mut count = (*runq).count.load(Ordering::Relaxed);
        if count > 0 {
            let mut q = &raw mut (*runq).runq[(*runq).low as usize];
            while count > 0 {
                let mut thread = (*q).cursor_front().current_ptr();
                while let Some(current) = thread {
                    let current = current.as_ptr();
                    // Capture the successor before the removal.
                    let next = {
                        let mut cursor = pin_queue(q).cursor_mut_from_ptr(
                            NonNull::new_unchecked(current),
                        );
                        cursor.move_next();
                        cursor.current_ptr()
                    };

                    if (*current).state() & TH_SCHED_STATE == TH_RUN
                        && sched_tick().wrapping_sub((*current).sched_stamp)
                            > 1
                    {
                        if STUCK_COUNT.load(Ordering::Relaxed)
                            == MAX_STUCK_THREADS as c_int
                        {
                            (*runq).lock.unlock();
                            spl::splx(s);
                            return true;
                        }
                        // A RUN thread cannot be deallocated until it stops
                        // running, so taking it off the queue here makes the
                        // later unlocked update safe.
                        pin_queue(q)
                            .remove_ptr(NonNull::new_unchecked(current));
                        add_single_writer(&(*runq).count, -1);
                        (*current).runq = RUN_QUEUE_NULL;
                        let index =
                            STUCK_COUNT.fetch_add(1, Ordering::Relaxed);
                        STUCK_THREADS[index as usize]
                            .store(current, Ordering::Relaxed);
                        if DO_THREAD_SCAN_DEBUG.load(Ordering::Relaxed) != 0 {
                            kprint!(
                                "do_runq_scan: adding thread {:x}\n",
                                current.expose_provenance()
                            );
                        }
                    }
                    count -= 1;
                    thread = next;
                }
                q = q.add(1);
            }
        }
        (*runq).lock.unlock();
        spl::splx(s);
    }
    false
}

/// `do_thread_scan()` of `kern/sched_prim.c`: pass two of the stuck-thread scan,
/// updating the priority of every thread it found.
///
/// # Safety
///
/// Runs in thread context with no lock held; the scan takes the locks it
/// needs.
pub(crate) unsafe fn do_thread_scan() {
    let mut restart_needed = false;
    loop {
        // `MACH_HOST` is 1 in both configured builds.
        // SAFETY: the all-psets lock serializes the list, and each run queue
        // has its own lock taken by `do_runq_scan()`.
        unsafe {
            let lock = processor::all_psets_lock();
            (*lock).lock();
            let head = processor::all_psets();
            let mut cursor = head.cursor_front();
            while let Some(pset) = cursor.current_ptr() {
                cursor.move_next();
                let pset = pset.as_ptr();
                if do_runq_scan(&raw mut (*pset).runq) {
                    restart_needed = true;
                    break;
                }
            }
            (*lock).unlock();
        }

        if !restart_needed {
            for processor in processor::iter() {
                // SAFETY: the processor record is static, and the
                // projection only computes the field's address.
                let runq = unsafe { &raw mut (*processor.as_ptr()).runq };
                // SAFETY: the run queue is the live one of the probed CPU.
                if unsafe { do_runq_scan(runq) } {
                    restart_needed = true;
                    break;
                }
            }
        }

        while STUCK_COUNT.load(Ordering::Relaxed) > 0 {
            // SAFETY: the array holds `stuck_count` live threads, and the
            // splsched level below is the one the fix-up needs.
            let (thread, s) = unsafe {
                let index =
                    (STUCK_COUNT.fetch_sub(1, Ordering::Relaxed) - 1) as usize;
                let thread = STUCK_THREADS[index]
                    .swap(ptr::null_mut(), Ordering::Relaxed);
                (thread, spl::splsched())
            };
            // SAFETY: the thread is live and off every run queue; its lock
            // protects the state and priority fields.
            unsafe {
                (*thread).lock.lock();
                if (*thread).state() & TH_SCHED_STATE == TH_RUN {
                    update_priority(thread);
                    thread_setrun(thread, 1);
                }
                (*thread).lock.unlock();
                spl::splx(s);
            }
        }

        if !restart_needed {
            break;
        }
    }
}

/// The effective priority of `thread`, from its base priority plus a shift of
/// its accumulated usage.
///
/// # Safety
///
/// `thread` must be a live thread whose lock the caller holds.
unsafe fn priority_computation(thread: *mut Thread) -> c_int {
    let pri = unsafe {
        let usage = (*thread).sched_usage >> (PRI_SHIFT + SCHED_SHIFT);
        // The C adds an `unsigned` to the `int` priority and stores the sum
        // back into an `int`, so the result wraps.
        (*thread).priority.wrapping_add(usage as c_int)
    };
    // The C clamps with `if (pri > NRQS - 1)`; a negative sum is left alone,
    // exactly as the C leaves it.
    if pri > NRQS as c_int - 1 {
        NRQS as c_int - 1
    } else {
        pri
    }
}

/// `compute_priority()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// `thread` must be a live thread whose lock the caller holds.
unsafe fn recompute_priority(thread: *mut Thread, resched: bool) {
    unsafe {
        if (*thread).policy == POLICY_TIMESHARE {
            let pri = priority_computation(thread);
            if (*thread).depress_priority < 0 {
                set_priority(thread, pri, resched);
            } else {
                (*thread).depress_priority = pri;
            }
        } else {
            set_priority(thread, (*thread).priority, resched);
        }
    }
}

/// `set_pri()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// `th` must be a live thread whose lock the caller holds, and the caller must
/// be at splsched.
unsafe fn set_priority(th: *mut Thread, pri: c_int, resched: bool) {
    unsafe {
        let rq = rem_runq(th);
        (*th).sched_pri = pri;
        if rq != RUN_QUEUE_NULL {
            if resched {
                setrun(th, true);
            } else {
                enqueue_run_queue(rq, th);
            }
        }
    }
}

/// `choose_pset_thread()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// The caller must be at splsched, must hold `pset`'s run-queue lock, and
/// `myprocessor` must be the current processor with `pset` its processor set.
unsafe fn pset_thread(
    myprocessor: *mut Processor,
    pset: *mut ProcessorSet,
) -> *mut Thread {
    unsafe {
        let runq = &raw mut (*pset).runq;
        let mut i = (*runq).low;
        if (*runq).count.load(Ordering::Relaxed) > 0 {
            while i < NRQS as c_int {
                let mut q = &raw mut (*runq).runq[i as usize];
                if !(*q).is_empty() {
                    let th = pin_queue(q)
                        .cursor_front_mut()
                        .remove_current()
                        .map_or(ptr::null_mut(), ptr::from_mut);
                    (*th).runq = RUN_QUEUE_NULL;
                    add_single_writer(&(*runq).count, -1);
                    if (*runq).count.load(Ordering::Relaxed) > 0
                        && (*pset).policies & POLICY_FIXEDPRI != 0
                    {
                        while (*q).is_empty() {
                            i += 1;
                            if i >= NRQS as c_int {
                                kpanic!(
                                    "choose_pset_thread",
                                    "choose_pset_thread"
                                )
                            }
                            q = &raw mut (*runq).runq[i as usize];
                        }
                    }
                    (*runq).low = i;
                    (*runq).lock.unlock();
                    return th;
                }
                i += 1;
            }
            kpanic!("choose_pset_thread", "choose_pset_thread")
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

/// `thread_set_timeout()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// Must be called between `assert_wait()` and `thread_block()` for the current
/// thread, as the C documents.
pub(crate) unsafe fn thread_set_timeout(t: c_int) {
    let thread = per_cpu::thread();
    // SAFETY: `splsched()` is the real asm routine of <machine/spl.h>;
    // the value is only handed back to the matching `splx()`.
    let s = unsafe { spl::splsched() };
    // SAFETY: `thread` is the current thread; its lock protects the state and
    // the timer element, as in C.
    unsafe {
        (*thread).lock.lock();
        if (*thread).state() & TH_WAIT != 0 {
            // A negative interval is a long wait, as the C `unsigned` cast
            // spelled; `Ticks` is 64-bit so it does not wrap.
            let ticks = if t < 0 {
                clock::Ticks::new(u64::from(t as c_uint))
            } else {
                clock::Ticks::new(t as u64)
            };
            // SAFETY: `thread` is the current thread and will not move.
            Thread::start_timer(thread, ticks);
        }
        (*thread).lock.unlock();
        spl::splx(s);
    }
}

/// `thread_bind()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// `thread` must be a live thread, and `processor` must be a live processor or
/// the C `PROCESSOR_NULL`, which the caller spells as a null pointer.
pub(crate) unsafe fn thread_bind(
    thread: *mut Thread,
    processor: *mut Processor,
) {
    // SAFETY: `splsched()` is the real asm routine of <machine/spl.h>;
    // the value is only handed back to the matching `splx()`.
    let s = unsafe { spl::splsched() };
    unsafe {
        (*thread).lock.lock();
        (*thread).bound_processor = processor;
        (*thread).lock.unlock();
        spl::splx(s);
    }
}

/// `thread_continue()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// The caller runs this on the current thread, at splsched, after a stack
/// swap; `old_thread` must be a live thread the context switch left to
/// dispatch, or null when there is none.
pub(crate) unsafe extern "C" fn thread_continue(old_thread: *mut Thread) {
    let continuation = unsafe { (*per_cpu::thread()).swap_func };

    if !old_thread.is_null() {
        unsafe { thread_dispatch(old_thread) };
    }
    // SAFETY: `spl0()` is the real asm routine of <machine/spl.h>.
    unsafe { spl::spl0() };

    // SAFETY: the C calls the continuation unconditionally; a null `swap_func`
    // means the thread was resumed without one, which cannot happen, so the
    // halt spells out what the C null call did.
    unsafe {
        match continuation {
            Some(continuation) => continuation(),
            None => kpanic!(
                "thread_continue",
                "thread_continue: null continuation"
            ),
        }
    }
}

/// `compute_priority()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// `thread` must be a live thread whose lock the caller holds.
pub(crate) unsafe fn compute_priority(thread: *mut Thread, resched: c_int) {
    unsafe { recompute_priority(thread, resched != 0) };
}

/// `compute_my_priority()` of `kern/sched_prim.c`.
///
/// # Safety
///
/// The caller must hold the thread lock and know the thread is timesharing and
/// not depressed, as the C documents.
pub(crate) unsafe fn compute_my_priority(thread: *mut Thread) {
    unsafe { (*thread).sched_pri = priority_computation(thread) };
}

/// The expiry of [`RECOMPUTE_PRIORITIES_TIMER`], which re-arms itself.
fn recompute_priorities_action(callout: Pin<&MachCallout>) {
    SCHED_TICK.fetch_add(1, Ordering::Relaxed);
    // A periodic 1 Hz scheduler timer (ADR 0042 allows re-arm from the action).
    callout.start(clock::Ticks::new(machine::CLOCK_HZ as u64));
    let thread = SCHED_THREAD_ID.load(Ordering::Acquire);
    if !thread.is_null() {
        // SAFETY: `thread` is the live scheduler thread the scan armed.
        unsafe { clear_wait(thread, THREAD_AWAKENED, 0) };
    }
}

/// `recompute_priorities()` of `kern/sched_prim.c`: arm the periodic scan.
pub(crate) fn recompute_priorities_start() {
    Pin::static_ref(&RECOMPUTE_PRIORITIES_TIMER)
        .start(clock::Ticks::new(machine::CLOCK_HZ as u64));
}
