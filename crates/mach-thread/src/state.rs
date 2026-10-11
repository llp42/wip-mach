// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The records the scheduler and the task and thread lifecycles share, whose
//! types name the platform.

use crate::all_psets::AllPsets;
use crate::cell::SyncCell;
use crate::platform::Platform;
use crate::processor_action::ActionQueue;
use crate::processor_set::ProcessorSet;
use crate::reaper_queue::ReaperQueue;
use crate::sched::Callout;
use crate::sched_prim::{
    MAX_STUCK_THREADS, NUMQUEUES, recompute_priorities_action,
};
use crate::smp::MAX_NCPUS;
use crate::stack_free_list::StackFreeList;
use crate::task::Task;
use crate::thread::{Thread, ThreadQueue};
use crate::thread_swap::SwapinQueue;
use crate::types::ProcessorSlot;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::AtomicPtr;
use lock::irq_spin_lock;
use lock::{IrqSpinLock, TicketLock};

/// The state of the tasks, threads and processors of one platform.  The kernel
/// keeps the one value in a static and hands it out through
/// [`Platform::task_state`].
pub struct TaskState<P: Platform> {
    /// The processor records, one per CPU; each CPU's per-CPU block links to
    /// its element once the platform's per-CPU setup has run.
    pub(crate) processors: [ProcessorSlot<P>; MAX_NCPUS],
    /// The set every task starts in.
    pub(crate) default_pset: SyncCell<ProcessorSet<P>>,
    /// Every processor set.
    pub all_psets: TicketLock<AllPsets<P>>,
    /// The set of every CPU but the boot CPU.
    pub(crate) slave_pset: AtomicPtr<ProcessorSet<P>>,
    /// The processors waiting for the action thread, under an irq spin lock,
    /// since processors are queued with their lock held at splsched.
    pub(crate) action_queue: IrqSpinLock<ActionQueue<P>, P::Lock>,
    /// The kernel's own task, the first created.
    pub(crate) kernel_task: AtomicPtr<Task<P>>,
    /// The image `Thread::create` copies.  Built by `Thread::new` in
    /// `Thread::init`, never zeroed.
    pub(crate) thread_template: SyncCell<MaybeUninit<Thread<P>>>,
    /// The threads waiting for the reaper, under an irq spin lock, since a
    /// terminating thread queues itself at splsched.
    pub(crate) reaper_queue: IrqSpinLock<ReaperQueue<P>, P::Lock>,
    /// The cached stacks, under an irq spin lock, since the scheduler frees a
    /// stack at splsched.
    pub(crate) stack_free: IrqSpinLock<StackFreeList, P::Lock>,
    /// The threads waiting for a stack, and the event the swapin thread
    /// sleeps on.  Under an irq spin lock, since the scheduler queues threads
    /// at splsched.
    pub(crate) swapin_queue: IrqSpinLock<SwapinQueue<P>, P::Lock>,
    /// The scheduler thread the priority recomputation wakes.
    pub(crate) sched_thread: AtomicPtr<Thread<P>>,
    /// The 1 Hz priority recomputation, never dropped.
    pub(crate) recompute_priorities_timer: Callout<P>,
    /// The wait buckets, one per hash value.
    pub(crate) wait_queue: SyncCell<[ThreadQueue<P>; NUMQUEUES]>,
    /// The threads the stuck-thread scan found.  Only the scan touches it,
    /// at splsched on one CPU at a time, so the accesses are `Relaxed`.
    pub(crate) stuck_threads: [AtomicPtr<Thread<P>>; MAX_STUCK_THREADS],
}

impl<P: Platform> TaskState<P> {
    /// The state before boot: no tasks, threads or sets, and zeroed
    /// processor records.  The value spans tens of kilobytes, more than a
    /// kernel stack holds, so only a static's initializer builds it.
    #[must_use]
    #[expect(
        clippy::large_stack_arrays,
        reason = "a static's initializer evaluates it at compile time"
    )]
    #[expect(
        clippy::new_without_default,
        reason = "a default value would be built on the stack it overflows"
    )]
    pub const fn new() -> Self {
        Self {
            // SAFETY: all-zero is a valid value of every field of a
            // processor record: the atomics, pointers, integers, locks and
            // list heads.
            processors: unsafe { core::mem::zeroed() },
            default_pset: SyncCell(UnsafeCell::new(ProcessorSet::zeroed())),
            all_psets: TicketLock::new(AllPsets::new()),
            slave_pset: AtomicPtr::new(ptr::null_mut()),
            action_queue: irq_spin_lock!("action queue", ActionQueue::new()),
            kernel_task: AtomicPtr::new(ptr::null_mut()),
            thread_template: SyncCell(UnsafeCell::new(MaybeUninit::uninit())),
            reaper_queue: irq_spin_lock!("reaper queue", ReaperQueue::new()),
            stack_free: irq_spin_lock!("stack free", StackFreeList::new()),
            swapin_queue: irq_spin_lock!("swapin queue", SwapinQueue::new()),
            sched_thread: AtomicPtr::new(ptr::null_mut()),
            recompute_priorities_timer: Callout::<P>::new(
                P::WHEEL,
                recompute_priorities_action::<P>,
                (),
            ),
            wait_queue: SyncCell(UnsafeCell::new(
                [const { ThreadQueue::new() }; NUMQUEUES],
            )),
            stuck_threads: [const { AtomicPtr::new(ptr::null_mut()) };
                MAX_STUCK_THREADS],
        }
    }
}
