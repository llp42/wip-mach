// SPDX-License-Identifier: CMU-Mach
// Derived from kern/thread.h:
//   Copyright (c) 1993-1987 Carnegie Mellon University.
// Derived from kern/thread.c:
//   Copyright (c) 1994-1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The thread module's cores.

use crate::arch::types::{AtomicVmSize, VmOffset, VmSize};
use crate::arch::vm_param::KERNEL_STACK_SIZE;
use crate::arch::x86_64::clock_platform::{MachCallout, wheel};
use crate::arch::x86_64::pcb::Pcb;
use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::spl;
use crate::ipc::IpcSpace;
use crate::ipc::ipc_thread::IpcWait;
use crate::ipc::mach_port;
use crate::kern::ast::{self, AstReason};
use crate::kern::debug::kpanic;
use crate::kern::error::Error;
use crate::kern::eventcount;
use crate::kern::host_time;
use crate::kern::ipc_mig::abort_rpc;
use crate::kern::ipc_tt::{
    ipc_thread_disable, ipc_thread_enable, ipc_thread_init,
    ipc_thread_terminate,
};
use crate::kern::lock::SimpleLock;
use crate::kern::machine;
use crate::kern::policy::{POLICY_FIXEDPRI, POLICY_TIMESHARE, invalid_policy};
use crate::kern::processor::{self, Processor, ProcessorRef, ProcessorSet};
use crate::kern::sched::{
    BASEPRI_SYSTEM, RUN_QUEUE_NULL, RunQueue, SCHED_SCALE, invalid_pri,
};
use crate::kern::sched_prim::{
    TH_RUN_SUSP, TH_RUN_SUSP_UNINT, TH_RUN_WAIT_SUSP, TH_RUN_WAIT_SUSP_UNINT,
    TH_WAIT_SUSP_UNINT, THREAD_AWAKENED, THREAD_INTERRUPTED, assert_wait,
    clear_wait, compute_priority, rem_runq, sched_tick, thread_block,
    thread_setrun, thread_sleep, thread_timeout_setup, thread_wakeup_prim,
};
use crate::kern::slab::{CacheInitFlags, KmemCache, kalloc, kfree};
use crate::kern::syscall_subr::depress_abort;
use crate::kern::task::{Task, add_time64, current_task, kernel_task};
use crate::kern::timer::{TIMER_RATE, Timer, TimerSave, read_times};
use crate::mig::time_value::TimeValue64;
use crate::vm::vm_map::{VmMap, round_page};
use collections::tail_queue::{self, TailQueue};
use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::mem::{MaybeUninit, offset_of};
use core::pin::Pin;
use core::ptr::{self, NonNull, with_exposed_provenance_mut};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
#[cfg(debug_assertions)]
use lock::HeldLocks;
use lock::IrqSpinLock;

/// The length of a thread's name, with its NUL.
pub const TASK_NAME_SIZE: usize = 32;

/// `i386_DEBUG_STATE`: the debug state, which the current thread can read and
/// write without suspending itself.
const I386_DEBUG_STATE: c_int = 6;
/// `i386_FSGS_BASE_STATE`: the segment bases, writable directly only for the
/// current thread.
const I386_FSGS_BASE_STATE: c_int = 7;
/// The pattern [`stack_init`] fills a fresh kernel stack with when the usage
/// check is on.
const STACK_MARKER: u32 = 0xdead_beef;

/// The thread is queued for waiting.
pub const TH_WAIT: u32 = 0x01;
/// `TH_SUSP`: the thread has been asked to stop.
pub const TH_SUSP: u32 = 0x02;
/// `TH_RUN`: the thread is running or on a run queue.
pub const TH_RUN: u32 = 0x04;
/// `TH_UNINT`: the thread is waiting uninterruptibly.
pub const TH_UNINT: u32 = 0x08;
/// `TH_HALTED`: the thread is halted at a clean point.
pub const TH_HALTED: u32 = 0x10;
/// `TH_IDLE`: the thread is an idle thread.
pub const TH_IDLE: u32 = 0x80;
/// `TH_SCHED_STATE`: the bits the state switches look at.
pub const TH_SCHED_STATE: u32 = TH_WAIT | TH_SUSP | TH_RUN | TH_UNINT;
/// `TH_SWAPPED`: the thread has no kernel stack.
pub const TH_SWAPPED: u32 = 0x0100;
/// `TH_SW_COMING_IN`: the thread waits for a kernel stack.
pub const TH_SW_COMING_IN: u32 = 0x0200;
/// `TH_SWAP_STATE`: the bits `thread_dispatch()` masks off.
pub const TH_SWAP_STATE: u32 = TH_SWAPPED | TH_SW_COMING_IN;

/// A continuation: where a thread resumes on a fresh stack, or `None` for
/// none.
pub type Continuation = Option<unsafe extern "C" fn()>;

/// A stack continuation: what a thread given a stack resumes through, with the
/// thread it switched from.
pub type StackResume = Option<unsafe extern "C" fn(*mut Thread)>;

/// The bitfield word of `struct thread`, which C declares as `unsigned
/// state:16; unsigned wake_active:1; unsigned active:1`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateBits(u32);

// These accessors mirror the C bitfields one for one; the `TH_*`
// constants in `sched_prim` carry the documentation, and a doc per
// getter/setter pair would only respell the field name.
#[allow(missing_docs)]
impl StateBits {
    const STATE_MASK: u32 = 0xffff;
    const WAKE_ACTIVE: u32 = 1 << 16;
    const ACTIVE: u32 = 1 << 17;

    #[must_use]
    pub const fn state(self) -> u32 {
        self.0 & Self::STATE_MASK
    }

    /// The `wake_active` bit: someone is waiting for this thread to become
    /// suspended.
    #[must_use]
    pub const fn wake_active(self) -> bool {
        self.0 & Self::WAKE_ACTIVE != 0
    }

    #[must_use]
    pub const fn active(self) -> bool {
        self.0 & Self::ACTIVE != 0
    }

    /// Replaces the `state` half, leaving the flag bits alone; the C
    /// assignment to the 16-bit field.
    pub const fn set_state(&mut self, state: u32) {
        self.0 = (self.0 & !Self::STATE_MASK) | (state & Self::STATE_MASK);
    }

    pub const fn set_wake_active(&mut self, active: bool) {
        if active {
            self.0 |= Self::WAKE_ACTIVE;
        } else {
            self.0 &= !Self::WAKE_ACTIVE;
        }
    }

    /// Replaces the `active` bit: how alive the thread is.
    pub const fn set_active(&mut self, active: bool) {
        if active {
            self.0 |= Self::ACTIVE;
        } else {
            self.0 &= !Self::ACTIVE;
        }
    }
}

/// The anonymous union of `struct thread` holding the bitfield word and
/// `event_key`.
#[repr(C)]
#[allow(missing_docs)]
pub union StateEvent {
    state: StateBits,
    event_key: *mut c_void,
}

/// A queue of kernel messages.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct IpcKmsgQueue {
    /// The first message, opaque here.
    pub base: *mut c_void,
}

/// The receive size or the received message, as the thread's receive state
/// needs.
#[repr(C)]
#[allow(missing_docs)]
pub union ThreadData {
    pub msize: c_uint,
    pub kmsg: *mut c_void,
}

/// The `receive` arm of `thread.saved`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct SavedReceive {
    /// `msg`: the user message header.
    pub msg: *mut c_void,
    pub option: c_int,
    pub rcv_size: c_uint,
    pub timeout: c_uint,
    /// `notify`: the notification port name.
    pub notify: c_uint,
    /// `object`: the object being received from.
    pub object: *mut c_void,
    pub mqueue: *mut c_void,
}

/// The `exception` arm of `thread.saved`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(missing_docs)]
pub struct SavedException {
    pub port: *mut c_void,
    pub exc: c_int,
    pub code: c_int,
    pub subcode: c_long,
}

/// The `saved` union of `struct thread`: what the state selection keeps if the
/// thread's stack is discarded.
#[repr(C)]
#[allow(missing_docs)]
pub union Saved {
    pub receive: SavedReceive,
    pub exception: SavedException,
    pub other: *mut c_void,
}

/// A kernel thread: its scheduling, IPC and accounting state.
///
/// The representation is free (ADR 0002): nothing MIG-visible reads it,
/// and the machine code takes field offsets with `offset_of!`.
#[allow(missing_docs)]
pub struct Thread {
    /// `links`: the run-queue or wait-queue links.
    pub links: tail_queue::Link,
    /// `runq`: the run queue the thread is on, or `RUN_QUEUE_NULL`.
    pub runq: *mut RunQueue,
    pub task: *mut Task,
    pub thread_list: tail_queue::Link,
    /// `state`, `wake_active`, `active` and `event_key`.
    pub state_event: StateEvent,
    pub pset_threads: tail_queue::Link,
    /// `lock`: the thread lock, taken at splsched.
    pub lock: SimpleLock,
    pub ref_count: c_int,
    /// `pcb`: the machine-dependent process control block.
    pub pcb: *mut Pcb,
    /// `kernel_stack`: accurate only when the thread is not swapped.
    pub kernel_stack: VmOffset,
    /// `stack_privilege`: the reserved kernel stack.
    pub stack_privilege: VmOffset,
    /// `swap_func`: where the thread starts after swap-in.
    pub swap_func: Continuation,
    pub wait_event: *mut c_void,
    /// `suspend_count`: internal use only.
    pub suspend_count: c_int,
    pub wait_result: c_int,
    /// `priority`: the base priority.
    pub priority: c_int,
    pub max_priority: c_int,
    /// `sched_pri`: the computed priority.
    pub sched_pri: c_int,
    /// `sched_data`: for use by the policy.
    pub sched_data: c_int,
    pub policy: c_int,
    /// `depress_priority`: the priority when depressed.
    pub depress_priority: c_int,
    /// `cpu_usage`: the decaying CPU usage, in percent.
    pub cpu_usage: c_uint,
    /// `sched_usage`: the load-weighted CPU usage.
    pub sched_usage: c_uint,
    /// `sched_stamp`: the last priority update time.
    pub sched_stamp: c_uint,
    /// `recover`: the page-fault recovery state.
    pub recover: VmOffset,
    /// `vm_privilege`: can the thread use reserved memory.
    pub vm_privilege: c_uint,
    /// `user_stop_count`: the outstanding stops.
    pub user_stop_count: c_int,
    /// `ith_next`: the IPC thread queue's next link.
    pub ith_next: *mut Self,
    /// `ith_prev`: the IPC thread queue's previous link.
    pub ith_prev: *mut Self,
    /// `ith_state`: what a blocked message transfer was left with.
    pub ith_state: IpcWait,
    /// `data`: the received message or its maximum size.
    pub data: ThreadData,
    /// `ith_seqno`: the sequence number of the received message.
    pub ith_seqno: c_uint,
    /// `ith_messages`: messages being destroyed.
    pub ith_messages: IpcKmsgQueue,
    /// `ith_lock_data`: the IPC thread lock.
    pub ith_lock_data: SimpleLock,
    /// `ith_self`: the thread port, not a right.
    pub ith_self: *mut c_void,
    /// `ith_sself`: the thread port, a send right.
    pub ith_sself: *mut c_void,
    /// `ith_exception`: the exception port, a send right.
    pub ith_exception: *mut c_void,
    /// `ith_mig_reply`: the reply port for MIG.
    pub ith_mig_reply: c_uint,
    /// `ith_rpc_reply`: the reply port for kernel RPCs.
    pub ith_rpc_reply: *mut c_void,
    /// `saved`: the state saved when the stack is discarded.
    pub saved: Saved,
    pub user_timer: Timer,
    pub system_timer: Timer,
    pub user_timer_save: TimerSave,
    pub system_timer_save: TimerSave,
    /// `cpu_delta`: the CPU usage since the last update.
    pub cpu_delta: c_uint,
    /// `sched_delta`: the weighted CPU usage since the last update.
    pub sched_delta: c_uint,
    pub creation_time: TimeValue64,
    /// `timer`: the wait timeout.
    pub(crate) timer: MachCallout,
    /// `depress_timer`: the priority-depression timeout.
    pub(crate) depress_timer: MachCallout,
    /// `ast`: the pending AST reasons.
    pub ast: AstReason,
    pub processor_set: *mut ProcessorSet,
    pub bound_processor: *mut Processor,
    /// Whether the thread's assignment may change.
    pub may_assign: c_int,
    /// Whether someone waits for `may_assign`.
    pub assign_active: c_int,
    /// `last_processor`: the processor the thread last ran on.
    pub last_processor: *mut Processor,
    pub name: [c_char; TASK_NAME_SIZE],
    /// Set by a `lock` unpark, cleared by the park it releases; the
    /// address is the event the thread parks on.
    pub(crate) park_token: AtomicBool,
    /// The locks the thread holds, for the `lock` order checker.
    #[cfg(debug_assertions)]
    pub(crate) held_locks: HeldLocks,
}

tail_queue::adapter!(
    /// The adapter for a thread's `links` in a run, wait, reaper or swapin
    /// queue.
    pub ThreadLinksAdapter = Thread { links }
);

tail_queue::adapter!(
    /// The adapter for a thread's `thread_list` in its task.
    pub ThreadTaskListAdapter = Thread { thread_list }
);

tail_queue::adapter!(
    /// The adapter for a thread's `pset_threads` in its processor set.
    pub ThreadPsetAdapter = Thread { pset_threads }
);

/// A run queue, wait bucket, reaper queue or swapin queue. All of them share
/// the thread's `links`, so it takes the strictest need: a thread leaves a
/// run queue or a wait bucket from the middle, in O(1).
pub type ThreadQueue = TailQueue<'static, ThreadLinksAdapter>;

/// A task's threads, in creation order.
pub type TaskThreadList = TailQueue<'static, ThreadTaskListAdapter>;

/// A processor set's threads, in the order they joined.
pub type PsetThreadList = TailQueue<'static, ThreadPsetAdapter>;

// The links are two words, so the offsets below hold.
const _: () = assert!(size_of::<tail_queue::Link>() == 16);
const _: () = assert!(size_of::<ThreadQueue>() == 16);
const _: () = assert!(size_of::<TaskThreadList>() == 16);
const _: () = assert!(size_of::<PsetThreadList>() == 16);

// The `state` and `wake_active` accessors mirror the C bitfields; the
// `TH_*` constants in `sched_prim` carry the documentation.
#[allow(missing_docs)]
impl Thread {
    /// `thread_create()` copies this image and fills in the fields that depend
    /// on the run-time task and processor set.
    #[must_use]
    pub fn new() -> Self {
        // Zero every field except the callouts, which have no all-zero
        // image (a null wheel pointer), and the held-lock record, whose
        // layout is `lock`'s; those are written before the value is
        // assumed initialized.
        let mut slot = MaybeUninit::<Self>::zeroed();
        // SAFETY: `slot` is uninit storage large enough for `Self`; the
        // writes below are the first initialization of those fields.
        unsafe {
            let base = slot.as_mut_ptr();
            ptr::addr_of_mut!((*base).timer).write(MachCallout::new(
                wheel(),
                thread_timeout_action,
                (),
            ));
            ptr::addr_of_mut!((*base).depress_timer).write(MachCallout::new(
                wheel(),
                depress_timeout_action,
                (),
            ));
            #[cfg(debug_assertions)]
            ptr::addr_of_mut!((*base).held_locks).write(HeldLocks::new());
        }
        // SAFETY: every field is now initialized: zeros accept the
        // pointers, unions, locks and park token, and the callouts and
        // held-lock record were written.
        let mut thread = unsafe { slot.assume_init() };

        thread.runq = RUN_QUEUE_NULL;
        thread.ref_count = 2;
        thread.set_state(TH_SUSP | TH_SWAPPED);
        thread.swap_func =
            Some(crate::arch::x86_64::locore::thread_bootstrap_return);
        thread.max_priority = BASEPRI_SYSTEM;
        thread.policy = POLICY_TIMESHARE;
        thread.depress_priority = -1;
        thread.user_stop_count = 1;
        thread.may_assign = 1;
        thread
    }

    /// Sets up the thread and stack caches and the template.
    ///
    /// # Safety
    ///
    /// Runs once, from the boot sequence, before any thread exists.
    pub(crate) unsafe fn init() {
        // SAFETY: the boot caller runs this once, before any thread exists.
        unsafe {
            (*ptr::addr_of_mut!(THREAD_CACHE)).init(
                b"thread",
                size_of::<Self>(),
                0,
                None,
                CacheInitFlags::EMPTY,
            );
            (*ptr::addr_of_mut!(THREAD_STACK_CACHE)).init(
                b"thread_stack",
                KERNEL_STACK_SIZE,
                KERNEL_STACK_SIZE,
                None,
                CacheInitFlags::EMPTY,
            );
            (*ptr::addr_of_mut!(THREAD_TEMPLATE)).write(Self::new());
            crate::arch::x86_64::pcb::pcb_module_init();
        }
    }

    /// Arm the thread's wait timeout.
    ///
    /// # Safety
    ///
    /// `thread` must be live and not move while the callout is armed.
    pub(crate) unsafe fn start_timer(thread: *mut Self, ticks: clock::Ticks) {
        // SAFETY: the thread is zone-allocated and does not move; `timer`
        // is its callout field.
        unsafe { Pin::new_unchecked(&(*thread).timer) }.start(ticks);
    }

    /// Cancels the wait timeout, if one is armed.
    ///
    /// # Safety
    ///
    /// `thread` must be live.
    pub(crate) unsafe fn stop_timer(thread: *mut Self) {
        // SAFETY: the thread is live.
        let _ = unsafe { (*thread).timer.stop() };
    }

    /// Arm the priority-depression timeout.
    ///
    /// # Safety
    ///
    /// `thread` must be live and not move while the callout is armed.
    pub(crate) unsafe fn start_depress_timer(
        thread: *mut Self,
        ticks: clock::Ticks,
    ) {
        // SAFETY: the thread is zone-allocated and does not move.
        unsafe { Pin::new_unchecked(&(*thread).depress_timer) }.start(ticks);
    }

    /// Cancel the priority-depression timeout if armed.
    ///
    /// # Safety
    ///
    /// `thread` must be live.
    pub(crate) unsafe fn stop_depress_timer(thread: *mut Self) {
        // SAFETY: the thread is live.
        let _ = unsafe { (*thread).depress_timer.stop() };
    }

    /// Recover the thread that owns `timer`.
    ///
    /// # Safety
    ///
    /// `callout` must be `&thread.timer` for a live thread.
    pub(crate) unsafe fn from_timer(callout: *const MachCallout) -> *mut Self {
        let base = callout
            .expose_provenance()
            .wrapping_sub(offset_of!(Self, timer));
        with_exposed_provenance_mut(base)
    }

    /// Recover the thread that owns `depress_timer`.
    ///
    /// # Safety
    ///
    /// `callout` must be `&thread.depress_timer` for a live thread.
    pub(crate) unsafe fn from_depress_timer(
        callout: *const MachCallout,
    ) -> *mut Self {
        let base = callout
            .expose_provenance()
            .wrapping_sub(offset_of!(Self, depress_timer));
        with_exposed_provenance_mut(base)
    }
}

/// The expiry of [`Thread::timer`].
pub(crate) fn thread_timeout_action(callout: Pin<&MachCallout>) {
    // SAFETY: `timer` is the callout field of a live thread.
    let thread =
        unsafe { Thread::from_timer(ptr::from_ref(callout.get_ref())) };
    // SAFETY: `thread` is live; the action runs from the wheel.
    unsafe {
        clear_wait(thread, crate::kern::sched_prim::THREAD_TIMED_OUT, 0);
    };
}

/// The expiry of [`Thread::depress_timer`].
pub(crate) fn depress_timeout_action(callout: Pin<&MachCallout>) {
    // SAFETY: `depress_timer` is the callout field of a live thread.
    let thread = unsafe {
        Thread::from_depress_timer(ptr::from_ref(callout.get_ref()))
    };
    // SAFETY: `thread` is live; the action runs from the wheel.
    unsafe {
        crate::kern::syscall_subr::depress_timeout(thread.cast::<c_void>());
    };
}

#[allow(missing_docs)]
impl Thread {
    /// Charges the user and system time since the last update to the thread's
    /// scheduler usage.
    ///
    /// # Safety
    ///
    /// `thread` must be live, and the caller must hold its lock at splsched,
    /// as `update_priority()` and the quantum expiry do.
    pub unsafe fn timer_delta(thread: *mut Self) {
        let delta = unsafe {
            let system =
                (*thread).system_timer_save.delta(&(*thread).system_timer);
            let user = (*thread).user_timer_save.delta(&(*thread).user_timer);
            system.wrapping_add(user)
        };
        let load = unsafe { (*(*thread).processor_set).sched_load };
        // The C multiplies an `unsigned` by a `long` and stores the product
        // into an `unsigned`, so only the low 32 bits survive; the truncating
        // cast is exact for that.
        let scaled = delta.wrapping_mul(load as c_uint);
        unsafe {
            (*thread).cpu_delta = (*thread).cpu_delta.wrapping_add(delta);
            (*thread).sched_delta = (*thread).sched_delta.wrapping_add(scaled);
        }
    }

    pub const fn state(&self) -> u32 {
        // SAFETY: the `state` member shares the low word with `event_key`, and
        // every bit pattern is a valid `StateBits`.
        unsafe { self.state_event.state.state() }
    }

    pub const fn set_state(&mut self, state: u32) {
        // SAFETY: the `state` member shares the low word with `event_key`, and
        // every bit pattern is a valid `StateBits` and the write only
        // touches the low word.
        unsafe { self.state_event.state.set_state(state) };
    }

    pub const fn wake_active(&self) -> bool {
        // SAFETY: the `state` member shares the low word with `event_key`, and
        // every bit pattern is a valid `StateBits`.
        unsafe { self.state_event.state.wake_active() }
    }

    pub const fn set_wake_active(&mut self, active: bool) {
        // SAFETY: the `state` member shares the low word with `event_key`, and
        // every bit pattern is a valid `StateBits`.
        unsafe { self.state_event.state.set_wake_active(active) };
    }

    /// The `active` bit: whether the thread is alive.
    pub const fn active(&self) -> bool {
        // SAFETY: the `state` member shares the low word with `event_key`, and
        // every bit pattern is a valid `StateBits`.
        unsafe { self.state_event.state.active() }
    }

    pub const fn set_active(&mut self, active: bool) {
        // SAFETY: the `state` member shares the low word with `event_key`, and
        // every bit pattern is a valid `StateBits`.
        unsafe { self.state_event.state.set_active(active) };
    }

    /// The address of `event_key`: the key a suspended thread's waker waits
    /// on.
    pub const fn wake_active_event(&self) -> *mut c_void {
        (&raw const self.state_event.event_key)
            .cast::<c_void>()
            .cast_mut()
    }

    /// The address one `event_key` on: the key a thread waiting for its state
    /// to become interruptible uses.
    pub const fn state_event(&self) -> *mut c_void {
        let event = (&raw const self.state_event.event_key).cast_mut();
        // SAFETY: the union holds one pointer, so one element past
        // `event_key` stays inside `state_event`; the C's `&event_key + 1`.
        unsafe { event.add(1) }.cast::<c_void>()
    }
}

impl Thread {
    /// Takes a reference on `thread`, when it is not null.
    ///
    /// # Safety
    ///
    /// `thread` must point at a live thread.
    pub unsafe fn reference(thread: *mut Self) {
        // SAFETY: `splsched()` is the C spl call and returns the level to
        // restore.
        let s = unsafe { spl::splsched() };
        unsafe {
            (*thread).lock.lock();
            (*thread).ref_count = (*thread).ref_count.wrapping_add(1);
            (*thread).lock.unlock();
            spl::splx(s);
        }
    }

    /// Counts one more suspension of `thread`.
    ///
    /// # Safety
    ///
    /// `thread` must point at a live thread.
    pub unsafe fn hold(thread: *mut Self) {
        // SAFETY: `splsched()` is the C spl call and returns the level to
        // restore.
        let s = unsafe { spl::splsched() };
        unsafe {
            (*thread).lock.lock();
            (*thread).suspend_count = (*thread).suspend_count.wrapping_add(1);
            let state = (*thread).state();
            (*thread).set_state(state | TH_SUSP);
            (*thread).lock.unlock();
            spl::splx(s);
        }
    }

    /// Counts one suspension of `thread` fewer, letting it run again with the
    /// last.
    ///
    /// # Safety
    ///
    /// `thread` must point at a live thread.
    pub unsafe fn release(thread: *mut Self) {
        // SAFETY: `splsched()` is the C spl call and returns the level to
        // restore.
        let s = unsafe { spl::splsched() };
        unsafe {
            (*thread).lock.lock();
            (*thread).suspend_count = (*thread).suspend_count.wrapping_sub(1);
            if (*thread).suspend_count == 0 {
                let state = (*thread).state() & !(TH_SUSP | TH_HALTED);
                (*thread).set_state(state);
                if state & (TH_WAIT | TH_RUN) == 0 {
                    (*thread).set_state(state | TH_RUN);
                    thread_setrun(thread, 1);
                }
            }
            (*thread).lock.unlock();
            spl::splx(s);
        }
    }

    /// Resumes `thread`, undoing one suspension.
    ///
    /// # Safety
    ///
    /// `thread` must be null or point at a live thread.
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when `thread` is null, and
    /// [`Error::Failure`] when the thread's user stop count is already
    /// zero.
    pub unsafe fn resume(thread: *mut Self) -> Result<(), Error> {
        if thread.is_null() {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: `splsched()` is the C spl call and returns the level to
        // restore.
        let s = unsafe { spl::splsched() };
        // SAFETY: the null check above; the lock
        // protects both stop counts and the state word, and `thread_setrun()`
        // expects the thread lock held.
        unsafe {
            (*thread).lock.lock();
            let result = if (*thread).user_stop_count > 0 {
                (*thread).user_stop_count =
                    (*thread).user_stop_count.wrapping_sub(1);
                if (*thread).user_stop_count == 0 {
                    (*thread).suspend_count =
                        (*thread).suspend_count.wrapping_sub(1);
                    if (*thread).suspend_count == 0 {
                        let state = (*thread).state() & !(TH_SUSP | TH_HALTED);
                        (*thread).set_state(state);
                        if state & (TH_WAIT | TH_RUN) == 0 {
                            (*thread).set_state(state | TH_RUN);
                            thread_setrun(thread, 1);
                        }
                    }
                }
                Ok(())
            } else {
                Err(Error::Failure)
            };
            (*thread).lock.unlock();
            spl::splx(s);
            result
        }
    }

    /// Terminates `thread` at once, as the task's termination does for each of
    /// its threads.
    ///
    /// # Safety
    ///
    /// `thread` must point at a live thread that is not the current thread;
    /// `task_terminate()` is the C caller.
    pub unsafe fn force_terminate(thread: *mut Self) {
        unsafe { ipc_thread_disable(thread) };

        unsafe { Self::freeze(thread) };

        let default_pset = default_pset();
        if unsafe { (*thread).processor_set } != default_pset {
            unsafe { Self::doassign(thread, default_pset, false) };
        }

        let deallocate_here = unsafe {
            let s = spl::splsched();
            (*thread).lock.lock();
            let active = (*thread).active();
            (*thread).set_active(false);
            (*thread).lock.unlock();
            spl::splx(s);
            active
        };

        let _ = unsafe { Self::halt(thread, true) };
        unsafe { ipc_thread_terminate(thread) };
        unsafe { Self::unfreeze(thread) };

        if deallocate_here {
            unsafe { Self::deallocate(thread) };
        }
    }

    /// Aborts the wait or the kernel call `thread` is in.
    ///
    /// # Safety
    ///
    /// `thread` must be null or point at a live thread.
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when `thread` is null or the
    /// current thread, and [`Error::Aborted`] when the halt fails.
    pub unsafe fn abort(thread: *mut Self) -> Result<(), Error> {
        if thread.is_null() || thread == per_cpu::thread() {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: the check above; the event count
        // takes the thread lock itself.
        unsafe { eventcount::notify_abort(thread) };

        if unsafe { Self::halt(thread, false) }.is_err() {
            return Err(Error::Aborted);
        }

        unsafe { abort_rpc(thread) };

        unsafe { Self::release(thread) };

        if unsafe { (*thread).depress_priority } != -1 {
            let _ = unsafe { depress_abort(thread) };
        }

        Ok(())
    }

    /// Sets the continuation the thread starts at.
    pub fn start(&mut self, start: Continuation) {
        self.swap_func = start;
    }

    /// Lets a frozen thread be assigned again.
    ///
    /// # Safety
    ///
    /// `thread` must point at a live thread.
    pub unsafe fn unfreeze(thread: *mut Self) {
        // SAFETY: `splsched()` is the C spl call and returns the level to
        // restore.
        let s = unsafe { spl::splsched() };
        unsafe {
            (*thread).lock.lock();
            (*thread).may_assign = 1;
            if (*thread).assign_active != 0 {
                (*thread).assign_active = 0;
                thread_wakeup_prim(
                    ptr::addr_of_mut!((*thread).assign_active)
                        .cast::<c_void>(),
                    0,
                    THREAD_AWAKENED,
                );
            }
            (*thread).lock.unlock();
            spl::splx(s);
        }
    }

    /// The processor set `thread` is assigned to, with a reference.
    ///
    /// # Safety
    ///
    /// `thread` must be null or point at a live thread.
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when `thread` is null.
    pub unsafe fn assignment(
        thread: *mut Self,
    ) -> Result<*mut ProcessorSet, Error> {
        if thread.is_null() {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: the check above; the set pointer
        // is the thread's own assignment.
        let pset = unsafe { (*thread).processor_set };
        unsafe { (*pset).reference() };
        Ok(pset)
    }
}

/// Compute the `sched_data` quantum a fixed-priority request yields: `data`
/// milliseconds, rounded up to whole `tick`s.
///
/// # Panics
///
/// Panics if the kernel's `tick` global is zero: the conversion divides by it.
const fn fixedpri_quantum(data: c_int) -> c_int {
    let tick_rate = machine::TICK;
    let temp = data.wrapping_mul(1000);
    let temp = if temp % tick_rate != 0 {
        temp.wrapping_add(tick_rate)
    } else {
        temp
    };
    temp / tick_rate
}

impl Thread {
    /// Reads `thread`'s machine state of `flavor` into `old_state`.
    ///
    /// # Safety
    ///
    /// `thread` must be null or point at a live thread; `old_state` must be
    /// writable for the words `*old_state_count` names, and `old_state_count`
    /// must be valid for a read and a write.
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when `thread` is null or the
    /// current thread; otherwise it returns the error the machine-dependent
    /// status routine reports.
    pub unsafe fn get_status(
        thread: *mut Self,
        flavor: c_int,
        old_state: *mut c_uint,
        old_state_count: *mut c_uint,
    ) -> Result<(), Error> {
        if flavor == I386_DEBUG_STATE && thread == per_cpu::thread() {
            return unsafe {
                crate::arch::x86_64::pcb::thread_getstatus(
                    thread,
                    flavor,
                    old_state,
                    old_state_count,
                )
            }
            .map_err(Error::from);
        }

        if thread.is_null() || thread == per_cpu::thread() {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: the checks above; the suspend and
        // the wait take the thread lock themselves.
        unsafe {
            Self::hold(thread);
            let _ = Self::dowait(thread, true);
        }

        let result = unsafe {
            crate::arch::x86_64::pcb::thread_getstatus(
                thread,
                flavor,
                old_state,
                old_state_count,
            )
        }
        .map_err(Error::from);

        unsafe { Self::release(thread) };

        result
    }

    /// Sets `thread`'s machine state of `flavor`.
    ///
    /// # Safety
    ///
    /// `thread` must be null or point at a live thread, and `new_state` must
    /// be readable for `new_state_count` words.
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when `thread` is null or the
    /// current thread; otherwise it returns the error the machine-dependent
    /// status routine reports.
    pub unsafe fn set_status(
        thread: *mut Self,
        flavor: c_int,
        new_state: *mut c_uint,
        new_state_count: c_uint,
    ) -> Result<(), Error> {
        if thread == per_cpu::thread()
            && (flavor == I386_DEBUG_STATE || flavor == I386_FSGS_BASE_STATE)
        {
            return unsafe {
                crate::arch::x86_64::pcb::thread_setstatus(
                    thread,
                    flavor,
                    new_state,
                    new_state_count,
                )
            }
            .map_err(Error::from);
        }

        if thread.is_null() || thread == per_cpu::thread() {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: the checks above; the suspend and
        // the wait take the thread lock themselves.
        unsafe {
            Self::hold(thread);
            let _ = Self::dowait(thread, true);
        }

        let result = unsafe {
            crate::arch::x86_64::pcb::thread_setstatus(
                thread,
                flavor,
                new_state,
                new_state_count,
            )
        }
        .map_err(Error::from);

        unsafe { Self::release(thread) };

        result
    }

    /// Sets `thread`'s base priority, and its maximum when `set_max` is set.
    ///
    /// # Safety
    ///
    /// `thread` must be null or point at a live thread.
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when `thread` is null or
    /// `priority` is invalid, and [`Error::Failure`] when `priority` is
    /// below the thread's maximum priority.
    pub unsafe fn priority(
        thread: *mut Self,
        priority: c_int,
        set_max: bool,
    ) -> Result<(), Error> {
        if thread.is_null() || invalid_pri(priority) {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: the thread lock is taken under `splsched()`.
        let s = unsafe { spl::splsched() };
        // SAFETY: the checks above; the thread lock
        // protects every field below.
        let result = unsafe {
            (*thread).lock.lock();
            let result = if priority < (*thread).max_priority {
                Err(Error::Failure)
            } else {
                if (*thread).depress_priority >= 0 {
                    (*thread).depress_priority = priority;
                } else {
                    (*thread).priority = priority;
                    compute_priority(thread, 1);
                }
                if set_max {
                    (*thread).max_priority = priority;
                }
                Ok(())
            };
            (*thread).lock.unlock();
            result
        };
        // SAFETY: `s` is the level `splsched()` returned.
        unsafe { spl::splx(s) };

        result
    }

    /// Sets the current thread's priority.
    ///
    /// # Safety
    ///
    /// The caller must be the current thread and hold no thread lock:
    /// `splsched()` raises the level and this takes the current thread's lock.
    pub unsafe fn set_own_priority(priority: c_int) {
        let thread = per_cpu::thread();
        // SAFETY: the thread lock is taken under `splsched()`.
        let s = unsafe { spl::splsched() };
        // SAFETY: `thread` is the live current thread, and the lock protects
        // the priority fields.
        unsafe {
            (*thread).lock.lock();
            if priority < (*thread).max_priority {
                (*thread).max_priority = priority;
            }
            (*thread).priority = priority;
            compute_priority(thread, 1);
            (*thread).lock.unlock();
            // SAFETY: `s` is the level `splsched()` returned.
            spl::splx(s);
        }
    }

    /// Sets `thread`'s maximum priority, with the authority of `pset`'s
    /// control port.
    ///
    /// # Safety
    ///
    /// `thread` and `pset` must be null or point at live objects.
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when an argument is null or
    /// `max_priority` is invalid, and [`Error::Failure`] when `pset` is
    /// not the thread's processor set.
    pub unsafe fn max_priority(
        thread: *mut Self,
        pset: *mut ProcessorSet,
        max_priority: c_int,
    ) -> Result<(), Error> {
        if thread.is_null() || pset.is_null() || invalid_pri(max_priority) {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: the thread lock is taken under `splsched()`.
        let s = unsafe { spl::splsched() };
        // SAFETY: the checks above; the thread lock
        // protects every field below.
        let result = unsafe {
            (*thread).lock.lock();
            let result = if pset == (*thread).processor_set {
                (*thread).max_priority = max_priority;
                if max_priority > (*thread).priority {
                    (*thread).priority = max_priority;
                    compute_priority(thread, 1);
                } else if (*thread).depress_priority >= 0
                    && max_priority > (*thread).depress_priority
                {
                    (*thread).depress_priority = max_priority;
                }
                Ok(())
            } else {
                Err(Error::Failure)
            };
            (*thread).lock.unlock();
            result
        };
        // SAFETY: `s` is the level `splsched()` returned.
        unsafe { spl::splx(s) };

        result
    }

    /// Sets `thread`'s scheduling policy to `policy`, with `data` its
    /// parameter.
    ///
    /// # Safety
    ///
    /// `thread` must be null or point at a live thread.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when `thread` is null or the
    /// policy is invalid, and [`Error::Failure`] when the thread's
    /// processor set does not support the policy.
    ///
    /// # Panics
    ///
    /// Panics through [`fixedpri_quantum()`] if the kernel's `tick` global is
    /// zero, which the C divides by in the same case.
    pub unsafe fn policy(
        thread: *mut Self,
        policy: c_int,
        data: c_int,
    ) -> Result<(), Error> {
        if thread.is_null() || invalid_policy(policy) {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: the thread lock is taken under `splsched()`.
        let s = unsafe { spl::splsched() };
        // SAFETY: the checks above; the thread lock
        // protects every field below.
        let result = unsafe {
            (*thread).lock.lock();
            let result = if policy == (*thread).policy {
                if policy == POLICY_FIXEDPRI {
                    (*thread).sched_data = fixedpri_quantum(data);
                }
                Ok(())
            } else {
                let pset = (*thread).processor_set;
                if ((*pset).policies & policy) == 0 {
                    Err(Error::Failure)
                } else {
                    (*thread).policy = policy;
                    if policy == POLICY_FIXEDPRI {
                        (*thread).sched_data = fixedpri_quantum(data);
                    }
                    compute_priority(thread, 1);
                    Ok(())
                }
            };
            (*thread).lock.unlock();
            result
        };
        // SAFETY: `s` is the level `splsched()` returned.
        unsafe { spl::splx(s) };

        result
    }

    /// Gives `thread` the VM privilege, or takes it away.
    ///
    /// # Safety
    ///
    /// `thread` must be null or point at a live thread.
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when `thread` is null or is
    /// not the current thread.
    pub unsafe fn wire(thread: *mut Self, wired: bool) -> Result<(), Error> {
        if thread.is_null() || thread != per_cpu::thread() {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: the thread lock is taken under `splsched()`.
        let s = unsafe { spl::splsched() };
        // SAFETY: the checks above; the thread lock
        // protects the privilege fields, and the Rust `stack_privilege()`
        // compares the thread with the current one, which the check above
        // already found equal.
        unsafe {
            (*thread).lock.lock();
            if wired {
                (*thread).vm_privilege = 1;
                (*thread).stack_privilege();
            } else {
                (*thread).vm_privilege = 0;
                (*thread).stack_privilege = 0;
            }
            (*thread).lock.unlock();
            spl::splx(s);
        }

        Ok(())
    }

    /// Sets `thread`'s name from `name`.
    ///
    /// # Safety
    ///
    /// `thread` must be null or point at a live thread, and `name` must be
    /// readable up to `TASK_NAME_SIZE - 1` bytes or a NUL inside them.
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when `thread` is null.
    pub unsafe fn set_name(
        thread: *mut Self,
        name: *const c_char,
    ) -> Result<(), Error> {
        if thread.is_null() {
            return Err(Error::InvalidArgument);
        }

        // The name ends at its first NUL or after `TASK_NAME_SIZE - 1` bytes,
        // and NULs fill the rest of the field.
        unsafe {
            let field = (&raw mut (*thread).name).cast::<c_char>();
            let mut len = 0;
            while len < TASK_NAME_SIZE - 1 && name.add(len).read() != 0 {
                field.add(len).write(name.add(len).read());
                len += 1;
            }
            field.add(len).write_bytes(0, TASK_NAME_SIZE - len);
        }
        Ok(())
    }

    /// Copies `thread`'s name into `name`.
    ///
    /// # Safety
    ///
    /// `thread` must be null or point at a live thread, and `name` must be
    /// writable for `TASK_NAME_SIZE` bytes.
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when `thread` is null.
    pub unsafe fn get_name(
        thread: *mut Self,
        name: *mut c_char,
    ) -> Result<(), Error> {
        if thread.is_null() {
            return Err(Error::InvalidArgument);
        }

        // The copy stops at the name's first NUL, and NULs fill the rest of
        // `name`.
        unsafe {
            let field = (&raw const (*thread).name).cast::<c_char>();
            let mut len = 0;
            while len < TASK_NAME_SIZE && field.add(len).read() != 0 {
                name.add(len).write(field.add(len).read());
                len += 1;
            }
            name.add(len).write_bytes(0, TASK_NAME_SIZE - len);
        }
        Ok(())
    }
}

impl Thread {
    /// Gives the thread a cached kernel stack without blocking, returning
    /// whether one was free, with `resume` as its resume point.
    ///
    /// # Safety
    ///
    /// The caller must hold this thread's lock at splsched, as the swap path
    /// does, and `resume` must be a stack continuation.
    #[must_use]
    pub(crate) unsafe fn stack_alloc_try(
        &mut self,
        resume: StackResume,
    ) -> bool {
        // SAFETY: every stack on the list is a live cache object, as `push`
        // requires.
        let stack = unsafe { STACK_FREE.lock().pop() };

        let stack = if stack != 0 {
            stack
        } else {
            self.stack_privilege
        };

        if stack == 0 {
            return false;
        }

        // SAFETY: `stack` is a whole cache object, or this thread's private
        // one, and the C `stack_attach()` writes only this thread's fields and
        // the stack's first frame.
        unsafe {
            crate::arch::x86_64::pcb::stack_attach(
                ptr::from_mut(self),
                stack,
                resume,
            );
        };

        true
    }

    /// Gives the thread a kernel stack, blocking until one is free, with
    /// `resume` as its resume point.
    ///
    /// # Safety
    ///
    /// The caller must hold no spin lock, because the cache allocation may
    /// block, and `resume` must be a stack continuation.
    pub(crate) unsafe fn stack_alloc(&mut self, resume: StackResume) {
        // SAFETY: every stack on the list is a live cache object, as `push`
        // requires.
        let stack = unsafe { STACK_FREE.lock().pop() };

        let stack = if stack == 0 {
            let fresh =
                unsafe { (*ptr::addr_of_mut!(THREAD_STACK_CACHE)).alloc() };
            let fresh = fresh.map_or(0, |buf| buf.as_ptr().addr());
            // SAFETY: `stack_init()` marks the fresh object when the usage
            // check is on, exactly as the C called it.
            unsafe { stack_init(fresh) };
            fresh
        } else {
            stack
        };

        unsafe {
            crate::arch::x86_64::pcb::stack_attach(
                ptr::from_mut(self),
                stack,
                resume,
            );
        };
    }

    /// Returns the thread's kernel stack to the cached-stack list or the
    /// cache.
    ///
    /// # Safety
    ///
    /// The caller must hold this thread's lock at splsched, and a stack must
    /// be attached: the C walks the returned stack's link word.
    pub(crate) unsafe fn stack_free(&mut self) {
        let privilege = self.stack_privilege;
        let stack = unsafe {
            crate::arch::x86_64::pcb::stack_detach(ptr::from_mut(self))
        };

        if stack != privilege {
            // SAFETY: the detached stack is a live cache object on no list.
            unsafe { STACK_FREE.lock().push(stack) };
        }
    }

    /// Frees the cached stacks beyond the limit.
    ///
    /// # Safety
    ///
    /// The caller must hold no spin lock.
    pub(crate) unsafe fn stack_collect() {
        let mut stacks = STACK_FREE.lock();
        while stacks.count > STACK_FREE_LIMIT.load(Ordering::Relaxed) {
            // SAFETY: every stack on the list is a live cache object, and a
            // count above the limit means the list is not empty.
            let stack = unsafe { stacks.pop() };
            // The list's lock is released for the free, which may block.
            stacks.unlocked(|| {
                // SAFETY: the stack is off the list, a whole object of
                // `THREAD_STACK_CACHE`, and nothing else references it.
                unsafe {
                    stack_finalize(stack);
                    if let Some(stack) =
                        NonNull::new(with_exposed_provenance_mut::<u8>(stack))
                    {
                        (*ptr::addr_of_mut!(THREAD_STACK_CACHE)).free(stack);
                    }
                }
            });
        }
    }

    /// Gives the thread a stack of its own, kept across switches.
    ///
    /// # Safety
    ///
    /// The caller must be running on `self`; the C halts the kernel otherwise.
    pub(crate) unsafe fn stack_privilege(&mut self) {
        if per_cpu::thread() != ptr::from_mut(self) {
            kpanic!("stack_privilege", "stack_privilege")
        }

        if self.stack_privilege == 0 {
            self.stack_privilege = per_cpu::stack();
        }
    }
}

impl Default for Thread {
    fn default() -> Self {
        Self::new()
    }
}

const _: () = assert!(size_of::<StateBits>() == size_of::<u32>());
const _: () = assert!(
    size_of::<StateEvent>()
        == if size_of::<*mut c_void>() > size_of::<u32>() {
            size_of::<*mut c_void>()
        } else {
            size_of::<u32>()
        }
);

const _: () = assert!(KERNEL_STACK_SIZE.is_multiple_of(size_of::<VmOffset>()));

const _: () = assert!(size_of::<IpcKmsgQueue>() == size_of::<*mut c_void>());
const _: () = {
    assert!(size_of::<SavedReceive>() == 40);
    assert!(size_of::<SavedException>() == 24);
    assert!(size_of::<Saved>() == 40);
};
const _: () = assert!(size_of::<ThreadData>() == 8);

/// The free-list link word of a stack object, in the last word of its
/// `KERNEL_STACK_SIZE` region.
///
/// # Safety
///
/// `stack` must be the base address of a live stack-cache object.
const unsafe fn stack_next(stack: VmOffset) -> VmOffset {
    unsafe {
        ptr::with_exposed_provenance::<VmOffset>(stack)
            .add(KERNEL_STACK_SIZE / size_of::<VmOffset>() - 1)
            .read()
    }
}

/// Store `next` as the free-list link of a stack object, the C's
/// `stack_next(stack) = next`.
///
/// # Safety
///
/// `stack` must be the base address of a live stack-cache object.
const unsafe fn set_stack_next(stack: VmOffset, next: VmOffset) {
    unsafe {
        with_exposed_provenance_mut::<VmOffset>(stack)
            .add(KERNEL_STACK_SIZE / size_of::<VmOffset>() - 1)
            .write(next);
    }
}

/// The cached stacks, linked through each stack's last word, and their count.
struct StackFreeList {
    /// The first stack, or zero when the list is empty.
    head: VmOffset,
    count: u32,
}

impl StackFreeList {
    /// Remove the first stack, or return zero when the list is empty.
    ///
    /// # Safety
    ///
    /// Every entry on the list must be a live cache object.
    const unsafe fn pop(&mut self) -> VmOffset {
        let stack = self.head;
        if stack != 0 {
            self.head = unsafe { stack_next(stack) };
            self.count -= 1;
        }
        stack
    }

    /// Return `stack` to the list.
    ///
    /// # Safety
    ///
    /// `stack` must be a live cache object on no list.
    const unsafe fn push(&mut self, stack: VmOffset) {
        unsafe { set_stack_next(stack, self.head) };
        self.head = stack;
        self.count += 1;
    }
}

/// The slab cache of [`Thread`] records.
static mut THREAD_CACHE: KmemCache = KmemCache::zeroed();

/// The kernel-stack slab cache.
static mut THREAD_STACK_CACHE: KmemCache = KmemCache::zeroed();

/// The image [`Thread::create`] copies.  Built by [`Thread::new`] in
/// [`Thread::init`], never zeroed.
static mut THREAD_TEMPLATE: MaybeUninit<Thread> = MaybeUninit::uninit();

/// The threads waiting for the reaper.
struct ReaperQueue(ThreadQueue);

// SAFETY: the queue links thread records, which every CPU shares.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "the linked threads are shared between CPUs, which their type \
              does not say"
)]
unsafe impl Send for ReaperQueue {}

impl ReaperQueue {
    /// The queue, pinned.
    const fn pinned(&mut self) -> Pin<&mut ThreadQueue> {
        // SAFETY: the one `ReaperQueue` is in `REAPER_QUEUE`, a static, which
        // never moves.
        unsafe { Pin::new_unchecked(&mut self.0) }
    }
}

/// The threads waiting for the reaper, under an irq spin lock, since a
/// terminating thread queues itself at splsched.
static REAPER_QUEUE: IrqSpinLock<ReaperQueue, MachPlatform> =
    IrqSpinLock::new(ReaperQueue(ThreadQueue::new()));

/// The reaper queue's address, the event the reaper thread waits on.
fn reaper_event() -> *mut c_void {
    ptr::from_ref(&REAPER_QUEUE).cast_mut().cast()
}

/// The cached stacks, under an irq spin lock, since the scheduler frees a
/// stack at splsched.
static STACK_FREE: IrqSpinLock<StackFreeList, MachPlatform> =
    IrqSpinLock::new(StackFreeList { head: 0, count: 0 });

/// The cached-stack high-water mark a debugger may lower or raise.
static STACK_FREE_LIMIT: AtomicU32 = AtomicU32::new(1);

/// How many stacks the deallocator freed, a counter for a debugger to read.
static THREAD_DEALLOCATE_STACK: AtomicU32 = AtomicU32::new(0);

/// Whether stack usage is tracked.
static STACK_CHECK_USAGE: AtomicI32 = AtomicI32::new(0);

/// The largest kernel-stack usage seen.
static STACK_MAX_USAGE: AtomicVmSize = AtomicVmSize::new(0);

/// No port name.
const MACH_PORT_NULL: c_uint = 0;

/// The default processor set.
pub(crate) fn default_pset() -> *mut ProcessorSet {
    processor::default_pset()
}

/// The stack accounting `host_stack_usage()` and
/// `processor_set_stack_usage()` report.
pub(crate) struct StackUsage {
    /// The number of stacks counted.
    pub total: c_uint,
    /// The VM space they reserve, equal to the resident space.
    pub space: VmSize,
    /// The largest usage seen, when `STACK_CHECK_USAGE` is on.
    pub maxusage: VmSize,
    /// The address of the thread with the largest stack.
    pub maxstack: VmOffset,
}

impl Thread {
    /// Reference `task`'s processor set, as `thread_create()` did.
    ///
    /// # Safety
    ///
    /// `task` must point at a live task.
    unsafe fn reference_pset(task: *mut Task) -> *mut ProcessorSet {
        // SAFETY: `task` is live; the lock covers the set pointer, and the
        // reference keeps the set alive past the unlock.
        unsafe {
            (*task).lock.lock();
            let pset = (*task).processor_set;
            (*pset).reference();
            (*task).lock.unlock();
            pset
        }
    }

    /// Follow `task`'s processor set until it settles, releasing the
    /// reference held on `pset`, as `thread_create()` did.
    ///
    /// # Safety
    ///
    /// `task` must point at a live task and `pset` be its previously
    /// referenced processor set.
    unsafe fn stabilize_pset(
        task: *mut Task,
        mut pset: *mut ProcessorSet,
    ) -> *mut ProcessorSet {
        // SAFETY: the task is live; the loop holds the new set's lock and
        // the task lock, and the reference keeps whichever set it settles
        // on alive.
        loop {
            // SAFETY: the task is live; the loop bounds the borrowed set,
            // whose lock and the task's lock it takes below.
            unsafe {
                (*pset).lock.lock();
                (*task).lock.lock();

                let mut cur_pset = (*task).processor_set;
                if (*cur_pset).active == 0 {
                    cur_pset = default_pset();
                }

                if cur_pset != pset {
                    (*cur_pset).reference();
                    (*task).lock.unlock();
                    (*pset).lock.unlock();
                    (*pset).deallocate();
                    pset = cur_pset;
                    continue;
                }
            }
            break;
        }

        pset
    }

    /// Creates a suspended thread in `parent_task`.
    ///
    /// # Safety
    ///
    /// `parent_task` must be null or point at a live task, and the caller
    /// must hold no locks: the routine allocates and may block.
    pub(crate) unsafe fn create(
        parent_task: *mut Task,
    ) -> Result<*mut Self, Error> {
        if parent_task.is_null() {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: `Thread::init` built the cache before any thread existed,
        // and the allocation may block, as the caller permits.
        let Some(buf) =
            (unsafe { (*ptr::addr_of_mut!(THREAD_CACHE)).alloc() })
        else {
            return Err(Error::ResourceShortage);
        };
        let new_thread = buf.as_ptr().cast::<Self>();

        // SAFETY: the storage is fresh and unshared; every field below is
        // written before the thread is visible to anything else.
        unsafe {
            new_thread.write(ptr::read(
                (*ptr::addr_of!(THREAD_TEMPLATE)).assume_init_ref(),
            ));
            host_time::record_time_stamp(ptr::addr_of_mut!(
                (*new_thread).creation_time
            ));
            (*new_thread).task = parent_task;

            let cur_thread = per_cpu::thread();
            if !cur_thread.is_null() {
                let cur_task = current_task();
                if cur_task != kernel_task()
                    && parent_task == cur_task
                    && (*cur_thread).vm_privilege != 0
                {
                    (*new_thread).vm_privilege = 1;
                }
            }
            (*new_thread).lock.init();
            (*new_thread).sched_stamp = sched_tick();
            thread_timeout_setup(new_thread);
            crate::arch::x86_64::pcb::pcb_init(parent_task, new_thread);
            ipc_thread_init(new_thread);
        }

        let pset = unsafe { Self::reference_pset(parent_task) };

        // SAFETY: the set is live and referenced; the load average and the
        // new thread's fields are the C's, under the same conditions.
        unsafe {
            let scale = SCHED_SCALE.unsigned_abs();
            let divisor = if (*pset).load_average >= c_long::from(SCHED_SCALE)
            {
                u32::try_from((*pset).load_average).unwrap_or(u32::MAX)
            } else {
                scale
            };
            (*new_thread).cpu_usage = (TIMER_RATE * scale) / divisor;
            (*new_thread).sched_usage = TIMER_RATE * scale;
        }

        let pset = unsafe { Self::stabilize_pset(parent_task, pset) };

        // SAFETY: both sets and the task are locked, and the thread is not
        // visible yet, so its fields are safe to set without its lock.
        unsafe {
            (*new_thread).priority = (*parent_task).priority;
            (*new_thread).max_priority = (*parent_task).max_priority;
            if (*pset).max_priority > (*new_thread).max_priority {
                (*new_thread).max_priority = (*pset).max_priority;
            }
            if (*new_thread).max_priority > (*new_thread).priority {
                (*new_thread).priority = (*new_thread).max_priority;
            }
            compute_priority(new_thread, 1);
            (*new_thread).suspend_count =
                (*parent_task).suspend_count.wrapping_add(1);

            (*pset).add_thread(new_thread);
            if (*pset).empty != 0 {
                (*new_thread).suspend_count =
                    (*new_thread).suspend_count.wrapping_add(1);
            }

            ptr::copy_nonoverlapping(
                (*parent_task).name.as_ptr(),
                (*new_thread).name.as_mut_ptr(),
                TASK_NAME_SIZE,
            );

            (*parent_task).ref_count =
                (*parent_task).ref_count.wrapping_add(1);
            (*parent_task).thread_count =
                (*parent_task).thread_count.wrapping_add(1);
            Task::threads_pinned(parent_task)
                .push_back_ptr(NonNull::new_unchecked(new_thread));

            (*new_thread).set_active(true);

            if !(*parent_task).active() {
                (*parent_task).lock.unlock();
                (*pset).lock.unlock();
                let _ = Self::terminate(new_thread);
                Self::deallocate(new_thread);
                return Err(Error::Failure);
            }
            (*parent_task).lock.unlock();
            (*pset).lock.unlock();
        }

        // SAFETY: the thread is live and active, and its IPC state is built.
        unsafe { ipc_thread_enable(new_thread) };

        Ok(new_thread)
    }

    /// Drops a reference on `thread`, freeing it on the last one.
    ///
    /// # Safety
    ///
    /// `thread` must be null or a live thread the caller holds a reference
    /// to, and the caller must hold no locks: the teardown may block.
    pub(crate) unsafe fn deallocate(thread: *mut Self) {
        if thread.is_null() {
            return;
        }

        unsafe {
            let s = spl::splsched();
            (*thread).lock.lock();
            (*thread).ref_count = (*thread).ref_count.wrapping_sub(1);
            if (*thread).ref_count > 0 {
                (*thread).lock.unlock();
                spl::splx(s);
                return;
            }

            (*thread).ref_count = 1;
            (*thread).lock.unlock();
            spl::splx(s);
        }

        unsafe {
            let mut pset = (*thread).processor_set;
            (*pset).lock.lock();

            while pset != (*thread).processor_set {
                (*pset).lock.unlock();
                pset = (*thread).processor_set;
                (*pset).lock.lock();
            }

            let task = (*thread).task;
            (*task).lock.lock();

            let s = spl::splsched();
            (*thread).lock.lock();

            (*thread).ref_count = (*thread).ref_count.wrapping_sub(1);
            if (*thread).ref_count > 0 {
                (*thread).lock.unlock();
                spl::splx(s);
                (*task).lock.unlock();
                (*pset).lock.unlock();
                return;
            }

            // Zone free does not run `Drop` (ADR 0040): cancel both
            // callouts before the thread returns to the cache.
            ptr::drop_in_place(ptr::addr_of_mut!((*thread).timer));
            ptr::drop_in_place(ptr::addr_of_mut!((*thread).depress_timer));
            (*thread).depress_priority = -1;

            let (user_time, system_time) = read_times(&*thread);
            add_time64(&mut (*task).total_user_time, user_time);
            add_time64(&mut (*task).total_system_time, system_time);

            (*task).thread_count = (*task).thread_count.wrapping_sub(1);
            Task::threads_pinned(task)
                .remove_ptr(NonNull::new_unchecked(thread));

            (*pset).remove_thread(thread);

            (*thread).lock.unlock();
            spl::splx(s);
            (*task).lock.unlock();
            (*pset).lock.unlock();
            (*pset).deallocate();
        }

        // SAFETY: the checks are the C's; a live thread is never the current
        // one here, and an unreferenced thread is suspended.
        unsafe {
            if thread == per_cpu::thread() {
                kpanic!("thread_deallocate", "thread deallocating itself")
            }
            if (*thread).state() & !(TH_RUN | TH_HALTED | TH_SWAPPED)
                != TH_SUSP
            {
                kpanic!("thread_deallocate", "unstopped thread destroyed!")
            }
        }

        // SAFETY: the thread holds the task reference it took at creation,
        // and it is not running; `task_deallocate()` may block.
        unsafe { crate::kern::task::deallocate((*thread).task) };

        // SAFETY: the thread is dead at splsched; its stack, if any, is
        // detached.
        unsafe {
            if (*thread).state() & TH_SWAPPED == 0 {
                let s = spl::splsched();
                (*thread).stack_free();
                spl::splx(s);
                THREAD_DEALLOCATE_STACK.fetch_add(1, Ordering::Relaxed);
            }
        }

        // SAFETY: the thread is dead; the event count takes its own lock.
        unsafe { eventcount::notify_abort(thread) };
        unsafe { crate::arch::x86_64::pcb::pcb_terminate(thread) };

        // SAFETY: the thread came from `THREAD_CACHE`, and the entry check
        // makes its pointer non-null, so the free is sound.
        unsafe {
            (*ptr::addr_of_mut!(THREAD_CACHE))
                .free(NonNull::new_unchecked(thread.cast::<u8>()));
        }
    }

    /// Terminates `thread`.
    ///
    /// # Safety
    ///
    /// `thread` must be null or point at a live thread, and the caller must
    /// hold no locks: the routine waits and may block.
    pub(crate) unsafe fn terminate(thread: *mut Self) -> Result<(), Error> {
        let cur_thread = per_cpu::thread();

        if thread.is_null() {
            return Err(Error::InvalidArgument);
        }

        unsafe { ipc_thread_disable(thread) };

        if thread == cur_thread {
            // SAFETY: the current thread is live; the lock protects the state
            // word and the AST reasons.
            unsafe {
                let s = spl::splsched();
                (*thread).lock.lock();
                if (*thread).active() {
                    (*thread).set_active(false);
                    (*thread).ast |= AstReason::TERMINATE;
                }
                (*thread).lock.unlock();
                ast::on(cpu_id(), AstReason::TERMINATE);
                spl::splx(s);
            }
            return Ok(());
        }

        unsafe {
            let cur_task = current_task();
            (*cur_task).lock.lock();
            let s = spl::splsched();
            if thread.addr() < cur_thread.addr() {
                (*thread).lock.lock();
                (*cur_thread).lock.lock();
            } else {
                (*cur_thread).lock.lock();
                (*thread).lock.lock();
            }

            if !(*cur_task).active() || !(*cur_thread).active() {
                (*cur_thread).lock.unlock();
                (*thread).lock.unlock();
                spl::splx(s);
                (*cur_task).lock.unlock();
                let _ = Self::terminate(cur_thread);
                return Err(Error::Failure);
            }

            (*cur_thread).lock.unlock();
            (*cur_task).lock.unlock();

            if !(*thread).active() {
                (*thread).lock.unlock();
                spl::splx(s);
                return Err(Error::Failure);
            }

            (*thread).set_active(false);
            (*thread).lock.unlock();
            spl::splx(s);
        }

        // SAFETY: the thread is live; the routines take the locks they need
        // and may block, as the C's did.
        unsafe {
            Self::freeze(thread);
            let default_pset = default_pset();
            if (*thread).processor_set != default_pset {
                Self::doassign(thread, default_pset, false);
            }
            let _ = Self::halt(thread, true);
            Self::unfreeze(thread);
            ipc_thread_terminate(thread);
            Self::deallocate(thread);
        }
        Ok(())
    }

    /// Terminates `thread` and releases, in `task`, its port name
    /// `thread_name`, the reply port `reply_port` and the memory at
    /// `address..address + size`.
    ///
    /// # Safety
    ///
    /// `thread` and `task` must be null or point at live objects, and the
    /// caller must hold no locks: the routine deallocates and may block.
    pub(crate) unsafe fn terminate_release(
        thread: *mut Self,
        task: *mut Task,
        thread_name: c_uint,
        reply_port: c_uint,
        address: VmOffset,
        size: VmSize,
    ) -> Result<(), Error> {
        if task.is_null() || thread.is_null() {
            return Err(Error::InvalidArgument);
        }

        unsafe {
            let space = IpcSpace::new((*task).itk_space);
            let _ = mach_port::deallocate(space, thread_name);
            if reply_port != MACH_PORT_NULL {
                let _ = mach_port::destroy(space, reply_port);
            }
        }

        if address != 0 || size != 0 {
            // SAFETY: the task is live, so its map is; `vm_deallocate()`
            // takes the map's own locks and reports failure rather than
            // panicking.
            unsafe {
                let map = (*task).map.cast::<VmMap>();
                if let Some(map) = map.as_mut() {
                    let _ = crate::vm::vm_user::deallocate(map, address, size);
                }
            }
        }

        unsafe { Self::terminate(thread) }
    }

    /// Halts `thread` at a clean point; with `must_halt`, even when it is in
    /// an uninterruptible wait.
    ///
    /// # Safety
    ///
    /// `thread` must be a live thread other than the current one, and the
    /// caller must hold no locks: the routine waits and may block.
    pub(crate) unsafe fn halt(
        thread: *mut Self,
        must_halt: bool,
    ) -> Result<(), Error> {
        let cur_thread = per_cpu::thread();

        if thread == cur_thread {
            kpanic!(
                "thread_halt",
                "thread_halt: trying to halt current thread."
            )
        }

        let s = unsafe {
            let s = spl::splsched();

            if must_halt {
                (*thread).lock.lock();

                if (*thread).state() & TH_HALTED != 0 {
                    (*thread).suspend_count =
                        (*thread).suspend_count.wrapping_add(1);
                    (*thread).lock.unlock();
                    spl::splx(s);
                    return Ok(());
                }
            } else {
                if thread.addr() < cur_thread.addr() {
                    (*thread).lock.lock();
                    (*cur_thread).lock.lock();
                } else {
                    (*cur_thread).lock.lock();
                    (*thread).lock.lock();
                }

                if (*thread).state() & TH_HALTED != 0 {
                    (*thread).suspend_count =
                        (*thread).suspend_count.wrapping_add(1);
                    (*cur_thread).lock.unlock();
                    (*thread).lock.unlock();
                    spl::splx(s);
                    return Ok(());
                }

                if (*cur_thread).ast.contains(AstReason::HALT) {
                    thread_wakeup_prim(
                        (*cur_thread).wake_active_event(),
                        0,
                        THREAD_INTERRUPTED,
                    );
                    (*thread).lock.unlock();
                    (*cur_thread).lock.unlock();
                    spl::splx(s);
                    return Err(Error::Failure);
                }

                (*cur_thread).lock.unlock();
            }

            s
        };

        // SAFETY: the thread lock is held here in either arm; the state and
        // the wait follow the C's.
        unsafe {
            (*thread).suspend_count = (*thread).suspend_count.wrapping_add(1);
            (*thread).set_state((*thread).state() | TH_SUSP);

            while (*thread).ast.contains(AstReason::HALT)
                && (*thread).state() & TH_HALTED == 0
            {
                (*thread).set_wake_active(true);
                thread_sleep(
                    (*thread).wake_active_event(),
                    ptr::addr_of_mut!((*thread).lock),
                    c_int::from(true),
                );

                if (*thread).state() & TH_HALTED != 0 {
                    spl::splx(s);
                    return Ok(());
                }
                if (*cur_thread).wait_result != THREAD_AWAKENED && !must_halt {
                    spl::splx(s);
                    Self::release(thread);
                    return Err(Error::Failure);
                }
                (*thread).lock.lock();
            }

            (*thread).ast |= AstReason::HALT;
        }

        // SAFETY: the thread is live, suspended and locked at the level `s`;
        // the helper releases and retakes the lock and the spl as the C did.
        unsafe { Self::halt_loop(thread, must_halt, s) }
    }

    /// The wait loop of [`Thread::halt()`]: wait until `thread` reaches a
    /// clean point, then park it at `TH_HALTED`.
    ///
    /// # Safety
    ///
    /// `thread` must be live, suspended and locked at the `splsched` level
    /// `s`, and the caller must hold no other locks.
    unsafe fn halt_loop(
        thread: *mut Self,
        must_halt: bool,
        mut s: c_int,
    ) -> Result<(), Error> {
        unsafe {
            loop {
                (*thread).lock.unlock();
                spl::splx(s);

                let ret = Self::dowait(thread, must_halt);

                if ret.is_err() {
                    s = spl::splsched();
                    (*thread).lock.lock();
                    (*thread).ast &= !AstReason::HALT;
                    thread_wakeup_prim(
                        (*thread).wake_active_event(),
                        0,
                        THREAD_INTERRUPTED,
                    );
                    (*thread).lock.unlock();
                    spl::splx(s);

                    Self::release(thread);
                    return Err(Error::Failure);
                }

                clear_wait(thread, THREAD_INTERRUPTED, c_int::from(true));

                if (*thread).state() & TH_HALTED != 0 {
                    return Ok(());
                }

                let swap_func = (*thread).swap_func;
                // The C compared the stored continuation against the clean
                // point routines by address; the bindings give the function
                // items the pointer type that comparison needs.
                let continue_fn: unsafe extern "C" fn() =
                    crate::ipc::mach_msg::mach_msg_continue;
                let receive_continue_fn: unsafe extern "C" fn() =
                    crate::ipc::mach_msg::mach_msg_receive_continue;
                let has_cleanup =
                    (swap_func.is_some_and(|f| {
                        ptr::fn_addr_eq(f, continue_fn)
                            || ptr::fn_addr_eq(f, receive_continue_fn)
                    })) && crate::ipc::mach_msg::interrupt(thread);
                let exception_return_fn: unsafe extern "C" fn() =
                    crate::arch::x86_64::locore::thread_exception_return;
                let bootstrap_return_fn: unsafe extern "C" fn() =
                    crate::arch::x86_64::locore::thread_bootstrap_return;
                let at_clean_point = has_cleanup
                    || swap_func.is_some_and(|f| {
                        ptr::fn_addr_eq(f, exception_return_fn)
                    })
                    || swap_func.is_some_and(|f| {
                        ptr::fn_addr_eq(f, bootstrap_return_fn)
                    });

                if at_clean_point {
                    s = spl::splsched();
                    (*thread).lock.lock();
                    (*thread).set_state((*thread).state() | TH_HALTED);
                    (*thread).ast &= !AstReason::HALT;
                    (*thread).lock.unlock();
                    spl::splx(s);
                    return Ok(());
                }

                s = spl::splsched();
                (*thread).lock.lock();
                if (*thread).state() & TH_SCHED_STATE != TH_SUSP {
                    kpanic!("thread_halt", "thread_halt")
                }
                (*thread).set_state((*thread).state() | TH_RUN | TH_UNINT);
                thread_setrun(thread, 0);
            }
        }
    }

    /// Halts the current thread at a clean point, resuming at `continuation`
    /// when it is released.
    ///
    /// # Safety
    ///
    /// Runs on the current thread, which must be at a clean kernel point with
    /// no lock held; `continuation` runs when the thread is released again.
    pub(crate) unsafe fn halt_self(continuation: Continuation) {
        let thread = per_cpu::thread();

        // SAFETY: the current thread is live; it queues itself for the reaper
        // and only the IPC teardown and the reaper touch it from here on.
        unsafe {
            if (*thread).ast.contains(AstReason::TERMINATE) {
                ipc_thread_terminate(thread);

                Self::hold(thread);

                let s = spl::splsched();
                REAPER_QUEUE
                    .lock()
                    .pinned()
                    .push_back_ptr(NonNull::new_unchecked(thread));

                (*thread).lock.lock();
                (*thread).set_state((*thread).state() | TH_HALTED);
                (*thread).lock.unlock();
                spl::splx(s);

                thread_wakeup_prim(reaper_event(), 0, THREAD_AWAKENED);
                thread_block(Some(walking_zombie));
            } else {
                let s = spl::splsched();
                (*thread).lock.lock();
                (*thread).set_state((*thread).state() | TH_HALTED);
                (*thread).ast &= !AstReason::HALT;
                (*thread).lock.unlock();
                spl::splx(s);
                thread_block(continuation);
            }
        }
    }

    /// Waits for `thread` to stop; with `must_halt`, until it is halted.
    ///
    /// # Safety
    ///
    /// `thread` must be a live thread other than the current one, and the
    /// caller must hold no locks: the routine waits and may block.
    pub(crate) unsafe fn dowait(
        thread: *mut Self,
        must_halt: bool,
    ) -> Result<(), Error> {
        if thread == per_cpu::thread() {
            kpanic!("thread_dowait", "thread_dowait")
        }

        let mut need_wakeup = false;

        unsafe {
            let s = spl::splsched();
            (*thread).lock.lock();

            let mut result = Ok(());
            loop {
                let mut need_wait = false;
                match (*thread).state() & TH_SCHED_STATE {
                    TH_RUN_SUSP => {
                        if rem_runq(thread) != RUN_QUEUE_NULL {
                            (*thread).set_state((*thread).state() & !TH_RUN);
                            need_wakeup = (*thread).wake_active();
                            (*thread).set_wake_active(false);
                            break;
                        }
                        let last = (*thread).last_processor;
                        if !last.is_null() {
                            // SAFETY: a non-null `last_processor` is one of
                            // the static processor records.
                            ProcessorRef::from_static(last).ast_check();
                        }
                        need_wait = true;
                    }
                    TH_RUN_SUSP_UNINT
                    | TH_RUN_WAIT_SUSP
                    | TH_RUN_WAIT_SUSP_UNINT
                    | TH_WAIT_SUSP_UNINT => need_wait = true,
                    _ => (),
                }
                if !need_wait {
                    break;
                }

                (*thread).set_wake_active(true);
                thread_sleep(
                    (*thread).wake_active_event(),
                    ptr::addr_of_mut!((*thread).lock),
                    c_int::from(true),
                );
                (*thread).lock.lock();
                if (*per_cpu::thread()).wait_result != THREAD_AWAKENED
                    && !must_halt
                {
                    result = Err(Error::Failure);
                    break;
                }
            }

            (*thread).lock.unlock();
            spl::splx(s);

            if need_wakeup {
                thread_wakeup_prim(
                    (*thread).wake_active_event(),
                    0,
                    THREAD_AWAKENED,
                );
            }
            result
        }
    }

    /// Suspends `thread` and waits for it to stop.
    ///
    /// # Safety
    ///
    /// `thread` must be null or point at a live thread, and the caller must
    /// hold no locks: the routine waits and may block.
    pub(crate) unsafe fn suspend(thread: *mut Self) -> Result<(), Error> {
        if thread.is_null() {
            return Err(Error::InvalidArgument);
        }

        let mut hold = false;
        // SAFETY: `splsched()` is the C spl call and returns the level to
        // restore.
        let mut spl = unsafe { spl::splsched() };

        unsafe {
            (*thread).lock.lock();
            while (*thread).state() & TH_UNINT != 0 {
                assert_wait(
                    NonNull::new((*thread).state_event()),
                    c_int::from(true),
                );
                (*thread).lock.unlock();
                thread_block(None);
                (*thread).lock.lock();
            }

            let stop_count = (*thread).user_stop_count;
            (*thread).user_stop_count = stop_count.wrapping_add(1);
            if stop_count == 0 {
                hold = true;
                (*thread).suspend_count =
                    (*thread).suspend_count.wrapping_add(1);
                (*thread).set_state((*thread).state() | TH_SUSP);
            }
            (*thread).lock.unlock();
            spl::splx(spl);
        }

        if hold {
            if thread == per_cpu::thread() {
                // SAFETY: the current thread is live; the AST write is
                // atomic and the level is restored afterwards.
                unsafe {
                    spl = spl::splsched();
                    ast::on(cpu_id(), AstReason::BLOCK);
                    spl::splx(spl);
                }
            } else {
                let _ = unsafe { Self::dowait(thread, true) };
            }
        }
        Ok(())
    }

    /// Freezes `thread`'s assignment, waiting for a change in progress to
    /// finish.
    ///
    /// # Safety
    ///
    /// `thread` must point at a live thread, and the caller must hold no
    /// locks: the wait may block.
    pub(crate) unsafe fn freeze(thread: *mut Self) {
        unsafe {
            let s = spl::splsched();
            (*thread).lock.lock();
            while (*thread).may_assign == 0 {
                (*thread).assign_active = 1;
                thread_sleep(
                    ptr::addr_of_mut!((*thread).assign_active)
                        .cast::<c_void>(),
                    ptr::addr_of_mut!((*thread).lock),
                    0,
                );
                (*thread).lock.lock();
            }
            (*thread).may_assign = 0;
            (*thread).lock.unlock();
            spl::splx(s);
        }
    }

    /// Moves `thread` to `new_pset`, unfreezing its assignment when
    /// `release_freeze` is set.
    ///
    /// # Safety
    ///
    /// `thread` must point at a live thread and `new_pset` at a live
    /// processor set, and the caller must hold no locks: the routine waits
    /// and may block.
    pub(crate) unsafe fn doassign(
        thread: *mut Self,
        new_pset: *mut ProcessorSet,
        release_freeze: bool,
    ) {
        let mut new_pset = new_pset;

        unsafe {
            let pset = (*thread).processor_set;
            if pset == new_pset {
                if release_freeze {
                    Self::unfreeze(thread);
                }
                return;
            }

            Self::hold(thread);
            if thread != per_cpu::thread() {
                let _ = Self::dowait(thread, true);
            }

            loop {
                if pset.addr() < new_pset.addr() {
                    (*pset).lock.lock();
                    (*new_pset).lock.lock();
                } else {
                    (*new_pset).lock.lock();
                    (*pset).lock.lock();
                }

                if (*new_pset).active == 0 {
                    (*pset).lock.unlock();
                    (*new_pset).lock.unlock();
                    new_pset = default_pset();
                    continue;
                }
                break;
            }

            (*new_pset).reference();

            let s = spl::splsched();
            (*thread).lock.lock();

            Self::change_psets(thread, pset, new_pset);

            let old_empty = (*pset).empty;
            let new_empty = (*new_pset).empty;

            (*pset).lock.unlock();

            let mut recompute_pri =
                if (*thread).policy & (*new_pset).policies == 0 {
                    (*thread).policy = POLICY_TIMESHARE;
                    true
                } else {
                    false
                };

            if (*thread).max_priority < (*new_pset).max_priority {
                (*thread).max_priority = (*new_pset).max_priority;
                if (*thread).priority < (*thread).max_priority {
                    (*thread).priority = (*thread).max_priority;
                    recompute_pri = true;
                } else if (*thread).depress_priority >= 0
                    && (*thread).depress_priority < (*thread).max_priority
                {
                    (*thread).depress_priority = (*thread).max_priority;
                }
            }

            (*new_pset).lock.unlock();

            if recompute_pri {
                compute_priority(thread, 1);
            }

            if release_freeze {
                (*thread).may_assign = 1;
                if (*thread).assign_active != 0 {
                    (*thread).assign_active = 0;
                    thread_wakeup_prim(
                        ptr::addr_of_mut!((*thread).assign_active)
                            .cast::<c_void>(),
                        0,
                        THREAD_AWAKENED,
                    );
                }
            }

            (*thread).lock.unlock();
            spl::splx(s);

            (*pset).deallocate();

            if old_empty != 0 {
                Self::release(thread);
            }
            if new_empty == 0 {
                Self::release(thread);
            }

            if thread == per_cpu::thread() {
                let s = spl::splsched();
                ast::on(cpu_id(), AstReason::BLOCK);
                spl::splx(s);
            }
        }
    }

    /// Moves `thread` to `new_pset`.
    ///
    /// # Safety
    ///
    /// `thread` must be null or a live thread the caller holds an extra
    /// reference to, `new_pset` must be null or a live processor set, and the
    /// caller must hold no locks.
    pub(crate) unsafe fn assign(
        thread: *mut Self,
        new_pset: *mut ProcessorSet,
    ) -> Result<(), Error> {
        if thread.is_null() || new_pset.is_null() {
            return Err(Error::InvalidArgument);
        }

        unsafe {
            Self::freeze(thread);
            Self::doassign(thread, new_pset, true);
        }
        Ok(())
    }
}

/// The continuation of a terminating thread: hands it to the reaper.
unsafe extern "C" fn walking_zombie() {
    kpanic!("walking_zombie", "the zombie walks!")
}

/// The reaper's loop, which frees the threads on the reaper queue forever.
///
/// # Safety
///
/// Runs as the reaper kernel thread, which `kernel_thread()` starts once.
pub(crate) unsafe extern "C" fn reaper_thread_continue() {
    loop {
        let mut queue = REAPER_QUEUE.lock();
        while let Some(thread) =
            queue.pinned().cursor_front_mut().remove_current()
        {
            let thread = ptr::from_mut(thread);
            // SAFETY: a queued thread is live and is not the reaper, and the
            // reference it holds for being alive is the one the reaper drops;
            // the queue's lock is released for the wait and the free, which
            // may block.
            queue.unlocked(|| unsafe {
                let _ = Thread::dowait(thread, true);
                Thread::deallocate(thread);
            });
        }

        // SAFETY: the wait is asserted before the queue's lock is released,
        // so a thread queued after the check still wakes the reaper, and the
        // block holds no lock.
        unsafe {
            assert_wait(NonNull::new(reaper_event()), 0);
            drop(queue);
            thread_block(Some(reaper_thread_continue));
        }
    }
}

/// Creates a kernel thread in `task` that starts at `start` with `arg`.
///
/// # Safety
///
/// `task` must point at a live task, `name` must be a NUL-terminated string,
/// `start` must be a continuation, and the caller must hold no locks: the
/// routine may block.
pub(crate) unsafe fn kernel_thread(
    task: *mut Task,
    _name: *const c_char,
    start: Continuation,
    arg: *mut c_void,
) -> *mut Thread {
    let Ok(thread) = (unsafe { Thread::create(task) }) else {
        return ptr::null_mut();
    };

    // SAFETY: the thread is live and holds the extra reference the C
    // released here; the swap-in may block and resumes it.
    unsafe {
        Thread::deallocate(thread);
        (*thread).start(start);
        (*thread).saved.other = arg;
        crate::kern::thread_swap::doswapin(thread);
        (*thread).max_priority = BASEPRI_SYSTEM;
        (*thread).priority = BASEPRI_SYSTEM;
        (*thread).sched_pri = BASEPRI_SYSTEM;
        let _ = Thread::resume(thread);
    }
    thread
}

/// How much of `stack` the marker fill no longer covers.
///
/// # Safety
///
/// `stack` must be the base address of a live `KERNEL_STACK_SIZE` kernel
/// stack object.
unsafe fn stack_usage(stack: VmOffset) -> VmSize {
    let words = unsafe {
        core::slice::from_raw_parts(
            ptr::with_exposed_provenance::<u32>(stack),
            KERNEL_STACK_SIZE / size_of::<u32>(),
        )
    };
    let used = words
        .iter()
        .position(|word| *word != STACK_MARKER)
        .unwrap_or(words.len());
    KERNEL_STACK_SIZE - used * size_of::<u32>()
}

/// Accounts for a stack about to be released.
///
/// # Safety
///
/// `stack` must be the base address of a live `KERNEL_STACK_SIZE` kernel
/// stack object.
pub(crate) unsafe fn stack_finalize(stack: VmOffset) {
    if STACK_CHECK_USAGE.load(Ordering::Relaxed) == 0 {
        return;
    }

    let used = unsafe { stack_usage(stack) };
    STACK_MAX_USAGE.fetch_max(used, Ordering::Relaxed);
}

/// Fills a fresh stack with the usage marker when the check is on.
///
/// # Safety
///
/// `stack` must be the base address of a live `KERNEL_STACK_SIZE` kernel
/// stack object.
pub(crate) unsafe fn stack_init(stack: VmOffset) {
    if STACK_CHECK_USAGE.load(Ordering::Relaxed) == 0 {
        return;
    }

    let words = unsafe {
        core::slice::from_raw_parts_mut(
            with_exposed_provenance_mut::<u32>(stack),
            KERNEL_STACK_SIZE / size_of::<u32>(),
        )
    };
    for word in words {
        *word = STACK_MARKER;
    }
}

/// The kernel-stack counts and usage `host_stack_usage()` reports.
///
/// # Safety
///
/// `host` must be null or the live host the MIG stub converted.
pub(crate) unsafe fn host_stack_usage(
    host: *mut c_void,
) -> Result<StackUsage, Error> {
    if host.is_null() {
        return Err(Error::InvalidHost);
    }

    let mut maxusage = STACK_MAX_USAGE.load(Ordering::Relaxed);
    let stacks = STACK_FREE.lock();
    if STACK_CHECK_USAGE.load(Ordering::Relaxed) != 0 {
        let mut stack = stacks.head;
        while stack != 0 {
            // SAFETY: every stack on the list is a live cache object, as
            // `push` requires.
            unsafe {
                let usage = stack_usage(stack);
                if usage > maxusage {
                    maxusage = usage;
                }
                stack = stack_next(stack);
            }
        }
    }
    let total = stacks.count;
    drop(stacks);

    // The C multiplied the `unsigned` count by a `vm_size_t`; the count fits
    // `usize` and the product wraps in the C too.
    let space = (total as usize).wrapping_mul(round_page(KERNEL_STACK_SIZE));
    Ok(StackUsage {
        total,
        space,
        maxusage,
        maxstack: 0,
    })
}

/// The kernel-stack counts and usage `processor_set_stack_usage()` reports.
///
/// # Safety
///
/// `pset` must be null or point at a live processor set, and the caller must
/// hold no locks: the routine allocates.
pub(crate) unsafe fn processor_set_stack_usage(
    pset: *mut ProcessorSet,
) -> Result<StackUsage, Error> {
    if pset.is_null() {
        return Err(Error::InvalidArgument);
    }

    let mut size: VmSize = 0;
    let mut addr: Option<NonNull<u8>> = None;
    let mut actual: c_uint;
    let mut size_needed: usize;

    loop {
        unsafe {
            (*pset).lock.lock();
            if (*pset).active == 0 {
                (*pset).lock.unlock();
                return Err(Error::InvalidArgument);
            }

            // The C read the `int` count into an `unsigned int`; it is the
            // number of threads and never negative.
            actual = (*pset).thread_count as c_uint;
            // The `unsigned int` count widens to `usize`.
            size_needed = actual as usize * size_of::<VmOffset>();
            if size_needed <= size {
                break;
            }

            (*pset).lock.unlock();
        }

        if let Some(old) = addr {
            // SAFETY: the old buffer is the live allocation of `size` bytes
            // made above.
            unsafe { kfree(old, size) };
        }
        size = size_needed;
        // SAFETY: `kalloc_init()` ran during the boot this routine follows.
        let Some(buf) = kalloc(size) else {
            return Err(Error::ResourceShortage);
        };
        addr = Some(buf);
    }

    let Some(buf) = addr else {
        // The count was zero on the first look, so nothing was allocated.
        // SAFETY: the set lock was left held by the break above.
        unsafe { (*pset).lock.unlock() };
        return Ok(StackUsage {
            total: 0,
            space: 0,
            maxusage: 0,
            maxstack: 0,
        });
    };

    let threads = buf.as_ptr().cast::<VmOffset>();
    // SAFETY: the set lock is held, so every queue entry is a live thread,
    // and the references taken here keep them alive.  An address is the same
    // width as the thread pointers the C stored.
    unsafe {
        let mut cursor = (*ptr::addr_of_mut!((*pset).threads)).cursor_front();
        for i in 0..actual as usize {
            let Some(thread) = cursor.current_ptr() else {
                break;
            };
            let thread = thread.as_ptr();
            Thread::reference(thread);
            threads.add(i).write(thread.addr());
            cursor.move_next();
        }
        (*pset).lock.unlock();
    }

    let mut total: c_uint = 0;
    let mut maxusage: VmSize = 0;
    let mut maxstack: VmOffset = 0;

    for i in 0..actual as usize {
        // SAFETY: every slot holds a referenced live thread, and the
        // reference is dropped at the end of the iteration.
        let thread = unsafe {
            with_exposed_provenance_mut::<Thread>(threads.add(i).read())
        };
        let mut stack: VmOffset = 0;

        // SAFETY: the thread is live; the state read is the C's unlocked
        // one, and a swapped thread's stack is not looked at.
        unsafe {
            if (*thread).state() & TH_SWAPPED == 0 {
                stack = (*thread).kernel_stack;

                for block in per_cpu::iter() {
                    if block.thread() == thread {
                        stack = block.stack();
                        break;
                    }
                }
            }

            if stack != 0 {
                total = total.wrapping_add(1);

                if STACK_CHECK_USAGE.load(Ordering::Relaxed) != 0 {
                    let usage = stack_usage(stack);

                    if usage > maxusage {
                        maxusage = usage;
                        maxstack = thread.addr();
                    }
                }
            }

            Thread::deallocate(thread);
        }
    }

    if size != 0 {
        // SAFETY: the buffer is the live allocation of `size` bytes, and
        // every reference it held was dropped above.
        unsafe { kfree(buf, size) };
    }

    // The C multiplied the `unsigned` count by a `vm_size_t`; the count fits
    // `usize` and the product wraps in the C too.
    let space = (total as usize).wrapping_mul(round_page(KERNEL_STACK_SIZE));
    Ok(StackUsage {
        total,
        space,
        maxusage,
        maxstack,
    })
}
