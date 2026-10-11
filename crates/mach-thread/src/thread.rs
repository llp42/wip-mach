// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The thread module's cores.

use crate::error::Error;
use crate::ipc_tt::{
    abort_rpc, ipc_thread_disable, ipc_thread_enable, ipc_thread_init,
    ipc_thread_terminate,
};
use crate::platform::Platform;
use crate::processor;
use crate::processor::Processor;
use crate::processor_ref::ProcessorRef;
use crate::processor_set::ProcessorSet;
use crate::sched::Callout;
use crate::sched_prim::{
    THREAD_AWAKENED, THREAD_INTERRUPTED, assert_wait, clear_wait,
    compute_priority, rem_runq, thread_block, thread_setrun, thread_sleep,
    thread_wakeup_prim,
};
use crate::smp::CpuId;
use crate::syscall_subr::depress_abort;
use crate::task::{Task, add_time64, current_task, kernel_task};
use crate::types::{
    Saved, StackUsage, StateBits, StateEvent, TaskCache, ThreadState,
};
use collections::tail_queue;
use collections::tail_queue::TailQueue;
use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::mem::{MaybeUninit, offset_of, size_of};
use core::pin::Pin;
use core::ptr;
use core::ptr::{NonNull, with_exposed_provenance_mut};
use core::sync::atomic::{
    AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering,
};
#[cfg(debug_assertions)]
use lock::HeldLocks;
use lock::MutexGuard;
use mach_ipc::ipc_thread::{ThreadIpc, ThreadRef};
use mach_ipc::{IpcSpace, mach_port};
use mach_sched::SchedInfo;
use mach_sched::ast::AstReason;
use mach_sched::policy::{POLICY_FIXEDPRI, POLICY_TIMESHARE, invalid_policy};
use mach_sched::sched::sched_tick;
use mach_sched::sched::{BASEPRI_SYSTEM, SCHED_SCALE, TICK, invalid_pri};
use mach_sched::time_value::TimeValue64;
use mach_sched::timer::TIMER_RATE;
use mach_vm::param::{VmOffset, VmSize};
use mach_vm::simple_lock::SimpleLock;
use mach_vm::vm_map::{VmMap, round_page};

/// `MACH_RCV_INTERRUPTED`: what an aborted receive returns.
pub const MACH_RCV_INTERRUPTED: c_int = 0x1000_4005;
/// The length of a thread's name, with its NUL.
pub const TASK_NAME_SIZE: usize = 32;

/// `i386_DEBUG_STATE`: the debug state, which the current thread can read and
/// `i386_FSGS_BASE_STATE`: the segment bases, writable directly only for the
/// The pattern [`stack_init`] fills a fresh kernel stack with when the usage
/// check is on.
const STACK_MARKER: u32 = 0xdead_beef;

bitfield::bitfield! {
    /// The thread's [`ThreadState`] in the low half of the state word, below
    /// the two flags [`StateBits`] names.
    struct StateWord(u32);
    u32;
    state, set_state: 15, 0;
}

/// A continuation: where a thread resumes on a fresh stack, or `None` for
/// none.
pub type Continuation = Option<unsafe extern "C" fn()>;

/// A stack continuation: what a thread given a stack resumes through, with the
/// thread it switched from.
pub type StackResume<P> = Option<unsafe extern "C" fn(*mut Thread<P>)>;

/// A kernel thread: its scheduling, IPC and accounting state.
///
/// The representation is free: nothing MIG-visible reads it, and the
/// machine code takes field offsets with `offset_of!`.
#[allow(missing_docs)]
pub struct Thread<P: Platform> {
    /// The scheduling record: the run-queue link, priorities, usage and
    /// CPU timers.
    pub sched: SchedInfo,
    pub task: *mut Task<P>,
    pub thread_list: tail_queue::Link,
    /// `state`, `wake_active`, `active` and `event_key`.
    pub state_event: StateEvent,
    pub pset_threads: tail_queue::Link,
    /// `lock`: the thread lock, taken at splsched.
    pub lock: SimpleLock,
    pub ref_count: c_int,
    /// `pcb`: the machine-dependent process control block.
    pub pcb: *mut <P as Platform>::Pcb,
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
    /// `recover`: the page-fault recovery state.
    pub recover: VmOffset,
    /// `vm_privilege`: can the thread use reserved memory.
    pub vm_privilege: c_uint,
    /// `user_stop_count`: the outstanding stops.
    pub user_stop_count: c_int,
    /// IPC's state: the thread's IPC queue links, its blocked transfer
    /// and the messages it is destroying.
    pub ipc: ThreadIpc,
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
    pub creation_time: TimeValue64,
    /// `timer`: the wait timeout.
    pub(crate) timer: Callout<P>,
    /// `depress_timer`: the priority-depression timeout.
    pub(crate) depress_timer: Callout<P>,
    /// `ast`: the pending AST reasons.
    pub ast: AstReason,
    pub processor_set: *mut ProcessorSet<P>,
    pub bound_processor: *mut Processor<P>,
    /// Whether the thread's assignment may change.
    pub may_assign: c_int,
    /// Whether someone waits for `may_assign`.
    pub assign_active: c_int,
    /// `last_processor`: the processor the thread last ran on.
    pub last_processor: *mut Processor<P>,
    pub name: [c_char; TASK_NAME_SIZE],
    /// Set by a `lock` unpark, cleared by the park it releases; the
    /// address is the event the thread parks on.
    pub park_token: AtomicBool,
    /// The locks the thread holds, for the `lock` order checker.
    #[cfg(debug_assertions)]
    pub held_locks: HeldLocks,
}

tail_queue::adapter!(
    /// The adapter for a thread's `links` in a run, wait, reaper or swapin
    /// queue.
    pub ThreadLinksAdapter<P: Platform> = Thread<P> { sched.links }
);

tail_queue::adapter!(
    /// The adapter for a thread's `thread_list` in its task.
    pub ThreadTaskListAdapter<P: Platform> = Thread<P> { thread_list }
);

tail_queue::adapter!(
    /// The adapter for a thread's `pset_threads` in its processor set.
    pub ThreadPsetAdapter<P: Platform> = Thread<P> { pset_threads }
);

/// A run queue, wait bucket, reaper queue or swapin queue. All of them share
/// the thread's `links`, so it takes the strictest need: a thread leaves a
/// run queue or a wait bucket from the middle, in O(1).
pub type ThreadQueue<P> = TailQueue<'static, ThreadLinksAdapter<P>>;

/// A task's threads, in creation order.
pub type TaskThreadList<P> = TailQueue<'static, ThreadTaskListAdapter<P>>;

/// A processor set's threads, in the order they joined.
pub type PsetThreadList<P> = TailQueue<'static, ThreadPsetAdapter<P>>;

// The `state` and `wake_active` accessors mirror the C bitfields; the
// flags of `ThreadState` and `StateBits` carry the documentation.
#[allow(missing_docs)]
impl<P: Platform> Thread<P> {
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
            ptr::addr_of_mut!((*base).timer).write(Callout::<P>::new(
                P::WHEEL,
                thread_timeout_action::<P>,
                (),
            ));
            ptr::addr_of_mut!((*base).depress_timer).write(Callout::<P>::new(
                P::WHEEL,
                depress_timeout_action::<P>,
                (),
            ));
            #[cfg(debug_assertions)]
            ptr::addr_of_mut!((*base).held_locks).write(HeldLocks::new());
        }
        // SAFETY: every field is now initialized: zeros accept the
        // pointers, unions, locks and park token, and the callouts and
        // held-lock record were written.
        let mut thread = unsafe { slot.assume_init() };

        thread.sched.runq = ptr::null_mut();
        thread.ref_count = 2;
        thread.set_state(ThreadState::SUSP | ThreadState::SWAPPED);
        thread.swap_func = Some(P::BOOTSTRAP_RETURN);
        thread.sched.max_priority = BASEPRI_SYSTEM;
        thread.sched.policy = POLICY_TIMESHARE;
        thread.sched.depress_priority = -1;
        thread.user_stop_count = 1;
        thread.may_assign = 1;
        thread
    }

    /// Sets up the thread and stack caches and the template.
    ///
    /// # Safety
    ///
    /// Runs once, from the boot sequence, before any thread exists.
    pub unsafe fn init() {
        // SAFETY: the boot caller runs this once, before any thread exists.
        unsafe {
            P::task_cache_init(
                TaskCache::Thread,
                b"thread",
                size_of::<Self>(),
                0,
            );
            P::task_cache_init(
                TaskCache::Stack,
                b"thread_stack",
                P::KERNEL_STACK_SIZE,
                P::KERNEL_STACK_SIZE,
            );
            (*P::task_state().thread_template.0.get()).write(Self::new());
            P::pcb_module_init();
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
    pub(crate) unsafe fn from_timer(callout: *const Callout<P>) -> *mut Self {
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
        callout: *const Callout<P>,
    ) -> *mut Self {
        let base = callout
            .expose_provenance()
            .wrapping_sub(offset_of!(Self, depress_timer));
        with_exposed_provenance_mut(base)
    }
}

/// The expiry of [`Thread::timer`].
pub(crate) fn thread_timeout_action<P: Platform>(callout: Pin<&Callout<P>>) {
    // SAFETY: `timer` is the callout field of a live thread.
    let thread =
        unsafe { Thread::<P>::from_timer(ptr::from_ref(callout.get_ref())) };
    // SAFETY: `thread` is live; the action runs from the wheel.
    unsafe {
        clear_wait(thread, crate::sched_prim::THREAD_TIMED_OUT, 0);
    };
}

/// The expiry of [`Thread::depress_timer`].
pub(crate) fn depress_timeout_action<P: Platform>(callout: Pin<&Callout<P>>) {
    // SAFETY: `depress_timer` is the callout field of a live thread.
    let thread = unsafe {
        Thread::<P>::from_depress_timer(ptr::from_ref(callout.get_ref()))
    };
    // SAFETY: `thread` is live; the action runs from the wheel.
    unsafe {
        crate::syscall_subr::depress_timeout::<P>(thread.cast::<c_void>());
    };
}

#[allow(missing_docs)]
impl<P: Platform> Thread<P> {
    /// The thread that embeds the scheduling record `sched`.
    ///
    /// # Safety
    ///
    /// `sched` must be the `sched` field of a live thread.
    pub const unsafe fn from_sched(sched: *mut SchedInfo) -> *mut Self {
        // SAFETY: the record is the thread's `sched` field, so stepping back
        // by its offset stays inside the thread.
        unsafe { sched.byte_sub(offset_of!(Self, sched)).cast::<Self>() }
    }

    /// Charges the user and system time since the last update to the thread's
    /// scheduler usage, weighted by its processor set's load.
    ///
    /// # Safety
    ///
    /// `thread` must be live, and the caller must hold its lock at splsched,
    /// as `update_priority()` and the quantum expiry do.
    pub unsafe fn timer_delta(thread: *mut Self) {
        // SAFETY: the thread and its set are live, and the caller holds the
        // thread lock.
        unsafe {
            let load = (*(*thread).processor_set).sched_load;
            (*thread).sched.timer_delta(load);
        }
    }

    pub fn state(&self) -> ThreadState {
        ThreadState::from_bits_retain(
            StateWord(self.state_bits().bits()).state(),
        )
    }

    /// Replaces the state, leaving the flag bits alone; the C assignment to
    /// the 16-bit field.
    pub fn set_state(&mut self, state: ThreadState) {
        let mut word = StateWord(self.state_bits().bits());
        word.set_state(state.bits());
        self.state_event.state = StateBits::from_bits_retain(word.0);
    }

    pub const fn wake_active(&self) -> bool {
        self.state_bits().contains(StateBits::WAKE_ACTIVE)
    }

    pub const fn set_wake_active(&mut self, active: bool) {
        self.set_state_bit(StateBits::WAKE_ACTIVE, active);
    }

    /// The `active` bit: whether the thread is alive.
    pub const fn active(&self) -> bool {
        self.state_bits().contains(StateBits::ACTIVE)
    }

    pub const fn set_active(&mut self, active: bool) {
        self.set_state_bit(StateBits::ACTIVE, active);
    }

    /// The word holding the state and its two flags.
    const fn state_bits(&self) -> StateBits {
        // SAFETY: the `state` member shares the low word with `event_key`,
        // and every bit pattern is a valid `StateBits`.
        unsafe { self.state_event.state }
    }

    /// Sets or clears one flag of the state word.
    const fn set_state_bit(&mut self, bit: StateBits, on: bool) {
        let bits = self.state_bits();
        self.state_event.state = if on {
            bits.union(bit)
        } else {
            bits.difference(bit)
        };
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

impl<P: Platform> Thread<P> {
    /// Takes a reference on `thread`, when it is not null.
    ///
    /// # Safety
    ///
    /// `thread` must point at a live thread.
    pub unsafe fn reference(thread: *mut Self) {
        let s = P::splsched();
        unsafe {
            (*thread).lock.lock();
            (*thread).ref_count = (*thread).ref_count.wrapping_add(1);
            (*thread).lock.unlock();
            P::splx(s);
        }
    }

    /// Counts one more suspension of `thread`.
    ///
    /// # Safety
    ///
    /// `thread` must point at a live thread.
    pub unsafe fn hold(thread: *mut Self) {
        let s = P::splsched();
        unsafe {
            (*thread).lock.lock();
            (*thread).suspend_count = (*thread).suspend_count.wrapping_add(1);
            let state = (*thread).state();
            (*thread).set_state(state | ThreadState::SUSP);
            (*thread).lock.unlock();
            P::splx(s);
        }
    }

    /// Counts one suspension of `thread` fewer, letting it run again with the
    /// last.
    ///
    /// # Safety
    ///
    /// `thread` must point at a live thread.
    pub unsafe fn release(thread: *mut Self) {
        let s = P::splsched();
        unsafe {
            (*thread).lock.lock();
            (*thread).suspend_count = (*thread).suspend_count.wrapping_sub(1);
            if (*thread).suspend_count == 0 {
                let state = (*thread).state()
                    & !(ThreadState::SUSP | ThreadState::HALTED);
                (*thread).set_state(state);
                if !state.intersects(ThreadState::WAIT | ThreadState::RUN) {
                    (*thread).set_state(state | ThreadState::RUN);
                    thread_setrun(thread, 1);
                }
            }
            (*thread).lock.unlock();
            P::splx(s);
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

        let s = P::splsched();
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
                        let state = (*thread).state()
                            & !(ThreadState::SUSP | ThreadState::HALTED);
                        (*thread).set_state(state);
                        if !state
                            .intersects(ThreadState::WAIT | ThreadState::RUN)
                        {
                            (*thread).set_state(state | ThreadState::RUN);
                            thread_setrun(thread, 1);
                        }
                    }
                }
                Ok(())
            } else {
                Err(Error::Failure)
            };
            (*thread).lock.unlock();
            P::splx(s);
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
            let s = P::splsched();
            (*thread).lock.lock();
            let active = (*thread).active();
            (*thread).set_active(false);
            (*thread).lock.unlock();
            P::splx(s);
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
        if thread.is_null() || thread == P::cpu_thread() {
            return Err(Error::InvalidArgument);
        }

        if unsafe { Self::halt(thread, false) }.is_err() {
            return Err(Error::Aborted);
        }

        unsafe { abort_rpc(thread) };

        unsafe { Self::release(thread) };

        if unsafe { (*thread).sched.depress_priority } != -1 {
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
        let s = P::splsched();
        unsafe {
            (*thread).lock.lock();
            (*thread).may_assign = 1;
            if (*thread).assign_active != 0 {
                (*thread).assign_active = 0;
                thread_wakeup_prim::<P>(
                    ptr::addr_of_mut!((*thread).assign_active)
                        .cast::<c_void>(),
                    0,
                    THREAD_AWAKENED,
                );
            }
            (*thread).lock.unlock();
            P::splx(s);
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
    ) -> Result<*mut ProcessorSet<P>, Error> {
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
    let tick_rate = TICK;
    let temp = data.wrapping_mul(1000);
    let temp = if temp % tick_rate != 0 {
        temp.wrapping_add(tick_rate)
    } else {
        temp
    };
    temp / tick_rate
}

impl<P: Platform> Thread<P> {
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
        if P::reads_own_state(flavor) && thread == P::cpu_thread() {
            return unsafe {
                P::get_state(thread, flavor, old_state, old_state_count)
            };
        }

        if thread.is_null() || thread == P::cpu_thread() {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: the checks above; the suspend and
        // the wait take the thread lock themselves.
        unsafe {
            Self::hold(thread);
            let _ = Self::dowait(thread, true);
        }

        let result = unsafe {
            P::get_state(thread, flavor, old_state, old_state_count)
        };

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
        if thread == P::cpu_thread() && P::writes_own_state(flavor) {
            return unsafe {
                P::set_state(thread, flavor, new_state, new_state_count)
            };
        }

        if thread.is_null() || thread == P::cpu_thread() {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: the checks above; the suspend and
        // the wait take the thread lock themselves.
        unsafe {
            Self::hold(thread);
            let _ = Self::dowait(thread, true);
        }

        let result = unsafe {
            P::set_state(thread, flavor, new_state, new_state_count)
        };

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

        let s = P::splsched();
        // SAFETY: the checks above; the thread lock
        // protects every field below.
        let result = unsafe {
            (*thread).lock.lock();
            let result = if priority < (*thread).sched.max_priority {
                Err(Error::Failure)
            } else {
                if (*thread).sched.depress_priority >= 0 {
                    (*thread).sched.depress_priority = priority;
                } else {
                    (*thread).sched.priority = priority;
                    compute_priority(thread, 1);
                }
                if set_max {
                    (*thread).sched.max_priority = priority;
                }
                Ok(())
            };
            (*thread).lock.unlock();
            result
        };
        // SAFETY: `s` is the level `splsched()` returned.
        unsafe { P::splx(s) };

        result
    }

    /// Sets the current thread's priority.
    ///
    /// # Safety
    ///
    /// The caller must be the current thread and hold no thread lock:
    /// `splsched()` raises the level and this takes the current thread's lock.
    pub unsafe fn set_own_priority(priority: c_int) {
        let thread = P::cpu_thread();
        let s = P::splsched();
        // SAFETY: `thread` is the live current thread, and the lock protects
        // the priority fields.
        unsafe {
            (*thread).lock.lock();
            if priority < (*thread).sched.max_priority {
                (*thread).sched.max_priority = priority;
            }
            (*thread).sched.priority = priority;
            compute_priority(thread, 1);
            (*thread).lock.unlock();
            // SAFETY: `s` is the level `splsched()` returned.
            P::splx(s);
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
        pset: *mut ProcessorSet<P>,
        max_priority: c_int,
    ) -> Result<(), Error> {
        if thread.is_null() || pset.is_null() || invalid_pri(max_priority) {
            return Err(Error::InvalidArgument);
        }

        let s = P::splsched();
        // SAFETY: the checks above; the thread lock
        // protects every field below.
        let result = unsafe {
            (*thread).lock.lock();
            let result = if pset == (*thread).processor_set {
                (*thread).sched.max_priority = max_priority;
                if max_priority > (*thread).sched.priority {
                    (*thread).sched.priority = max_priority;
                    compute_priority(thread, 1);
                } else if (*thread).sched.depress_priority >= 0
                    && max_priority > (*thread).sched.depress_priority
                {
                    (*thread).sched.depress_priority = max_priority;
                }
                Ok(())
            } else {
                Err(Error::Failure)
            };
            (*thread).lock.unlock();
            result
        };
        // SAFETY: `s` is the level `splsched()` returned.
        unsafe { P::splx(s) };

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
    /// Panics through `fixedpri_quantum()` if the kernel's `tick` global is
    /// zero, which the C divides by in the same case.
    pub unsafe fn policy(
        thread: *mut Self,
        policy: c_int,
        data: c_int,
    ) -> Result<(), Error> {
        if thread.is_null() || invalid_policy(policy) {
            return Err(Error::InvalidArgument);
        }

        let s = P::splsched();
        // SAFETY: the checks above; the thread lock
        // protects every field below.
        let result = unsafe {
            (*thread).lock.lock();
            let result = if policy == (*thread).sched.policy {
                if policy == POLICY_FIXEDPRI {
                    (*thread).sched.sched_data = fixedpri_quantum(data);
                }
                Ok(())
            } else {
                let pset = (*thread).processor_set;
                if ((*pset).policies & policy) == 0 {
                    Err(Error::Failure)
                } else {
                    (*thread).sched.policy = policy;
                    if policy == POLICY_FIXEDPRI {
                        (*thread).sched.sched_data = fixedpri_quantum(data);
                    }
                    compute_priority(thread, 1);
                    Ok(())
                }
            };
            (*thread).lock.unlock();
            result
        };
        // SAFETY: `s` is the level `splsched()` returned.
        unsafe { P::splx(s) };

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
        if thread.is_null() || thread != P::cpu_thread() {
            return Err(Error::InvalidArgument);
        }

        let s = P::splsched();
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
            P::splx(s);
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

impl<P: Platform> Thread<P> {
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
        resume: StackResume<P>,
    ) -> bool {
        // SAFETY: every stack on the list is a live cache object, as `push`
        // requires.
        let stack = unsafe { P::task_state().stack_free.lock().pop::<P>() };

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
            P::stack_attach(ptr::from_mut(self), stack, resume);
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
    pub(crate) unsafe fn stack_alloc(&mut self, resume: StackResume<P>) {
        // SAFETY: every stack on the list is a live cache object, as `push`
        // requires.
        let stack = unsafe { P::task_state().stack_free.lock().pop::<P>() };

        let stack = if stack == 0 {
            let fresh = unsafe { P::task_cache_alloc(TaskCache::Stack) };
            let fresh = fresh.map_or(0, |buf| buf.as_ptr().addr());
            // SAFETY: `stack_init()` marks the fresh object when the usage
            // check is on, exactly as the C called it.
            unsafe { stack_init::<P>(fresh) };
            fresh
        } else {
            stack
        };

        unsafe {
            P::stack_attach(ptr::from_mut(self), stack, resume);
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
        let stack = unsafe { P::stack_detach(ptr::from_mut(self)) };

        if stack != privilege {
            // SAFETY: the detached stack is a live cache object on no list.
            unsafe { P::task_state().stack_free.lock().push::<P>(stack) };
        }
    }

    /// Frees the cached stacks beyond the limit.
    ///
    /// # Safety
    ///
    /// The caller must hold no spin lock.
    pub unsafe fn stack_collect() {
        let mut stacks = P::task_state().stack_free.lock();
        while stacks.count > STACK_FREE_LIMIT.load(Ordering::Relaxed) {
            // SAFETY: every stack on the list is a live cache object, and a
            // count above the limit means the list is not empty.
            let stack = unsafe { stacks.pop::<P>() };
            // The list's lock is released for the free, which may block.
            MutexGuard::unlocked(&mut stacks, || {
                // SAFETY: the stack is off the list, a whole object of
                // the stack cache, and nothing else references it.
                unsafe {
                    stack_finalize::<P>(stack);
                    if let Some(stack) =
                        NonNull::new(with_exposed_provenance_mut::<u8>(stack))
                    {
                        P::task_cache_free(TaskCache::Stack, stack);
                    }
                }
            });
        }
    }

    /// Gives the thread a stack of its own, kept across switches.
    ///
    /// # Panics
    ///
    /// If `self` is not the running thread, as the C halts the kernel.
    pub fn stack_privilege(&mut self) {
        assert!(P::cpu_thread() == ptr::from_mut(self), "stack_privilege");

        if self.stack_privilege == 0 {
            self.stack_privilege = P::cpu_stack();
        }
    }
}

impl<P: Platform> Default for Thread<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// The free-list link word of a stack object, in the last word of its
/// `P::KERNEL_STACK_SIZE` region.
///
/// # Safety
///
/// `stack` must be the base address of a live stack-cache object.
pub(crate) const unsafe fn stack_next<P: Platform>(
    stack: VmOffset,
) -> VmOffset {
    unsafe {
        ptr::with_exposed_provenance::<VmOffset>(stack)
            .add(P::KERNEL_STACK_SIZE / size_of::<VmOffset>() - 1)
            .read()
    }
}

/// Store `next` as the free-list link of a stack object, the C's
/// `stack_next(stack) = next`.
///
/// # Safety
///
/// `stack` must be the base address of a live stack-cache object.
pub(crate) const unsafe fn set_stack_next<P: Platform>(
    stack: VmOffset,
    next: VmOffset,
) {
    unsafe {
        with_exposed_provenance_mut::<VmOffset>(stack)
            .add(P::KERNEL_STACK_SIZE / size_of::<VmOffset>() - 1)
            .write(next);
    }
}

/// The reaper queue's address, the event the reaper thread waits on.
fn reaper_event<P: Platform>() -> *mut c_void {
    ptr::from_ref(&P::task_state().reaper_queue)
        .cast_mut()
        .cast()
}

/// The cached-stack high-water mark a debugger may lower or raise.
static STACK_FREE_LIMIT: AtomicU32 = AtomicU32::new(1);

/// How many stacks the deallocator freed, a counter for a debugger to read.
static THREAD_DEALLOCATE_STACK: AtomicU32 = AtomicU32::new(0);

/// Whether stack usage is tracked.
static STACK_CHECK_USAGE: AtomicI32 = AtomicI32::new(0);

/// The largest kernel-stack usage seen.
static STACK_MAX_USAGE: AtomicUsize = AtomicUsize::new(0);

/// No port name.
const MACH_PORT_NULL: c_uint = 0;

/// The default processor set.
#[must_use]
pub fn default_pset<P: Platform>() -> *mut ProcessorSet<P> {
    processor::default_pset()
}

impl<P: Platform> Thread<P> {
    /// Reference `task`'s processor set, as `thread_create()` did.
    ///
    /// # Safety
    ///
    /// `task` must point at a live task.
    unsafe fn reference_pset(task: *mut Task<P>) -> *mut ProcessorSet<P> {
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
        task: *mut Task<P>,
        mut pset: *mut ProcessorSet<P>,
    ) -> *mut ProcessorSet<P> {
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
    pub unsafe fn create(
        parent_task: *mut Task<P>,
    ) -> Result<*mut Self, Error> {
        if parent_task.is_null() {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: `Thread::init` built the cache before any thread existed,
        // and the allocation may block, as the caller permits.
        let Some(buf) = (unsafe { P::task_cache_alloc(TaskCache::Thread) })
        else {
            return Err(Error::ResourceShortage);
        };
        let new_thread = buf.as_ptr().cast::<Self>();

        // SAFETY: the storage is fresh and unshared; every field below is
        // written before the thread is visible to anything else.
        unsafe {
            new_thread.write(ptr::read(
                (*P::task_state().thread_template.0.get()).assume_init_ref(),
            ));
            ptr::addr_of_mut!((*new_thread).creation_time)
                .write(P::time_stamp());
            (*new_thread).task = parent_task;

            let cur_thread = P::cpu_thread();
            if !cur_thread.is_null() {
                let cur_task = current_task().as_ptr();
                if cur_task != kernel_task()
                    && parent_task == cur_task
                    && (*cur_thread).vm_privilege != 0
                {
                    (*new_thread).vm_privilege = 1;
                }
            }
            (*new_thread).lock.init();
            (*new_thread).sched.sched_stamp = sched_tick();
            P::pcb_init(parent_task, new_thread);
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
            (*new_thread).sched.cpu_usage = (TIMER_RATE * scale) / divisor;
            (*new_thread).sched.sched_usage = TIMER_RATE * scale;
        }

        let pset = unsafe { Self::stabilize_pset(parent_task, pset) };

        // SAFETY: both sets and the task are locked, and the thread is not
        // visible yet, so its fields are safe to set without its lock.
        unsafe {
            (*new_thread).sched.priority = (*parent_task).priority;
            (*new_thread).sched.max_priority = (*parent_task).max_priority;
            if (*pset).max_priority > (*new_thread).sched.max_priority {
                (*new_thread).sched.max_priority = (*pset).max_priority;
            }
            if (*new_thread).sched.max_priority > (*new_thread).sched.priority
            {
                (*new_thread).sched.priority =
                    (*new_thread).sched.max_priority;
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
            Task::<P>::threads_pinned(parent_task)
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
    /// # Panics
    ///
    /// If the last reference is the running thread's own, or the thread is
    /// not suspended when it goes.
    ///
    /// # Safety
    ///
    /// `thread` must be null or a live thread the caller holds a reference
    /// to, and the caller must hold no locks: the teardown may block.
    pub unsafe fn deallocate(thread: *mut Self) {
        if thread.is_null() {
            return;
        }

        unsafe {
            let s = P::splsched();
            (*thread).lock.lock();
            (*thread).ref_count = (*thread).ref_count.wrapping_sub(1);
            if (*thread).ref_count > 0 {
                (*thread).lock.unlock();
                P::splx(s);
                return;
            }

            (*thread).ref_count = 1;
            (*thread).lock.unlock();
            P::splx(s);
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

            let s = P::splsched();
            (*thread).lock.lock();

            (*thread).ref_count = (*thread).ref_count.wrapping_sub(1);
            if (*thread).ref_count > 0 {
                (*thread).lock.unlock();
                P::splx(s);
                (*task).lock.unlock();
                (*pset).lock.unlock();
                return;
            }

            // Zone free does not run `Drop`: cancel both callouts before
            // the thread returns to the cache.
            ptr::drop_in_place(ptr::addr_of_mut!((*thread).timer));
            ptr::drop_in_place(ptr::addr_of_mut!((*thread).depress_timer));
            (*thread).sched.depress_priority = -1;

            let (user_time, system_time) = (*thread).sched.read_times();
            add_time64(&mut (*task).total_user_time, user_time);
            add_time64(&mut (*task).total_system_time, system_time);

            (*task).thread_count = (*task).thread_count.wrapping_sub(1);
            Task::<P>::threads_pinned(task)
                .remove_ptr(NonNull::new_unchecked(thread));

            (*pset).remove_thread(thread);

            (*thread).lock.unlock();
            P::splx(s);
            (*task).lock.unlock();
            (*pset).lock.unlock();
            (*pset).deallocate();
        }

        // SAFETY: the checks are the C's; a live thread is never the current
        // one here, and an unreferenced thread is suspended.
        unsafe {
            assert!(
                thread != P::cpu_thread(),
                "thread_deallocate: thread deallocating itself"
            );
            if (*thread).state()
                & !(ThreadState::RUN
                    | ThreadState::HALTED
                    | ThreadState::SWAPPED)
                != ThreadState::SUSP
            {
                panic!("thread_deallocate: unstopped thread destroyed!")
            }
        }

        // SAFETY: the thread holds the task reference it took at creation,
        // and it is not running; `task_deallocate()` may block.
        unsafe { crate::task::deallocate((*thread).task) };

        // SAFETY: the thread is dead at splsched; its stack, if any, is
        // detached.
        unsafe {
            if !(*thread).state().intersects(ThreadState::SWAPPED) {
                let s = P::splsched();
                (*thread).stack_free();
                P::splx(s);
                THREAD_DEALLOCATE_STACK.fetch_add(1, Ordering::Relaxed);
            }
        }

        unsafe { P::pcb_terminate(thread) };

        // SAFETY: the thread came from the thread cache, and the entry check
        // makes its pointer non-null, so the free is sound.
        unsafe {
            P::task_cache_free(
                TaskCache::Thread,
                NonNull::new_unchecked(thread.cast::<u8>()),
            );
        }
    }

    /// Terminates `thread`.
    ///
    /// # Safety
    ///
    /// `thread` must be null or point at a live thread, and the caller must
    /// hold no locks: the routine waits and may block.
    pub unsafe fn terminate(thread: *mut Self) -> Result<(), Error> {
        let cur_thread = P::cpu_thread();

        if thread.is_null() {
            return Err(Error::InvalidArgument);
        }

        unsafe { ipc_thread_disable(thread) };

        if thread == cur_thread {
            // SAFETY: the current thread is live; the lock protects the state
            // word and the AST reasons.
            unsafe {
                let s = P::splsched();
                (*thread).lock.lock();
                if (*thread).active() {
                    (*thread).set_active(false);
                    (*thread).ast |= AstReason::TERMINATE;
                }
                (*thread).lock.unlock();
                mach_sched::ast::on(P::current_cpu(), AstReason::TERMINATE);
                P::splx(s);
            }
            return Ok(());
        }

        unsafe {
            let cur_task = current_task::<P>().as_ptr();
            (*cur_task).lock.lock();
            let s = P::splsched();
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
                P::splx(s);
                (*cur_task).lock.unlock();
                let _ = Self::terminate(cur_thread);
                return Err(Error::Failure);
            }

            (*cur_thread).lock.unlock();
            (*cur_task).lock.unlock();

            if !(*thread).active() {
                (*thread).lock.unlock();
                P::splx(s);
                return Err(Error::Failure);
            }

            (*thread).set_active(false);
            (*thread).lock.unlock();
            P::splx(s);
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
    pub unsafe fn terminate_release(
        thread: *mut Self,
        task: *mut Task<P>,
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
            let _ = mach_port::deallocate::<P>(space, thread_name);
            if reply_port != MACH_PORT_NULL {
                let _ = mach_port::destroy::<P>(space, reply_port);
            }
        }

        if address != 0 || size != 0 {
            // SAFETY: the task is live, so its map is; `vm_deallocate()`
            // takes the map's own locks and reports failure rather than
            // panicking.
            unsafe {
                let map = (*task).map.cast::<VmMap<P>>();
                if let Some(map) = map.as_mut() {
                    let _ = mach_vm::vm_user::deallocate(map, address, size);
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
        let cur_thread = P::cpu_thread();

        assert!(
            thread != cur_thread,
            "thread_halt: trying to halt current thread."
        );

        let s = unsafe {
            let s = P::splsched();

            if must_halt {
                (*thread).lock.lock();

                if (*thread).state().intersects(ThreadState::HALTED) {
                    (*thread).suspend_count =
                        (*thread).suspend_count.wrapping_add(1);
                    (*thread).lock.unlock();
                    P::splx(s);
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

                if (*thread).state().intersects(ThreadState::HALTED) {
                    (*thread).suspend_count =
                        (*thread).suspend_count.wrapping_add(1);
                    (*cur_thread).lock.unlock();
                    (*thread).lock.unlock();
                    P::splx(s);
                    return Ok(());
                }

                if (*cur_thread).ast.contains(AstReason::HALT) {
                    thread_wakeup_prim::<P>(
                        (*cur_thread).wake_active_event(),
                        0,
                        THREAD_INTERRUPTED,
                    );
                    (*thread).lock.unlock();
                    (*cur_thread).lock.unlock();
                    P::splx(s);
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
            (*thread).set_state((*thread).state() | ThreadState::SUSP);

            while (*thread).ast.contains(AstReason::HALT)
                && !(*thread).state().intersects(ThreadState::HALTED)
            {
                (*thread).set_wake_active(true);
                thread_sleep::<P>(
                    (*thread).wake_active_event(),
                    ptr::addr_of_mut!((*thread).lock),
                    c_int::from(true),
                );

                if (*thread).state().intersects(ThreadState::HALTED) {
                    P::splx(s);
                    return Ok(());
                }
                if (*cur_thread).wait_result != THREAD_AWAKENED && !must_halt {
                    P::splx(s);
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
    /// clean point, then park it at `ThreadState::HALTED`.
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
                P::splx(s);

                let ret = Self::dowait(thread, must_halt);

                if ret.is_err() {
                    s = P::splsched();
                    (*thread).lock.lock();
                    (*thread).ast &= !AstReason::HALT;
                    thread_wakeup_prim::<P>(
                        (*thread).wake_active_event(),
                        0,
                        THREAD_INTERRUPTED,
                    );
                    (*thread).lock.unlock();
                    P::splx(s);

                    Self::release(thread);
                    return Err(Error::Failure);
                }

                clear_wait(thread, THREAD_INTERRUPTED, c_int::from(true));

                if (*thread).state().intersects(ThreadState::HALTED) {
                    return Ok(());
                }

                let swap_func = (*thread).swap_func;
                // The C compared the stored continuation against the clean
                // point routines by address; the bindings give the function
                // items the pointer type that comparison needs.
                let continue_fn: unsafe extern "C" fn() =
                    <P as mach_ipc::Platform>::MSG_CONTINUE;
                let receive_continue_fn: unsafe extern "C" fn() =
                    <P as mach_ipc::Platform>::RECEIVE_CONTINUE;
                let has_cleanup = (swap_func.is_some_and(|f| {
                    ptr::fn_addr_eq(f, continue_fn)
                        || ptr::fn_addr_eq(f, receive_continue_fn)
                })) && mach_ipc::mach_msg::interrupt::<P>(
                    ThreadRef::new(thread.cast()),
                );
                if has_cleanup {
                    // The thread is not runnable, so its syscall return and
                    // resume point are this call's to set.
                    P::set_syscall_return(thread, MACH_RCV_INTERRUPTED);
                    (*thread).swap_func = Some(P::EXCEPTION_RETURN);
                }
                let exception_return_fn: unsafe extern "C" fn() =
                    P::EXCEPTION_RETURN;
                let bootstrap_return_fn: unsafe extern "C" fn() =
                    P::BOOTSTRAP_RETURN;
                let at_clean_point = has_cleanup
                    || swap_func.is_some_and(|f| {
                        ptr::fn_addr_eq(f, exception_return_fn)
                    })
                    || swap_func.is_some_and(|f| {
                        ptr::fn_addr_eq(f, bootstrap_return_fn)
                    });

                if at_clean_point {
                    s = P::splsched();
                    (*thread).lock.lock();
                    (*thread)
                        .set_state((*thread).state() | ThreadState::HALTED);
                    (*thread).ast &= !AstReason::HALT;
                    (*thread).lock.unlock();
                    P::splx(s);
                    return Ok(());
                }

                s = P::splsched();
                (*thread).lock.lock();
                assert!(
                    (*thread).state() & ThreadState::SCHED_STATE
                        == ThreadState::SUSP,
                    "thread_halt"
                );
                (*thread).set_state(
                    (*thread).state() | ThreadState::RUN | ThreadState::UNINT,
                );
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
    pub unsafe fn halt_self(continuation: Continuation) {
        let thread = P::cpu_thread();

        // SAFETY: the current thread is live; it queues itself for the reaper
        // and only the IPC teardown and the reaper touch it from here on.
        unsafe {
            if (*thread).ast.contains(AstReason::TERMINATE) {
                ipc_thread_terminate(thread);

                Self::hold(thread);

                let s = P::splsched();
                P::task_state()
                    .reaper_queue
                    .lock()
                    .pinned()
                    .push_back_ptr(NonNull::new_unchecked(thread));

                (*thread).lock.lock();
                (*thread).set_state((*thread).state() | ThreadState::HALTED);
                (*thread).lock.unlock();
                P::splx(s);

                thread_wakeup_prim::<P>(
                    reaper_event::<P>(),
                    0,
                    THREAD_AWAKENED,
                );
                thread_block::<P>(Some(walking_zombie));
            } else {
                let s = P::splsched();
                (*thread).lock.lock();
                (*thread).set_state((*thread).state() | ThreadState::HALTED);
                (*thread).ast &= !AstReason::HALT;
                (*thread).lock.unlock();
                P::splx(s);
                thread_block::<P>(continuation);
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
        assert!(thread != P::cpu_thread(), "thread_dowait");

        let mut need_wakeup = false;

        unsafe {
            let s = P::splsched();
            (*thread).lock.lock();

            let mut result = Ok(());
            loop {
                let mut need_wait = false;
                match (*thread).state() & ThreadState::SCHED_STATE {
                    ThreadState::RUN_SUSP => {
                        if !rem_runq(thread).is_null() {
                            (*thread).set_state(
                                (*thread).state() & !ThreadState::RUN,
                            );
                            need_wakeup = (*thread).wake_active();
                            (*thread).set_wake_active(false);
                            break;
                        }
                        let last = (*thread).last_processor;
                        if !last.is_null() {
                            // SAFETY: a non-null `last_processor` is one of
                            // the static processor records.
                            ProcessorRef::<P>::from_static(last).ast_check();
                        }
                        need_wait = true;
                    }
                    ThreadState::RUN_SUSP_UNINT
                    | ThreadState::RUN_WAIT_SUSP
                    | ThreadState::RUN_WAIT_SUSP_UNINT
                    | ThreadState::WAIT_SUSP_UNINT => need_wait = true,
                    _ => (),
                }
                if !need_wait {
                    break;
                }

                (*thread).set_wake_active(true);
                thread_sleep::<P>(
                    (*thread).wake_active_event(),
                    ptr::addr_of_mut!((*thread).lock),
                    c_int::from(true),
                );
                (*thread).lock.lock();
                if (*P::cpu_thread()).wait_result != THREAD_AWAKENED
                    && !must_halt
                {
                    result = Err(Error::Failure);
                    break;
                }
            }

            (*thread).lock.unlock();
            P::splx(s);

            if need_wakeup {
                thread_wakeup_prim::<P>(
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
    pub unsafe fn suspend(thread: *mut Self) -> Result<(), Error> {
        if thread.is_null() {
            return Err(Error::InvalidArgument);
        }

        let mut hold = false;
        let mut spl = P::splsched();

        unsafe {
            (*thread).lock.lock();
            while (*thread).state().intersects(ThreadState::UNINT) {
                assert_wait::<P>(
                    NonNull::new((*thread).state_event()),
                    c_int::from(true),
                );
                (*thread).lock.unlock();
                thread_block::<P>(None);
                (*thread).lock.lock();
            }

            let stop_count = (*thread).user_stop_count;
            (*thread).user_stop_count = stop_count.wrapping_add(1);
            if stop_count == 0 {
                hold = true;
                (*thread).suspend_count =
                    (*thread).suspend_count.wrapping_add(1);
                (*thread).set_state((*thread).state() | ThreadState::SUSP);
            }
            (*thread).lock.unlock();
            P::splx(spl);
        }

        if hold {
            if thread == P::cpu_thread() {
                // SAFETY: the current thread is live; the AST write is
                // atomic and the level is restored afterwards.
                unsafe {
                    spl = P::splsched();
                    mach_sched::ast::on(P::current_cpu(), AstReason::BLOCK);
                    P::splx(spl);
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
            let s = P::splsched();
            (*thread).lock.lock();
            while (*thread).may_assign == 0 {
                (*thread).assign_active = 1;
                thread_sleep::<P>(
                    ptr::addr_of_mut!((*thread).assign_active)
                        .cast::<c_void>(),
                    ptr::addr_of_mut!((*thread).lock),
                    0,
                );
                (*thread).lock.lock();
            }
            (*thread).may_assign = 0;
            (*thread).lock.unlock();
            P::splx(s);
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
        new_pset: *mut ProcessorSet<P>,
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
            if thread != P::cpu_thread() {
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

            let s = P::splsched();
            (*thread).lock.lock();

            Self::change_psets(thread, pset, new_pset);

            let old_empty = (*pset).empty;
            let new_empty = (*new_pset).empty;

            (*pset).lock.unlock();

            let mut recompute_pri =
                if (*thread).sched.policy & (*new_pset).policies == 0 {
                    (*thread).sched.policy = POLICY_TIMESHARE;
                    true
                } else {
                    false
                };

            if (*thread).sched.max_priority < (*new_pset).max_priority {
                (*thread).sched.max_priority = (*new_pset).max_priority;
                if (*thread).sched.priority < (*thread).sched.max_priority {
                    (*thread).sched.priority = (*thread).sched.max_priority;
                    recompute_pri = true;
                } else if (*thread).sched.depress_priority >= 0
                    && (*thread).sched.depress_priority
                        < (*thread).sched.max_priority
                {
                    (*thread).sched.depress_priority =
                        (*thread).sched.max_priority;
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
                    thread_wakeup_prim::<P>(
                        ptr::addr_of_mut!((*thread).assign_active)
                            .cast::<c_void>(),
                        0,
                        THREAD_AWAKENED,
                    );
                }
            }

            (*thread).lock.unlock();
            P::splx(s);

            (*pset).deallocate();

            if old_empty != 0 {
                Self::release(thread);
            }
            if new_empty == 0 {
                Self::release(thread);
            }

            if thread == P::cpu_thread() {
                let s = P::splsched();
                mach_sched::ast::on(P::current_cpu(), AstReason::BLOCK);
                P::splx(s);
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
    pub unsafe fn assign(
        thread: *mut Self,
        new_pset: *mut ProcessorSet<P>,
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
    panic!("walking_zombie: the zombie walks!")
}

/// The reaper's loop, which frees the threads on the reaper queue forever.
///
/// # Safety
///
/// Runs as the reaper kernel thread, which `kernel_thread()` starts once.
pub unsafe extern "C" fn reaper_thread_continue<P: Platform>() {
    loop {
        let mut queue = P::task_state().reaper_queue.lock();
        while let Some(thread) =
            queue.pinned().cursor_front_mut().remove_current()
        {
            let thread = ptr::from_mut(thread);
            // SAFETY: a queued thread is live and is not the reaper, and the
            // reference it holds for being alive is the one the reaper drops;
            // the queue's lock is released for the wait and the free, which
            // may block.
            MutexGuard::unlocked(&mut queue, || unsafe {
                let _ = Thread::<P>::dowait(thread, true);
                Thread::<P>::deallocate(thread);
            });
        }

        // SAFETY: the wait is asserted before the queue's lock is released,
        // so a thread queued after the check still wakes the reaper, and the
        // block holds no lock.
        unsafe {
            assert_wait::<P>(NonNull::new(reaper_event::<P>()), 0);
            drop(queue);
            thread_block::<P>(Some(reaper_thread_continue::<P>));
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
pub unsafe fn kernel_thread<P: Platform>(
    task: *mut Task<P>,
    _name: *const c_char,
    start: Continuation,
    arg: *mut c_void,
) -> *mut Thread<P> {
    let Ok(thread) = (unsafe { Thread::<P>::create(task) }) else {
        return ptr::null_mut();
    };

    // SAFETY: the thread is live and holds the extra reference the C
    // released here; the swap-in may block and resumes it.
    unsafe {
        Thread::<P>::deallocate(thread);
        (*thread).start(start);
        (*thread).saved.other = arg;
        crate::thread_swap::doswapin(thread);
        (*thread).sched.max_priority = BASEPRI_SYSTEM;
        (*thread).sched.priority = BASEPRI_SYSTEM;
        (*thread).sched.sched_pri = BASEPRI_SYSTEM;
        let _ = Thread::<P>::resume(thread);
    }
    thread
}

/// How much of `stack` the marker fill no longer covers.
///
/// # Safety
///
/// `stack` must be the base address of a live `P::KERNEL_STACK_SIZE` kernel
/// stack object.
unsafe fn stack_usage<P: Platform>(stack: VmOffset) -> VmSize {
    let words = unsafe {
        core::slice::from_raw_parts(
            ptr::with_exposed_provenance::<u32>(stack),
            P::KERNEL_STACK_SIZE / size_of::<u32>(),
        )
    };
    let used = words
        .iter()
        .position(|word| *word != STACK_MARKER)
        .unwrap_or(words.len());
    P::KERNEL_STACK_SIZE - used * size_of::<u32>()
}

/// Accounts for a stack about to be released.
///
/// # Safety
///
/// `stack` must be the base address of a live `P::KERNEL_STACK_SIZE` kernel
/// stack object.
pub(crate) unsafe fn stack_finalize<P: Platform>(stack: VmOffset) {
    if STACK_CHECK_USAGE.load(Ordering::Relaxed) == 0 {
        return;
    }

    let used = unsafe { stack_usage::<P>(stack) };
    STACK_MAX_USAGE.fetch_max(used, Ordering::Relaxed);
}

/// Fills a fresh stack with the usage marker when the check is on.
///
/// # Safety
///
/// `stack` must be the base address of a live `P::KERNEL_STACK_SIZE` kernel
/// stack object.
pub(crate) unsafe fn stack_init<P: Platform>(stack: VmOffset) {
    if STACK_CHECK_USAGE.load(Ordering::Relaxed) == 0 {
        return;
    }

    let words = unsafe {
        core::slice::from_raw_parts_mut(
            with_exposed_provenance_mut::<u32>(stack),
            P::KERNEL_STACK_SIZE / size_of::<u32>(),
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
pub unsafe fn host_stack_usage<P: Platform>(
    host: *mut c_void,
) -> Result<StackUsage, Error> {
    if host.is_null() {
        return Err(Error::InvalidHost);
    }

    let mut maxusage = STACK_MAX_USAGE.load(Ordering::Relaxed);
    let stacks = P::task_state().stack_free.lock();
    if STACK_CHECK_USAGE.load(Ordering::Relaxed) != 0 {
        let mut stack = stacks.head;
        while stack != 0 {
            // SAFETY: every stack on the list is a live cache object, as
            // `push` requires.
            unsafe {
                let usage = stack_usage::<P>(stack);
                if usage > maxusage {
                    maxusage = usage;
                }
                stack = stack_next::<P>(stack);
            }
        }
    }
    let total = stacks.count;
    drop(stacks);

    // The C multiplied the `unsigned` count by a `vm_size_t`; the count fits
    // `usize` and the product wraps in the C too.
    let space =
        (total as usize).wrapping_mul(round_page(P::KERNEL_STACK_SIZE));
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
pub unsafe fn processor_set_stack_usage<P: Platform>(
    pset: *mut ProcessorSet<P>,
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
            unsafe { P::kfree(old, size) };
        }
        size = size_needed;
        // SAFETY: `kalloc_init()` ran during the boot this routine follows.
        let Some(buf) = P::kalloc(size) else {
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
            Thread::<P>::reference(thread);
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
            with_exposed_provenance_mut::<Thread<P>>(threads.add(i).read())
        };
        let mut stack: VmOffset = 0;

        // SAFETY: the thread is live; the state read is the C's unlocked
        // one, and a swapped thread's stack is not looked at.
        unsafe {
            if !(*thread).state().intersects(ThreadState::SWAPPED) {
                stack = (*thread).kernel_stack;

                for cpu in CpuId::online() {
                    if P::cpu_thread_at(cpu) == thread {
                        stack = P::cpu_stack_at(cpu);
                        break;
                    }
                }
            }

            if stack != 0 {
                total = total.wrapping_add(1);

                if STACK_CHECK_USAGE.load(Ordering::Relaxed) != 0 {
                    let usage = stack_usage::<P>(stack);

                    if usage > maxusage {
                        maxusage = usage;
                        maxstack = thread.addr();
                    }
                }
            }

            Thread::<P>::deallocate(thread);
        }
    }

    if size != 0 {
        // SAFETY: the buffer is the live allocation of `size` bytes, and
        // every reference it held was dropped above.
        unsafe { P::kfree(buf, size) };
    }

    // The C multiplied the `unsigned` count by a `vm_size_t`; the count fits
    // `usize` and the product wraps in the C too.
    let space =
        (total as usize).wrapping_mul(round_page(P::KERNEL_STACK_SIZE));
    Ok(StackUsage {
        total,
        space,
        maxusage,
        maxstack,
    })
}

impl<P: Platform> Thread<P> {
    /// Moves `thread` from `old_pset` to `new_pset`.
    ///
    /// # Safety
    ///
    /// The caller must hold the locks of both sets and of the thread, as the C
    /// requires, and `thread` must be live and linked into `old_pset`'s thread
    /// list.
    unsafe fn change_psets(
        thread: *mut Self,
        old_pset: *mut ProcessorSet<P>,
        new_pset: *mut ProcessorSet<P>,
    ) {
        unsafe {
            (*old_pset)
                .threads_pinned()
                .remove_ptr(NonNull::new_unchecked(thread));
            (*old_pset).thread_count =
                (*old_pset).thread_count.wrapping_sub(1);
            (*new_pset)
                .threads_pinned()
                .push_back_ptr(NonNull::new_unchecked(thread));
            (*thread).processor_set = new_pset;
            (*new_pset).thread_count =
                (*new_pset).thread_count.wrapping_add(1);
        }
    }
}
