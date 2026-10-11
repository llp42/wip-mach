// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! Processors coming up and going down, and the action thread that
//! assigns them to processor sets and shuts them down.

use crate::error::Error;
use crate::platform::Platform;
use crate::processor::{
    Processor, ProcessorQueue, boot_processor, processor_at, slave_pset,
};
use crate::processor_set::ProcessorSet;
use crate::sched_prim::{
    THREAD_AWAKENED, assert_wait, thread_bind, thread_block,
    thread_wakeup_prim,
};
use crate::smp::CpuId;
use crate::thread::{Thread, default_pset};
use crate::types::ProcessorState;
use core::ffi::{c_int, c_void};
use core::pin::Pin;
use core::ptr;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
use lock::MutexGuard;

/// The processors waiting for the action thread.
pub(crate) struct ActionQueue<P: Platform>(ProcessorQueue<P>);

// SAFETY: the queue links processor records, which every CPU shares.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "the linked processors are shared between CPUs, which their type \
              does not say"
)]
unsafe impl<P: Platform> Send for ActionQueue<P> {}

impl<P: Platform> ActionQueue<P> {
    /// An empty queue.
    pub(crate) const fn new() -> Self {
        Self(ProcessorQueue::new())
    }

    /// The queue, pinned.
    const fn pinned(&mut self) -> Pin<&mut ProcessorQueue<P>> {
        // SAFETY: the one `ActionQueue` is in the platform's task state, a
        // static, which never moves.
        unsafe { Pin::new_unchecked(&mut self.0) }
    }
}

/// The action queue's address, the event the action thread waits on.
fn action_event<P: Platform>() -> *mut c_void {
    ptr::from_ref(&P::task_state().action_queue)
        .cast_mut()
        .cast()
}

/// Flags `cpu` as up and running.  Called when a processor comes online.
///
/// # Safety
///
/// `cpu` must be a CPU the machine reports, and the boot or the hot-plug path
/// must call this with nothing locked on the processor.
pub unsafe fn cpu_up<P: Platform>(cpu: c_int) {
    let cpu = unsafe { CpuId::from_c_int(cpu) };
    let processor = processor_at::<P>(cpu).as_ptr();
    let default = default_pset();
    let slave = slave_pset();

    unsafe {
        (*default).lock.lock();
        (*slave).lock.lock();

        let s = P::splsched();
        (*processor).lock.lock();

        P::set_cpu_running(cpu, true);

        if cpu == CpuId::BOOT {
            (*default).add_processor(processor);
        } else {
            (*slave).add_processor(processor);
        }
        (*processor)
            .state
            .store(ProcessorState::Running, Ordering::Release);

        (*processor).lock.unlock();
        P::splx(s);
        (*slave).lock.unlock();
        (*default).lock.unlock();
    }
}

/// Flags `cpu` as down.  Called when a processor is about to go offline.
///
/// # Safety
///
/// `cpu` must be a CPU the machine reports whose processor has already been
/// removed from its set.
unsafe fn cpu_down<P: Platform>(cpu: CpuId) {
    unsafe {
        let s = P::splsched();
        let processor = processor_at::<P>(cpu).as_ptr();
        (*processor).lock.lock();

        P::set_cpu_running(cpu, false);
        (*processor).processor_set_next = ptr::null_mut();
        (*processor)
            .state
            .store(ProcessorState::OffLine, Ordering::Release);

        (*processor).lock.unlock();
        P::splx(s);
    }
}

/// Queues `processor` for assignment to `new_pset`, or for shutdown when it is
/// null.
///
/// # Safety
///
/// `processor` must be a live processor in a live set with its lock held by
/// the caller, as [`assign`] and [`shutdown`] arrange.
unsafe fn request_action<P: Platform>(
    processor: *mut Processor<P>,
    new_pset: Option<NonNull<ProcessorSet<P>>>,
) {
    unsafe {
        let pset = (*processor).processor_set.load(Ordering::Acquire);
        (*pset).idle_lock.lock();

        loop {
            // The processor's own idle loop clears the state, without this
            // lock.
            if (*processor).state.load(Ordering::Acquire)
                != ProcessorState::Dispatching
            {
                break;
            }
            core::hint::spin_loop();
        }

        let mut queue = P::task_state().action_queue.lock();

        match (*processor).state.load(Ordering::Acquire) {
            ProcessorState::Idle => {
                let _ = (*pset)
                    .idle_queue_pinned()
                    .remove_ptr(processor.cast_const());
                (*pset).idle_count = (*pset).idle_count.wrapping_sub(1);
                queue
                    .pinned()
                    .push_back_ptr(NonNull::new_unchecked(processor));
                set_action_state(processor, new_pset);
            }
            ProcessorState::Running => {
                queue
                    .pinned()
                    .push_back_ptr(NonNull::new_unchecked(processor));
                set_action_state(processor, new_pset);
            }
            ProcessorState::Assign => {
                set_action_state(processor, new_pset);
            }
            state @ (ProcessorState::OffLine
            | ProcessorState::Dispatching
            | ProcessorState::Shutdown) => {
                P::print(format_args!("state: {state:?}\n"));
                panic!("processor_request_action: bad state");
            }
        }

        drop(queue);
        (*pset).idle_lock.unlock();

        let _ =
            thread_wakeup_prim::<P>(action_event::<P>(), 0, THREAD_AWAKENED);
    }
}

/// The state store the three action cases share.
///
/// # Safety
///
/// `processor` must be a live processor whose lock the caller holds.
unsafe fn set_action_state<P: Platform>(
    processor: *mut Processor<P>,
    new_pset: Option<NonNull<ProcessorSet<P>>>,
) {
    unsafe {
        match new_pset {
            None => {
                (*processor)
                    .state
                    .store(ProcessorState::Shutdown, Ordering::Release);
            }
            Some(new_pset) => {
                (*processor)
                    .state
                    .store(ProcessorState::Assign, Ordering::Release);
                (*processor).processor_set_next = new_pset.as_ptr();
            }
        }
    }
}

/// Changes the set `processor` is assigned to.
///
/// # Safety
///
/// `processor` must be null or a live processor, `new_pset` null or a live
/// set, and the caller must hold no lock: the routine waits and may block.
pub unsafe fn assign<P: Platform>(
    processor: *mut Processor<P>,
    new_pset: *mut ProcessorSet<P>,
    wait: bool,
) -> Result<(), Error> {
    if processor.is_null()
        || new_pset.is_null()
        || processor == boot_processor()
    {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: `new_pset` is live; the reference is the one the action takes.
    unsafe { (*new_pset).reference() };

    loop {
        unsafe {
            let mut s = P::splsched();
            (*processor).lock.lock();

            let state = (*processor).state.load(Ordering::Acquire);
            if state == ProcessorState::OffLine
                || state == ProcessorState::Shutdown
            {
                (*processor).lock.unlock();
                P::splx(s);
                (*new_pset).deallocate();
                return Err(Error::Failure);
            }

            if state == ProcessorState::Assign {
                assert_wait::<P>(NonNull::new(processor.cast::<c_void>()), 1);
                (*processor).lock.unlock();
                P::splx(s);
                thread_block::<P>(None);
                continue;
            }

            if (*processor).processor_set.load(Ordering::Acquire) == new_pset {
                (*processor).lock.unlock();
                P::splx(s);
                (*new_pset).deallocate();
                return Ok(());
            }

            request_action(processor, NonNull::new(new_pset));

            if wait {
                loop {
                    let state = (*processor).state.load(Ordering::Acquire);
                    if state != ProcessorState::Assign
                        && state != ProcessorState::Shutdown
                    {
                        break;
                    }
                    assert_wait::<P>(
                        NonNull::new(processor.cast::<c_void>()),
                        1,
                    );
                    (*processor).lock.unlock();
                    P::splx(s);
                    thread_block::<P>(None);
                    s = P::splsched();
                    (*processor).lock.lock();
                }
            }

            (*processor).lock.unlock();
            P::splx(s);
            return Ok(());
        }
    }
}

/// Queues `processor` for shutdown.
///
/// # Safety
///
/// `processor` must be null or a live processor; the routine takes the
/// processor lock itself and may be called from interrupt level.
pub(crate) unsafe fn shutdown<P: Platform>(
    processor: *mut Processor<P>,
) -> Result<(), Error> {
    if processor.is_null() {
        return Err(Error::InvalidArgument);
    }

    unsafe {
        let s = P::splsched();
        (*processor).lock.lock();

        let state = (*processor).state.load(Ordering::Acquire);
        if state == ProcessorState::OffLine
            || state == ProcessorState::Shutdown
        {
            (*processor).lock.unlock();
            P::splx(s);
            return Ok(());
        }

        request_action(processor, None);
        (*processor).lock.unlock();
        P::splx(s);

        Ok(())
    }
}

/// Performs the shutdown or the reassignment the action queue recorded.
///
/// # Safety
///
/// `processor` must be a live processor queued on the action queue with a
/// state of assign or shutdown, and the caller must be the action thread.
unsafe fn doaction<P: Platform>(processor: *mut Processor<P>) {
    let this_thread = P::cpu_thread();
    // SAFETY: the action thread is the current thread and the processor is
    // live; the bind only stores the pairing.
    unsafe { thread_bind(this_thread, processor) };
    // SAFETY: the action thread has no wait state set, so the block returns
    // immediately when this thread is the one selected to run.
    unsafe { thread_block::<P>(None) };

    let pset = unsafe { (*processor).processor_set.load(Ordering::Acquire) };
    let mut prev_thread: *mut Thread<P> = ptr::null_mut();
    let mut have_pset_ref = false;

    // SAFETY: `pset` is the set the processor belongs to, and this is the
    // action thread, so the set lock serializes the thread list.
    unsafe {
        (*pset).lock.lock();
        if (*pset).processor_count == 1 {
            let mut cursor = (*pset).threads.cursor_front();
            while let Some(thread) = cursor.current_ptr() {
                cursor.move_next();
                Thread::<P>::hold(thread.as_ptr());
            }
            (*pset).empty = 1;
            (*pset).ref_count = (*pset).ref_count.wrapping_add(1);
            have_pset_ref = true;

            'restart_thread: loop {
                prev_thread = ptr::null_mut();
                let mut thread = (*pset).threads.cursor_front().current_ptr();
                while let Some(current) = thread {
                    let current = current.as_ptr();
                    Thread::<P>::reference(current);
                    (*pset).lock.unlock();
                    if !prev_thread.is_null() {
                        Thread::<P>::deallocate(prev_thread);
                    }

                    Thread::<P>::freeze(current);
                    if (*current).processor_set != pset {
                        Thread::<P>::unfreeze(current);
                        Thread::<P>::deallocate(current);
                        (*pset).lock.lock();
                        continue 'restart_thread;
                    }

                    let _ = Thread::<P>::dowait(current, true);
                    prev_thread = current;
                    (*pset).lock.lock();
                    Thread::<P>::unfreeze(prev_thread);
                    // The reference held on `current` keeps it linked.
                    let mut cursor = (*pset)
                        .threads_pinned()
                        .cursor_mut_from_ptr(NonNull::new_unchecked(current));
                    cursor.move_next();
                    thread = cursor.current_ptr();
                }
                break;
            }
        }
        (*pset).lock.unlock();
    }

    let new_pset = unsafe { (*processor).processor_set_next };

    if !new_pset.is_null() {
        // SAFETY: `processor` is live, `new_pset` is the live set it
        // names, and this is the action thread.
        unsafe {
            reassign_processor(
                processor,
                pset,
                new_pset,
                this_thread,
                have_pset_ref,
                prev_thread,
            );
        }
        return;
    }

    // SAFETY: the fall-through shutdown takes the processor lock at
    // splsched, as the C did after its `shutdown:` label.
    unsafe {
        if (*processor).state.load(Ordering::Acquire)
            != ProcessorState::Shutdown
        {
            P::print(format_args!(
                "state: {:?}\n",
                (*processor).state.load(Ordering::Acquire)
            ));
            panic!("processor_doaction: action_thread -- bad processor state");
        }

        let s = P::splsched();
        (*processor).lock.lock();
        shutdown_tail(
            pset,
            processor,
            NonNull::new(new_pset),
            this_thread,
            have_pset_ref,
            NonNull::new(prev_thread),
            s,
        );
    }
}

/// The processor-reassignment path of [`doaction()`]: move the processor
/// into `new_pset`, restarting the attempt around the races the C's
/// `restart_pset` label handled.
///
/// # Safety
///
/// As [`doaction()`]; `new_pset` must be the live set the processor's
/// `processor_set_next` named.
unsafe fn reassign_processor<P: Platform>(
    processor: *mut Processor<P>,
    pset: *mut ProcessorSet<P>,
    mut new_pset: *mut ProcessorSet<P>,
    this_thread: *mut Thread<P>,
    have_pset_ref: bool,
    prev_thread: *mut Thread<P>,
) {
    if !new_pset.is_null() {
        'restart_pset: loop {
            // SAFETY: both sets are live, and the C locks them in address
            // order to avoid deadlock.
            unsafe {
                if (pset as usize) < (new_pset as usize) {
                    (*pset).lock.lock();
                    (*new_pset).lock.lock();
                } else {
                    (*new_pset).lock.lock();
                    (*pset).lock.lock();
                }

                if (*new_pset).active == 0 {
                    (*new_pset).lock.unlock();
                    (*pset).lock.unlock();
                    (*new_pset).deallocate();
                    new_pset = default_pset();
                    (*new_pset).reference();
                    continue 'restart_pset;
                }

                if (*new_pset).empty != 0 && (*new_pset).processor_count > 0 {
                    (*new_pset).lock.unlock();
                    (*pset).lock.unlock();
                    loop {
                        // Another action thread clears the race under the set
                        // lock; the volatile reads are the C's.
                        let empty = ptr::read_volatile(ptr::addr_of!(
                            (*new_pset).empty
                        ));
                        let count = ptr::read_volatile(ptr::addr_of!(
                            (*new_pset).processor_count
                        ));
                        if empty == 0 || count == 0 {
                            break;
                        }
                        core::hint::spin_loop();
                    }
                    continue 'restart_pset;
                }

                let s = P::splsched();
                (*processor).lock.lock();

                if (*processor).state.load(Ordering::Acquire)
                    == ProcessorState::Shutdown
                {
                    (*processor).processor_set_next = ptr::null_mut();
                    (*new_pset).lock.unlock();
                    shutdown_tail(
                        pset,
                        processor,
                        NonNull::new(new_pset),
                        this_thread,
                        have_pset_ref,
                        NonNull::new(prev_thread),
                        s,
                    );
                    return;
                }

                (*pset).remove_processor(processor);
                (*pset).lock.unlock();
                (*new_pset).add_processor(processor);
                if (*new_pset).empty != 0 {
                    let mut entry =
                        (*new_pset).threads.cursor_front().current_ptr();
                    while let Some(thread) = entry {
                        let thread = thread.as_ptr();
                        // Capture the successor before `release()` may
                        // unlink `thread`.
                        let mut cursor =
                            (*new_pset).threads_pinned().cursor_mut_from_ptr(
                                NonNull::new_unchecked(thread),
                            );
                        cursor.move_next();
                        entry = cursor.current_ptr();
                        Thread::<P>::release(thread);
                    }
                    (*new_pset).empty = 0;
                }
                (*processor).processor_set_next = ptr::null_mut();
                (*processor)
                    .state
                    .store(ProcessorState::Running, Ordering::Release);
                let _ = thread_wakeup_prim::<P>(
                    processor.cast::<c_void>(),
                    0,
                    THREAD_AWAKENED,
                );
                (*processor).lock.unlock();
                P::splx(s);
                (*new_pset).lock.unlock();

                (*new_pset).deallocate();
                if have_pset_ref {
                    (*pset).deallocate();
                }
                if !prev_thread.is_null() {
                    Thread::<P>::deallocate(prev_thread);
                }
                thread_bind(this_thread, ptr::null_mut());
                thread_block::<P>(None);
                return;
            }
        }
    }
}

/// The tail the assignment and shutdown paths share: drop the processor from
/// its set, release every reference, and leave through the shutdown context.
///
/// # Safety
///
/// `processor` must be live, its lock held and its set's lock held at
/// splsched `s`, and `pset` must be the set it is leaving.
unsafe fn shutdown_tail<P: Platform>(
    pset: *mut ProcessorSet<P>,
    processor: *mut Processor<P>,
    new_pset: Option<NonNull<ProcessorSet<P>>>,
    this_thread: *mut Thread<P>,
    have_pset_ref: bool,
    prev_thread: Option<NonNull<Thread<P>>>,
    s: c_int,
) {
    unsafe {
        (*pset).remove_processor(processor);
        (*processor).lock.unlock();
        (*pset).lock.unlock();
        P::splx(s);

        if let Some(new_pset) = new_pset {
            (*new_pset.as_ptr()).deallocate();
        }
        if have_pset_ref {
            (*pset).deallocate();
        }
        if let Some(prev_thread) = prev_thread {
            Thread::<P>::deallocate(prev_thread.as_ptr());
        }

        thread_bind(this_thread, ptr::null_mut());
        P::switch_to_shutdown_context(
            this_thread,
            processor_doshutdown,
            processor,
        );
    }
}

/// Drains the action queue, shutting processors down or reassigning them.
///
/// # Safety
///
/// The boot path is the only caller; it starts this as a kernel thread with
/// nothing locked.
pub unsafe extern "C" fn action_thread<P: Platform>() {
    // SAFETY: this is the action thread, the only drainer of the queue, and
    // `engine()` never returns.
    unsafe { engine::<P>() };
}

/// The action loop itself, separate so the continuation pointer can be a
/// plain `extern "C" fn()`.
///
/// # Safety
///
/// The thread that runs this must be the action thread, and nothing else may
/// drain the action queue.
unsafe fn engine<P: Platform>() -> ! {
    // The continuation must be typed `extern "C" fn()`; the trampoline
    // re-enters the loop below on the resumed stack.
    unsafe extern "C" fn resume<P: Platform>() {
        // SAFETY: `engine()` never returns.
        unsafe { engine::<P>() }
    }

    loop {
        let mut queue = P::task_state().action_queue.lock();
        while let Some(processor) = queue.pinned().pop_front() {
            let processor = ptr::from_mut(processor);
            // SAFETY: `request_action` queues only live processors, in the
            // assign or shutdown state; the queue's lock is released for the
            // action, which blocks.
            MutexGuard::unlocked(&mut queue, || unsafe {
                doaction(processor);
            });
        }

        // SAFETY: the wait is asserted before the queue's lock is released,
        // so a processor queued after the check still wakes this thread, and
        // the block holds no lock.
        unsafe {
            assert_wait::<P>(NonNull::new(action_event::<P>()), 0);
            drop(queue);
            thread_block::<P>(Some(resume::<P>));
        }
    }
}

/// Takes `processor` out of the system, running on its shutdown stack.
///
/// # Safety
///
/// `processor` must be the live processor whose shutdown context invoked
/// this, and the call must come from `switch_to_shutdown_context()`.
pub(crate) unsafe extern "C" fn processor_doshutdown<P: Platform>(
    processor: *mut Processor<P>,
) {
    // SAFETY: the processor owns the CPU it runs on, and `P::halt_cpu()` never
    // returns, as the C required.
    unsafe {
        let cpu = (*processor).cpu_id;

        P::cpu_shutdown(cpu);
        cpu_down::<P>(cpu);
        let _ = thread_wakeup_prim::<P>(
            processor.cast::<c_void>(),
            0,
            THREAD_AWAKENED,
        );
        P::halt_cpu();
    }
}
