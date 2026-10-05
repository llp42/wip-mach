// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from kern/machine.h:
//   Copyright (C) 2008 Free Software Foundation, Inc.
// Derived from kern/machine.c:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// Derived from include/mach/machine.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The machine slots and the machine abstraction: CPUs coming up and going
//! down, processor assignment and shutdown, and reboot.

use crate::arch::x86_64::cswitch;
use crate::arch::x86_64::model_dep::halt_cpu;
use crate::arch::x86_64::per_cpu::{self, per_cpu_at};
use crate::arch::x86_64::pmap;
use crate::arch::x86_64::spl;
use crate::config::MAX_NCPUS;
use crate::kern::console::kprint;
use crate::kern::debug::{self, kpanic};
use crate::kern::error::Error;
use crate::kern::lock::SimpleLock;
use crate::kern::priority;
use crate::kern::processor::{
    Processor, ProcessorQueue, ProcessorSet, ProcessorState, boot_processor,
    default_pset, processor_at, slave_pset,
};
use crate::kern::sched_prim::{
    THREAD_AWAKENED, assert_wait, thread_bind, thread_block,
    thread_wakeup_prim,
};
use crate::kern::smp::CpuId;
use crate::kern::thread::Thread;
use crate::utils::cell::SyncCell;
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::offset_of;
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::Ordering;

/// The per-state tick counters every machine slot carries.
pub const CPU_STATE_MAX: usize = 3;

/// The ticks per second.
pub const CLOCK_HZ: c_int = 100;
const _: () = assert!(CLOCK_HZ as u64 == clock::HZ);

/// The microseconds per tick.
pub const TICK: c_int = 1_000_000 / CLOCK_HZ;

/// The `cpu_ticks` user index.
pub(crate) const CPU_STATE_USER: c_int = 0;
/// The `cpu_ticks` system index.
pub(crate) const CPU_STATE_SYSTEM: c_int = 1;
/// The `cpu_ticks` idle index.
pub(crate) const CPU_STATE_IDLE: c_int = 2;

/// `struct machine_slot`: what the arch probe records about each possible CPU.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct MachineSlot {
    pub is_cpu: c_int,
    pub cpu_type: c_int,
    pub cpu_subtype: c_int,
    pub running: c_int,
    /// `cpu_ticks`: the ticks accumulated per `CPU_STATE_*`.
    pub cpu_ticks: [c_int; CPU_STATE_MAX],
    /// `clock_freq`: the clock interrupt frequency.
    pub clock_freq: c_int,
}

impl MachineSlot {
    /// The all-zero image a C `static struct machine_slot` began with.
    const fn zeroed() -> Self {
        Self {
            is_cpu: 0,
            cpu_type: 0,
            cpu_subtype: 0,
            running: 0,
            cpu_ticks: [0; CPU_STATE_MAX],
            clock_freq: 0,
        }
    }
}

const _: () = assert!(size_of::<MachineSlot>() == 32);
const _: () = assert!(align_of::<MachineSlot>() == align_of::<c_int>());
const _: () = assert!(offset_of!(MachineSlot, is_cpu) == 0);
const _: () = assert!(offset_of!(MachineSlot, cpu_type) == 4);
const _: () = assert!(offset_of!(MachineSlot, cpu_subtype) == 8);
const _: () = assert!(offset_of!(MachineSlot, running) == 12);
const _: () = assert!(offset_of!(MachineSlot, cpu_ticks) == 16);
const _: () = assert!(offset_of!(MachineSlot, clock_freq) == 28);

/// `struct machine_info`: what the boot path records about the machine as a
/// whole.
#[repr(C)]
#[allow(missing_docs)]
pub struct MachineInfo {
    pub major_version: c_int,
    pub minor_version: c_int,
    pub max_cpus: c_int,
    pub avail_cpus: c_int,
    /// `memory_size`: a `vm_size_t`, eight bytes on `x86_64`.
    pub memory_size: usize,
}

const _: () = {
    assert!(size_of::<MachineInfo>() == 24);
    assert!(align_of::<MachineInfo>() == 8);
    assert!(offset_of!(MachineInfo, major_version) == 0);
    assert!(offset_of!(MachineInfo, minor_version) == 4);
    assert!(offset_of!(MachineInfo, max_cpus) == 8);
    assert!(offset_of!(MachineInfo, avail_cpus) == 12);
    assert!(offset_of!(MachineInfo, memory_size) == 16);
};

/// What the boot path records about the machine as a whole.
static mut MACHINE_INFO: MachineInfo = MachineInfo {
    major_version: 0,
    minor_version: 0,
    max_cpus: 0,
    avail_cpus: 0,
    memory_size: 0,
};

/// The slot of each possible CPU.
///
/// The `x86_64` `pmap` reads the symbol's `cpu_type` field.
pub(crate) static mut MACHINE_SLOT: [MachineSlot; MAX_NCPUS] =
    [const { MachineSlot::zeroed() }; MAX_NCPUS];

/// The assign/shutdown queue.
static ACTION_QUEUE: SyncCell<ProcessorQueue> =
    SyncCell(UnsafeCell::new(ProcessorQueue::new()));

/// Serializes the action queue.
static ACTION_LOCK: SimpleLock = SimpleLock::new();

/// The slot of CPU `cpu`.
pub(crate) fn slot(cpu: CpuId) -> *mut MachineSlot {
    // SAFETY: `cpu` is below `MAX_NCPUS`, the array's length, so the element
    // the offset reaches is inside the array.
    unsafe {
        ptr::addr_of_mut!(MACHINE_SLOT)
            .cast::<MachineSlot>()
            .add(cpu.as_usize())
    }
}

/// Whether CPU `cpu` is idle.
fn cpu_idle(cpu: CpuId) -> bool {
    processor_at(cpu).state() == ProcessorState::Idle
}

/// Charge one clock tick to the interrupted context's user/system timers
/// and this CPU's `cpu_ticks`.
///
/// # Safety
///
/// `thread` must be the interrupted thread or null, and only this CPU may
/// write its own `cpu_ticks` slot.
pub(crate) unsafe fn tick_accounting(
    thread: *mut Thread,
    usec: c_uint,
    usermode: bool,
) {
    let my_cpu = per_cpu::cpu_id();

    if usermode {
        // SAFETY: the clock interrupt runs on the interrupted thread, and
        // `usermode` says that thread is live.
        unsafe { (*thread).user_timer.bump(usec) };
    } else if !thread.is_null() {
        // SAFETY: the interrupted thread is live and this CPU is the only
        // writer of its timer.
        unsafe { (*thread).system_timer.bump(usec) };
    }

    let state = if usermode {
        CPU_STATE_USER
    } else if cpu_idle(my_cpu) {
        CPU_STATE_IDLE
    } else {
        CPU_STATE_SYSTEM
    };

    // SAFETY: `my_cpu` is the running CPU, so it indexes `machine_slot`, and
    // `state` is one of the three `CPU_STATE_*` values the `cpu_ticks` array
    // holds.  Only this CPU's clock interrupt writes its counters.
    unsafe {
        let s = slot(my_cpu);
        let ticks = &mut (*s).cpu_ticks[state as usize];
        *ticks = ticks.wrapping_add(1);
    }

    // SAFETY: `thread` is the interrupted thread or null before the
    // scheduler exists, which is what the C passed; the routine reads it for
    // the quantum.
    unsafe {
        priority::thread_quantum_update(thread, 1, state);
    }
}

/// The live `machine_info`.
pub(crate) fn info() -> *mut MachineInfo {
    ptr::addr_of_mut!(MACHINE_INFO)
}

/// The action queue's address, the event the action thread waits on.
fn action_event() -> *mut c_void {
    ACTION_QUEUE.0.get().cast()
}

/// The live `action_queue`.
///
/// # Safety
///
/// The caller must hold `action_lock` for as long as it uses the queue.
unsafe fn action_queue() -> Pin<&'static mut ProcessorQueue> {
    // SAFETY: the static never moves, and the lock the caller holds keeps
    // anything else from reaching the queue.
    unsafe { Pin::new_unchecked(&mut *ACTION_QUEUE.0.get()) }
}

/// The live `action_lock`.
pub(crate) fn action_lock() -> &'static SimpleLock {
    &ACTION_LOCK
}

/// The option word of `host_reboot()`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RebootOptions(c_int);

impl RebootOptions {
    /// Enter the kernel debugger from user level instead of rebooting.
    const DEBUGGER: Self = Self(0x1000);
    /// Halt instead of rebooting.
    const HALT: Self = Self(0x08);

    /// Whether every bit of `other` is set in `self`.
    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// Reboot or halt the host, or enter the debugger.
fn reboot(
    host: Option<NonNull<c_void>>,
    options: RebootOptions,
) -> Result<(), Error> {
    if host.is_none() {
        return Err(Error::InvalidHost);
    }

    if options.contains(RebootOptions::DEBUGGER) {
        // SAFETY: `Debugger` takes a readable NUL-terminated message; this one
        // is a literal, and the call never returns.
        unsafe { debug::debugger(c"debugger".as_ptr()) };
    } else {
        // `halt_all_cpus` never returns.
        let reboot = c_int::from(!options.contains(RebootOptions::HALT));
        crate::arch::x86_64::model_dep::halt_all_cpus(reboot);
    }

    Ok(())
}

/// Flags `cpu` as up and running.  Called when a processor comes online.
///
/// # Safety
///
/// `cpu` must be a CPU the machine reports, and the boot or the hot-plug path
/// must call this with nothing locked on the processor.
pub(crate) unsafe fn cpu_up(cpu: c_int) {
    let cpu = unsafe { CpuId::from_c_int(cpu) };
    let processor = processor_at(cpu).as_ptr();
    let default = default_pset();
    let slave = slave_pset();

    unsafe {
        (*default).lock.lock();
        (*slave).lock.lock();

        let s = spl::splsched();
        (*processor).lock.lock();

        (*slot(cpu)).running = 1;
        let info = info();
        (*info).avail_cpus = (*info).avail_cpus.wrapping_add(1);

        if cpu == CpuId::BOOT {
            (*default).add_processor(processor);
        } else {
            (*slave).add_processor(processor);
        }
        (*processor)
            .state
            .store(ProcessorState::Running, Ordering::Release);

        (*processor).lock.unlock();
        spl::splx(s);
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
unsafe fn cpu_down(cpu: CpuId) {
    unsafe {
        let s = spl::splsched();
        let processor = processor_at(cpu).as_ptr();
        (*processor).lock.lock();

        (*slot(cpu)).running = 0;
        let info = info();
        (*info).avail_cpus = (*info).avail_cpus.wrapping_sub(1);
        (*processor).processor_set_next = ptr::null_mut();
        (*processor)
            .state
            .store(ProcessorState::OffLine, Ordering::Release);

        (*processor).lock.unlock();
        spl::splx(s);
    }
}

/// Queues `processor` for assignment to `new_pset`, or for shutdown when it is
/// null.
///
/// # Safety
///
/// `processor` must be a live processor in a live set with its lock held by
/// the caller, as [`assign`] and [`shutdown`] arrange.
unsafe fn request_action(
    processor: *mut Processor,
    new_pset: Option<NonNull<ProcessorSet>>,
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

        action_lock().lock();

        match (*processor).state.load(Ordering::Acquire) {
            ProcessorState::Idle => {
                let _ = (*pset)
                    .idle_queue_pinned()
                    .remove_ptr(processor.cast_const());
                (*pset).idle_count = (*pset).idle_count.wrapping_sub(1);
                action_queue()
                    .push_back_ptr(NonNull::new_unchecked(processor));
                set_action_state(processor, new_pset);
            }
            ProcessorState::Running => {
                action_queue()
                    .push_back_ptr(NonNull::new_unchecked(processor));
                set_action_state(processor, new_pset);
            }
            ProcessorState::Assign => {
                set_action_state(processor, new_pset);
            }
            state @ (ProcessorState::OffLine
            | ProcessorState::Dispatching
            | ProcessorState::Shutdown) => {
                kprint!("state: {:?}\n", state);
                kpanic!(
                    "processor_request_action",
                    "processor_request_action: bad state"
                );
            }
        }

        action_lock().unlock();
        (*pset).idle_lock.unlock();

        let _ = thread_wakeup_prim(action_event(), 0, THREAD_AWAKENED);
    }
}

/// The state store the three action cases share.
///
/// # Safety
///
/// `processor` must be a live processor whose lock the caller holds.
unsafe fn set_action_state(
    processor: *mut Processor,
    new_pset: Option<NonNull<ProcessorSet>>,
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
pub(crate) unsafe fn assign(
    processor: *mut Processor,
    new_pset: *mut ProcessorSet,
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
            let mut s = spl::splsched();
            (*processor).lock.lock();

            let state = (*processor).state.load(Ordering::Acquire);
            if state == ProcessorState::OffLine
                || state == ProcessorState::Shutdown
            {
                (*processor).lock.unlock();
                spl::splx(s);
                (*new_pset).deallocate();
                return Err(Error::Failure);
            }

            if state == ProcessorState::Assign {
                assert_wait(NonNull::new(processor.cast::<c_void>()), 1);
                (*processor).lock.unlock();
                spl::splx(s);
                thread_block(None);
                continue;
            }

            if (*processor).processor_set.load(Ordering::Acquire) == new_pset {
                (*processor).lock.unlock();
                spl::splx(s);
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
                    assert_wait(NonNull::new(processor.cast::<c_void>()), 1);
                    (*processor).lock.unlock();
                    spl::splx(s);
                    thread_block(None);
                    s = spl::splsched();
                    (*processor).lock.lock();
                }
            }

            (*processor).lock.unlock();
            spl::splx(s);
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
pub(crate) unsafe fn shutdown(processor: *mut Processor) -> Result<(), Error> {
    if processor.is_null() {
        return Err(Error::InvalidArgument);
    }

    unsafe {
        let s = spl::splsched();
        (*processor).lock.lock();

        let state = (*processor).state.load(Ordering::Acquire);
        if state == ProcessorState::OffLine
            || state == ProcessorState::Shutdown
        {
            (*processor).lock.unlock();
            spl::splx(s);
            return Ok(());
        }

        request_action(processor, None);
        (*processor).lock.unlock();
        spl::splx(s);

        Ok(())
    }
}

/// Performs the shutdown or the reassignment the action queue recorded.
///
/// # Safety
///
/// `processor` must be a live processor queued on `action_queue` with a state
/// of assign or shutdown, and the caller must be the action thread.
unsafe fn doaction(processor: *mut Processor) {
    let this_thread = per_cpu::thread();
    // SAFETY: the action thread is the current thread and the processor is
    // live; the bind only stores the pairing.
    unsafe { thread_bind(this_thread, processor) };
    // SAFETY: the action thread has no wait state set, so the block returns
    // immediately when this thread is the one selected to run.
    unsafe { thread_block(None) };

    let pset = unsafe { (*processor).processor_set.load(Ordering::Acquire) };
    let mut prev_thread: *mut Thread = ptr::null_mut();
    let mut have_pset_ref = false;

    // SAFETY: `pset` is the set the processor belongs to, and this is the
    // action thread, so the set lock serializes the thread list.
    unsafe {
        (*pset).lock.lock();
        if (*pset).processor_count == 1 {
            let mut cursor = (*pset).threads.cursor_front();
            while let Some(thread) = cursor.current_ptr() {
                cursor.move_next();
                Thread::hold(thread.as_ptr());
            }
            (*pset).empty = 1;
            (*pset).ref_count = (*pset).ref_count.wrapping_add(1);
            have_pset_ref = true;

            'restart_thread: loop {
                prev_thread = ptr::null_mut();
                let mut thread = (*pset).threads.cursor_front().current_ptr();
                while let Some(current) = thread {
                    let current = current.as_ptr();
                    Thread::reference(current);
                    (*pset).lock.unlock();
                    if !prev_thread.is_null() {
                        Thread::deallocate(prev_thread);
                    }

                    Thread::freeze(current);
                    if (*current).processor_set != pset {
                        Thread::unfreeze(current);
                        Thread::deallocate(current);
                        (*pset).lock.lock();
                        continue 'restart_thread;
                    }

                    let _ = Thread::dowait(current, true);
                    prev_thread = current;
                    (*pset).lock.lock();
                    Thread::unfreeze(prev_thread);
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
            kprint!(
                "state: {:?}\n",
                (*processor).state.load(Ordering::Acquire)
            );
            kpanic!(
                "processor_doaction",
                "action_thread -- bad processor state"
            );
        }

        let s = spl::splsched();
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
unsafe fn reassign_processor(
    processor: *mut Processor,
    pset: *mut ProcessorSet,
    mut new_pset: *mut ProcessorSet,
    this_thread: *mut Thread,
    have_pset_ref: bool,
    prev_thread: *mut Thread,
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

                let s = spl::splsched();
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
                        Thread::release(thread);
                    }
                    (*new_pset).empty = 0;
                }
                (*processor).processor_set_next = ptr::null_mut();
                (*processor)
                    .state
                    .store(ProcessorState::Running, Ordering::Release);
                let _ = thread_wakeup_prim(
                    processor.cast::<c_void>(),
                    0,
                    THREAD_AWAKENED,
                );
                (*processor).lock.unlock();
                spl::splx(s);
                (*new_pset).lock.unlock();

                (*new_pset).deallocate();
                if have_pset_ref {
                    (*pset).deallocate();
                }
                if !prev_thread.is_null() {
                    Thread::deallocate(prev_thread);
                }
                thread_bind(this_thread, ptr::null_mut());
                thread_block(None);
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
unsafe fn shutdown_tail(
    pset: *mut ProcessorSet,
    processor: *mut Processor,
    new_pset: Option<NonNull<ProcessorSet>>,
    this_thread: *mut Thread,
    have_pset_ref: bool,
    prev_thread: Option<NonNull<Thread>>,
    s: c_int,
) {
    unsafe {
        (*pset).remove_processor(processor);
        (*processor).lock.unlock();
        (*pset).lock.unlock();
        spl::splx(s);

        if let Some(new_pset) = new_pset {
            (*new_pset.as_ptr()).deallocate();
        }
        if have_pset_ref {
            (*pset).deallocate();
        }
        if let Some(prev_thread) = prev_thread {
            Thread::deallocate(prev_thread.as_ptr());
        }

        thread_bind(this_thread, ptr::null_mut());
        cswitch::switch_to_shutdown_context(
            this_thread,
            Some(processor_doshutdown),
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
pub(crate) unsafe extern "C" fn action_thread() {
    // SAFETY: this is the action thread, the only drainer of the queue, and
    // `engine()` never returns.
    unsafe { engine() };
}

/// The action loop itself, separate so the continuation pointer can be a
/// plain `extern "C" fn()`.
///
/// # Safety
///
/// The thread that runs this must be the action thread, and nothing else may
/// drain `action_queue`.
unsafe fn engine() -> ! {
    loop {
        // SAFETY: the action thread is the only drainer of the queue, and the
        // action lock serializes the walk.
        unsafe {
            // The continuation must be typed `extern "C" fn()`; the
            // trampoline re-enters the loop above on the resumed stack.
            unsafe extern "C" fn resume() {
                // SAFETY: `engine()` never returns.
                unsafe { engine() }
            }

            let mut s = spl::splsched();
            action_lock().lock();

            while let Some(processor) = action_queue().pop_front() {
                let processor = ptr::from_mut(processor);
                action_lock().unlock();
                spl::splx(s);

                doaction(processor);

                s = spl::splsched();
                action_lock().lock();
            }

            assert_wait(NonNull::new(action_event()), 0);
            action_lock().unlock();
            spl::splx(s);

            thread_block(Some(resume));
        }
    }
}

/// Takes `processor` out of the system, running on its shutdown stack.
///
/// # Safety
///
/// `processor` must be the live processor whose shutdown context invoked
/// this, and the call must come from `switch_to_shutdown_context()`.
pub(crate) unsafe extern "C" fn processor_doshutdown(
    processor: *mut Processor,
) {
    // SAFETY: the processor owns the CPU it runs on, and `halt_cpu()` never
    // returns, as the C required.
    unsafe {
        let cpu = (*processor).cpu_id;

        pmap::deactivate_kernel(cpu.bits() as c_int);
        per_cpu_at(cpu).set_thread(ptr::null_mut());
        cpu_down(cpu);
        let _ =
            thread_wakeup_prim(processor.cast::<c_void>(), 0, THREAD_AWAKENED);
        halt_cpu();
    }
}

/// Reboots or halts the machine, as `options` asks.
///
/// # Safety
///
/// `host_priv` must be null or the live host privilege pointer the MIG stub
/// converted the request port into.
pub(crate) unsafe fn host_reboot(
    host_priv: *mut c_void,
    options: c_int,
) -> Result<(), Error> {
    reboot(NonNull::new(host_priv), RebootOptions(options))
}
