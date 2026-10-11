// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! Processors: the per-CPU scheduling records.

use crate::atomic_processor_state::AtomicProcessorState;
use crate::error::Error;
use crate::platform::Platform;
use crate::processor_ref::ProcessorRef;
use crate::processor_set::ProcessorSet;
use crate::smp::{CpuId, ncpus};
use crate::thread::Thread;
use crate::types::{ProcessorState, TaskCache, Thing};
use crate::{ipc_processor, processor_action};
use collections::simple_queue;
use collections::simple_queue::SimpleQueue;
use core::ffi::{c_int, c_uint, c_void};
use core::mem::size_of;
use core::ptr;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};
use mach_sched::RunQueue;
use mach_vm::simple_lock::SimpleLock;

/// A processor: one CPU's scheduling state.
///
/// The atomic fields are the ones code reads without the lock guarding their
/// writes, from another CPU or at interrupt level. `state`, `next_thread`
/// and `processor_set` publish with `Release` and read with `Acquire`, so a
/// dispatched thread is visible once its state is; the rest are `Relaxed`.
pub struct Processor<P: Platform> {
    /// `runq`: the run queue of threads bound to this processor.
    pub runq: RunQueue,
    /// `processor_queue`: the idle/assign/shutdown queue link.
    pub processor_queue: simple_queue::Link,
    /// `state`: the processor's state.
    pub state: AtomicProcessorState,
    /// `next_thread`: the thread to run if dispatched.
    pub next_thread: AtomicPtr<Thread<P>>,
    /// `idle_thread`: the idle thread, null before the processor starts.
    pub idle_thread: AtomicPtr<Thread<P>>,
    /// `quantum`: the quantum left to the running thread.
    pub quantum: AtomicI32,
    /// `first_quantum`: whether the running thread is in its first quantum.
    pub first_quantum: AtomicI32,
    /// `last_quantum`: the set quantum this processor last adjusted for.
    pub last_quantum: AtomicI32,
    /// `processor_set`: the set the processor belongs to, null while it is
    /// out of every set.
    pub processor_set: AtomicPtr<ProcessorSet<P>>,
    /// `processor_set_next`: the set a pending assign moves it to.
    pub processor_set_next: *mut ProcessorSet<P>,
    /// `processors`: the link in its set's processor list.
    pub processors: simple_queue::Link,
    /// `lock`: taken at splsched.
    pub lock: SimpleLock,
    /// `processor_self`: the port for operations.
    pub processor_self: *mut c_void,
    /// `processor_name_self`: the unprivileged name port.
    pub processor_name_self: *mut c_void,
    /// `cpu_id`: the CPU whose record this is.
    pub cpu_id: CpuId,
}

/// Returns CPU `cpu`'s processor record.
///
/// # Panics
///
/// If `cpu` is not below `MAX_NCPUS`, which only a `CpuId` built against its
/// unchecked constructors' contract can be.
#[inline]
#[must_use]
pub fn processor_at<P: Platform>(cpu: CpuId) -> ProcessorRef<P> {
    // SAFETY: the element is one of the static processor records.
    unsafe {
        ProcessorRef::<P>::from_static(
            P::task_state().processors[cpu.as_usize()].0.get(),
        )
    }
}

/// Returns the processor records of the CPUs the machine brought up,
/// `0..NCPUS`.
pub fn iter<P: Platform>() -> impl Iterator<Item = ProcessorRef<P>> {
    P::task_state()
        .processors
        .iter()
        .take(usize::from(ncpus()))
        // SAFETY: each element is one of the static processor records.
        .map(|slot| unsafe { ProcessorRef::<P>::from_static(slot.0.get()) })
}

simple_queue::adapter!(
    /// The adapter for a processor's `processor_queue` in an idle, action or
    /// shutdown queue.
    pub ProcessorQueueAdapter<P: Platform> = Processor<P> { processor_queue }
);

simple_queue::adapter!(
    /// The adapter for a processor's `processors` in its set.
    pub ProcessorPsetAdapter<P: Platform> = Processor<P> { processors }
);

/// The idle processors of a set, or the processors waiting for an action:
/// they join at either end, are taken from the front, and leave from the
/// middle of a short queue.
pub type ProcessorQueue<P> = SimpleQueue<'static, ProcessorQueueAdapter<P>>;

/// A set's member processors, at most one per CPU.
pub type ProcessorList<P> = SimpleQueue<'static, ProcessorPsetAdapter<P>>;

/// The live `default_pset` static.
#[must_use]
pub fn default_pset<P: Platform>() -> *mut ProcessorSet<P> {
    P::task_state().default_pset.0.get()
}

/// The boot CPU's processor record.
#[must_use]
pub fn boot_processor<P: Platform>() -> *mut Processor<P> {
    processor_at(CpuId::BOOT).as_ptr()
}

/// The live set of every CPU but the boot CPU, or null before [`system_init`]
/// sets it.
pub(crate) fn slave_pset<P: Platform>() -> *mut ProcessorSet<P> {
    P::task_state().slave_pset.load(Ordering::Relaxed)
}

/// Puts an unlocked simple lock in `storage`.
///
/// # Safety
///
/// `storage` must point at writable [`SimpleLock`] storage that no other
/// thread can see yet.
pub(crate) const unsafe fn init_lock(storage: *mut SimpleLock) {
    unsafe { storage.write(SimpleLock::new()) };
}

impl<P: Platform> Processor<P> {
    /// Initialize the processor of CPU `cpu`.
    ///
    /// # Safety
    ///
    /// `pr` must point at writable storage for a [`Processor`] that no other
    /// thread can see yet; `bootstrap` is the only caller.
    pub unsafe fn init(pr: *mut Self, cpu: CpuId) {
        unsafe {
            RunQueue::init(&raw mut (*pr).runq);
            (*pr)
                .state
                .store(ProcessorState::OffLine, Ordering::Release);
            (*pr).next_thread.store(ptr::null_mut(), Ordering::Release);
            (*pr).idle_thread.store(ptr::null_mut(), Ordering::Relaxed);
            (*pr).quantum.store(0, Ordering::Relaxed);
            (*pr).first_quantum.store(0, Ordering::Relaxed);
            (*pr).last_quantum.store(0, Ordering::Relaxed);
            (*pr)
                .processor_set
                .store(ptr::null_mut(), Ordering::Release);
            (*pr).processor_set_next = ptr::null_mut();
            init_lock(&raw mut (*pr).lock);
            (*pr).processor_self = ptr::null_mut();
            (*pr).processor_name_self = ptr::null_mut();
            (*pr).cpu_id = cpu;
        }
    }

    /// Starts the processor's CPU; starting a CPU at run time is not
    /// supported.
    ///
    /// # Errors
    ///
    /// Always returns [`Error::Failure`]: starting the boot processor is
    /// not supported.
    pub const fn start(&mut self) -> Result<(), Error> {
        Err(Error::Failure)
    }

    /// Takes the processor's CPU offline.
    ///
    /// # Errors
    ///
    /// Returns the error the machine shutdown routine reports when it cannot
    /// stop the processor.
    pub fn exit(&mut self) -> Result<(), Error> {
        // SAFETY: `self` is a live processor, and the machine routine takes
        // the processor lock it needs itself.
        unsafe { processor_action::shutdown(ptr::from_mut(self)) }
    }

    /// Hands `info` to the processor's machine-dependent control.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when the control data does not
    /// fit the C `natural_t` count, and otherwise the error `P::cpu_control()`
    /// reports.
    pub fn control(&mut self, info: &[c_int]) -> Result<(), Error> {
        let Ok(count) = c_uint::try_from(info.len()) else {
            return Err(Error::InvalidArgument);
        };

        // SAFETY: the slice's pointer and length agree, so `info` is valid for
        // `count` reads; the hook only prints the pointer.
        unsafe { P::cpu_control(self.cpu_id, info.as_ptr(), count) }
    }

    /// The set the processor is assigned to.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Failure`] when the processor is shut down or
    /// off-line, as the C did.
    pub fn get_assignment(&self) -> Result<*mut ProcessorSet<P>, Error> {
        let state = self.state.load(Ordering::Acquire);
        if state == ProcessorState::Shutdown
            || state == ProcessorState::OffLine
        {
            return Err(Error::Failure);
        }

        let pset = self.processor_set.load(Ordering::Acquire);
        // SAFETY: a processor that is neither off-line nor shutting down has a
        // live set assigned, which the C dereferences here; the set's lock
        // serializes the count.
        unsafe { (*pset).reference() };
        Ok(pset)
    }
}

/// Builds the default set and the processor records so the scheduler can run.
///
/// # Safety
///
/// The scheduler's init is the only caller, and it runs during the
/// single-threaded boot before any other CPU starts.
pub(crate) unsafe fn bootstrap<P: Platform>() {
    // SAFETY: single-threaded boot; this is the first initialization of the
    // default set, the per-CPU records and the global list.
    unsafe {
        ProcessorSet::<P>::init(default_pset());
        // The default set counts as populated before `cpu_up()` adds the boot
        // CPU, or `thread_create()` gives the startup thread an extra suspend
        // count that its one `thread_resume()` never drops.
        (*default_pset::<P>()).empty = 0;

        for cpu in CpuId::all() {
            Processor::<P>::init(processor_at(cpu).as_ptr(), cpu);
        }

        let mut all_psets = P::task_state().all_psets.lock();
        all_psets
            .list_pinned()
            .push_back_ptr(NonNull::new_unchecked(default_pset()));
        all_psets.count = 1;
        drop(all_psets);
        (*default_pset::<P>()).active = 1;
    }
}

/// Builds a fresh set.
///
/// # Safety
///
/// `host` must be null or the live host privilege object, and no other thread
/// may reach the new set before this returns.
pub unsafe fn create<P: Platform>(
    host: *mut c_void,
) -> Result<*mut ProcessorSet<P>, Error> {
    if host.is_null() {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: the cache was initialized by `system_init`, and the object is
    // unshared until it is linked below.
    let Some(mem) = (unsafe { P::task_cache_alloc(TaskCache::Pset) }) else {
        return Err(Error::ResourceShortage);
    };
    let pset = mem.as_ptr().cast::<ProcessorSet<P>>();

    // SAFETY: `pset` is a fresh cache object; the two references are the
    // caller's two out-arguments, as the C took them.
    unsafe {
        ProcessorSet::<P>::init(pset);
        (*pset).reference();
        (*pset).reference();
        ipc_processor::pset_init(&mut *pset);
        (*pset).active = 1;

        let mut all_psets = P::task_state().all_psets.lock();
        all_psets
            .list_pinned()
            .push_back_ptr(NonNull::new_unchecked(pset));
        all_psets.count = all_psets.count.wrapping_add(1);
        drop(all_psets);

        ipc_processor::pset_enable(&mut *pset);
    }

    Ok(pset)
}

/// The rest of the processor-set system initialization: the set cache, the
/// control port of every CPU but the boot CPU, and the slave set.
///
/// # Safety
///
/// The boot path is the only caller; it runs after `bootstrap()` and before
/// any other CPU is started.
pub unsafe fn system_init<P: Platform>() {
    // SAFETY: the set cache is the one this boot step sets up, and the
    // initializer only writes the cache's own fields.
    unsafe {
        P::task_cache_init(
            TaskCache::Pset,
            b"processor_set",
            size_of::<ProcessorSet<P>>(),
            0,
        );
    }

    let boot = boot_processor::<P>();

    for cpu in CpuId::all() {
        let processor = processor_at(cpu).as_ptr();
        let is_cpu = P::cpu_present(cpu);
        if processor != boot && is_cpu {
            // SAFETY: the processor is a live CPU's own record, and no other
            // thread can reach its two port fields yet.
            unsafe { ipc_processor::processor_init(&mut *processor) };
        }
    }

    // SAFETY: the host is the live host object and `slave_pset` the pointer
    // this call sets; the set allocator takes the cache just initialized.
    unsafe {
        let result = create(P::host());
        P::task_state()
            .slave_pset
            .store(result.unwrap_or(ptr::null_mut()), Ordering::Relaxed);
    }
}

/// Send rights for the tasks in the set.
///
/// # Safety
///
/// `pset` must be null or point at a live processor set.
pub unsafe fn tasks<P: Platform>(
    pset: *mut ProcessorSet<P>,
) -> Result<(*mut c_void, c_uint), Error> {
    let Some(pset) = NonNull::new(pset) else {
        return Err(Error::InvalidArgument);
    };
    unsafe { (*pset.as_ptr()).things(Thing::Task) }
}

/// Send rights for the threads in the set.
///
/// # Safety
///
/// `pset` must be null or point at a live processor set.
pub unsafe fn threads<P: Platform>(
    pset: *mut ProcessorSet<P>,
) -> Result<(*mut c_void, c_uint), Error> {
    let Some(pset) = NonNull::new(pset) else {
        return Err(Error::InvalidArgument);
    };
    unsafe { (*pset.as_ptr()).things(Thing::Thread) }
}
