// SPDX-License-Identifier: CMU-Mach
// Derived from kern/processor.h:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// Derived from kern/processor.c:
//   Copyright (c) 1993-1988 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Processors and processor sets.

use crate::arch::x86_64::mp_desc::cpu_control;
use crate::arch::x86_64::{per_cpu, smp};
use crate::config::MAX_NCPUS;
use crate::ipc::IpcPort;
use crate::kern::debug::kpanic;
use crate::kern::error::Error;
use crate::kern::ipc_host;
use crate::kern::ipc_tt::{convert_task_to_port, convert_thread_to_port};
use crate::kern::lock::SimpleLock;
use crate::kern::machine;
use crate::kern::policy::{POLICY_TIMESHARE, invalid_policy};
use crate::kern::sched::{
    BASEPRI_SYSTEM, NRQS, RunQueue, SCHED_SCALE, invalid_pri,
};
use crate::kern::sched_prim::min_quantum;
use crate::kern::slab::{CacheInitFlags, KmemCache, kalloc, kfree};
use crate::kern::smp::{CpuId, ncpus};
use crate::kern::task::{self as task, PsetTaskList, Task};
use crate::kern::thread::{PsetThreadList, Thread, ThreadQueue};
use crate::utils::cell::SyncCell;
use collections::simple_queue::{self, SimpleQueue};
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_long, c_uint, c_void};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU8, Ordering};

/// The state of a [`Processor`], as its `state` member stores it.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessorState {
    /// Not in the system.
    OffLine = 0,
    /// In service and running threads.
    Running = 1,
    /// In service and on its set's idle queue.
    Idle = 2,
    /// Woken with a thread to run, not yet running it.
    Dispatching = 3,
    /// Being moved to another processor set.
    Assign = 4,
    /// Being taken out of service.
    Shutdown = 5,
}

/// The `state` member of a [`Processor`]: one [`ProcessorState`] in a
/// byte, published with `Release` and read with `Acquire` as the struct's
/// comment documents.
#[repr(transparent)]
pub struct AtomicProcessorState(AtomicU8);

impl AtomicProcessorState {
    /// Returns the processor's state.
    ///
    /// # Panics
    ///
    /// If the byte is not a state this kernel stores, which only a bug can
    /// leave behind.
    pub fn load(&self, order: Ordering) -> ProcessorState {
        match self.0.load(order) {
            0 => ProcessorState::OffLine,
            1 => ProcessorState::Running,
            2 => ProcessorState::Idle,
            3 => ProcessorState::Dispatching,
            4 => ProcessorState::Assign,
            5 => ProcessorState::Shutdown,
            _ => kpanic!("processor state", "invalid processor state byte"),
        }
    }

    /// Sets the processor's state.
    pub fn store(&self, state: ProcessorState, order: Ordering) {
        self.0.store(state as u8, order);
    }
}

/// A processor: one CPU's scheduling state.
///
/// The atomic fields are the ones code reads without the lock guarding their
/// writes, from another CPU or at interrupt level. `state`, `next_thread`
/// and `processor_set` publish with `Release` and read with `Acquire`, so a
/// dispatched thread is visible once its state is; the rest are `Relaxed`.
pub struct Processor {
    /// `runq`: the run queue of threads bound to this processor.
    pub runq: RunQueue,
    /// `processor_queue`: the idle/assign/shutdown queue link.
    pub processor_queue: simple_queue::Link,
    /// `state`: the processor's state.
    pub state: AtomicProcessorState,
    /// `next_thread`: the thread to run if dispatched.
    pub next_thread: AtomicPtr<Thread>,
    /// `idle_thread`: the idle thread, null before the processor starts.
    pub idle_thread: AtomicPtr<Thread>,
    /// `quantum`: the quantum left to the running thread.
    pub quantum: AtomicI32,
    /// `first_quantum`: whether the running thread is in its first quantum.
    pub first_quantum: AtomicI32,
    /// `last_quantum`: the set quantum this processor last adjusted for.
    pub last_quantum: AtomicI32,
    /// `processor_set`: the set the processor belongs to, null while it is
    /// out of every set.
    pub processor_set: AtomicPtr<ProcessorSet>,
    /// `processor_set_next`: the set a pending assign moves it to.
    pub processor_set_next: *mut ProcessorSet,
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

/// A handle on one of the static per-CPU [`Processor`] records, as
/// [`processor_at()`] and
/// [`per_cpu::processor()`](crate::arch::x86_64::per_cpu::processor) hand it
/// out.
///
/// The record outlives every handle, so each accessor is safe: it touches one
/// atomic field, never the whole record, whose other fields change under
/// their locks. A handle kept across a block still names the processor it was
/// taken on, which may no longer be the running one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessorRef(*mut Processor);

impl ProcessorRef {
    /// Wraps `processor` in a handle.
    ///
    /// # Safety
    ///
    /// `processor` must point at one of the static per-CPU processor records.
    #[must_use]
    pub(crate) const unsafe fn from_static(processor: *mut Processor) -> Self {
        Self(processor)
    }

    /// Returns the record's address, for the routines that take the lock
    /// guarding its other fields.
    #[must_use]
    pub const fn as_ptr(self) -> *mut Processor {
        self.0
    }

    /// Returns the record, for projection onto one of its atomic fields only.
    const fn record(self) -> *const Processor {
        self.0.cast_const()
    }

    /// Returns the processor's state.
    #[must_use]
    pub fn state(self) -> ProcessorState {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).state.load(Ordering::Acquire) }
    }

    /// Sets the processor's state.
    pub fn set_state(self, state: ProcessorState) {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).state.store(state, Ordering::Release) }
    }

    /// Returns the thread a dispatch left for this processor, or null.
    #[must_use]
    pub fn next_thread(self) -> *mut Thread {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).next_thread.load(Ordering::Acquire) }
    }

    /// Sets the thread a dispatch leaves for this processor.
    pub fn set_next_thread(self, thread: *mut Thread) {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe {
            (*self.record())
                .next_thread
                .store(thread, Ordering::Release);
        }
    }

    /// Returns the processor's idle thread, or null before it starts.
    #[must_use]
    pub fn idle_thread(self) -> *mut Thread {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).idle_thread.load(Ordering::Relaxed) }
    }

    /// Records `thread` as the processor's idle thread.
    pub fn set_idle_thread(self, thread: *mut Thread) {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe {
            (*self.record())
                .idle_thread
                .store(thread, Ordering::Relaxed);
        }
    }

    /// Sets the quantum left to the running thread.
    pub fn set_quantum(self, quantum: c_int) {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).quantum.store(quantum, Ordering::Relaxed) }
    }

    /// Sets whether the running thread is still in its first quantum.
    pub fn set_first_quantum(self, first: bool) {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe {
            (*self.record())
                .first_quantum
                .store(c_int::from(first), Ordering::Relaxed);
        }
    }

    /// Returns whether the running thread is still in its first quantum.
    #[must_use]
    pub fn first_quantum(self) -> bool {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).first_quantum.load(Ordering::Relaxed) != 0 }
    }

    /// Returns the set the processor belongs to, or null while it is out of
    /// every set.
    #[must_use]
    pub fn processor_set(self) -> *mut ProcessorSet {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).processor_set.load(Ordering::Acquire) }
    }

    /// Returns the number of threads on the processor's own run queue.
    #[must_use]
    pub fn runq_count(self) -> c_int {
        // SAFETY: the record is static, and the reference covers the atomic
        // field alone.
        unsafe { (*self.record()).runq.count.load(Ordering::Relaxed) }
    }

    /// Returns whether the processor or its set has a thread to run.
    ///
    /// # Panics
    ///
    /// If this is not the running CPU's processor: the set it names stays
    /// live only for code on that CPU.
    #[must_use]
    pub fn has_runnable(self) -> bool {
        assert!(
            self == per_cpu::processor(),
            "has_runnable: not the running CPU's processor"
        );
        if self.runq_count() > 0 {
            return true;
        }
        let pset = self.processor_set();
        // SAFETY: only this CPU's action thread takes the processor out of
        // its set, never while this code runs, and a set is not freed while
        // a processor remains in it; the set is null only between the
        // shutdown's removal and the CPU's halt.
        !pset.is_null()
            && unsafe { (*pset).runq.count.load(Ordering::Relaxed) } > 0
    }

    /// Returns the CPU the record belongs to.
    #[must_use]
    pub fn cpu(self) -> CpuId {
        let offset = self.0.addr() - PROCESSOR_ARRAY.as_ptr().addr();
        let index = offset / size_of::<ProcessorSlot>();
        // SAFETY: the handle names an element of `PROCESSOR_ARRAY`, which
        // holds `MAX_NCPUS` records, so `index` is below `MAX_NCPUS` and the
        // narrowing cannot wrap.
        unsafe { CpuId::new_unchecked(index as u32) }
    }

    /// Interrupts the processor so that it runs
    /// [`check()`](crate::kern::ast::check) and acts on the
    /// dispatch, reschedule or suspension just made for it.
    pub fn ast_check(self) {
        smp::remote_ast(self.cpu());
    }
}

/// A processor record on cache lines of its own.
#[repr(align(64))]
struct ProcessorSlot(UnsafeCell<Processor>);

// SAFETY: code reaches the record's atomic fields from any CPU, and its other
// fields only under the locks that guard them.
unsafe impl Sync for ProcessorSlot {}

/// The processor records, one per CPU; each CPU's per-CPU block links to its
/// element once `per_cpu::init()` has run.
static PROCESSOR_ARRAY: [ProcessorSlot; MAX_NCPUS] =
    // SAFETY: all-zero is a valid value of every field: the atomics,
    // pointers, integers, locks and list heads.
    unsafe { core::mem::zeroed() };

/// Returns CPU `cpu`'s processor record.
///
/// # Panics
///
/// If `cpu` is not below `MAX_NCPUS`, which only a `CpuId` built against its
/// unchecked constructors' contract can be.
#[inline]
#[must_use]
pub fn processor_at(cpu: CpuId) -> ProcessorRef {
    // SAFETY: the element is one of the static processor records.
    unsafe {
        ProcessorRef::from_static(PROCESSOR_ARRAY[cpu.as_usize()].0.get())
    }
}

/// Returns the processor records of the CPUs the machine brought up,
/// `0..NCPUS`.
pub fn iter() -> impl Iterator<Item = ProcessorRef> {
    PROCESSOR_ARRAY
        .iter()
        .take(usize::from(ncpus()))
        // SAFETY: each element is one of the static processor records.
        .map(|slot| unsafe { ProcessorRef::from_static(slot.0.get()) })
}

/// A processor set: the processors, tasks and threads that schedule together.
pub struct ProcessorSet {
    /// `runq`: the run queue the set's unbound threads wait on.
    pub runq: RunQueue,
    /// `idle_queue`: the set's idle processors.
    pub idle_queue: ProcessorQueue,
    /// `idle_count`: how many processors sit on `idle_queue`.
    pub idle_count: c_int,
    /// `idle_lock`: protects the two fields above, at splsched.
    pub idle_lock: SimpleLock,
    /// `processors`: the member processors.
    pub processors: ProcessorList,
    /// `processor_count`: how many processors are members.
    pub processor_count: c_int,
    /// `empty`: set while the set's last processor is gone, so threads
    /// joining it are held until one rejoins.
    pub empty: c_int,
    /// `tasks`: the member tasks.
    pub tasks: PsetTaskList,
    /// `task_count`: how many tasks are members.
    pub task_count: c_int,
    /// `threads`: the member threads.
    pub threads: PsetThreadList,
    /// `thread_count`: how many threads are members.
    pub thread_count: c_int,
    /// `ref_count`: the live references.
    pub ref_count: c_int,
    /// `ref_lock`: protects `ref_count`.
    pub ref_lock: SimpleLock,
    /// `all_psets`: the link in the global processor-set list.
    pub all_psets: simple_queue::Link,
    /// `active`: zero once destroy has taken the set.
    pub active: c_int,
    /// `lock`: protects everything else.
    pub lock: SimpleLock,
    /// `pset_self`: the port for operations.
    pub pset_self: *mut c_void,
    /// `pset_name_self`: the port for information.
    pub pset_name_self: *mut c_void,
    /// `max_priority`: the ceiling on member threads' priority.
    pub max_priority: c_int,
    /// `policies`: the bit vector of enabled policies.
    pub policies: c_int,
    /// `set_quantum`: the quantum the set's processors run.
    pub set_quantum: c_int,
    /// `quantum_adj_index`: the round-robin slot staggering the processors'
    /// quantum adjustments.
    pub quantum_adj_index: c_int,
    /// Protects `quantum_adj_index`.
    pub quantum_adj_lock: SimpleLock,
    /// `machine_quantum`: the quantum for each processor count the set may
    /// run.
    pub machine_quantum: [c_int; MAX_NCPUS + 1],
    /// `mach_factor`: the scaled Mach factor.
    pub mach_factor: c_long,
    /// `load_average`: the scaled load average.
    pub load_average: c_long,
    /// `sched_load`: the scheduler's scaled load.
    pub sched_load: c_long,
}

simple_queue::adapter!(
    /// The adapter for a processor's `processor_queue` in an idle, action or
    /// shutdown queue.
    pub ProcessorQueueAdapter = Processor { processor_queue }
);

simple_queue::adapter!(
    /// The adapter for a processor's `processors` in its set.
    pub ProcessorPsetAdapter = Processor { processors }
);

simple_queue::adapter!(
    /// The adapter for a processor set's `all_psets` in the global list.
    pub ProcessorSetAllAdapter = ProcessorSet { all_psets }
);

/// The idle processors of a set, or the processors waiting for an action:
/// they join at either end, are taken from the front, and leave from the
/// middle of a short queue.
pub type ProcessorQueue = SimpleQueue<'static, ProcessorQueueAdapter>;

/// A set's member processors, at most one per CPU.
pub type ProcessorList = SimpleQueue<'static, ProcessorPsetAdapter>;

/// Every processor set.
pub type PsetList = SimpleQueue<'static, ProcessorSetAllAdapter>;

/// The set every task starts in.
static mut DEFAULT_PSET: ProcessorSet = ProcessorSet::zeroed();

/// The chain of every processor set.
static ALL_PSETS: SyncCell<PsetList> =
    SyncCell(UnsafeCell::new(PsetList::new()));

/// How many sets [`ALL_PSETS`] holds, under [`ALL_PSETS_LOCK`].
static ALL_PSETS_COUNT: SyncCell<u32> = SyncCell(UnsafeCell::new(0));

/// Serializes the set list.
static ALL_PSETS_LOCK: SimpleLock = SimpleLock::new();

/// The slab cache of [`ProcessorSet`] records.
static mut PSET_CACHE: KmemCache = KmemCache::zeroed();

/// The set of every CPU but the boot CPU.
static SLAVE_PSET: AtomicPtr<ProcessorSet> = AtomicPtr::new(ptr::null_mut());

/// The live `default_pset` static.
pub(crate) fn default_pset() -> *mut ProcessorSet {
    ptr::addr_of_mut!(DEFAULT_PSET)
}

/// The live `all_psets` queue head.
///
/// # Safety
///
/// The caller must hold `all_psets_lock` for as long as it uses the list.
pub(crate) unsafe fn all_psets() -> Pin<&'static mut PsetList> {
    // SAFETY: the static never moves, and the lock the caller holds keeps
    // anything else from reaching the list.
    unsafe { Pin::new_unchecked(&mut *ALL_PSETS.0.get()) }
}

/// The processor set after `pset` in the global list, or the first for
/// `None`.
///
/// # Safety
///
/// The caller must hold `all_psets_lock`, and `pset` must be `None` or on the
/// list.
pub(crate) unsafe fn next_pset(
    pset: Option<*mut ProcessorSet>,
) -> Option<NonNull<ProcessorSet>> {
    // SAFETY: the lock is held.
    let mut head = unsafe { all_psets() };
    let Some(pset) = pset else {
        return head.cursor_front().current_ptr();
    };
    // SAFETY: `pset` is on the list.
    let mut cursor = unsafe {
        head.as_mut()
            .cursor_mut_from_ptr(NonNull::new_unchecked(pset))
    };
    cursor.move_next();
    cursor.current_ptr()
}

/// The live `all_psets_count` counter, under `all_psets_lock`.
pub(crate) fn all_psets_count() -> *mut u32 {
    ALL_PSETS_COUNT.0.get()
}

/// The live `all_psets_lock`.
pub(crate) fn all_psets_lock() -> &'static SimpleLock {
    &ALL_PSETS_LOCK
}

/// The boot CPU's processor record.
pub(crate) fn boot_processor() -> *mut Processor {
    processor_at(CpuId::BOOT).as_ptr()
}

/// The live set of every CPU but the boot CPU, or null before [`system_init`]
/// sets it.
pub(crate) fn slave_pset() -> *mut ProcessorSet {
    SLAVE_PSET.load(Ordering::Relaxed)
}

/// The `pset_cache` the boot initialized.
fn pset_cache() -> *mut KmemCache {
    ptr::addr_of_mut!(PSET_CACHE)
}

/// Puts an unlocked simple lock in `storage`.
///
/// # Safety
///
/// `storage` must point at writable [`SimpleLock`] storage that no other
/// thread can see yet.
const unsafe fn init_lock(storage: *mut SimpleLock) {
    unsafe { storage.write(SimpleLock::new()) };
}

/// Self-links the `NRQS` run-queue heads of `runq`.
///
/// # Safety
///
/// `runq` must point at writable storage for a [`RunQueue`] that no other
/// thread can see yet.
unsafe fn init_runq(runq: *mut RunQueue) {
    unsafe {
        init_lock(&raw mut (*runq).lock);
        (*runq).low = 0;
        (*runq).count.store(0, Ordering::Relaxed);
        (*runq).runq = [const { ThreadQueue::new() }; NRQS];
    }
}

impl Processor {
    /// Initialize the processor of CPU `cpu`.
    ///
    /// # Safety
    ///
    /// `pr` must point at writable storage for a [`Processor`] that no other
    /// thread can see yet; [`bootstrap`] is the only caller.
    pub unsafe fn init(pr: *mut Self, cpu: CpuId) {
        unsafe {
            init_runq(&raw mut (*pr).runq);
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
        unsafe { machine::shutdown(ptr::from_mut(self)) }
    }

    /// Hands `info` to the processor's machine-dependent control.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when the control data does not
    /// fit the C `natural_t` count, and otherwise the error `cpu_control()`
    /// reports.
    pub fn control(&mut self, info: &[c_int]) -> Result<(), Error> {
        let Ok(count) = c_uint::try_from(info.len()) else {
            return Err(Error::InvalidArgument);
        };

        // SAFETY: the slice's pointer and length agree, so `info` is valid for
        // `count` reads; the hook only prints the pointer.
        unsafe { cpu_control(self.cpu_id, info.as_ptr(), count) }
            .map_err(Error::from)
    }

    /// The set the processor is assigned to.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Failure`] when the processor is shut down or
    /// off-line, as the C did.
    pub fn get_assignment(&self) -> Result<*mut ProcessorSet, Error> {
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

impl ProcessorSet {
    /// The member threads, pinned.
    ///
    /// # Safety
    ///
    /// The set is a static or a slab object and never moves, and the caller
    /// must hold its lock for as long as it uses the list.
    pub(crate) const unsafe fn threads_pinned(
        &mut self,
    ) -> Pin<&mut PsetThreadList> {
        // SAFETY: the set never moves, and the lock the caller holds keeps
        // anything else from reaching the list.
        unsafe { Pin::new_unchecked(&mut self.threads) }
    }

    /// The member tasks, pinned.
    ///
    /// # Safety
    ///
    /// Same contract as [`ProcessorSet::threads_pinned()`].
    pub(crate) const unsafe fn tasks_pinned(
        &mut self,
    ) -> Pin<&mut PsetTaskList> {
        // SAFETY: as for the threads.
        unsafe { Pin::new_unchecked(&mut self.tasks) }
    }

    /// The member processors, pinned.
    ///
    /// # Safety
    ///
    /// Same contract as [`ProcessorSet::threads_pinned()`].
    pub(crate) const unsafe fn processors_pinned(
        &mut self,
    ) -> Pin<&mut ProcessorList> {
        // SAFETY: as for the threads.
        unsafe { Pin::new_unchecked(&mut self.processors) }
    }

    /// The idle processors, pinned.
    ///
    /// # Safety
    ///
    /// The set is a static or a slab object and never moves, and the caller
    /// must hold `idle_lock` for as long as it uses the queue.
    pub(crate) const unsafe fn idle_queue_pinned(
        &mut self,
    ) -> Pin<&mut ProcessorQueue> {
        // SAFETY: the set never moves, and the lock the caller holds keeps
        // anything else from reaching the queue.
        unsafe { Pin::new_unchecked(&mut self.idle_queue) }
    }

    /// The all-zero image a C `static struct processor_set` began with.
    const fn zeroed() -> Self {
        Self {
            runq: RunQueue {
                runq: [const { ThreadQueue::new() }; NRQS],
                lock: SimpleLock::new(),
                low: 0,
                count: AtomicI32::new(0),
            },
            idle_queue: ProcessorQueue::new(),
            idle_count: 0,
            idle_lock: SimpleLock::new(),
            processors: ProcessorList::new(),
            processor_count: 0,
            empty: 0,
            tasks: PsetTaskList::new(),
            task_count: 0,
            threads: PsetThreadList::new(),
            thread_count: 0,
            ref_count: 0,
            ref_lock: SimpleLock::new(),
            all_psets: simple_queue::Link::new(),
            active: 0,
            lock: SimpleLock::new(),
            pset_self: ptr::null_mut(),
            pset_name_self: ptr::null_mut(),
            max_priority: 0,
            policies: 0,
            set_quantum: 0,
            quantum_adj_index: 0,
            quantum_adj_lock: SimpleLock::new(),
            machine_quantum: [0; MAX_NCPUS + 1],
            mach_factor: 0,
            load_average: 0,
            sched_load: 0,
        }
    }

    /// Initialize the processor set.
    ///
    /// # Safety
    ///
    /// `pset` must point at writable storage for a full [`ProcessorSet`] that
    /// no other thread can see yet; [`bootstrap`] and [`create`] are the
    /// callers.
    pub unsafe fn init(pset: *mut Self) {
        unsafe {
            init_runq(&raw mut (*pset).runq);
            (*pset).idle_queue = ProcessorQueue::new();
            (*pset).idle_count = 0;
            init_lock(&raw mut (*pset).idle_lock);
            (*pset).processors = ProcessorList::new();
            (*pset).processor_count = 0;
            (*pset).empty = 1;
            (*pset).tasks = PsetTaskList::new();
            (*pset).task_count = 0;
            (*pset).threads = PsetThreadList::new();
            (*pset).thread_count = 0;
            (*pset).ref_count = 1;
            init_lock(&raw mut (*pset).ref_lock);
            (*pset).active = 0;
            init_lock(&raw mut (*pset).lock);
            (*pset).pset_self = ptr::null_mut();
            (*pset).pset_name_self = ptr::null_mut();
            (*pset).max_priority = BASEPRI_SYSTEM;
            (*pset).policies = POLICY_TIMESHARE;
            // The scheduler set the quantum before `bootstrap` calls this
            // init.
            let quantum_min = min_quantum();
            (*pset).set_quantum = quantum_min;
            (*pset).quantum_adj_index = 0;
            init_lock(&raw mut (*pset).quantum_adj_lock);
            (*pset).machine_quantum.fill(quantum_min);
            (*pset).mach_factor = 0;
            (*pset).load_average = 0;
            (*pset).sched_load = c_long::from(SCHED_SCALE);
        }
    }

    /// Takes a reference on the set.
    pub fn reference(&mut self) {
        self.ref_lock.lock();
        self.ref_count = self.ref_count.wrapping_add(1);
        self.ref_lock.unlock();
    }

    /// Drops a reference on the set, freeing it on the last one.
    pub fn deallocate(&mut self) {
        self.ref_lock.lock();
        self.ref_count = self.ref_count.wrapping_sub(1);
        if self.ref_count > 0 {
            self.ref_lock.unlock();
            return;
        }

        self.ref_count = 1;
        self.ref_lock.unlock();

        // SAFETY: the lock guards the list, and the C order is
        // `all_psets_lock` before the set's `ref_lock`.
        let all_psets_lock = all_psets_lock();
        all_psets_lock.lock();
        self.ref_lock.lock();
        self.ref_count = self.ref_count.wrapping_sub(1);
        if self.ref_count > 0 {
            self.ref_lock.unlock();
            all_psets_lock.unlock();
            return;
        }

        let is_default =
            ptr::eq(ptr::from_ref(self), default_pset().cast_const());
        if is_default
            || self.thread_count > 0
            || self.task_count > 0
            || self.processor_count > 0
        {
            kpanic!(
                "pset_deallocate",
                "pset_deallocate: destroy default or active pset"
            )
        }

        // SAFETY: the set is linked into `all_psets` and both locks are held;
        // the removal keeps the list consistent.
        unsafe {
            let _ = all_psets().remove_ptr(ptr::from_ref(self));
            let count = all_psets_count();
            *count = (*count).wrapping_sub(1);
        }

        self.ref_lock.unlock();
        all_psets_lock.unlock();

        // SAFETY: the set came from `pset_cache` and nothing references it any
        // more; `.addr()` is the address the allocator handed out.
        unsafe { (*pset_cache()).free(NonNull::from_mut(self).cast::<u8>()) };
    }

    /// Adds `thread` to the set.
    ///
    /// # Safety
    ///
    /// The caller must hold the set's lock and the thread's lock, as the C
    /// requires, and `thread` must be live and not linked into a processor
    /// set's thread list.
    pub unsafe fn add_thread(&mut self, thread: *mut Thread) {
        unsafe {
            self.threads_pinned()
                .push_back_ptr(NonNull::new_unchecked(thread));
            (*thread).processor_set = ptr::from_mut(self);
            self.thread_count = self.thread_count.wrapping_add(1);
        }
    }

    /// Removes `thread` from the set.
    ///
    /// # Safety
    ///
    /// The caller must hold the set's lock and the thread's lock, as the C
    /// requires, and `thread` must be live and linked into this set's thread
    /// list.
    pub unsafe fn remove_thread(&mut self, thread: *mut Thread) {
        unsafe {
            self.threads_pinned()
                .remove_ptr(NonNull::new_unchecked(thread));
            (*thread).processor_set = ptr::null_mut();
            self.thread_count = self.thread_count.wrapping_sub(1);
        }
    }

    /// Adds `task` to the set.
    ///
    /// # Safety
    ///
    /// The caller must hold the set's lock and the task's lock, as the C
    /// requires, and `task` must be live and not linked into a processor set.
    pub unsafe fn add_task(&mut self, task: *mut Task) {
        unsafe {
            self.tasks_pinned()
                .push_back_ptr(NonNull::new_unchecked(task));
            (*task).processor_set = ptr::from_mut(self);
            self.task_count = self.task_count.wrapping_add(1);
        }
    }

    /// Removes `task` from the set.
    ///
    /// # Safety
    ///
    /// The caller must hold the set's lock and the task's lock, as the C
    /// requires; `task` must be live, and the routine is a no-op unless it is
    /// linked into this set.
    pub unsafe fn remove_task(&mut self, task: *mut Task) {
        if ptr::from_mut(self) != unsafe { (*task).processor_set } {
            return;
        }

        unsafe {
            self.tasks_pinned().remove_ptr(NonNull::new_unchecked(task));
            (*task).processor_set = ptr::null_mut();
            self.task_count = self.task_count.wrapping_sub(1);
        }
    }

    /// Sets the set's quantum for each possible number of runnable threads,
    /// from its processor count.
    pub fn quantum_set(&mut self) {
        let ncpus = self.processor_count;
        let runq_count = self.runq.count.load(Ordering::Relaxed);

        // The quantum the scheduler stored before `bootstrap` built this
        // set.
        let quantum_min = min_quantum();

        for i in 1..=ncpus {
            let quantum =
                quantum_min.wrapping_mul(ncpus).wrapping_add(i / 2) / i;
            // The C indexed with an `int`; the cast cannot wrap because
            // `1 <= i <= ncpus`, and a set holds at most `MAX_NCPUS`
            // processors.
            let Some(slot) = self.machine_quantum.get_mut(i as usize) else {
                break;
            };
            *slot = quantum;
        }

        // The tail has at least two entries, so index one exists; the
        // doubled value wraps as the C's does.
        if let [first, second, ..] = &mut self.machine_quantum[..] {
            *first = second.wrapping_mul(2);
        }

        let i = core::cmp::min(runq_count, ncpus);
        // The C indexed with an `int`; the cast cannot wrap because
        // `0 <= i <= ncpus <= MAX_NCPUS`.
        if let Some(slot) = self.machine_quantum.get(i as usize) {
            self.set_quantum = *slot;
        }
    }

    /// Adds `processor` to the set.
    ///
    /// # Safety
    ///
    /// The caller must hold the set's lock and the processor's lock, as the C
    /// requires, and `processor` must be live and not linked into any set's
    /// processor list.
    pub unsafe fn add_processor(&mut self, processor: *mut Processor) {
        unsafe {
            self.processors_pinned()
                .push_back_ptr(NonNull::new_unchecked(processor));
            (*processor)
                .processor_set
                .store(ptr::from_mut(self), Ordering::Release);
            self.processor_count = self.processor_count.wrapping_add(1);
            self.empty = 0;
        }
        self.quantum_set();
    }

    /// Removes `processor` from the set.
    ///
    /// # Safety
    ///
    /// The caller must hold the set's lock and the processor's lock, as the C
    /// requires, and `processor` must be live and linked into this set's
    /// processor list.
    ///
    /// # Panics
    ///
    /// Panics through [`kpanic!`] when `processor` does not belong to this
    /// set, as the C `panic()` did.
    pub unsafe fn remove_processor(&mut self, processor: *mut Processor) {
        unsafe {
            if ptr::from_mut(self)
                != (*processor).processor_set.load(Ordering::Acquire)
            {
                kpanic!(
                    "pset_remove_processor",
                    "pset_remove_processor: wrong pset"
                )
            }
            let _ =
                self.processors_pinned().remove_ptr(processor.cast_const());
            (*processor)
                .processor_set
                .store(ptr::null_mut(), Ordering::Release);
            self.processor_count = self.processor_count.wrapping_sub(1);
        }
        self.quantum_set();
    }

    /// Enables `policy` for the set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when `policy` is not one of the
    /// policies the scheduler supports.
    pub fn policy_enable(&mut self, policy: c_int) -> Result<(), Error> {
        if invalid_policy(policy) {
            return Err(Error::InvalidArgument);
        }

        self.lock.lock();
        self.policies |= policy;
        self.lock.unlock();

        Ok(())
    }

    /// Disables `policy` for the set, moving its threads that use it back to
    /// timesharing when `change_threads` is set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when `policy` is timesharing or
    /// not one of the policies the scheduler supports.
    pub fn policy_disable(
        &mut self,
        policy: c_int,
        change_threads: c_int,
    ) -> Result<(), Error> {
        if policy == POLICY_TIMESHARE || invalid_policy(policy) {
            return Err(Error::InvalidArgument);
        }

        self.lock.lock();

        if (self.policies & policy) != 0 {
            self.policies &= !policy;

            if change_threads != 0 {
                // SAFETY: the set lock is held, so every link is a live thread
                // whose chain stays put during the walk.
                let mut cursor = self.threads.cursor_front();
                while let Some(thread) = cursor.current_ptr() {
                    cursor.move_next();
                    let thread = thread.as_ptr();
                    // SAFETY: `thread` is a live member of the list.
                    if unsafe { (*thread).policy == policy } {
                        // SAFETY: the Rust `Thread::policy()` takes the thread
                        // lock itself, and timesharing is a policy this set
                        // can switch a thread to.
                        unsafe {
                            let _ =
                                Thread::policy(thread, POLICY_TIMESHARE, 0);
                        }
                    }
                }
            }
        }

        self.lock.unlock();

        Ok(())
    }

    /// Sets the set's maximum priority, lowering its threads to it when
    /// `change_threads` is set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when `max_priority` is outside
    /// the range the scheduler supports.
    pub fn max_priority(
        &mut self,
        max_priority: c_int,
        change_threads: c_int,
    ) -> Result<(), Error> {
        if invalid_pri(max_priority) {
            return Err(Error::InvalidArgument);
        }

        self.lock.lock();
        self.max_priority = max_priority;

        if change_threads != 0 {
            let pset = ptr::from_mut(self);
            // SAFETY: the set lock is held, so every link is a live thread
            // whose chain stays put during the walk; `pset` is this set, which
            // `thread_max_priority()` only compares.
            unsafe {
                let mut cursor = (*pset).threads.cursor_front();
                while let Some(thread) = cursor.current_ptr() {
                    cursor.move_next();
                    let thread = thread.as_ptr();
                    // SAFETY: `thread` is a live member of the list.
                    if (*thread).max_priority < max_priority {
                        // SAFETY: the Rust `Thread::max_priority()` takes the
                        // thread lock itself.
                        let _ =
                            Thread::max_priority(thread, pset, max_priority);
                    }
                }
            }
        }

        self.lock.unlock();

        Ok(())
    }
}

impl Thread {
    /// Moves `thread` from `old_pset` to `new_pset`.
    ///
    /// # Safety
    ///
    /// The caller must hold the locks of both sets and of the thread, as the C
    /// requires, and `thread` must be live and linked into `old_pset`'s thread
    /// list.
    pub unsafe fn change_psets(
        thread: *mut Self,
        old_pset: *mut ProcessorSet,
        new_pset: *mut ProcessorSet,
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

/// Which member list `ProcessorSet::things()` copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Thing {
    Task,
    Thread,
}

impl ProcessorSet {
    /// Reassigns everything in the set and releases it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for the default set and
    /// [`Error::Failure`] when the set is not active.
    ///
    /// # Safety
    ///
    /// `self` must be a live set the caller holds a reference to, and the set
    /// must not be the default one.
    pub unsafe fn destroy(&mut self) -> Result<(), Error> {
        let default = default_pset();
        if ptr::eq(self, default) {
            return Err(Error::InvalidArgument);
        }

        self.lock.lock();
        if self.active == 0 {
            self.lock.unlock();
            return Err(Error::Failure);
        }

        self.active = 0;
        ipc_host::pset_disable(self);

        // SAFETY: the set lock is held, so every link is a live task whose
        // chain stays put during the walk; each reference taken here moves to
        // `task_assign()`.
        unsafe {
            while let Some(task) = self.tasks.cursor_front().current_ptr() {
                let task = task.as_ptr();
                task::reference(task);
                self.lock.unlock();
                let _ = task::assign(task, default, false);
                task::deallocate(task);
                self.lock.lock();
            }
        }

        unsafe {
            while let Some(thread) = self.threads.cursor_front().current_ptr()
            {
                let thread = thread.as_ptr();
                Thread::reference(thread);
                self.lock.unlock();
                let _ = Thread::assign(thread, default);
                Thread::deallocate(thread);
                self.lock.lock();
            }
        }

        unsafe {
            while let Some(processor) =
                self.processors.cursor_front().current_ptr()
            {
                let processor = processor.as_ptr();
                self.lock.unlock();
                let _ = machine::assign(processor, default, true);
                self.lock.lock();
            }
        }

        self.lock.unlock();

        ipc_host::pset_terminate(self);
        self.deallocate();
        Ok(())
    }

    /// The task or thread ports of every member of the set, in the array
    /// `kalloc()` built.
    ///
    /// # Safety
    ///
    /// `self` must be a live set.
    unsafe fn things(
        &mut self,
        kind: Thing,
    ) -> Result<(*mut c_void, c_uint), Error> {
        let mut size: usize = 0;
        let mut addr: *mut u8 = ptr::null_mut();

        let (actual, size_needed) = loop {
            self.lock.lock();
            if self.active == 0 {
                self.lock.unlock();
                return Err(Error::Failure);
            }

            let count = match kind {
                Thing::Task => self.task_count,
                Thing::Thread => self.thread_count,
            };
            // A live list's count is never negative.
            let Ok(actual) = usize::try_from(count) else {
                self.lock.unlock();
                return Err(Error::Failure);
            };

            let needed = actual.wrapping_mul(size_of::<*mut c_void>());
            if needed <= size {
                break (actual, needed);
            }

            self.lock.unlock();

            if let Some(old) = NonNull::new(addr) {
                // SAFETY: `old` came from `kalloc(size)`.
                unsafe { kfree(old, size) };
            }
            size = needed;

            let Some(buffer) = kalloc(size) else {
                return Err(Error::ResourceShortage);
            };
            addr = buffer.as_ptr();
        };

        // SAFETY: the set is locked and active, so every one of the `actual`
        // links is a live task or thread whose chain stays put during the
        // walk; the references taken here are the ones the port conversion
        // below consumes.
        unsafe {
            match kind {
                Thing::Task => {
                    let mut cursor = self.tasks.cursor_front();
                    for i in 0..actual {
                        let Some(task) = cursor.current_ptr() else {
                            break;
                        };
                        let task = task.as_ptr();
                        task::reference(task);
                        addr.cast::<*mut Task>().add(i).write(task);
                        cursor.move_next();
                    }
                }
                Thing::Thread => {
                    let mut cursor = self.threads.cursor_front();
                    for i in 0..actual {
                        let Some(thread) = cursor.current_ptr() else {
                            break;
                        };
                        let thread = thread.as_ptr();
                        Thread::reference(thread);
                        addr.cast::<*mut Thread>().add(i).write(thread);
                        cursor.move_next();
                    }
                }
            }
            self.lock.unlock();
        }

        if actual == 0 {
            if let Some(old) = NonNull::new(addr) {
                // SAFETY: `old` came from `kalloc(size)`.
                unsafe { kfree(old, size) };
            }
            return Ok((ptr::null_mut(), 0));
        }

        // SAFETY: `addr` holds `actual` live task or thread references, and
        // the conversion below consumes them into the slots' ports.
        unsafe {
            Self::shrink_and_convert(addr, size, size_needed, actual, kind)
        }
    }

    /// Shrink the slot array to `size_needed` bytes and convert every
    /// reference it holds into the port that replaces it.
    ///
    /// # Safety
    ///
    /// `addr` must point at `actual` live task or thread references, `size`
    /// must be the `kalloc()` size it came from, and `size_needed` must equal
    /// `actual * size_of::<*mut c_void>()` and not exceed `size`.
    unsafe fn shrink_and_convert(
        addr: *mut u8,
        size: usize,
        size_needed: usize,
        actual: usize,
        kind: Thing,
    ) -> Result<(*mut c_void, c_uint), Error> {
        let mut addr = addr;
        if size_needed < size {
            let Some(buffer) = kalloc(size_needed) else {
                // SAFETY: every slot holds a reference the port conversion
                // below never reached, and `addr` came from `kalloc(size)`.
                unsafe {
                    Self::release_slots(addr, actual, kind);
                    kfree(NonNull::new_unchecked(addr), size);
                }
                return Err(Error::ResourceShortage);
            };
            // SAFETY: both buffers are live, and `size_needed` is the byte
            // count of the references `addr` holds.
            unsafe {
                ptr::copy_nonoverlapping(addr, buffer.as_ptr(), size_needed);
                kfree(NonNull::new_unchecked(addr), size);
            }
            addr = buffer.as_ptr();
        }

        // SAFETY: every slot holds a task or thread reference, and the
        // conversion consumes it into the port the slot then holds.
        unsafe {
            match kind {
                Thing::Task => {
                    let ports = addr.cast::<*mut Task>();
                    for i in 0..actual {
                        let task = ports.add(i).read();
                        ports.add(i).write(
                            convert_task_to_port(task)
                                .map_or(ptr::null_mut(), IpcPort::as_ptr)
                                .cast::<Task>(),
                        );
                    }
                }
                Thing::Thread => {
                    let ports = addr.cast::<*mut Thread>();
                    for i in 0..actual {
                        let thread = ports.add(i).read();
                        ports.add(i).write(
                            convert_thread_to_port(thread)
                                .map_or(ptr::null_mut(), IpcPort::as_ptr)
                                .cast::<Thread>(),
                        );
                    }
                }
            }
        }

        // `actual` came from a non-negative `c_int`, so the C's `unsigned int`
        // assignment cannot truncate it.
        Ok((addr.cast::<c_void>(), actual as c_uint))
    }

    /// Release the references in the first `actual` slots of `addr`.
    ///
    /// # Safety
    ///
    /// `addr` must point at `actual` live task or thread references.
    unsafe fn release_slots(addr: *mut u8, actual: usize, kind: Thing) {
        unsafe {
            match kind {
                Thing::Task => {
                    for i in 0..actual {
                        task::deallocate(
                            addr.cast::<*mut Task>().add(i).read(),
                        );
                    }
                }
                Thing::Thread => {
                    for i in 0..actual {
                        Thread::deallocate(
                            addr.cast::<*mut Thread>().add(i).read(),
                        );
                    }
                }
            }
        }
    }
}

/// Builds the default set and the processor records so the scheduler can run.
///
/// # Safety
///
/// The scheduler's init is the only caller, and it runs during the
/// single-threaded boot before any other CPU starts.
pub(crate) unsafe fn bootstrap() {
    // SAFETY: single-threaded boot; this is the first initialization of the
    // default set, the per-CPU records and the global list.
    unsafe {
        ProcessorSet::init(default_pset());
        // The default set counts as populated before `cpu_up()` adds the boot
        // CPU, or `thread_create()` gives the startup thread an extra suspend
        // count that its one `thread_resume()` never drops.
        (*default_pset()).empty = 0;

        for cpu in CpuId::all() {
            Processor::init(processor_at(cpu).as_ptr(), cpu);
        }

        all_psets_lock().init();
        all_psets().push_back_ptr(NonNull::new_unchecked(default_pset()));
        *all_psets_count() = 1;
        (*default_pset()).active = 1;
    }
}

/// Builds a fresh set.
///
/// # Safety
///
/// `host` must be null or the live host privilege object, and no other thread
/// may reach the new set before this returns.
pub(crate) unsafe fn create(
    host: *mut c_void,
) -> Result<*mut ProcessorSet, Error> {
    if host.is_null() {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: the cache was initialized by `system_init`, and the object is
    // unshared until it is linked below.
    let Some(mem) = (unsafe { (*pset_cache()).alloc() }) else {
        return Err(Error::ResourceShortage);
    };
    let pset = mem.as_ptr().cast::<ProcessorSet>();

    // SAFETY: `pset` is a fresh cache object; the two references are the
    // caller's two out-arguments, as the C took them.
    unsafe {
        ProcessorSet::init(pset);
        (*pset).reference();
        (*pset).reference();
        ipc_host::pset_init(&mut *pset);
        (*pset).active = 1;

        let lock = all_psets_lock();
        lock.lock();
        all_psets().push_back_ptr(NonNull::new_unchecked(pset));
        let count = all_psets_count();
        *count = (*count).wrapping_add(1);
        lock.unlock();

        ipc_host::pset_enable(&mut *pset);
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
pub(crate) unsafe fn system_init() {
    // SAFETY: `pset_cache` is the cache storage this boot step owns, and the
    // initializer only writes the cache's own fields.
    unsafe {
        (*pset_cache()).init(
            b"processor_set",
            size_of::<ProcessorSet>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
    }

    let boot = boot_processor();

    for cpu in CpuId::all() {
        let processor = processor_at(cpu).as_ptr();
        // SAFETY: the slot is `cpu`'s own `machine_slot`, which the probe
        // filled and the machine never frees; `is_cpu` is a plain integer.
        let is_cpu = unsafe { (*machine::slot(cpu)).is_cpu } != 0;
        if processor != boot && is_cpu {
            // SAFETY: the processor is a live CPU's own record, and no other
            // thread can reach its two port fields yet.
            unsafe { ipc_host::processor_init(&mut *processor) };
        }
    }

    // SAFETY: `realhost` is the live host object and `slave_pset` the pointer
    // this call sets; the set allocator takes the cache just initialized.
    unsafe {
        let result = create(crate::kern::host::realhost().cast::<c_void>());
        SLAVE_PSET.store(result.unwrap_or(ptr::null_mut()), Ordering::Relaxed);
    }
}

/// Send rights for the tasks in the set.
///
/// # Safety
///
/// `pset` must be null or point at a live processor set.
pub(crate) unsafe fn tasks(
    pset: *mut ProcessorSet,
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
pub(crate) unsafe fn threads(
    pset: *mut ProcessorSet,
) -> Result<(*mut c_void, c_uint), Error> {
    let Some(pset) = NonNull::new(pset) else {
        return Err(Error::InvalidArgument);
    };
    unsafe { (*pset.as_ptr()).things(Thing::Thread) }
}
