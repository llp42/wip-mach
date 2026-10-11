// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! Processor sets: the scheduling partitions that group processors, and
//! the tasks and threads assigned to them.

use crate::error::Error;
use crate::ipc_tt::{convert_task_to_port, convert_thread_to_port};
use crate::platform::Platform;
use crate::processor::{Processor, ProcessorList, ProcessorQueue, init_lock};
use crate::smp::MAX_NCPUS;
use crate::task::{PsetTaskList, Task};
use crate::thread::{PsetThreadList, Thread, default_pset};
use crate::types::{TaskCache, Thing};
use crate::{ipc_processor, processor_action, task};
use collections::simple_queue;
use collections::simple_queue::SimpleQueue;
use core::ffi::{c_int, c_long, c_uint, c_void};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
use mach_ipc::IpcPort;
use mach_sched::RunQueue;
use mach_sched::policy::{POLICY_TIMESHARE, invalid_policy};
use mach_sched::sched::min_quantum;
use mach_sched::sched::{BASEPRI_SYSTEM, SCHED_SCALE, invalid_pri};
use mach_vm::simple_lock::SimpleLock;

/// A processor set: the processors, tasks and threads that schedule together.
pub struct ProcessorSet<P: Platform> {
    /// `runq`: the run queue the set's unbound threads wait on.
    pub runq: RunQueue,
    /// `idle_queue`: the set's idle processors.
    pub idle_queue: ProcessorQueue<P>,
    /// `idle_count`: how many processors sit on `idle_queue`.
    pub idle_count: c_int,
    /// `idle_lock`: protects the two fields above, at splsched.
    pub idle_lock: SimpleLock,
    /// `processors`: the member processors.
    pub processors: ProcessorList<P>,
    /// `processor_count`: how many processors are members.
    pub processor_count: c_int,
    /// `empty`: set while the set's last processor is gone, so threads
    /// joining it are held until one rejoins.
    pub empty: c_int,
    /// `tasks`: the member tasks.
    pub tasks: PsetTaskList<P>,
    /// `task_count`: how many tasks are members.
    pub task_count: c_int,
    /// `threads`: the member threads.
    pub threads: PsetThreadList<P>,
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
    /// The adapter for a processor set's `all_psets` in the global list.
    pub ProcessorSetAllAdapter<P: Platform> = ProcessorSet<P> { all_psets }
);

/// Every processor set.
pub type PsetList<P> = SimpleQueue<'static, ProcessorSetAllAdapter<P>>;

impl<P: Platform> ProcessorSet<P> {
    /// The member threads, pinned.
    ///
    /// # Safety
    ///
    /// The set is a static or a slab object and never moves, and the caller
    /// must hold its lock for as long as it uses the list.
    pub(crate) const unsafe fn threads_pinned(
        &mut self,
    ) -> Pin<&mut PsetThreadList<P>> {
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
    ) -> Pin<&mut PsetTaskList<P>> {
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
    ) -> Pin<&mut ProcessorList<P>> {
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
    ) -> Pin<&mut ProcessorQueue<P>> {
        // SAFETY: the set never moves, and the lock the caller holds keeps
        // anything else from reaching the queue.
        unsafe { Pin::new_unchecked(&mut self.idle_queue) }
    }

    /// The all-zero image a C `static struct processor_set` began with.
    pub(crate) const fn zeroed() -> Self {
        Self {
            runq: RunQueue::new(),
            idle_queue: ProcessorQueue::<P>::new(),
            idle_count: 0,
            idle_lock: SimpleLock::new(),
            processors: ProcessorList::<P>::new(),
            processor_count: 0,
            empty: 0,
            tasks: PsetTaskList::<P>::new(),
            task_count: 0,
            threads: PsetThreadList::<P>::new(),
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
    /// no other thread can see yet; `bootstrap` and
    /// [`create`](crate::processor::create) are the callers.
    pub unsafe fn init(pset: *mut Self) {
        unsafe {
            RunQueue::init(&raw mut (*pset).runq);
            (*pset).idle_queue = ProcessorQueue::<P>::new();
            (*pset).idle_count = 0;
            init_lock(&raw mut (*pset).idle_lock);
            (*pset).processors = ProcessorList::<P>::new();
            (*pset).processor_count = 0;
            (*pset).empty = 1;
            (*pset).tasks = PsetTaskList::<P>::new();
            (*pset).task_count = 0;
            (*pset).threads = PsetThreadList::<P>::new();
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
    ///
    /// # Panics
    ///
    /// If the last reference goes while the set is still active, or the set
    /// is the default one: both are kernel invariants.
    pub fn deallocate(&mut self) {
        self.ref_lock.lock();
        self.ref_count = self.ref_count.wrapping_sub(1);
        if self.ref_count > 0 {
            self.ref_lock.unlock();
            return;
        }

        self.ref_count = 1;
        self.ref_lock.unlock();

        // The C order is the set list's lock before the set's `ref_lock`.
        let mut all_psets = P::task_state().all_psets.lock();
        self.ref_lock.lock();
        self.ref_count = self.ref_count.wrapping_sub(1);
        if self.ref_count > 0 {
            self.ref_lock.unlock();
            drop(all_psets);
            return;
        }

        let is_default =
            ptr::eq(ptr::from_ref(self), default_pset().cast_const());
        if is_default
            || self.thread_count > 0
            || self.task_count > 0
            || self.processor_count > 0
        {
            panic!("pset_deallocate: destroy default or active pset")
        }

        let _ = all_psets.list_pinned().remove_ptr(ptr::from_ref(self));
        all_psets.count = all_psets.count.wrapping_sub(1);

        self.ref_lock.unlock();
        drop(all_psets);

        // SAFETY: the set came from the set cache and nothing references it
        // any more; `.addr()` is the address the allocator handed out.
        unsafe {
            P::task_cache_free(
                TaskCache::Pset,
                NonNull::from_mut(self).cast::<u8>(),
            );
        }
    }

    /// Adds `thread` to the set.
    ///
    /// # Safety
    ///
    /// The caller must hold the set's lock and the thread's lock, as the C
    /// requires, and `thread` must be live and not linked into a processor
    /// set's thread list.
    pub unsafe fn add_thread(&mut self, thread: *mut Thread<P>) {
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
    pub unsafe fn remove_thread(&mut self, thread: *mut Thread<P>) {
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
    pub unsafe fn add_task(&mut self, task: *mut Task<P>) {
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
    pub unsafe fn remove_task(&mut self, task: *mut Task<P>) {
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
    fn quantum_set(&mut self) {
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
    pub unsafe fn add_processor(&mut self, processor: *mut Processor<P>) {
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
    /// Panics when `processor` does not belong to this
    /// set, as the C `panic()` did.
    pub unsafe fn remove_processor(&mut self, processor: *mut Processor<P>) {
        unsafe {
            if ptr::from_mut(self)
                != (*processor).processor_set.load(Ordering::Acquire)
            {
                panic!("pset_remove_processor: wrong pset")
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
                    if unsafe { (*thread).sched.policy == policy } {
                        // SAFETY: the Rust `Thread::policy()` takes the thread
                        // lock itself, and timesharing is a policy this set
                        // can switch a thread to.
                        unsafe {
                            let _ = Thread::<P>::policy(
                                thread,
                                POLICY_TIMESHARE,
                                0,
                            );
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
                    if (*thread).sched.max_priority < max_priority {
                        // SAFETY: the Rust `Thread::max_priority()` takes the
                        // thread lock itself.
                        let _ = Thread::<P>::max_priority(
                            thread,
                            pset,
                            max_priority,
                        );
                    }
                }
            }
        }

        self.lock.unlock();

        Ok(())
    }
}

impl<P: Platform> ProcessorSet<P> {
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
        ipc_processor::pset_disable(self);

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
                Thread::<P>::reference(thread);
                self.lock.unlock();
                let _ = Thread::<P>::assign(thread, default);
                Thread::<P>::deallocate(thread);
                self.lock.lock();
            }
        }

        unsafe {
            while let Some(processor) =
                self.processors.cursor_front().current_ptr()
            {
                let processor = processor.as_ptr();
                self.lock.unlock();
                let _ = processor_action::assign(processor, default, true);
                self.lock.lock();
            }
        }

        self.lock.unlock();

        ipc_processor::pset_terminate(self);
        self.deallocate();
        Ok(())
    }

    /// The task or thread ports of every member of the set, in the array
    /// `P::kalloc()` built.
    ///
    /// # Safety
    ///
    /// `self` must be a live set.
    pub(crate) unsafe fn things(
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
                // SAFETY: `old` came from `P::kalloc(size)`.
                unsafe { P::kfree(old, size) };
            }
            size = needed;

            let Some(buffer) = P::kalloc(size) else {
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
                        addr.cast::<*mut Task<P>>().add(i).write(task);
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
                        Thread::<P>::reference(thread);
                        addr.cast::<*mut Thread<P>>().add(i).write(thread);
                        cursor.move_next();
                    }
                }
            }
            self.lock.unlock();
        }

        if actual == 0 {
            if let Some(old) = NonNull::new(addr) {
                // SAFETY: `old` came from `P::kalloc(size)`.
                unsafe { P::kfree(old, size) };
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
    /// must be the `P::kalloc()` size it came from, and `size_needed` must
    /// equal `actual * size_of::<*mut c_void>()` and not exceed `size`.
    unsafe fn shrink_and_convert(
        addr: *mut u8,
        size: usize,
        size_needed: usize,
        actual: usize,
        kind: Thing,
    ) -> Result<(*mut c_void, c_uint), Error> {
        let mut addr = addr;
        if size_needed < size {
            let Some(buffer) = P::kalloc(size_needed) else {
                // SAFETY: every slot holds a reference the port conversion
                // below never reached, and `addr` came from `P::kalloc(size)`.
                unsafe {
                    Self::release_slots(addr, actual, kind);
                    P::kfree(NonNull::new_unchecked(addr), size);
                }
                return Err(Error::ResourceShortage);
            };
            // SAFETY: both buffers are live, and `size_needed` is the byte
            // count of the references `addr` holds.
            unsafe {
                ptr::copy_nonoverlapping(addr, buffer.as_ptr(), size_needed);
                P::kfree(NonNull::new_unchecked(addr), size);
            }
            addr = buffer.as_ptr();
        }

        // SAFETY: every slot holds a task or thread reference, and the
        // conversion consumes it into the port the slot then holds.
        unsafe {
            match kind {
                Thing::Task => {
                    let ports = addr.cast::<*mut Task<P>>();
                    for i in 0..actual {
                        let task = ports.add(i).read();
                        ports.add(i).write(
                            convert_task_to_port(task)
                                .map_or(ptr::null_mut(), IpcPort::as_ptr)
                                .cast::<Task<P>>(),
                        );
                    }
                }
                Thing::Thread => {
                    let ports = addr.cast::<*mut Thread<P>>();
                    for i in 0..actual {
                        let thread = ports.add(i).read();
                        ports.add(i).write(
                            convert_thread_to_port(thread)
                                .map_or(ptr::null_mut(), IpcPort::as_ptr)
                                .cast::<Thread<P>>(),
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
                            addr.cast::<*mut Task<P>>().add(i).read(),
                        );
                    }
                }
                Thing::Thread => {
                    for i in 0..actual {
                        Thread::<P>::deallocate(
                            addr.cast::<*mut Thread<P>>().add(i).read(),
                        );
                    }
                }
            }
        }
    }
}
