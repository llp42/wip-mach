// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Read-copy update, in the quiescent-state-based (QSBR) flavor.
//!
//! Kernel code is not preempted: a thread leaves its CPU in kernel mode only
//! through [`thread_invoke`](crate::kern::sched_prim::thread_invoke). So a
//! context switch, a pass through the idle loop, or a clock tick taken in
//! user mode is a quiescent state (QS): the CPU cannot be inside a read
//! section there. Once every online CPU has passed a QS after a grace period
//! (GP) started, no reader can still hold a pointer unpublished before it,
//! and the memory can be reclaimed. Readers therefore pay nothing; writers
//! and the GP thread pay for everything.
//!
//! # Grace periods
//!
//! [`GP_SEQ`] counts GPs, `rcu_seq` style: odd while one runs. The GP thread
//! starts one by setting [`QS_PENDING`] to the online CPUs and making the
//! count odd; each CPU clears its bit at its next QS ([`note_qs`]), and the
//! last one wakes the GP thread, which makes the count even again and runs
//! the callbacks queued before the GP started. Idle CPUs need no nudge:
//! every CPU takes clock ticks, and each tick wakes a halted CPU back
//! through the idle loop.
//!
//! # Rules the compiler cannot check
//!
//! - A read section must not block. Debug builds count sections per CPU and
//!   panic when a CPU with one open reaches a QS.
//! - [`synchronize_rcu`] and [`rcu_barrier`] block, so they need thread
//!   context outside any read section.

use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::spl;
use crate::config::MAX_NCPUS;
use crate::kern::kheap::try_box;
use crate::kern::kmutex::KMutex;
use crate::kern::lock::SimpleLock;
use crate::kern::machine;
use crate::kern::sched_prim::{
    THREAD_AWAKENED, assert_wait, clear_wait, thread_block, thread_wakeup_prim,
};
use crate::kern::smp::CpuId;
use crate::utils::cell::SyncCell;
use alloc::boxed::Box;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::ops::Deref;
use core::ptr::{self, NonNull};
use core::sync::atomic::{
    AtomicBool, AtomicPtr, AtomicUsize, Ordering, fence,
};

// One `QS_PENDING` bit per CPU.
const _: () = assert!(MAX_NCPUS <= usize::BITS as usize);

/// The grace-period sequence: the low bit is set while a GP runs, and the
/// rest counts GPs.
static GP_SEQ: AtomicUsize = AtomicUsize::new(0);

/// The CPUs that still owe the running GP a quiescent state, one bit each.
static QS_PENDING: AtomicUsize = AtomicUsize::new(0);

/// A CPU's RCU state, on its own cache line so reporting never bounces a
/// line another CPU writes.
#[repr(align(64))]
struct RcuCpu {
    /// The last `GP_SEQ` this CPU reported a QS for; only the CPU writes it.
    gp_seq_seen: AtomicUsize,
    /// Open read sections on this CPU.
    #[cfg(debug_assertions)]
    read_nesting: AtomicUsize,
}

impl RcuCpu {
    /// A CPU that has reported nothing.
    const fn new() -> Self {
        Self {
            gp_seq_seen: AtomicUsize::new(0),
            #[cfg(debug_assertions)]
            read_nesting: AtomicUsize::new(0),
        }
    }
}

/// Every CPU's RCU state, indexed by `cpu_id()`.
static RCU_CPU: [RcuCpu; MAX_NCPUS] = [const { RcuCpu::new() }; MAX_NCPUS];

/// The running CPU's RCU state.
#[cfg(debug_assertions)]
fn this_cpu() -> &'static RcuCpu {
    &RCU_CPU[cpu_id().as_usize()]
}

/// Panic if the running CPU is inside a read section.
// Only the debug body keeps it from being `const`.
#[allow(clippy::missing_const_for_fn)]
#[cfg_attr(not(debug_assertions), allow(unused_variables))]
fn assert_not_reading(what: &str) {
    #[cfg(debug_assertions)]
    assert!(
        this_cpu().read_nesting.load(Ordering::Relaxed) == 0,
        "rcu: {what} inside a read section"
    );
}

/// Report a quiescent state for the running CPU.
///
/// The scheduler calls this when a thread gives up the CPU, the idle loop
/// on each pass, and the clock interrupt on a tick taken in user mode; the
/// CPU cannot be inside a read section at any of them.
pub(crate) fn note_qs() {
    let seq = GP_SEQ.load(Ordering::Acquire);
    if seq & 1 == 0 {
        return;
    }

    let cpu = cpu_id().as_usize();
    let rcu_cpu = &RCU_CPU[cpu];
    if rcu_cpu.gp_seq_seen.load(Ordering::Relaxed) == seq {
        return;
    }
    assert_not_reading("quiescent state");
    rcu_cpu.gp_seq_seen.store(seq, Ordering::Relaxed);

    // The release orders this CPU's reads of unpublished versions before
    // the GP thread's acquire of the empty mask, hence before their free.
    let bit = 1 << cpu;
    if QS_PENDING.fetch_and(!bit, Ordering::AcqRel) == bit {
        // SAFETY: the event is a static's address, used only as a key.
        unsafe { thread_wakeup_prim(qs_event(), 0, THREAD_AWAKENED) };
    }
}

/// The event the GP thread sleeps on while CPUs owe a QS.
fn qs_event() -> *mut c_void {
    ptr::from_ref(&QS_PENDING).cast_mut().cast()
}

/// The event the GP thread sleeps on while no callback is queued.
fn work_event() -> *mut c_void {
    ptr::from_ref(&CALLBACKS).cast_mut().cast()
}

// ---------------------------------------------------------------------------
// Callbacks

/// A callback link, embedded in the object to reclaim (`struct rcu_head`).
#[repr(C)]
#[allow(missing_docs)]
pub struct RcuHead {
    next: *mut Self,
    /// What to run once a GP has elapsed.
    ///
    /// [`gp_thread_continue()`] invokes it on the GP thread with the live
    /// `head` it is embedded in, once no reader can still see it, as
    /// [`call_rcu()`] requires of the function it installs here.
    func: Option<unsafe fn(*mut Self)>,
}

impl RcuHead {
    /// An unqueued head.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: ptr::null_mut(),
            func: None,
        }
    }
}

impl Default for RcuHead {
    fn default() -> Self {
        Self::new()
    }
}

/// A FIFO of callbacks.
struct CallbackList {
    head: *mut RcuHead,
    tail: *mut RcuHead,
}

impl CallbackList {
    /// An empty list.
    const fn new() -> Self {
        Self {
            head: ptr::null_mut(),
            tail: ptr::null_mut(),
        }
    }

    /// Whether nothing is queued.
    const fn is_empty(&self) -> bool {
        self.head.is_null()
    }

    /// Append `head`.
    ///
    /// # Safety
    ///
    /// `head` must be a live, unqueued callback.
    unsafe fn push(&mut self, head: *mut RcuHead) {
        unsafe {
            (*head).next = ptr::null_mut();
            if self.tail.is_null() {
                self.head = head;
            } else {
                (*self.tail).next = head;
            }
        }
        self.tail = head;
    }

    /// Take every entry, leaving the list empty.
    const fn take(&mut self) -> Self {
        let list = Self {
            head: self.head,
            tail: self.tail,
        };
        self.head = ptr::null_mut();
        self.tail = ptr::null_mut();
        list
    }
}

/// The callbacks queued since the GP thread last took them. Global rather
/// than per CPU: with few CPUs and rare updates one queue does not contend,
/// and its order makes [`rcu_barrier`] trivial.
static CALLBACKS: SyncCell<CallbackList> =
    SyncCell(UnsafeCell::new(CallbackList::new()));

/// Protects [`CALLBACKS`]; taken at splsched.
static CALLBACKS_LOCK: SimpleLock = SimpleLock::new();

/// `call_rcu()`: run `func(head)` in the GP thread once a GP has elapsed,
/// i.e. once no reader can still see what `head` is embedded in.
///
/// # Safety
///
/// `head` must be live and unqueued until `func` runs, and `func` must be
/// sound to call on it from the GP thread.
pub(crate) unsafe fn call_rcu(
    head: *mut RcuHead,
    func: unsafe fn(*mut RcuHead),
) {
    unsafe { (*head).func = Some(func) };

    // SAFETY: `splsched()` is the real asm routine; `s` goes back to
    // `splx()`.
    let s = unsafe { spl::splsched() };
    CALLBACKS_LOCK.lock();
    unsafe { (*CALLBACKS.0.get()).push(head) };
    CALLBACKS_LOCK.unlock();
    // SAFETY: `s` is the level `splsched()` returned.
    unsafe { spl::splx(s) };

    // SAFETY: the event is a static's address, used only as a key.
    unsafe { thread_wakeup_prim(work_event(), 0, THREAD_AWAKENED) };
}

/// Block until `done` is set, having asserted the wait on its address
/// before each check so the setter's wakeup cannot be lost.
fn wait_until(done: &AtomicBool) {
    let event = ptr::from_ref(done).cast_mut().cast::<c_void>();
    loop {
        // SAFETY: thread context, outside any read section; the wait is
        // either cleared or blocked on right below.
        unsafe { assert_wait(NonNull::new(event), 0) };
        if done.load(Ordering::Acquire) {
            // SAFETY: the current thread is live.
            unsafe { clear_wait(per_cpu::thread(), THREAD_AWAKENED, 0) };
            return;
        }
        // SAFETY: the current thread is live; nothing is locked.
        unsafe { thread_block(None) };
    }
}

/// A [`synchronize_rcu`] caller's stack record; `head` first so the
/// callback can recover it.
#[repr(C)]
#[allow(missing_docs)]
struct SyncWaiter {
    head: RcuHead,
    done: AtomicBool,
}

/// The [`SyncWaiter`] callback: mark the GP over and wake the waiter.
///
/// # Safety
///
/// `head` must be the `head` of a live `SyncWaiter`.
unsafe fn wake_sync_waiter(head: *mut RcuHead) {
    let waiter = head.cast::<SyncWaiter>();
    unsafe {
        let event = (&raw const (*waiter).done).cast_mut().cast::<c_void>();
        (*waiter).done.store(true, Ordering::Release);
        thread_wakeup_prim(event, 0, THREAD_AWAKENED);
    }
}

/// `synchronize_rcu()`: block until a full GP has elapsed, so every reader
/// that could see something unpublished before the call is gone.
///
/// Needs thread context outside any read section, after the GP thread has
/// started.
pub fn synchronize_rcu() {
    assert_not_reading("synchronize_rcu");
    let mut waiter = SyncWaiter {
        head: RcuHead::new(),
        done: AtomicBool::new(false),
    };
    // SAFETY: `waiter` outlives the callback, which sets `done` last, and
    // this frame waits for it.
    unsafe { call_rcu(&raw mut waiter.head, wake_sync_waiter) };
    wait_until(&waiter.done);
}

/// `rcu_barrier()`: block until every callback queued before the call has
/// run.
///
/// Callbacks run in queue order, so the callback [`synchronize_rcu`] queues
/// runs after every earlier one.
pub fn rcu_barrier() {
    synchronize_rcu();
}

// ---------------------------------------------------------------------------
// The grace-period thread

/// The CPUs that are up, as a `QS_PENDING` mask.
fn online_cpus() -> usize {
    CpuId::all()
        // SAFETY: the slot is `cpu`'s own `machine_slot`, and `running` only
        // goes from 0 to 1, when the CPU comes up before it runs a thread.
        .filter(|&cpu| unsafe {
            (&raw const (*machine::slot(cpu)).running).read_volatile() != 0
        })
        .fold(0, |mask, cpu| mask | 1 << cpu.as_usize())
}

/// Run one grace period, from start to end.
fn run_grace_period() {
    // A CPU that comes up after this read runs no reader until it is up,
    // and the fence orders the read after the unpublishing writes the
    // callbacks were queued behind.
    fence(Ordering::SeqCst);
    QS_PENDING.store(online_cpus(), Ordering::Relaxed);
    // The release publishes the mask to `note_qs()`'s acquire of the count.
    GP_SEQ.fetch_add(1, Ordering::Release);

    loop {
        // This thread is outside any read section.
        note_qs();
        // SAFETY: thread context; the wait is cleared or blocked on below.
        unsafe { assert_wait(NonNull::new(qs_event()), 0) };
        if QS_PENDING.load(Ordering::Acquire) == 0 {
            // SAFETY: the current thread is live.
            unsafe { clear_wait(per_cpu::thread(), THREAD_AWAKENED, 0) };
            break;
        }
        // SAFETY: nothing is locked.
        unsafe { thread_block(None) };
    }

    GP_SEQ.fetch_add(1, Ordering::Release);
}

/// Take every queued callback, sleeping until there is one.
fn wait_for_callbacks() -> CallbackList {
    loop {
        // SAFETY: `splsched()` is the real asm routine; `s` goes back to
        // `splx()`.
        let s = unsafe { spl::splsched() };
        CALLBACKS_LOCK.lock();
        // SAFETY: the lock serializes the queue.
        let list = unsafe { (*CALLBACKS.0.get()).take() };
        if list.is_empty() {
            // Asserted under the lock, so `call_rcu()`'s wakeup, which
            // follows its push, cannot be lost.
            // SAFETY: thread context, at splsched as the wait allows.
            unsafe { assert_wait(NonNull::new(work_event()), 0) };
        }
        CALLBACKS_LOCK.unlock();
        // SAFETY: `s` is the level `splsched()` returned.
        unsafe { spl::splx(s) };

        if !list.is_empty() {
            return list;
        }
        // SAFETY: nothing is locked.
        unsafe { thread_block(None) };
    }
}

/// The GP thread: wait for callbacks, run a GP, run them; forever.
///
/// # Safety
///
/// Runs as the one GP kernel thread, which `start_kernel_threads()`
/// creates.
pub(crate) unsafe extern "C" fn gp_thread_continue() {
    loop {
        let list = wait_for_callbacks();
        // Every callback in `list` was queued before this GP starts.
        run_grace_period();

        let mut head = list.head;
        while !head.is_null() {
            // SAFETY: `head` is a queued callback that its GP has released
            // to this thread; its link is read before `func` may free it.
            unsafe {
                let next = (*head).next;
                if let Some(func) = (*head).func {
                    func(head);
                }
                head = next;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Read sections

/// An open read section, as `rcu_read_lock()`/`rcu_read_unlock()` bracket
/// in C. Free outside debug builds.
///
/// It is neither `Send` nor `Sync`: it belongs to its CPU, which the
/// section never leaves because it never blocks.
pub struct RcuGuard {
    _not_send: PhantomData<*const ()>,
}

impl RcuGuard {
    /// Open a read section.
    // Only the debug body keeps it from being `const`.
    #[allow(clippy::missing_const_for_fn)]
    fn new() -> Self {
        #[cfg(debug_assertions)]
        this_cpu().read_nesting.fetch_add(1, Ordering::Relaxed);
        Self {
            _not_send: PhantomData,
        }
    }
}

impl Drop for RcuGuard {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        this_cpu().read_nesting.fetch_sub(1, Ordering::Relaxed);
    }
}

/// `rcu_read_lock()`: open a read section that several [`Rcu::read_in`]
/// calls can share.
#[must_use]
pub fn read_lock() -> RcuGuard {
    RcuGuard::new()
}

/// A read section over one [`Rcu`], dereferencing to the version it saw.
pub struct RcuReadGuard<'a, T> {
    value: &'a T,
    _guard: RcuGuard,
}

impl<T> Deref for RcuReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.value
    }
}

// ---------------------------------------------------------------------------
// Rcu<T>

/// One published version: `head` first, so its callback can recover the
/// box.
#[repr(C)]
#[allow(missing_docs)]
struct RcuBox<T> {
    head: RcuHead,
    value: T,
}

/// The callback that frees an unpublished version.
///
/// # Safety
///
/// `head` must be the `head` of an `RcuBox<T>` from `Box::into_raw` that
/// no one can reach any more.
unsafe fn free_box<T>(head: *mut RcuHead) {
    drop(unsafe { Box::from_raw(head.cast::<RcuBox<T>>()) });
}

/// A value readers see without locking, replaced whole by writers: the
/// RCU-protected cousin of `RwLock<T>`.
///
/// Readers never block and never write shared memory. Writers are
/// serialized by a sleeping mutex, so an update closure may block and
/// allocate; each replaces the published version with a new one and frees
/// the old one after a grace period. Allocation is fallible: every writer
/// hands its value back when the heap is exhausted.
pub struct Rcu<T> {
    /// The published version; never null.
    ptr: AtomicPtr<RcuBox<T>>,
    /// Serializes writers, so none frees what another is reading.
    writer: KMutex,
    /// `T` is owned, and dropped in the GP thread.
    _marker: PhantomData<*mut T>,
}

// SAFETY: sending the `Rcu` sends its `T`.
unsafe impl<T: Send> Send for Rcu<T> {}
// SAFETY: readers on many CPUs share `&T`, so `T: Sync`, and old versions
// are dropped in the GP thread, so `T: Send`.
unsafe impl<T: Send + Sync> Sync for Rcu<T> {}

impl<T: Send + Sync> Rcu<T> {
    /// Wrap `value` as the first published version.
    ///
    /// # Errors
    ///
    /// `Err(value)` if the heap is exhausted.
    pub fn try_new(value: T) -> Result<Self, T> {
        let version = Self::try_version(value)?;
        Ok(Self {
            ptr: AtomicPtr::new(version),
            writer: KMutex::new(),
            _marker: PhantomData,
        })
    }

    /// Box `value` as a version to publish.
    fn try_version(value: T) -> Result<*mut RcuBox<T>, T> {
        try_box(RcuBox {
            head: RcuHead::new(),
            value,
        })
        .map(Box::into_raw)
        .map_err(|version| version.value)
    }

    /// Read the published version. The guard is a read section: do not
    /// block while holding it.
    #[must_use]
    pub fn read(&self) -> RcuReadGuard<'_, T> {
        let guard = read_lock();
        let version = self.ptr.load(Ordering::Acquire);
        RcuReadGuard {
            // SAFETY: the version is live while the section is open: its
            // free waits for a GP, which waits for this CPU's next QS.
            value: unsafe { &(*version).value },
            _guard: guard,
        }
    }

    /// Read the published version within an open section shared with
    /// other reads.
    #[must_use]
    pub fn read_in<'a>(&'a self, _guard: &'a RcuGuard) -> &'a T {
        let version = self.ptr.load(Ordering::Acquire);
        // SAFETY: the version is live while the section is open: its free
        // waits for a GP, which waits for this CPU's next QS; for as
        // long as `_guard` is open.
        unsafe { &(*version).value }
    }

    /// Lock out other writers; the published version stays live until
    /// the unlock, and `ptr` changes only under the lock.
    fn lock_writer(&self) {
        // An uninterruptible lock cannot fail.
        let _ = self.writer.lock(false);
    }

    /// Publish `version` in place of the current one, which is returned.
    /// The caller holds the writer lock.
    fn publish(&self, version: *mut RcuBox<T>) -> *mut RcuBox<T> {
        self.ptr.swap(version, Ordering::AcqRel)
    }

    /// Free `old` after a grace period.
    ///
    /// # Safety
    ///
    /// `old` must be a version this `Rcu` has just unpublished.
    unsafe fn retire(old: *mut RcuBox<T>) {
        unsafe { call_rcu(&raw mut (*old).head, free_box::<T>) };
    }

    /// Publish `f(current)` in place of the current version. `f` may block.
    ///
    /// # Errors
    ///
    /// `Err(new)` with `f`'s result if the heap is exhausted; the current
    /// version stays published.
    pub fn try_update(&self, f: impl FnOnce(&T) -> T) -> Result<(), T> {
        self.lock_writer();
        let current = self.ptr.load(Ordering::Relaxed);
        // SAFETY: only writers unpublish, and the lock excludes them.
        let value = f(unsafe { &(*current).value });
        let result = Self::try_version(value).map(|version| {
            let old = self.publish(version);
            // SAFETY: `old` was just unpublished.
            unsafe { Self::retire(old) };
        });
        self.writer.unlock();
        result
    }

    /// Publish `new` in place of the current version, which is dropped
    /// after a grace period.
    ///
    /// # Errors
    ///
    /// `Err(new)` if the heap is exhausted.
    pub fn replace(&self, new: T) -> Result<(), T> {
        let version = Self::try_version(new)?;
        self.lock_writer();
        let old = self.publish(version);
        self.writer.unlock();
        // SAFETY: `old` was just unpublished.
        unsafe { Self::retire(old) };
        Ok(())
    }

    /// Publish `new`, wait out a grace period, and hand the old value back.
    ///
    /// # Errors
    ///
    /// `Err(new)` if the heap is exhausted.
    pub fn replace_sync(&self, new: T) -> Result<T, T> {
        let version = Self::try_version(new)?;
        self.lock_writer();
        let old = self.publish(version);
        self.writer.unlock();
        synchronize_rcu();
        // SAFETY: `old` came from `Box::into_raw`, and after the GP no
        // reader holds it.
        Ok(unsafe { Box::from_raw(old) }.value)
    }

    /// The value, mutably: `&mut self` proves no reader or writer exists.
    pub fn get_mut(&mut self) -> &mut T {
        // SAFETY: the exclusive borrow excludes every reader and writer.
        unsafe { &mut (*self.ptr.load(Ordering::Relaxed)).value }
    }
}

impl<T: Clone + Send + Sync> Rcu<T> {
    /// Publish a copy of the current version with `f` applied. `f` may
    /// block.
    ///
    /// # Errors
    ///
    /// `Err(copy)` with the modified copy if the heap is exhausted.
    pub fn try_modify(&self, f: impl FnOnce(&mut T)) -> Result<(), T> {
        self.try_update(|current| {
            let mut copy = current.clone();
            f(&mut copy);
            copy
        })
    }
}

impl<T> Drop for Rcu<T> {
    fn drop(&mut self) {
        // SAFETY: `&mut self` excludes every reader, so the version can go
        // now; it came from `Box::into_raw`.
        drop(unsafe { Box::from_raw(*self.ptr.get_mut()) });
    }
}
