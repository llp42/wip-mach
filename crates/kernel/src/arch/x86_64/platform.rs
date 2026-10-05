// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`MachPlatform`], the kernel's modular backend for the portable crates,
//! and its `lock` services: threads, irq-quiet sections over spl, and
//! parking on scheduler events.

use crate::arch::x86_64::per_cpu::{self, cpu_id};
use crate::arch::x86_64::{ioapic, spl};
use crate::config::MAX_NCPUS;
use crate::kern::debug::kpanic;
use crate::kern::sched_prim::{
    NUMQUEUES, THREAD_AWAKENED, assert_wait, clear_wait, thread_block,
    thread_wakeup_prim,
};
use crate::kern::thread::Thread;
#[cfg(debug_assertions)]
use crate::utils::cell::SyncCell;
#[cfg(debug_assertions)]
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
#[cfg(debug_assertions)]
use lock::HeldLocks;
use lock::{Bucket, Platform, ThreadRef, WaitTable};

/// The machine and kernel services the portable crates need, as this
/// kernel provides them.
pub(crate) struct MachPlatform;

/// A CPU's irq-quiet sections.
///
/// Only the CPU itself touches its record; an interrupt handler that
/// lands between two updates leaves its sections balanced, and so the
/// record as it found it.
#[repr(align(64))]
struct IrqQuietCpu {
    depth: AtomicUsize,
    /// Whether the outermost section raised the spl.  It does not before
    /// the interrupt system is up: interrupts are off then, and restoring
    /// the level would turn them on.
    raised: AtomicBool,
    /// The spl level the outermost section replaced, if it raised.
    saved: AtomicI32,
}

impl IrqQuietCpu {
    const fn new() -> Self {
        Self {
            depth: AtomicUsize::new(0),
            raised: AtomicBool::new(false),
            saved: AtomicI32::new(0),
        }
    }
}

/// Every CPU's irq-quiet sections, indexed by `cpu_id()`.
///
/// A count per CPU is a count per thread: a thread never leaves its CPU
/// inside a section.
static IRQ_QUIET: [IrqQuietCpu; MAX_NCPUS] =
    [const { IrqQuietCpu::new() }; MAX_NCPUS];

/// The buckets of [`WAIT_TABLE`].
static WAIT_BUCKETS: [Bucket; NUMQUEUES] =
    [const { Bucket::new() }; NUMQUEUES];

/// The wait table every kernel `Mutex`, `RwLock` and `Condvar` parks in.
static WAIT_TABLE: WaitTable = WaitTable::new(&WAIT_BUCKETS);

/// The held-lock record of each CPU while it runs no thread, during boot.
///
/// Only the CPU and its interrupt handlers reach its record.
#[cfg(debug_assertions)]
static BOOT_HELD_LOCKS: [SyncCell<HeldLocks>; MAX_NCPUS] =
    [const { SyncCell(UnsafeCell::new(HeldLocks::new())) }; MAX_NCPUS];

/// Returns the event the thread parks on: its park token's address.
fn park_event(thread: *mut Thread) -> *mut c_void {
    // SAFETY: only the field's address is taken; the callers keep the
    // thread's record live.
    unsafe { (&raw const (*thread).park_token).cast_mut().cast() }
}

// SAFETY: each function keeps the contract `lock::Platform` states, as
// argued at each one below.
unsafe impl Platform for MachPlatform {
    /// Returns the running thread, or, while the CPU runs none during
    /// boot, its per-CPU block, which no thread record can alias.
    fn current() -> ThreadRef {
        let record = NonNull::new(per_cpu::thread().cast::<u8>())
            .unwrap_or_else(|| {
                NonNull::from(per_cpu::per_cpu_at(cpu_id())).cast()
            });
        ThreadRef::new(record)
    }

    /// Returns whether a CPU names `thread` as the one it runs.  A CPU's
    /// boot context reads as not running, so its waiters park rather than
    /// spin.
    fn is_running(thread: ThreadRef) -> bool {
        per_cpu::iter().any(|block| {
            block.thread().cast::<u8>() == thread.as_ptr().as_ptr()
        })
    }

    fn irq_quiet_enter() {
        let cpu = &IRQ_QUIET[cpu_id().as_usize()];
        let depth = cpu.depth.load(Ordering::Relaxed);
        if depth == 0 {
            let raised = ioapic::SPL_INIT.load(Ordering::Relaxed);
            if raised {
                // SAFETY: the interrupt system is up, and the level goes
                // back to `splx()` when the outermost section ends.
                let level = unsafe { spl::splhigh() };
                cpu.saved.store(level, Ordering::Relaxed);
            }
            cpu.raised.store(raised, Ordering::Relaxed);
        }
        cpu.depth.store(depth + 1, Ordering::Relaxed);
    }

    unsafe fn irq_quiet_exit() {
        let cpu = &IRQ_QUIET[cpu_id().as_usize()];
        let depth = cpu.depth.load(Ordering::Relaxed) - 1;
        cpu.depth.store(depth, Ordering::Relaxed);
        // The record is final before `splx()`, which may run the softclock
        // and so enter sections of its own.
        if depth == 0 && cpu.raised.load(Ordering::Relaxed) {
            let level: c_int = cpu.saved.load(Ordering::Relaxed);
            // SAFETY: `level` is what the outermost `splhigh()` returned
            // on this CPU.
            let _ = unsafe { spl::splx(level) };
        }
    }

    /// Sleeps on the running thread's park token until it is set.
    ///
    /// # Panics
    ///
    /// If the CPU runs no thread: nothing sleeps during boot.
    fn park() {
        let thread = per_cpu::thread();
        if thread.is_null() {
            kpanic!("park", "park: no thread to sleep\n");
        }
        // SAFETY: `thread` is the running thread, live while it runs.
        let token = unsafe { &(*thread).park_token };
        if token.swap(false, Ordering::Acquire) {
            return;
        }
        // The token is read again after the wait is asserted: an unpark
        // that set it before then finds no waiter to wake.
        // SAFETY: thread context, outside any irq-quiet section, and the
        // wait is cleared or blocked on right below.
        unsafe { assert_wait(NonNull::new(park_event(thread)), 0) };
        if token.swap(false, Ordering::Acquire) {
            // SAFETY: `thread` is the running thread.
            unsafe { clear_wait(thread, THREAD_AWAKENED, 0) };
            return;
        }
        // SAFETY: the wait is asserted, and the lock crate parks holding
        // no spin lock.
        unsafe { thread_block(None) };
        let _ = token.swap(false, Ordering::Acquire);
    }

    fn unpark(thread: ThreadRef) {
        let thread = thread.as_ptr().as_ptr().cast::<Thread>();
        // SAFETY: `thread` waited in a wait table, so it is a thread
        // record, not a boot context; the wait has not returned, so the
        // thread has not exited and its record is live.
        unsafe {
            (*thread).park_token.store(true, Ordering::Release);
            let _ = thread_wakeup_prim(park_event(thread), 0, THREAD_AWAKENED);
        }
    }

    fn wait_table() -> &'static WaitTable {
        &WAIT_TABLE
    }

    #[cfg(debug_assertions)]
    fn held_locks() -> &'static HeldLocks {
        let thread = per_cpu::thread();
        if thread.is_null() {
            let boot = &BOOT_HELD_LOCKS[cpu_id().as_usize()];
            // SAFETY: only this CPU and its interrupt handlers reach its
            // boot record, which a handler may share.
            return unsafe { &*boot.0.get() };
        }
        // SAFETY: `thread` is the running thread; its record outlives
        // every lock it holds, since it holds none when it dies.
        unsafe { &(*thread).held_locks }
    }
}
