// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`Host`], a [`Platform`] over host threads for the tests: std threads,
//! or loom's under `cfg(loom)`.
//!
//! Each thread counts its own irq-quiet sections and parks, so a test can
//! check that a lock kept the platform contract, and parking inside a
//! section panics.

#[cfg(debug_assertions)]
use crate::checker::HeldLocks;
use crate::platform::{Platform, ThreadRef};
use crate::wait::{Bucket, WaitTable};
use core::cell::Cell;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(loom)]
use loom::thread::{self, Thread};
#[cfg(not(loom))]
use std::thread::{self, Thread};

/// The host platform.
#[derive(Debug)]
pub(crate) struct Host;

/// The per-thread record a [`ThreadRef`] points at.
///
/// `parked` feeds [`Platform::is_running`] only; it is a plain atomic even
/// under loom, which is not asked to model it.
#[repr(align(8))]
struct HostThread {
    thread: Thread,
    parked: AtomicBool,
}

struct Local {
    me: &'static HostThread,
    irq_quiet: Cell<usize>,
    parks: Cell<usize>,
    /// Set by [`Host::panic_in_next_park`].
    interrupt_park: Cell<bool>,
    #[cfg(debug_assertions)]
    held: &'static HeldLocks,
}

impl Local {
    fn new() -> Self {
        // Leaked, so a late unpark of a finished thread stays sound.
        let me = Box::leak(Box::new(HostThread {
            thread: thread::current(),
            parked: AtomicBool::new(false),
        }));
        Self {
            me,
            irq_quiet: Cell::new(0),
            parks: Cell::new(0),
            interrupt_park: Cell::new(false),
            #[cfg(debug_assertions)]
            held: Box::leak(Box::new(HeldLocks::new())),
        }
    }
}

#[cfg(not(loom))]
std::thread_local! {
    static LOCAL: Local = Local::new();
}
#[cfg(loom)]
loom::thread_local! {
    static LOCAL: Local = Local::new();
}

/// One bucket, shared by every test's keys, so that each wait-table walk
/// also skips waiters of other keys.
#[cfg(not(loom))]
static BUCKETS: [Bucket; 1] = [const { Bucket::new() }; 1];

#[cfg(not(loom))]
static TABLE: WaitTable = WaitTable::new(&BUCKETS);

#[cfg(loom)]
loom::lazy_static! {
    // Two buckets, so the models also see unrelated locks share one.
    static ref BUCKETS: [Bucket; 2] = [Bucket::new(), Bucket::new()];
    static ref TABLE: WaitTable = WaitTable::new(&*BUCKETS);
}

impl Host {
    /// Returns how many irq-quiet sections the running thread is in.
    pub(crate) fn irq_quiet_depth() -> usize {
        LOCAL.with(|local| local.irq_quiet.get())
    }

    /// Returns how many times the running thread has parked.
    #[cfg(not(loom))]
    pub(crate) fn parks() -> usize {
        LOCAL.with(|local| local.parks.get())
    }

    /// Makes the running thread's next park panic with "park interrupted"
    /// once it wakes, as a thread unwinding out of a wait.
    #[cfg(not(loom))]
    pub(crate) fn panic_in_next_park() {
        LOCAL.with(|local| local.interrupt_park.set(true));
    }
}

/// Yields until `done` returns true, asking it only after a yield; the
/// tests' racy waits go through here, so that their coverage does not
/// depend on which thread wins the race.
#[cfg(not(loom))]
pub(crate) fn yield_until(mut done: impl FnMut() -> bool) {
    let _tries = (0..usize::MAX).find(|_| {
        thread::yield_now();
        done()
    });
}

/// Spawns a thread that runs `wait`, and returns once `wait` has parked
/// it, with the thread's identity.
///
/// `wait` must park the thread once and only in the lock it waits for, as
/// taking a held lock does.
#[cfg(not(loom))]
pub(crate) fn spawn_parked<'scope, T: Send + 'scope>(
    scope: &'scope thread::Scope<'scope, '_>,
    wait: impl FnOnce() -> T + Send + 'scope,
) -> (ThreadRef, thread::ScopedJoinHandle<'scope, T>) {
    let (send, receive) = std::sync::mpsc::channel();
    let handle = scope.spawn(move || {
        send.send(Host::current()).unwrap();
        wait()
    });
    let waiter = receive.recv().unwrap();
    yield_until(|| !Host::is_running(waiter));
    (waiter, handle)
}

fn host_thread(thread: ThreadRef) -> &'static HostThread {
    // SAFETY: every `ThreadRef` of `Host` comes from `Host::current`, the
    // address of a leaked `HostThread`.
    unsafe { thread.as_ptr().cast::<HostThread>().as_ref() }
}

// SAFETY: sections are counted per thread, `park` and `unpark` are the
// host's, whose token semantics match the contract, and every thread has
// its own leaked record.
unsafe impl Platform for Host {
    fn current() -> ThreadRef {
        LOCAL.with(|local| ThreadRef::new(NonNull::from(local.me).cast()))
    }

    fn is_running(thread: ThreadRef) -> bool {
        // Under loom a spinning waiter would only grow the state space.
        !cfg!(loom) && !host_thread(thread).parked.load(Ordering::Relaxed)
    }

    fn irq_quiet_enter() {
        LOCAL.with(|local| local.irq_quiet.set(local.irq_quiet.get() + 1));
    }

    unsafe fn irq_quiet_exit() {
        LOCAL.with(|local| {
            let depth = local.irq_quiet.get();
            assert!(depth > 0, "irq-quiet exit without an entry");
            local.irq_quiet.set(depth - 1);
        });
    }

    fn park() {
        let (me, interrupt) = LOCAL.with(|local| {
            assert_eq!(local.irq_quiet.get(), 0, "park inside a section");
            local.parks.set(local.parks.get() + 1);
            (local.me, local.interrupt_park.replace(false))
        });
        me.parked.store(true, Ordering::Relaxed);
        thread::park();
        me.parked.store(false, Ordering::Relaxed);
        assert!(!interrupt, "park interrupted");
    }

    fn unpark(thread: ThreadRef) {
        host_thread(thread).thread.unpark();
    }

    fn wait_table() -> &'static WaitTable {
        &TABLE
    }

    #[cfg(debug_assertions)]
    fn held_locks() -> &'static HeldLocks {
        LOCAL.with(|local| local.held)
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::Host;
    use crate::platform::Platform;
    use crate::section::IrqQuiet;

    #[test]
    fn sections_nest_as_a_count() {
        let outer = IrqQuiet::<Host>::enter();
        let inner = IrqQuiet::<Host>::enter();
        assert_eq!(Host::irq_quiet_depth(), 2);
        drop(outer);
        assert_eq!(Host::irq_quiet_depth(), 1);
        drop(inner);
        assert_eq!(Host::irq_quiet_depth(), 0);
    }

    #[test]
    #[should_panic = "park interrupted"]
    fn park_after_a_panic_request_panics_once_woken() {
        Host::panic_in_next_park();
        Host::unpark(Host::current());
        Host::park();
    }

    #[test]
    fn unpark_before_park_returns_at_once() {
        Host::unpark(Host::current());
        Host::park();
        assert_eq!(Host::parks(), 1);
        assert!(Host::is_running(Host::current()));
    }

    #[test]
    #[should_panic = "park inside a section"]
    fn park_inside_a_section_panics() {
        let _section = IrqQuiet::<Host>::enter();
        Host::park();
    }

    #[test]
    #[should_panic = "irq-quiet exit without an entry"]
    fn unbalanced_irq_quiet_exit_panics() {
        // SAFETY: none; the fake is expected to catch the broken contract.
        unsafe { Host::irq_quiet_exit() };
    }
}
