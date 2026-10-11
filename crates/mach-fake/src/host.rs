// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`Host`]: a `lock` platform on std threads, which parks a waiter with
//! `std::thread::park`.

use crate::types::{HostThread, Local};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(debug_assertions)]
use lock::HeldLocks;
use lock::{Bucket, ThreadRef, WaitTable};
use std::thread;

/// The `lock` platform of the tests.
///
/// Nothing interrupts a host thread, so an irq-quiet section does nothing.
pub struct Host;

std::thread_local! {
    static LOCAL: Local = Local {
        me: Box::leak(Box::new(HostThread {
            thread: thread::current(),
            parked: AtomicBool::new(false),
        })),
        #[cfg(debug_assertions)]
        held: Box::leak(Box::new(HeldLocks::new())),
    };
}

/// One bucket, which every lock of the tests shares.
static BUCKETS: [Bucket; 1] = [const { Bucket::new() }; 1];

static TABLE: WaitTable = WaitTable::new(&BUCKETS);

/// Returns the record `thread` names.
const fn record(thread: ThreadRef) -> &'static HostThread {
    // SAFETY: every `ThreadRef` of `Host` names a leaked `HostThread`.
    unsafe { thread.as_ptr().cast::<HostThread>().as_ref() }
}

// SAFETY: a thread's record is its own and leaked, `park` and `unpark`
// are std's, which keep a token, and every lock shares one wait table.
unsafe impl lock::Platform for Host {
    fn current() -> ThreadRef {
        LOCAL.with(|local| ThreadRef::new(NonNull::from(local.me).cast()))
    }

    fn is_running(thread: ThreadRef) -> bool {
        !record(thread).parked.load(Ordering::SeqCst)
    }

    fn irq_quiet_enter() {}

    unsafe fn irq_quiet_exit() {}

    fn park() {
        LOCAL.with(|local| local.me.parked.store(true, Ordering::SeqCst));
        thread::park();
        LOCAL.with(|local| local.me.parked.store(false, Ordering::SeqCst));
    }

    fn unpark(thread: ThreadRef) {
        record(thread).thread.unpark();
    }

    fn wait_table() -> &'static WaitTable {
        &TABLE
    }

    #[cfg(debug_assertions)]
    fn held_locks() -> &'static HeldLocks {
        LOCAL.with(|local| local.held)
    }
}
