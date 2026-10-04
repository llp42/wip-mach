// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The fake platforms the host tests drive: [`Fake`] for the clock's
//! hardware, and [`Host`], the `lock` platform, over std threads.

use crate::platform::{Calendar, Locking, TimeCounter, TimePage};
use crate::types::{Instant, WallTime};
use core::ptr::NonNull;
use core::sync::atomic::{
    AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering,
};
#[cfg(debug_assertions)]
use lock::HeldLocks;
use lock::{Bucket, Platform, ThreadRef, WaitTable};
use std::thread::{self, Thread};

/// A platform whose hardware the tests control.
#[derive(Default)]
pub struct Fake {
    counter: AtomicU32,
    period_nsec: AtomicU32,
    rtc: AtomicI64,
    published_wall: AtomicU64,
    published_uptime: AtomicU64,
}

impl Fake {
    /// A fake at counter zero with the given counter unit.
    pub(crate) fn with_period_nsec(period_nsec: u32) -> Self {
        Self {
            period_nsec: AtomicU32::new(period_nsec),
            ..Self::default()
        }
    }

    /// Sets the counter value.
    pub(crate) fn set_counter(&self, value: u32) {
        self.counter.store(value, Ordering::Relaxed);
    }

    /// The seconds last programmed into the RTC.
    pub(crate) fn rtc_seconds(&self) -> i64 {
        self.rtc.load(Ordering::Relaxed)
    }

    /// The last pair published to the time page.
    pub(crate) fn published(&self) -> (WallTime, Instant) {
        (
            WallTime::from_nanos(self.published_wall.load(Ordering::Relaxed)),
            Instant::from_nanos(self.published_uptime.load(Ordering::Relaxed)),
        )
    }
}

impl TimeCounter for Fake {
    fn counter(&self) -> u32 {
        self.counter.load(Ordering::Relaxed)
    }

    fn counter_period_nsec(&self) -> u32 {
        self.period_nsec.load(Ordering::Relaxed)
    }
}

impl Locking for Fake {
    type Lock = Host;
}

impl Calendar for Fake {
    fn set_rtc(&self, seconds: i64) {
        self.rtc.store(seconds, Ordering::Relaxed);
    }
}

impl TimePage for Fake {
    fn publish(&self, wall: WallTime, uptime: Instant) {
        self.published_wall
            .store(wall.as_nanos(), Ordering::Relaxed);
        self.published_uptime
            .store(uptime.as_nanos(), Ordering::Relaxed);
    }
}

/// The `lock` platform of the tests.
///
/// Nothing interrupts a host thread, so an irq-quiet section only counts
/// its entries.
pub struct Host;

/// The record a [`ThreadRef`] of [`Host`] points at; leaked, so a late
/// unpark of a finished thread stays sound.
#[repr(align(8))]
struct HostThread {
    thread: Thread,
    parked: AtomicBool,
    irq_quiet_entries: AtomicU64,
}

/// The running thread's records.
struct Local {
    me: &'static HostThread,
    #[cfg(debug_assertions)]
    held: &'static HeldLocks,
}

std::thread_local! {
    static LOCAL: Local = Local {
        me: Box::leak(Box::new(HostThread {
            thread: thread::current(),
            parked: AtomicBool::new(false),
            irq_quiet_entries: AtomicU64::new(0),
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

impl Host {
    /// Returns how many irq-quiet sections `thread` has entered, so a test
    /// can watch another thread take locks.
    pub fn irq_quiet_entries(thread: ThreadRef) -> u64 {
        record(thread).irq_quiet_entries.load(Ordering::SeqCst)
    }
}

// SAFETY: a thread's record is its own and leaked, `park` and `unpark`
// are std's, which keep a token, and every lock shares one wait table.
unsafe impl Platform for Host {
    fn current() -> ThreadRef {
        LOCAL.with(|local| ThreadRef::new(NonNull::from(local.me).cast()))
    }

    fn is_running(thread: ThreadRef) -> bool {
        !record(thread).parked.load(Ordering::SeqCst)
    }

    fn irq_quiet_enter() {
        LOCAL.with(|local| {
            local.me.irq_quiet_entries.fetch_add(1, Ordering::SeqCst);
        });
    }

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

mod tests {
    use super::Host;
    use lock::{Mutex, Platform};
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn a_contended_mutex_parks_its_waiter_until_the_owner_unlocks() {
        let lock = Mutex::<u32, Host>::new(0);
        let (send, receive) = mpsc::channel();
        thread::scope(|scope| {
            let mut guard = lock.lock();
            let contender = scope.spawn(|| {
                send.send(Host::current()).unwrap();
                *lock.lock() += 1;
            });
            let waiter = receive.recv().unwrap();
            let _parked = (0..usize::MAX).find(|_| {
                thread::yield_now();
                !Host::is_running(waiter)
            });
            *guard += 10;
            drop(guard);
            contender.join().unwrap();
        });
        assert_eq!(lock.into_inner(), 11);
    }
}
