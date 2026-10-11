// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! A wrong lock nesting, which the checker catches before it waits.
//!
//! The checker records the order every pair of lock names has been taken
//! in and panics at the first acquisition that would close a cycle in it.
//! Nothing else catches this one: the two locks are distinct, so the
//! re-take check reads two different addresses, and the nesting is a hang
//! the first time two threads take them the opposite way round.

#[cfg(debug_assertions)]
mod ordered {
    use core::ptr::NonNull;
    use lock::{
        Bucket, HeldLocks, IrqSpinLock, Platform, ThreadRef, WaitTable,
        irq_spin_lock,
    };

    /// The test's one thread.
    struct Thread {
        held: HeldLocks,
    }

    // SAFETY: only the one test thread reaches it.
    unsafe impl Sync for Thread {}

    static THREAD: Thread = Thread {
        held: HeldLocks::new(),
    };
    static BUCKETS: [Bucket; 1] = [Bucket::new()];
    static WAITS: WaitTable = WaitTable::new(&BUCKETS);

    /// The test's platform: one thread, which never waits and whose
    /// sections quiet nothing.
    struct Host;

    // SAFETY: the one thread is always running and never waits, and the
    // sections are counted by the checker alone.
    unsafe impl Platform for Host {
        fn current() -> ThreadRef {
            ThreadRef::new(NonNull::from(&THREAD).cast())
        }

        fn is_running(_: ThreadRef) -> bool {
            true
        }

        fn irq_quiet_enter() {}

        unsafe fn irq_quiet_exit() {}

        fn park() {
            unreachable!("the one thread never waits");
        }

        fn unpark(_: ThreadRef) {}

        fn wait_table() -> &'static WaitTable {
            &WAITS
        }

        fn held_locks() -> &'static HeldLocks {
            &THREAD.held
        }
    }

    /// The lock the kernel takes first.
    static OUTER: IrqSpinLock<(), Host> = irq_spin_lock!("outer", ());
    /// The lock the kernel takes second.
    static INNER: IrqSpinLock<(), Host> = irq_spin_lock!("inner", ());

    #[test]
    fn a_cycle_between_two_names_panics() {
        // The order the kernel takes them in: whole, and released.
        let outer = OUTER.lock();
        drop(INNER.lock());
        drop(outer);

        // The reverse closes a cycle, and panics before it waits.
        let caught = std::panic::catch_unwind(|| {
            let _inner = INNER.lock();
            let _outer = OUTER.lock();
        });
        let message = caught.expect_err("the checker let a cycle through");
        let message = message
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| message.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        assert!(
            message.contains("outer") && message.contains("inner"),
            "the panic names neither lock: {message}",
        );
    }
}
