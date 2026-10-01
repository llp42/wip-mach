// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The order checker's tests, through the public lock API.
//!
//! Lock classes are global and the tests run in parallel, so each test
//! builds its locks on lines of its own.

use crate::checker::HeldLocks;
use crate::condvar::Condvar;
use crate::mutex::Mutex;
use crate::rwlock::{RawRwLock, RwLock};
use crate::section::{self, IrqQuiet};
use crate::spin::{IrqSpinLock, RawIrqSpinLock, RawSpinLock, SpinLock};
use crate::test_support::Host;
use std::process::Command;

#[test]
#[should_panic = "lock order cycle"]
fn abba_order_panics() {
    let a = SpinLock::<(), Host>::new(());
    let b = SpinLock::<(), Host>::new(());
    drop((a.lock(), b.lock()));
    let _b = b.lock();
    let _a = a.lock();
}

#[test]
#[should_panic = "lock order cycle"]
fn three_lock_cycle_panics() {
    let a = SpinLock::<(), Host>::new(());
    let b = SpinLock::<(), Host>::new(());
    let c = SpinLock::<(), Host>::new(());
    drop((a.lock(), b.lock()));
    drop((b.lock(), c.lock()));
    let _c = c.lock();
    let _a = a.lock();
}

#[test]
fn consistent_order_passes() {
    let a = IrqSpinLock::<(), Host>::new(());
    let b = SpinLock::<(), Host>::new(());
    let c = SpinLock::<(), Host>::new(());
    for _ in 0..3 {
        let _a = a.lock();
        let _b = b.lock();
        let _c = c.lock();
    }
    let _b = b.lock();
    let _c = c.lock();
}

#[test]
fn try_lock_inversion_passes() {
    let a = SpinLock::<(), Host>::new(());
    let b = SpinLock::<(), Host>::new(());
    let c = SpinLock::<(), Host>::new(());
    drop((a.lock(), b.lock()));
    let _b = b.lock();
    let _a = a.try_lock().expect("a is free");
    let _c = c.lock();
}

#[test]
#[should_panic = "lock order cycle"]
fn lock_taken_after_a_try_lock_is_ordered_after_it() {
    let a = SpinLock::<(), Host>::new(());
    let b = SpinLock::<(), Host>::new(());
    drop((a.try_lock(), b.lock()));
    let _b = b.lock();
    let _a = a.lock();
}

#[test]
#[should_panic = "second lock of class"]
fn second_lock_of_a_class_panics() {
    let locks = [(); 2].map(|()| SpinLock::<(), Host>::new(()));
    let _first = locks[0].lock();
    let _second = locks[1].lock();
}

#[test]
#[should_panic = "second lock of class"]
fn second_try_lock_of_a_class_panics() {
    let locks = [(); 2].map(|()| SpinLock::<(), Host>::new(()));
    let _first = locks[0].lock();
    let _second = locks[1].try_lock();
}

#[test]
#[should_panic = "second lock of class"]
fn second_lock_of_a_class_panics_whatever_its_kind() {
    let locks = [(); 2].map(|()| RwLock::<(), Host>::new(()));
    let _first = locks[0].read();
    let _second = locks[1].write();
}

#[test]
fn locks_of_a_class_taken_one_at_a_time_pass() {
    let locks = [(); 2].map(|()| SpinLock::<(), Host>::new(()));
    drop(locks[0].lock());
    drop(locks[1].lock());
    let first = locks[0].lock();
    drop(first);
    drop(locks[1].lock());
}

#[test]
fn locks_built_in_statics_are_of_the_callers_classes() {
    static A: SpinLock<(), Host> = SpinLock::new(());
    static B: SpinLock<(), Host> = SpinLock::new(());
    drop((A.lock(), B.lock()));
}

#[test]
fn locks_built_by_default_are_of_the_callers_classes() {
    let a = SpinLock::<(), Host>::default();
    let b = SpinLock::<(), Host>::default();
    drop((a.lock(), b.lock()));
}

#[test]
#[should_panic = "recursive acquisition: Spin lock"]
fn recursive_spin_lock_panics() {
    let lock = SpinLock::<(), Host>::new(());
    let _outer = lock.lock();
    let _inner = lock.lock();
}

#[test]
fn out_of_order_release_passes() {
    let a = RawSpinLock::<Host>::new();
    let b = RawIrqSpinLock::<Host>::new();
    let c = RawSpinLock::<Host>::new();
    a.lock();
    b.lock();
    // SAFETY: this thread took `a` above.
    unsafe { a.unlock() };
    c.lock();
    // SAFETY: this thread holds `b` and `c`.
    unsafe {
        b.unlock();
        c.unlock();
    }
    a.lock();
    // SAFETY: this thread took `a` again above.
    unsafe { a.unlock() };
}

#[test]
#[should_panic = "held-lock stack overflow"]
fn holding_too_many_locks_panics() {
    let locks = locks_of_33_classes();
    let _guards = locks.each_ref().map(SpinLock::lock);
}

#[test]
#[should_panic = "release of a lock this thread does not hold"]
fn raw_unlock_of_an_unheld_lock_panics() {
    let lock = RawSpinLock::<Host>::new();
    // SAFETY: none; the checker is expected to catch the broken contract.
    unsafe { lock.unlock() };
}

#[test]
#[should_panic = "release of a lock this thread does not hold"]
fn raw_unlock_on_another_thread_panics() {
    let lock = RawSpinLock::<Host>::new();
    lock.lock();
    let released = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                // SAFETY: none; the checker is expected to catch a release
                // by a thread that does not hold the lock.
                unsafe { lock.unlock() };
            })
            .join()
    });
    std::panic::resume_unwind(released.expect_err("the release panics"));
}

#[test]
#[should_panic = "lock order cycle: Mutex lock"]
fn mutex_abba_order_panics() {
    let a = Mutex::<(), Host>::new(());
    let b = Mutex::<(), Host>::new(());
    drop((a.lock(), b.lock()));
    let _b = b.lock();
    let _a = a.lock();
}

#[test]
#[should_panic = "may sleep while holding Spin lock of class"]
fn mutex_under_a_spin_lock_panics() {
    let spin = SpinLock::<(), Host>::new(());
    let mutex = Mutex::<(), Host>::new(());
    let _spin = spin.lock();
    let _mutex = mutex.lock();
}

#[test]
#[should_panic = "may sleep inside an irq-quiet section"]
fn rwlock_write_in_an_irq_quiet_section_panics() {
    let rwlock = RwLock::<(), Host>::new(());
    let _section = IrqQuiet::<Host>::enter();
    let _write = rwlock.write();
}

// The checker runs before a lock waits, so a recursive `lock` or `read`
// panics instead of deadlocking.

#[test]
#[should_panic = "recursive acquisition: Mutex lock"]
fn recursive_mutex_lock_panics() {
    let mutex = Mutex::<(), Host>::new(());
    let _outer = mutex.lock();
    let _inner = mutex.lock();
}

#[test]
#[should_panic = "recursive acquisition: Read lock"]
fn recursive_rwlock_read_panics() {
    let rwlock = RwLock::<(), Host>::new(());
    let _outer = rwlock.read();
    let _inner = rwlock.read();
}

#[test]
fn rwlock_write_downgraded_then_released_passes() {
    let rwlock = RwLock::<u8, Host>::new(0);
    let spin = SpinLock::<(), Host>::new(());
    let mut write = rwlock.write();
    *write = 1;
    let read = write.downgrade();
    drop(spin.lock());
    assert_eq!(*read, 1);
    drop(read);
    drop(rwlock.write());
}

#[test]
#[should_panic = "release of a lock this thread does not hold as Read"]
fn raw_read_unlock_of_a_write_hold_panics() {
    let rwlock = RawRwLock::<Host>::new();
    rwlock.write();
    // SAFETY: none; the checker is expected to catch the broken contract.
    unsafe { rwlock.unlock_read() };
}

#[test]
#[should_panic = "release of a lock this thread does not hold as Write"]
fn raw_write_unlock_of_a_read_hold_panics() {
    let rwlock = RawRwLock::<Host>::new();
    rwlock.read();
    // SAFETY: none; the checker is expected to catch the broken contract.
    unsafe { rwlock.unlock_write() };
}

#[test]
#[should_panic = "downgrade of a lock this thread does not hold as Write"]
fn raw_downgrade_of_a_read_hold_panics() {
    let rwlock = RawRwLock::<Host>::new();
    rwlock.read();
    // SAFETY: none; the checker is expected to catch the broken contract.
    unsafe { rwlock.downgrade() };
}

#[test]
#[should_panic = "downgrade of a lock this thread does not hold as Write"]
fn raw_downgrade_of_an_unheld_lock_panics() {
    let rwlock = RawRwLock::<Host>::new();
    // SAFETY: none; the checker is expected to catch the broken contract.
    unsafe { rwlock.downgrade() };
}

#[test]
#[should_panic = "may sleep while holding Spin lock of class"]
fn condvar_wait_under_another_spin_lock_panics() {
    let other = SpinLock::<(), Host>::new(());
    let waited = SpinLock::<(), Host>::new(());
    let condvar = Condvar::<Host>::new();
    let _other = other.lock();
    let _waited = condvar.wait(waited.lock());
}

#[test]
#[should_panic = "unbalanced irq-quiet section exit"]
fn unbalanced_section_exit_panics() {
    // SAFETY: none; the checker is expected to catch the broken contract.
    unsafe { section::exit_irq_quiet::<Host>() };
}

#[test]
fn default_record_is_empty() {
    assert_eq!(
        format!("{:?}", HeldLocks::default()),
        format!("{:?}", HeldLocks::new()),
    );
}

/// Set in the child process that fills the class table, which is global,
/// so a full one would fail every test after it.
const FILL_CLASS_TABLE: &str = "LOCK_CHECKER_FILL_CLASS_TABLE";

#[test]
fn class_table_overflow_panics() {
    let name = concat!(module_path!(), "::class_table_overflow_panics");
    let (_crate, name) = name.split_once("::").expect("a crate path");
    if std::env::var_os(FILL_CLASS_TABLE).is_some() {
        take_locks_of_520_classes();
        panic!("the class table took 520 classes");
    }
    let child = Command::new(std::env::current_exe().expect("test binary"))
        .args([name, "--exact", "--nocapture"])
        .env(FILL_CLASS_TABLE, "1")
        .output()
        .expect("child test runs");
    let stderr = String::from_utf8_lossy(&child.stderr);
    assert!(!child.status.success(), "{stderr}");
    assert!(stderr.contains("lock class table full"), "{stderr}");
}

/// Builds a lock of each of 33 classes: every `s!()` is a construction
/// site of its own.
#[rustfmt::skip]
const fn locks_of_33_classes() -> [SpinLock<(), Host>; 33] {
    macro_rules! s {
        () => { SpinLock::<(), Host>::new(()) };
    }
    [
        s!(), s!(), s!(), s!(), s!(), s!(), s!(), s!(), s!(), s!(), s!(),
        s!(), s!(), s!(), s!(), s!(), s!(), s!(), s!(), s!(), s!(), s!(),
        s!(), s!(), s!(), s!(), s!(), s!(), s!(), s!(), s!(), s!(), s!(),
    ]
}

/// Takes and releases one lock of each of 520 classes: every `s!()` is a
/// construction site of its own.
#[rustfmt::skip]
fn take_locks_of_520_classes() {
    macro_rules! s {
        () => { drop(SpinLock::<(), Host>::new(()).lock()) };
    }
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!(); s!();
    s!(); s!(); s!(); s!();
}
