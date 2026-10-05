// SPDX-License-Identifier: CMU-Mach
// Derived from kern/lock.c and kern/lock.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel's simple and sleep-capable locks.

use crate::arch::x86_64::per_cpu;
use crate::kern::sched_prim::{
    THREAD_AWAKENED, thread_sleep, thread_wakeup_prim,
};
use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};
use core::ptr::{self, addr_of_mut};
use core::sync::atomic::{AtomicU32, Ordering};

/// A simple spin lock.
#[repr(transparent)]
pub struct SimpleLock {
    lock_data: AtomicU32,
}

const _: () = assert!(size_of::<SimpleLock>() == size_of::<u32>());
const _: () = assert!(align_of::<SimpleLock>() == align_of::<u32>());

impl SimpleLock {
    /// An unlocked lock, the image a C `static` began with.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lock_data: AtomicU32::new(0),
        }
    }

    /// Initializes the lock unheld.  The store is `Relaxed`: the caller's
    /// proof that no one holds the lock, not an ordering, is what makes it
    /// safe.
    pub fn init(&self) {
        self.lock_data.store(0, Ordering::Relaxed);
    }

    /// Whether the lock is currently held, as a non-synchronizing query.
    /// The `Relaxed` load may be stale by the time the caller acts on it.
    pub fn is_locked(&self) -> bool {
        self.lock_data.load(Ordering::Relaxed) != 0
    }

    /// Acquires the lock, spinning while it is held.  The `swap` acquires the
    /// releasing unlock's publishes; the inner load is its
    /// test-and-test-and-set read and may be `Relaxed`.
    pub fn lock(&self) {
        while self.lock_data.swap(1, Ordering::AcqRel) != 0 {
            while self.lock_data.load(Ordering::Relaxed) != 0 {
                core::hint::spin_loop();
            }
        }
    }

    /// Takes the lock when it is free.  The `swap` acquires on success, as
    /// `lock()` does.
    #[must_use]
    pub fn try_lock(&self) -> bool {
        self.lock_data.swap(1, Ordering::AcqRel) == 0
    }

    /// Releases the lock.  The `AcqRel` store publishes everything this
    /// critical section wrote to the next successful locker.
    pub fn unlock(&self) {
        self.lock_data.swap(0, Ordering::AcqRel);
    }
}

impl Default for SimpleLock {
    fn default() -> Self {
        Self::new()
    }
}

/// The sleep-capable recursive reader-writer lock.
///
/// # Invariants
///
/// Every field access below happens while the caller holds the interlock,
/// except the owner written or read at [`LockData::init`] time, when the
/// storage is still unshared.
#[repr(C)]
#[allow(missing_docs)]
pub struct LockData {
    thread: UnsafeCell<*mut c_void>,
    state: UnsafeCell<u32>,
    interlock: SimpleLock,
}

const _: () = assert!(size_of::<LockData>() == 16);
const _: () = assert!(align_of::<LockData>() == align_of::<*mut c_void>());
const _: () = assert!(core::mem::offset_of!(LockData, thread) == 0);
const _: () = assert!(
    core::mem::offset_of!(LockData, interlock)
        == core::mem::offset_of!(LockData, state) + size_of::<u32>()
);

/// How many times a waiter spins before it sleeps.
const LOCK_WAIT_TIME: c_int = 100;

/// `(struct thread *)-1`, the owner of a lock no thread owns.
const NO_THREAD: *mut c_void = ptr::without_provenance_mut(usize::MAX);

const READ_COUNT_SHIFT: u32 = 0;
const READ_COUNT_MASK: u32 = 0x0000_ffff;
const WANT_UPGRADE_SHIFT: u32 = 16;
const WANT_UPGRADE_MASK: u32 = 0x1;
const WANT_WRITE_SHIFT: u32 = 17;
const WANT_WRITE_MASK: u32 = 0x1;
const WAITING_SHIFT: u32 = 18;
const WAITING_MASK: u32 = 0x1;
const CAN_SLEEP_SHIFT: u32 = 19;
const CAN_SLEEP_MASK: u32 = 0x1;
const RECURSION_DEPTH_SHIFT: u32 = 20;
const RECURSION_DEPTH_MASK: u32 = 0x0000_0fff;

impl LockData {
    /// The all-zero lock a static begins with; [`LockData::init`] completes
    /// it.
    pub(crate) const fn zeroed() -> Self {
        Self {
            thread: UnsafeCell::new(ptr::null_mut()),
            state: UnsafeCell::new(0),
            interlock: SimpleLock::new(),
        }
    }

    /// Initializes the lock, letting waiters sleep when `can_sleep` is set.
    ///
    /// # Safety
    ///
    /// `lock` must point at writable storage for a [`LockData`] that no other
    /// thread can see yet.
    pub(crate) unsafe fn init(lock: *mut Self, can_sleep: bool) {
        unsafe {
            addr_of_mut!((*lock).thread)
                .cast::<*mut c_void>()
                .write(NO_THREAD);
            addr_of_mut!((*lock).state)
                .cast::<u32>()
                .write(u32::from(can_sleep) << CAN_SLEEP_SHIFT);
            (*lock).interlock.init();
        }
    }

    /// The raw bitfield word.
    const fn state(&self) -> u32 {
        // SAFETY: the interlock serializes every access to the word, and the
        // caller holds it; `state` is `UnsafeCell` so a read through `&self`
        // is allowed.
        unsafe { self.state.get().read() }
    }

    /// Overwrite the bitfield word.
    const fn set_state(&self, word: u32) {
        // SAFETY: the interlock serializes every access to the word, and the
        // caller holds it; `state` is `UnsafeCell` so a read through
        // `&self` is allowed; the caller holds the interlock and the
        // field is interior-mutable.
        unsafe { self.state.get().write(word) };
    }

    /// Extract the packed field at `shift`, `mask` bits wide.
    const fn field(&self, shift: u32, mask: u32) -> u32 {
        (self.state() >> shift) & mask
    }

    /// Replace the packed field at `shift`, leaving the rest alone.
    const fn set_field(&self, shift: u32, mask: u32, value: u32) {
        let cleared = self.state() & !(mask << shift);
        self.set_state(cleared | ((value & mask) << shift));
    }

    const fn read_count(&self) -> u32 {
        self.field(READ_COUNT_SHIFT, READ_COUNT_MASK)
    }

    const fn set_read_count(&self, value: u32) {
        self.set_field(READ_COUNT_SHIFT, READ_COUNT_MASK, value);
    }

    const fn want_upgrade(&self) -> bool {
        self.field(WANT_UPGRADE_SHIFT, WANT_UPGRADE_MASK) != 0
    }

    fn set_want_upgrade(&self, on: bool) {
        self.set_field(WANT_UPGRADE_SHIFT, WANT_UPGRADE_MASK, u32::from(on));
    }

    const fn want_write(&self) -> bool {
        self.field(WANT_WRITE_SHIFT, WANT_WRITE_MASK) != 0
    }

    fn set_want_write(&self, on: bool) {
        self.set_field(WANT_WRITE_SHIFT, WANT_WRITE_MASK, u32::from(on));
    }

    const fn waiting(&self) -> bool {
        self.field(WAITING_SHIFT, WAITING_MASK) != 0
    }

    fn set_waiting(&self, on: bool) {
        self.set_field(WAITING_SHIFT, WAITING_MASK, u32::from(on));
    }

    const fn can_sleep(&self) -> bool {
        self.field(CAN_SLEEP_SHIFT, CAN_SLEEP_MASK) != 0
    }

    const fn recursion_depth(&self) -> u32 {
        self.field(RECURSION_DEPTH_SHIFT, RECURSION_DEPTH_MASK)
    }

    const fn set_recursion_depth(&self, value: u32) {
        self.set_field(RECURSION_DEPTH_SHIFT, RECURSION_DEPTH_MASK, value);
    }

    /// The owner of the lock, the `thread` field.
    const fn thread(&self) -> *mut c_void {
        // SAFETY: the interlock serializes ownership, and the caller holds it;
        // `thread` is interior-mutable.
        unsafe { self.thread.get().read() }
    }

    /// Whether the calling thread already owns the lock for recursive use.
    fn owned_by_current(&self) -> bool {
        self.thread() == per_cpu::thread().cast::<c_void>()
    }

    /// This lock's address, the event every sleeper registers and every wakeup
    /// names.
    const fn event(&self) -> *mut c_void {
        ptr::from_ref(self).cast_mut().cast::<c_void>()
    }

    /// The C's bounded spin: release the interlock, pause up to
    /// `LOCK_WAIT_TIME` times while `cond` holds, then re-take the interlock.
    fn pause_until(&self, cond: impl Fn() -> bool) {
        let mut i = LOCK_WAIT_TIME;
        if i > 0 {
            self.interlock.unlock();
            loop {
                i -= 1;
                if i <= 0 || !cond() {
                    break;
                }
                core::hint::spin_loop();
            }
            self.interlock.lock();
        }
    }

    /// Set `waiting`, sleep on this lock's address and re-take the interlock.
    fn sleep(&self) {
        self.set_waiting(true);
        // SAFETY: the caller holds the interlock, which `thread_sleep()`
        // releases before blocking; `self` outlives the call because the
        // caller owns the lock storage.
        unsafe {
            thread_sleep(
                self.event(),
                ptr::from_ref(&self.interlock).cast_mut(),
                0,
            );
        }
        self.interlock.lock();
    }

    /// Clear `waiting` and wake the sleeper.
    fn wakeup(&self) {
        self.set_waiting(false);
        // SAFETY: the event is the address every sleeper registered with, and
        // the caller holds the interlock.
        unsafe { thread_wakeup_prim(self.event(), 0, THREAD_AWAKENED) };
    }

    /// Takes the lock for writing.
    pub(crate) fn write(&self) {
        self.interlock.lock();

        if self.owned_by_current() {
            self.set_recursion_depth(self.recursion_depth().wrapping_add(1));
            self.interlock.unlock();
            return;
        }

        while self.want_write() {
            self.pause_until(|| self.want_write());

            if self.can_sleep() && self.want_write() {
                self.sleep();
            }
        }
        self.set_want_write(true);

        while self.read_count() != 0 || self.want_upgrade() {
            self.pause_until(|| self.read_count() != 0 || self.want_upgrade());

            if self.can_sleep()
                && (self.read_count() != 0 || self.want_upgrade())
            {
                self.sleep();
            }
        }
        self.interlock.unlock();
    }

    /// Releases a read or write hold.
    pub(crate) fn done(&self) {
        self.interlock.lock();

        if self.read_count() != 0 {
            self.set_read_count(self.read_count().wrapping_sub(1));
        } else if self.recursion_depth() != 0 {
            self.set_recursion_depth(self.recursion_depth().wrapping_sub(1));
        } else if self.want_upgrade() {
            self.set_want_upgrade(false);
        } else {
            self.set_want_write(false);
        }

        if self.waiting() && self.read_count() == 0 {
            self.wakeup();
        }

        self.interlock.unlock();
    }

    /// Takes the lock for reading.
    pub(crate) fn read(&self) {
        self.interlock.lock();

        if self.owned_by_current() {
            self.set_read_count(self.read_count().wrapping_add(1));
            self.interlock.unlock();
            return;
        }

        while self.want_write() || self.want_upgrade() {
            self.pause_until(|| self.want_write() || self.want_upgrade());

            if self.can_sleep() && (self.want_write() || self.want_upgrade()) {
                self.sleep();
            }
        }

        self.set_read_count(self.read_count().wrapping_add(1));
        self.interlock.unlock();
    }

    /// Upgrades a read hold to a write hold; returns `true` when another
    /// upgrade won and the read hold is gone.
    #[must_use]
    pub(crate) fn read_to_write(&self) -> bool {
        self.interlock.lock();

        self.set_read_count(self.read_count().wrapping_sub(1));

        if self.owned_by_current() {
            self.set_recursion_depth(self.recursion_depth().wrapping_add(1));
            self.interlock.unlock();
            return false;
        }

        if self.want_upgrade() {
            if self.waiting() && self.read_count() == 0 {
                self.wakeup();
            }

            self.interlock.unlock();
            return true;
        }

        self.set_want_upgrade(true);

        while self.read_count() != 0 {
            self.pause_until(|| self.read_count() != 0);

            if self.can_sleep() && self.read_count() != 0 {
                self.sleep();
            }
        }

        self.interlock.unlock();
        false
    }

    /// Downgrades a write hold to a read hold.
    pub(crate) fn write_to_read(&self) {
        self.interlock.lock();

        self.set_read_count(self.read_count().wrapping_add(1));
        if self.recursion_depth() != 0 {
            self.set_recursion_depth(self.recursion_depth().wrapping_sub(1));
        } else if self.want_upgrade() {
            self.set_want_upgrade(false);
        } else {
            self.set_want_write(false);
        }

        if self.waiting() {
            self.wakeup();
        }

        self.interlock.unlock();
    }
}
