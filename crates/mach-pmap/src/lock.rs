// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The spinning reader-writer lock the pmap system takes.

use core::hint;
use core::sync::atomic::{AtomicU32, Ordering};
use mach_page::simple_lock::SimpleLock;

/// How many times a waiter looks at the state with the interlock released
/// before it takes the interlock to look again.
const LOCK_WAIT_TIME: u32 = 100;

/// A writer holds the lock or waits for the readers to leave.
const WANT_WRITE: u32 = 1 << 16;

/// The read count's bits of the state word.
const READ_COUNT: u32 = WANT_WRITE - 1;

/// The pmap system's reader-writer lock: readers share it, a writer waits
/// for them to leave, and every waiter spins.
pub struct LockData {
    /// The read count and [`WANT_WRITE`]: written only with the interlock
    /// held, and read without it by a waiter spinning for a change.
    state: AtomicU32,
    interlock: SimpleLock,
}

impl LockData {
    /// An unheld lock.
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(0),
            interlock: SimpleLock::new(),
        }
    }

    // Relaxed, here and in the stores: the interlock orders every change,
    // and a waiter re-reads the word under it before it acts.
    fn state(&self) -> u32 {
        self.state.load(Ordering::Relaxed)
    }

    fn set_state(&self, state: u32) {
        self.state.store(state, Ordering::Relaxed);
    }

    /// The C's bounded spin: release the interlock, pause up to
    /// `LOCK_WAIT_TIME` times while `held` says the state still keeps the
    /// caller out, then re-take the interlock.
    fn pause_while(&self, held: impl Fn(u32) -> bool) {
        self.interlock.unlock();
        for _ in 1..LOCK_WAIT_TIME {
            if !held(self.state()) {
                break;
            }
            hint::spin_loop();
        }
        self.interlock.lock();
    }

    /// Takes the lock for writing.
    pub fn write(&self) {
        self.interlock.lock();
        while self.state() & WANT_WRITE != 0 {
            self.pause_while(|state| state & WANT_WRITE != 0);
        }
        self.set_state(self.state() | WANT_WRITE);
        while self.state() & READ_COUNT != 0 {
            self.pause_while(|state| state & READ_COUNT != 0);
        }
        self.interlock.unlock();
    }

    /// Releases a read or write hold.
    pub fn done(&self) {
        self.interlock.lock();
        let state = self.state();
        if state & READ_COUNT != 0 {
            self.set_state(state - 1);
        } else {
            self.set_state(state & !WANT_WRITE);
        }
        self.interlock.unlock();
    }

    /// Takes the lock for reading.
    pub fn read(&self) {
        self.interlock.lock();
        while self.state() & WANT_WRITE != 0 {
            self.pause_while(|state| state & WANT_WRITE != 0);
        }
        let state = self.state();
        // The C's 16-bit read count wrapped.
        self.set_state(
            (state & !READ_COUNT) | (state.wrapping_add(1) & READ_COUNT),
        );
        self.interlock.unlock();
    }
}

impl Default for LockData {
    fn default() -> Self {
        Self::new()
    }
}
