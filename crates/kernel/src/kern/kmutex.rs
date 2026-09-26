// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from kern/kmutex.c and kern/kmutex.h:
//   Copyright (C) 2017 Free Software Foundation, Inc.
//   Contributed by Agustina Arzille <avarzille@riseup.net>, 2017.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel mutex, which `kern/kmutex.c` used to define.

use crate::arch::x86_64::per_cpu;
use crate::kern::lock::SimpleLock;
use crate::kern::sched_prim::{
    THREAD_AWAKENED, thread_sleep, thread_wakeup_prim,
};
use crate::kern::types::KernError;
use core::ffi::{c_int, c_void};
use core::mem::offset_of;
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

/// The three states of a mutex, the `KMUTEX_*` constants of <kern/kmutex.h>.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
enum State {
    /// `KMUTEX_AVAIL`: unowned.
    Avail = 0,
    /// `KMUTEX_LOCKED`: owned, with no known sleeper.
    Locked = 1,
    /// `KMUTEX_CONTENDED`: owned, with a sleeper to wake.
    Contended = 2,
}

impl State {
    /// The `unsigned int` the state is stored in.
    const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// `struct kmutex` of <kern/kmutex.h>: the three-state sleepable mutex.
///
/// # Invariants
///
/// `state` always holds one of the three `KMUTEX_*` values, and `lock`
/// serializes every slow path.
#[repr(C)]
#[allow(missing_docs)]
pub struct KMutex {
    state: AtomicU32,
    lock: SimpleLock,
}

const _: () = assert!(size_of::<KMutex>() == 8);
const _: () = assert!(align_of::<KMutex>() == 4);
const _: () = assert!(offset_of!(KMutex, state) == 0);
const _: () = assert!(offset_of!(KMutex, lock) == 4);

impl KMutex {
    /// A fresh mutex: available, with an unlocked interlock.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(State::Avail.as_u32()),
            lock: SimpleLock::new(),
        }
    }

    /// `kmutex_trylock()` in C.  The compare-exchange acquires on success;
    /// its failure is `Relaxed`, since the failure path takes the interlock
    /// before it reads anything the state protects.
    ///
    /// # Errors
    ///
    /// Returns [`KernError::Failure`] when the mutex is already held.
    pub fn try_lock(&self) -> Result<(), KernError> {
        if self
            .state
            .compare_exchange(
                State::Avail.as_u32(),
                State::Locked.as_u32(),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            Ok(())
        } else {
            Err(KernError::Failure)
        }
    }

    /// `kmutex_lock()` in C.
    ///
    /// # Errors
    ///
    /// Returns [`KernError::Interrupted`] when `interruptible` is set and the
    /// sleep ends early; the mutex then belongs to its owner, which sets the
    /// state.
    pub fn lock(&self, interruptible: bool) -> Result<(), KernError> {
        if self.try_lock().is_ok() {
            return Ok(());
        }

        self.lock.lock();
        if self
            .state
            .swap(State::Contended.as_u32(), Ordering::Acquire)
            == State::Avail.as_u32()
        {
            self.lock.unlock();
            return Ok(());
        }

        // SAFETY: this mutex is live and outlives the call, and the interlock
        // `thread_sleep()` is handed is the live second field of the same
        // record; the call releases it before blocking, taking over the hold
        // from above.
        unsafe {
            thread_sleep(
                ptr::from_ref(self).cast_mut().cast::<c_void>(),
                ptr::from_ref(&self.lock).cast_mut(),
                c_int::from(interruptible),
            );
        }

        // SAFETY: this is the thread that just slept, and `per_cpu::thread()`
        // reads it from the live per-CPU block.
        let wait_result = unsafe { (*per_cpu::thread()).wait_result };
        if wait_result == THREAD_AWAKENED {
            Ok(())
        } else {
            Err(KernError::Interrupted)
        }
    }

    /// `kmutex_unlock()` in C.  The compare-exchange releases on success,
    /// like the C `atomic_cas_rel()`; its failure and the later reset store
    /// are `Relaxed`, since the interlock orders the slow path.
    pub fn unlock(&self) {
        if self
            .state
            .compare_exchange(
                State::Locked.as_u32(),
                State::Avail.as_u32(),
                Ordering::Release,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            return;
        }

        self.lock.lock();

        // SAFETY: the event is this live mutex, the key its sleepers
        // registered with, and the caller owns it for the call.
        let woke = unsafe {
            thread_wakeup_prim(
                ptr::from_ref(self).cast_mut().cast::<c_void>(),
                1,
                THREAD_AWAKENED,
            )
        };

        if woke == 0 {
            // Every sleeper was interrupted and left; reset the state.
            self.state.store(State::Avail.as_u32(), Ordering::Relaxed);
        }

        self.lock.unlock();
    }
}

impl Default for KMutex {
    fn default() -> Self {
        Self::new()
    }
}
