// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Locks for the kernel and its crates, free of spl: each lock type fixes
//! its own interrupt policy.
//!
//! The kernel is non-preemptible: a thread leaves its CPU only by
//! sleeping.  An irq spin lock's holder is in an irq-quiet section, so
//! an interrupt handler may share it with threads; a spin lock enters no
//! section, and the sleeping locks, [`Mutex`] and [`RwLock`], never touch
//! interrupts.  A [`Mutex`] hands off to its first waiter, and an
//! [`RwLock`] serves its waiters first come, first served.  Every lock is
//! generic over a [`Platform`], the zero-sized type through which it
//! reaches the kernel.
//!
//! The four locks are aliases of one [`Lock`] over a raw lock, and their
//! guards of one [`Guard`] or [`SharedGuard`]; the raw locks implement
//! [`RawLock`] and [`RawSharedLock`].  A thread holds at most one lock of
//! a class, the locks built at one site, at a time: the order checker
//! panics on a second.

#![cfg_attr(not(test), no_std)]

#[cfg(debug_assertions)]
mod checker;
mod condvar;
mod guard;
mod lock;
mod mutex;
mod platform;
mod rwlock;
pub mod section;
mod spin;
mod sync;
#[cfg(test)]
mod test_support;
mod wait;

#[cfg(debug_assertions)]
pub use checker::HeldLocks;
pub use condvar::Condvar;
pub use guard::{Guard, SharedGuard};
pub use lock::{Lock, RawLock, RawSharedLock};
pub use mutex::{Mutex, MutexGuard, RawMutex};
pub use platform::{Platform, ThreadRef};
pub use rwlock::{RawRwLock, RwLock, RwLockReadGuard, RwLockWriteGuard};
pub use spin::{
    IrqSpinLock, IrqSpinLockGuard, RawIrqSpinLock, RawSpinLock, SpinLock,
    SpinLockGuard,
};
pub use wait::{Bucket, WaitTable};
