// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Locks for the kernel and its crates, free of spl: each lock type fixes
//! its own interrupt policy.
//!
//! The kernel is non-preemptible: a thread leaves its CPU only by
//! sleeping.  An [`IrqSpinLock`]'s holder is in an irq-quiet section, so
//! an interrupt handler may share it with threads; a [`SpinMutex`] or a
//! [`TicketLock`] enters no section, and the sleeping locks, [`Mutex`] and
//! [`RwLock`], never touch interrupts.  A [`Mutex`] hands off to its first
//! waiter, and an [`RwLock`] serves its waiters first come, first served.
//! The sleeping locks are generic over a [`Platform`], the zero-sized type
//! through which they reach the kernel.
//!
//! Each lock is a [`lock_api`] [`Mutex`](lock_api::Mutex) or
//! [`RwLock`](lock_api::RwLock) over one of this crate's raw locks, which
//! carry the policy: the flag or ticket word, the irq-quiet section, the
//! handoff and the order checker's hooks.  The guards are `lock_api`'s.
//! The raw locks stay public for a record whose lock word sits beside data
//! it guards, which `lock_api::Mutex` cannot express because it owns its
//! data.
//!
//! Every lock also carries a **name** — the debug checker's node for it,
//! set by [`irq_spin_lock!`] and [`mutex!`], and dropped from
//! a release build, which keeps the lock one word.
//!
//! One lock, one file: each of [`SpinMutex`], [`TicketLock`],
//! [`IrqSpinLock`], [`Mutex`] and [`RwLock`] is one module holding that
//! lock's raw type, its trait impls and its alias, and nothing else.  No
//! lock's module is reached from another's, and no two locks share a
//! word: where two would want the same shape, each carries its own.  Only
//! what is not a lock is shared — [`Platform`], the seam a lock names,
//! [`Bucket`] and [`WaitTable`], the queues the sleeping locks park in,
//! and the debug checker.

#![no_std]

#[cfg(debug_assertions)]
pub mod checker;
mod irq_spin_lock;
mod mutex;
mod platform;
mod rwlock;
mod spin_mutex;
mod ticket_lock;
mod wait;

#[cfg(debug_assertions)]
pub use checker::HeldLocks;
pub use irq_spin_lock::{IrqSpinLock, RawIrqSpinLock};
pub use lock_api;
pub use lock_api::MutexGuard;
pub use mutex::{Mutex, RawMutex};
pub use platform::{Platform, ThreadRef};
pub use rwlock::{RawRwLock, RwLock};
pub use spin_mutex::{RawSpinMutex, SpinMutex};
pub use ticket_lock::{RawTicketLock, TicketLock};
pub use wait::{Bucket, WaitTable};
