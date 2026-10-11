// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The data-only records of the fakes.

use core::cell::Cell;
use core::sync::atomic::AtomicBool;
#[cfg(debug_assertions)]
use lock::HeldLocks;
use mach_ipc::ipc_thread::{SavedReceive, ThreadIpc};
use std::thread::Thread;

/// A pmap of the tests: nothing to translate, only an identity.
pub struct FakePmap;

/// How many pmaps the running thread created and destroyed.
pub struct PmapCounts {
    /// Pmaps `pmap_create` made.
    pub created: Cell<usize>,
    /// Pmaps `pmap_destroy` freed.
    pub destroyed: Cell<usize>,
}

/// The record a `lock::ThreadRef` of [`Host`](crate::Host) points at;
/// leaked, so a late unpark of a finished thread stays sound.
#[repr(align(8))]
pub struct HostThread {
    pub thread: Thread,
    pub parked: AtomicBool,
}

/// The running thread's records under [`Host`](crate::Host).
pub struct Local {
    pub me: &'static HostThread,
    #[cfg(debug_assertions)]
    pub held: &'static HeldLocks,
}

/// The IPC state a host thread carries, as the kernel's thread does.
pub struct FakeThread {
    pub ipc: ThreadIpc,
    pub saved: SavedReceive,
}
