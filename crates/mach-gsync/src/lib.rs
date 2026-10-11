// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! GNU Mach's address-based synchronization: a thread waits on a word of a
//! task's memory, keyed by the task's map or, for shared memory, by the VM
//! object behind it, until another thread wakes it.
//!
//! Everything gsync asks of the rest of the kernel arrives through
//! [`Platform`], a zero-sized type parameter the kernel implements.  It
//! extends [`mach_vm::Platform`], so map lookup, the kernel map, user copy
//! and the running thread's block come from VM's seam; gsync's own adds the
//! running thread, the wait it starts and the wakeup of a waiting thread.
//! The kernel keeps the one [`Gsync`] table in a static and calls its
//! methods.

#![no_std]
// These routines mirror the C's integer and pointer conversions one for
// one: the widths and alignments are known at each site, and the
// truncations, sign changes and wraps are deliberate.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_ptr_alignment,
    clippy::cast_sign_loss
)]

mod bucket;
pub mod error;
pub mod gsync;
pub mod platform;
mod probe;
pub mod types;
mod waiter;

pub use gsync::Gsync;
pub use platform::Platform;
pub use types::Flags;
