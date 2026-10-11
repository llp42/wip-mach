// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel services gsync calls beyond VM's, supplied as a zero-sized
//! type.
//!
//! [`Platform`] extends [`mach_vm::Platform`]: map lookup, the kernel map,
//! user copy and the running thread's block and wait result come from VM's
//! seam, and this trait adds the thread-directed wait and wakeup gsync's
//! waiters need.

use core::ffi::{c_uint, c_void};
use core::ptr::NonNull;

/// The kernel services gsync calls beyond VM's.
///
/// # Safety
///
/// gsync's correctness rests on each function keeping the contract its
/// documentation states, as the kernel's own callers rely on it.
pub unsafe trait Platform: mach_vm::Platform {
    /// Returns the running thread, as [`Self::wake_thread`] takes it.
    ///
    /// # Panics
    ///
    /// If the CPU runs no thread.
    fn current_thread() -> NonNull<c_void>;

    /// Declares that the running thread is about to wait, for at most
    /// `timeout` milliseconds when there is one; the thread then blocks with
    /// [`mach_vm::Platform::thread_block`].
    ///
    /// # Safety
    ///
    /// Thread context.
    unsafe fn will_wait(timeout: Option<c_uint>);

    /// Ends the wait of `thread`, which [`Self::will_wait`] began, with a
    /// wakeup.
    ///
    /// # Safety
    ///
    /// `thread` must be a live thread [`Self::current_thread`] returned; the
    /// call takes the thread's own locks.
    unsafe fn wake_thread(thread: NonNull<c_void>);
}
