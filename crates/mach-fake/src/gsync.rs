// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! [`Fake`] as gsync's platform: a thread record per host thread; the wait
//! and wakeup no test reaches panic with their name.

use crate::fake::Fake;
use core::ffi::{c_uint, c_void};
use core::ptr::NonNull;
use mach_gsync::Platform;

std::thread_local! {
    /// The running thread's record; leaked, so its address stays valid.
    static THREAD: NonNull<c_void> =
        NonNull::from(Box::leak(Box::new(0_u64))).cast();
}

// SAFETY: the implemented function keeps the trait's contract with a
// per-thread record; the rest panic before doing anything.
unsafe impl Platform for Fake {
    fn current_thread() -> NonNull<c_void> {
        THREAD.with(|thread| *thread)
    }

    unsafe fn will_wait(_timeout: Option<c_uint>) {
        unimplemented!("will_wait")
    }

    unsafe fn wake_thread(_thread: NonNull<c_void>) {
        unimplemented!("wake_thread")
    }
}
