// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel's gsync [`Platform`] and its table of waiters.

use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::platform::MachPlatform;
use core::ffi::{c_uint, c_void};
use core::ptr::NonNull;
use mach_gsync::{Gsync, Platform};
use mach_thread::ipc_sched;
use mach_thread::sched_prim::{self, THREAD_AWAKENED};

/// The kernel's table of threads waiting on an address.
pub static GSYNC: Gsync<MachPlatform> = Gsync::new();

// SAFETY: each function forwards to the kernel routine gsync called before
// the seam, whose contract the trait restates.
unsafe impl Platform for MachPlatform {
    fn current_thread() -> NonNull<c_void> {
        let thread = per_cpu::thread();
        assert!(!thread.is_null(), "current_thread: no current thread");
        // SAFETY: checked non-null above.
        unsafe { NonNull::new_unchecked(thread.cast()) }
    }

    unsafe fn will_wait(timeout: Option<c_uint>) {
        let thread = per_cpu::thread();
        // SAFETY: thread context, so the running thread is live.
        match timeout {
            Some(msecs) => unsafe {
                ipc_sched::thread_will_wait_with_timeout(thread, msecs);
            },
            None => unsafe { ipc_sched::thread_will_wait(thread) },
        }
    }

    unsafe fn wake_thread(thread: NonNull<c_void>) {
        // SAFETY: the caller passes a live thread that declared its wait;
        // `clear_wait()` takes the thread lock itself.
        unsafe {
            sched_prim::clear_wait::<Self>(
                thread.as_ptr().cast(),
                THREAD_AWAKENED,
                0,
            );
        }
    }
}
