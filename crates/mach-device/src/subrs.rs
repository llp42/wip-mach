// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The device subroutines.

use crate::platform::Platform;
use core::ffi::c_void;
use core::ptr;
use mach_thread::sched_prim::{THREAD_AWAKENED, thread_wakeup_prim};
use mach_vm::param::VmOffset;

/// The event a wait and its matching wake share: an opaque address nothing
/// ever dereferences.
const fn event(channel: VmOffset) -> *mut c_void {
    ptr::with_exposed_provenance_mut(channel)
}

/// Wakes the threads waiting on `channel`, the event the matching `sleep()`
/// or `assert_wait()` names.
pub fn wakeup<P: Platform>(channel: VmOffset) {
    thread_wakeup_prim::<P>(event(channel), 0, THREAD_AWAKENED);
}
