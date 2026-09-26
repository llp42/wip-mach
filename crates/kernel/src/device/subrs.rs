// SPDX-License-Identifier: CMU-Mach
// Derived from device/subrs.c:
//   Copyright (c) 1993,1991,1990,1989,1988 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The random device subroutines of `device/subrs.c`, declared in
//! <device/subrs.h> and <`device/if_ether.h`>.

use crate::arch::types::VmOffset;
use crate::kern::sched_prim::{THREAD_AWAKENED, thread_wakeup_prim};
use core::ffi::c_void;
use core::ptr;

/// The event a wait and its matching wake share: an opaque `vm_offset_t` that
/// nothing ever dereferences, the C `(event_t) channel` cast.
const fn event(channel: VmOffset) -> *mut c_void {
    ptr::with_exposed_provenance_mut(channel)
}

/// `wakeup()` of device/subrs.c, the BSD compatibility name for the
/// [`thread_wakeup_prim()`] call the C's `thread_wakeup` macro expands to.
///
/// # Safety
///
/// `channel` must be the event the matching [`sleep()`] or `assert_wait()`
/// names.
pub(crate) unsafe fn wakeup(channel: VmOffset) {
    unsafe {
        thread_wakeup_prim(event(channel), 0, THREAD_AWAKENED);
    }
}
