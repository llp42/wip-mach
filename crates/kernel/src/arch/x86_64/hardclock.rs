// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/hardclock.c and i386/i386/hardclock.h:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
//   Copyright (c) 1991 IBM Corporation.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The clock interrupt, which `i386/i386/hardclock.c` used to define and
//! `i386/i386/hardclock.h` declares.

use crate::arch::x86_64::locore;
use crate::arch::x86_64::pcb::I386InterruptState;
use crate::arch::x86_64::trap::EFL_VM;
use crate::kern::mach_clock;
use core::ffi::{c_char, c_int};
use core::ptr;

/// `SPL0` of <i386/ipl.h>: the base interrupt level.
const SPL0: c_int = 0;

/// `hardclock()` of `i386/i386/hardclock.c`: charge one clock tick to the
/// interrupted context.
///
/// # Safety
///
/// `regs` must point at the saved interrupt state; it is read only when
/// `ret_addr` is the stub's return, the case the C dereferenced it in.
pub(crate) unsafe fn hardclock(
    _iunit: c_int,
    old_ipl: c_int,
    ret_addr: *const c_char,
    regs: *mut I386InterruptState,
) {
    let interrupted_user = ret_addr == ptr::addr_of!(locore::return_to_iret);
    if interrupted_user {
        let regs = unsafe { &*regs };
        let usermode = regs.efl & EFL_VM != 0 || regs.cs & 0x03 != 0;
        mach_clock::interrupt(mach_clock::TICK, usermode, old_ipl == SPL0);
    } else {
        mach_clock::interrupt(mach_clock::TICK, false, false);
    }
}

/// `hardclock()` of <i386/hardclock.h>: the `ivect` entry the interrupt
/// trampoline calls.
///
/// # Safety
///
/// `regs` must point at the interrupt state the entry code pushed, which
/// stays valid for the call.
pub(crate) unsafe extern "C" fn hardclock_entry(
    iunit: c_int,
    old_ipl: c_int,
    ret_addr: *const c_char,
    regs: *mut I386InterruptState,
) {
    unsafe { hardclock(iunit, old_ipl, ret_addr, regs) };
}
