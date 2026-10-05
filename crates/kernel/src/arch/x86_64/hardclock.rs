// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/hardclock.c and i386/i386/hardclock.h:
//   Copyright (c) 1991,1990 Carnegie Mellon University.
//   Copyright (c) 1991 IBM Corporation.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The clock interrupt.

use crate::arch::x86_64::clock_platform;
use crate::arch::x86_64::locore;
use crate::arch::x86_64::pcb::I386InterruptState;
use crate::arch::x86_64::per_cpu;
use crate::arch::x86_64::trap::EFL_VM;
use crate::kern::machine;
use crate::kern::smp::CpuId;
use core::ffi::{c_char, c_int, c_uint};
use core::ptr;

/// The base interrupt level.
const SPL0: c_int = 0;

/// Charges one clock tick to the interrupted context.
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
    let (usermode, basepri) = if interrupted_user {
        let regs = unsafe { &*regs };
        (
            regs.efl & EFL_VM != 0 || regs.cs & 0x03 != 0,
            old_ipl == SPL0,
        )
    } else {
        (false, false)
    };

    let thread = per_cpu::thread();
    // SAFETY: `thread` is the interrupted thread or null, and this CPU
    // owns its own accounting.
    unsafe {
        machine::tick_accounting(thread, machine::TICK as c_uint, usermode);
    }

    if per_cpu::cpu_id() == CpuId::BOOT {
        clock_platform::tick(basepri);
    }
}

/// The interrupt entry the trampoline calls for the clock.
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
