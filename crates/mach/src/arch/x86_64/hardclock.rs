// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The clock interrupt.

use crate::arch::x86_64::clock_platform;
use crate::arch::x86_64::locore;
use crate::arch::x86_64::pcb::I386InterruptState;
use crate::arch::x86_64::per_cpu;
use core::ffi::{c_char, c_int, c_uint};
use core::ptr;
use mach_host::machine;
use mach_thread::smp::CpuId;
use x86_64::registers::rflags::RFlags;

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
            RFlags::from_bits_retain(regs.efl as u64)
                .contains(RFlags::VIRTUAL_8086_MODE)
                || regs.cs & 0x03 != 0,
            old_ipl == SPL0,
        )
    } else {
        (false, false)
    };

    let thread = per_cpu::thread();
    // SAFETY: `thread` is the interrupted thread or null, and this CPU
    // owns its own accounting.
    unsafe {
        machine::tick_accounting(
            thread,
            mach_sched::sched::TICK as c_uint,
            usermode,
        );
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
