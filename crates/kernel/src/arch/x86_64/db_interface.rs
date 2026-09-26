// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/db_interface.c:
//   Copyright (c) 1993,1992,1991,1990 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The debug register interface, which `i386/i386/db_interface.c` used to
//! define and `i386/i386/db_interface.h` declares.
//!

use crate::arch::types::VmOffset;
use crate::arch::vm_param::VM_MAX_USER_ADDRESS;
use crate::arch::x86_64::pcb::{I386DebugState, I386SavedState, Pcb};
use crate::arch::x86_64::per_cpu;
use crate::kern::types::KernError;
use core::arch::asm;
use core::ffi::c_ulong;
use core::sync::atomic::{AtomicBool, Ordering};

/// `zero_dr` of `i386/i386/db_interface.c`: whether the current debug
/// registers are zero.  The `Relaxed` ordering is enough because the value
/// only skips redundant register writes and no other thread synchronizes on
/// it.
static ZERO_DR: AtomicBool = AtomicBool::new(false);

/// `ddb_regs` of <`i386/db_machdep.h>`: the register state the debugger reads
/// through `DDB_REGS`.
pub static mut DDB_REGS: I386SavedState =
    // SAFETY: every field is an integer or an array of them, so the all-zero
    // pattern is a valid `I386SavedState`.
    unsafe { core::mem::zeroed() };

/// The C's `set_dr0()` of <`i386/proc_reg.h`>.
fn set_dr0(value: c_ulong) {
    // SAFETY: a debug-register write is a CPL0 operation.
    unsafe {
        asm!("mov {value}, %dr0", value = in(reg) value, options(att_syntax, nostack, preserves_flags));
    };
}

/// The C's `set_dr1()` of <`i386/proc_reg.h`>.
fn set_dr1(value: c_ulong) {
    // SAFETY: a debug-register write is a CPL0 operation.
    unsafe {
        asm!("mov {value}, %dr1", value = in(reg) value, options(att_syntax, nostack, preserves_flags));
    };
}

/// The C's `set_dr2()` of <`i386/proc_reg.h`>.
fn set_dr2(value: c_ulong) {
    // SAFETY: a debug-register write is a CPL0 operation.
    unsafe {
        asm!("mov {value}, %dr2", value = in(reg) value, options(att_syntax, nostack, preserves_flags));
    };
}

/// The C's `set_dr3()` of <`i386/proc_reg.h`>.
fn set_dr3(value: c_ulong) {
    // SAFETY: a debug-register write is a CPL0 operation.
    unsafe {
        asm!("mov {value}, %dr3", value = in(reg) value, options(att_syntax, nostack, preserves_flags));
    };
}

/// The C's `set_dr7()` of <`i386/proc_reg.h`>.
fn set_dr7(value: c_ulong) {
    // SAFETY: a debug-register write is a CPL0 operation.
    unsafe {
        asm!("mov {value}, %dr7", value = in(reg) value, options(att_syntax, nostack, preserves_flags));
    };
}

/// `db_load_context()` of <`i386/db_interface.h`>.
///
/// # Safety
///
/// `pcb` must be the live pcb of a thread about to run on this CPU.
pub(crate) unsafe fn load_context(pcb: *mut Pcb) {
    let dr = unsafe { (*pcb).ims.ids.dr };
    let will_zero_dr =
        dr[0] == 0 && dr[1] == 0 && dr[2] == 0 && dr[3] == 0 && dr[7] == 0;

    if !(ZERO_DR.load(Ordering::Relaxed) && will_zero_dr) {
        set_dr0(c_ulong::from(dr[0]));
        set_dr1(c_ulong::from(dr[1]));
        set_dr2(c_ulong::from(dr[2]));
        set_dr3(c_ulong::from(dr[3]));
        set_dr7(c_ulong::from(dr[7]));
        ZERO_DR.store(will_zero_dr, Ordering::Relaxed);
    }
}

/// `db_get_debug_state()` of <`i386/db_interface.h`>.
///
/// # Safety
///
/// `pcb` must be live and `state` writable.
pub(crate) unsafe fn get_debug_state(
    pcb: *mut Pcb,
    state: *mut I386DebugState,
) {
    unsafe { *state = (*pcb).ims.ids };
}

/// `db_set_debug_state()` of <`i386/db_interface.h`>.
///
/// # Safety
///
/// `pcb` must be live and `state` readable.
pub(crate) unsafe fn set_debug_state(
    pcb: *mut Pcb,
    state: *const I386DebugState,
) -> Result<(), KernError> {
    let state = unsafe { &*state };

    for i in 0..=3 {
        // `c_uint` widens exactly into a `VmOffset`, and
        // `VM_MIN_USER_ADDRESS` is zero, so only the C's upper-bound test
        // can bite.
        let addr = state.dr[i] as VmOffset;
        if addr >= VM_MAX_USER_ADDRESS {
            return Err(KernError::InvalidArgument);
        }
    }
    unsafe { (*pcb).ims.ids = *state };

    // SAFETY: the running thread's `pcb` field is live.
    if pcb == unsafe { (*per_cpu::thread()).pcb } {
        // SAFETY: the check above makes this the running thread's pcb.
        unsafe { load_context(pcb) };
    }

    Ok(())
}
