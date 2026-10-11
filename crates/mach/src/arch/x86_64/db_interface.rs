// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The debug-register interface: each thread's breakpoints, loaded when it
//! runs.

use crate::arch::types::VmOffset;
use crate::arch::vm_param::VM_MAX_USER_ADDRESS;
use crate::arch::x86_64::error::Error;
use crate::arch::x86_64::pcb::{I386DebugState, Pcb};
use crate::arch::x86_64::per_cpu;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::registers::debug::{
    DebugAddressRegister, Dr0, Dr1, Dr2, Dr3, Dr7,
};

/// Whether the current debug registers are zero.  The `Relaxed` ordering is
/// enough because the value only skips redundant register writes and no other
/// thread synchronizes on it.
static ZERO_DR: AtomicBool = AtomicBool::new(false);

/// Loads the debug registers of `pcb`'s thread, skipping the writes when they
/// and the loaded ones are all zero.
///
/// # Safety
///
/// `pcb` must be the live pcb of a thread about to run on this CPU.
pub(crate) unsafe fn load_context(pcb: *mut Pcb) {
    let dr = unsafe { (*pcb).ims.ids.dr };
    let will_zero_dr =
        dr[0] == 0 && dr[1] == 0 && dr[2] == 0 && dr[3] == 0 && dr[7] == 0;

    if !(ZERO_DR.load(Ordering::Relaxed) && will_zero_dr) {
        Dr0::write(u64::from(dr[0]));
        Dr1::write(u64::from(dr[1]));
        Dr2::write(u64::from(dr[2]));
        Dr3::write(u64::from(dr[3]));
        Dr7::write_raw(u64::from(dr[7]));
        ZERO_DR.store(will_zero_dr, Ordering::Relaxed);
    }
}

/// Reports the debug state of `pcb`'s thread into `state`.
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

/// Sets the debug state of `pcb`'s thread from `state`.
///
/// # Safety
///
/// `pcb` must be live and `state` readable.
pub(crate) unsafe fn set_debug_state(
    pcb: *mut Pcb,
    state: *const I386DebugState,
) -> Result<(), Error> {
    let state = unsafe { &*state };

    for i in 0..=3 {
        // `c_uint` widens exactly into a `VmOffset`, and
        // `VM_MIN_USER_ADDRESS` is zero, so only the C's upper-bound test
        // can bite.
        let addr = state.dr[i] as VmOffset;
        if addr >= VM_MAX_USER_ADDRESS {
            return Err(Error::InvalidArgument);
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
