// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! `thread_set_self_state`: the trap that loads the caller's own state
//! and returns to user mode through it.

use crate::platform::Platform;
use core::ffi::{c_int, c_uint};
use mach_thread::error::Error as TaskError;

/// The code a successful `thread_set_self_state` leaves for the caller.
const KERN_SUCCESS: c_int = 0;

/// The `natural_t` words the C scratch array of `thread_set_self_state()`
/// held.
const MAX_SELF_STATE: usize = 150;

/// Copy the user's state words into `scratch`, reporting how many were copied.
///
/// # Safety
///
/// A `count` in range requires `new_state` to be readable for that many
/// `natural_t` words; a fault is what `copyin()` reports.
unsafe fn copy_self_state<P: Platform>(
    new_state: *mut c_uint,
    count: c_uint,
    scratch: &mut [c_uint; MAX_SELF_STATE],
) -> Option<usize> {
    let words = usize::try_from(count).ok()?;
    if words == 0 || words > MAX_SELF_STATE {
        return None;
    }

    let faulted =
        unsafe { P::copyin_into(new_state.cast(), &mut scratch[..words]) };
    if faulted.is_err() { None } else { Some(words) }
}

/// Set the current thread's machine state from a user buffer.
///
/// # Safety
///
/// Reached as trap -77 with a user `new_state`; a fault is what `copyin()`
/// reports.
pub unsafe fn set_self_state<P: Platform>(
    flavor: c_int,
    new_state: *mut c_uint,
    count: c_uint,
) -> Result<(), TaskError> {
    let mut scratch = [0; MAX_SELF_STATE];

    let Some(words) =
        (unsafe { copy_self_state::<P>(new_state, count, &mut scratch) })
    else {
        return Err(TaskError::InvalidArgument);
    };

    let thread = P::cpu_thread();
    // SAFETY: `thread` is the running thread.
    unsafe {
        P::set_syscall_return(thread, KERN_SUCCESS);
        let result = P::set_state(
            thread,
            flavor,
            scratch.as_mut_ptr(),
            // `words` is at most `MAX_SELF_STATE`, so the narrowing cannot
            // lose anything.
            words as c_uint,
        );
        if result.is_ok() {
            (P::EXCEPTION_RETURN)();
        }
        result
    }
}
