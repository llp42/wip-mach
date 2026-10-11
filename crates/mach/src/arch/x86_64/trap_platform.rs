// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The traps' platform: what the trap bodies ask of the `x86_64` machine.

use crate::arch::x86_64::locore::thread_syscall_return;
use crate::arch::x86_64::platform::MachPlatform;
use crate::mig::code::{kern_return, receive_return};
use mach_ipc::error::ReceiveError;
use mach_trap::platform::Platform;

// SAFETY: the return goes through `thread_syscall_return`, which leaves for
// user mode with the code in the trap's return register.
unsafe impl Platform for MachPlatform {
    unsafe fn return_from_receive(result: Result<(), ReceiveError>) -> ! {
        // SAFETY: the caller is in a `mach_msg` receive, whose result this
        // is.
        unsafe {
            thread_syscall_return(kern_return(result.map_err(receive_return)))
        }
    }
}
