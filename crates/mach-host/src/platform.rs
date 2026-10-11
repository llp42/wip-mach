// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! What the host asks of the machine.

use crate::types::Halt;
use core::ffi::c_int;

/// The machine services the host needs beyond the task platform's.
///
/// The kernel implements it on the same zero-sized type as the VM, IPC and
/// task platforms. Tasks, threads, processors, ports and `kalloc` come from
/// those seams; this one adds the machine clock and the CPUs' end.
///
/// # Safety
///
/// Each item must keep the contract its documentation states.
pub unsafe trait Platform:
    mach_thread::platform::Platform + clock::Platform
{
    /// The machine clock: the wall clock, uptime and the gradual adjustment.
    fn clock() -> &'static clock::Clock<Self>;

    /// Raises the interrupt level to the clock's and returns the old level.
    ///
    /// # Safety
    ///
    /// The caller must hand the result back to `splx`.
    unsafe fn splclock() -> c_int;

    /// Stops every CPU as `halt` says: into the debugger, halted, or
    /// rebooting.
    fn halt(halt: Halt) -> !;
}
