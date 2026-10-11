// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! What the bootstrap asks of the machine.

use core::ffi::CStr;
use mach_vm::param::{VmOffset, VmSize};

/// A module the boot loader left: a command line and an image.
pub trait Module {
    /// The module's command line.
    fn command_line(&self) -> &CStr;

    /// The module's image bytes.
    fn image(&self) -> &[u8];
}

/// The machine services the bootstrap needs beyond the task platform's.
///
/// The kernel implements it on the same zero-sized type as the VM, IPC and
/// task platforms. Tasks, threads, ports, maps and user copy come from
/// those seams; this one adds the machine.
///
/// # Safety
///
/// Each item must keep the contract its documentation states.
pub unsafe trait Platform: mach_thread::platform::Platform {
    /// A module the boot loader left.
    type Module: Module;

    /// The first address above user space: the first thread's stack ends
    /// there.
    const USER_ADDRESS_END: VmOffset;

    /// Points the current thread's user registers at `entry`, with its stack
    /// at the top of `stack_base..stack_base + stack_size` below `arg_size`
    /// bytes of arguments, and returns the arguments' address.
    ///
    /// # Safety
    ///
    /// Runs on the current thread, a user thread whose machine state is
    /// live.
    unsafe fn set_user_regs(
        stack_base: VmOffset,
        stack_size: VmSize,
        entry: VmOffset,
        arg_size: VmSize,
    ) -> VmOffset;

    /// Reads a line from the console into `line`, for the boot script's
    /// pause.
    fn read_line(line: &mut [u8]);
}
