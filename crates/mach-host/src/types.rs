// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The plain data the host hands the machine.

/// How `host_reboot` stops the machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Halt {
    /// Enter the kernel debugger.
    Debugger,
    /// Halt every CPU.
    Halt,
    /// Reboot the machine.
    Reboot,
}
