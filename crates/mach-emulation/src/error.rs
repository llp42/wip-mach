// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The errors the emulation calls report.

use mach_vm::error::Error as VmError;

/// A failed emulation call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A dispatch table or staging buffer could not be allocated.
    ResourceShortage,
    /// A virtual-memory operation failed.
    Vm(VmError),
}

impl From<VmError> for Error {
    fn from(error: VmError) -> Self {
        Self::Vm(error)
    }
}
