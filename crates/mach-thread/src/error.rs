// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The errors the task, thread and processor operations report.

use mach_emulation::Error as EmulationError;
use mach_ipc::error::Error as IpcError;
use mach_vm::error::Error as VmError;

/// A failed operation on a task, thread, processor or processor set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An argument does not apply to this call: a null or inactive object,
    /// or a flavor, priority or policy out of range.
    InvalidArgument,
    /// The object's current state does not allow the call.
    Failure,
    /// A kernel resource could not be allocated.
    ResourceShortage,
    /// A table the machine keeps has no free slot.
    NoSpace,
    /// The machine refused the access the call asked for.
    ProtectionFailure,
    /// The host argument is not the host, or not the privileged host.
    InvalidHost,
    /// The emulation call's task is null.
    NoEmulationTask,
    /// The caller lacks the privilege the call needs.
    NoAccess,
    /// The thread could not be stopped.
    Aborted,
    /// A wait was interrupted.
    Interrupted,
    /// An operation on a right or a space failed.
    Ipc(IpcError),
    /// A virtual-memory operation failed.
    Vm(VmError),
}

impl From<EmulationError> for Error {
    fn from(error: EmulationError) -> Self {
        match error {
            EmulationError::ResourceShortage => Self::ResourceShortage,
            EmulationError::Vm(error) => Self::Vm(error),
        }
    }
}

impl From<IpcError> for Error {
    fn from(error: IpcError) -> Self {
        Self::Ipc(error)
    }
}

impl From<VmError> for Error {
    fn from(error: VmError) -> Self {
        Self::Vm(error)
    }
}
