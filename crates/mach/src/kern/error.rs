// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The errors the task, thread, processor and host operations report, and
//! the traps that short-circuit their RPCs.

use crate::arch::x86_64::error::Error as MachineError;
use mach_gsync::error::Error as GsyncError;
use mach_host::error::Error as HostError;
use mach_ipc::error::Error as IpcError;
use mach_thread::error::Error as TaskError;
use mach_vm::error::Error as VmError;

/// A failed operation on a task, thread, processor, processor set or host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An argument does not apply to this call: a null or inactive object,
    /// or a flavor, priority or policy out of range.
    InvalidArgument,
    /// The object's current state does not allow the call.
    Failure,
    /// The kernel does not implement the call.
    NotImplemented,
    /// A kernel resource could not be allocated.
    ResourceShortage,
    /// The host argument is not the host, or not the privileged host.
    InvalidHost,
    /// The target task is null.
    InvalidTask,
    /// The emulation call's task is null.
    NoEmulationTask,
    /// The address is not valid in the caller's map.
    InvalidAddress,
    /// The memory behind the address could not be read.
    MemoryFailure,
    /// The caller lacks the privilege the call needs.
    NoAccess,
    /// The event table has no free slot.
    NoSpace,
    /// The machine refused the access the call asked for.
    ProtectionFailure,
    /// The thread could not be stopped.
    Aborted,
    /// A wait was interrupted.
    Interrupted,
    /// A wait timed out.
    TimedOut,
    /// An operation on a right or a space failed.
    Ipc(IpcError),
    /// A virtual-memory operation failed.
    Vm(VmError),
    /// The machine layer failed.
    Machine(MachineError),
}

impl From<IpcError> for Error {
    fn from(error: IpcError) -> Self {
        Self::Ipc(error)
    }
}

impl From<GsyncError> for Error {
    fn from(error: GsyncError) -> Self {
        match error {
            GsyncError::InvalidAddress => Self::InvalidAddress,
            GsyncError::MemoryFailure => Self::MemoryFailure,
            GsyncError::InvalidArgument => Self::InvalidArgument,
            GsyncError::Interrupted => Self::Interrupted,
            GsyncError::TimedOut => Self::TimedOut,
        }
    }
}

impl From<HostError> for Error {
    fn from(error: HostError) -> Self {
        match error {
            HostError::InvalidArgument => Self::InvalidArgument,
            HostError::InvalidHost => Self::InvalidHost,
            HostError::ResourceShortage => Self::ResourceShortage,
        }
    }
}

impl From<TaskError> for Error {
    fn from(error: TaskError) -> Self {
        match error {
            TaskError::InvalidArgument => Self::InvalidArgument,
            TaskError::Failure => Self::Failure,
            TaskError::ResourceShortage => Self::ResourceShortage,
            TaskError::NoSpace => Self::NoSpace,
            TaskError::ProtectionFailure => Self::ProtectionFailure,
            TaskError::InvalidHost => Self::InvalidHost,
            TaskError::NoEmulationTask => Self::NoEmulationTask,
            TaskError::NoAccess => Self::NoAccess,
            TaskError::Aborted => Self::Aborted,
            TaskError::Interrupted => Self::Interrupted,
            TaskError::Ipc(error) => Self::Ipc(error),
            TaskError::Vm(error) => Self::Vm(error),
        }
    }
}

impl From<VmError> for Error {
    fn from(error: VmError) -> Self {
        Self::Vm(error)
    }
}

impl From<MachineError> for Error {
    fn from(error: MachineError) -> Self {
        Self::Machine(error)
    }
}
