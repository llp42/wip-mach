// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Why a trap failed.

use mach_device::r#return::DeviceError;
use mach_ipc::error::Error as IpcError;
use mach_thread::error::Error as TaskError;
use mach_vm::error::Error as VmError;

/// Why a trap that stands in for an RPC failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The name does not denote the kernel object the trap needs; the user
    /// stub sends the RPC as a message instead.
    NotKernelObject,
    /// A task or thread operation failed.
    Task(TaskError),
    /// An operation on a right or a space failed.
    Ipc(IpcError),
    /// A virtual-memory operation failed.
    Vm(VmError),
    /// A device operation failed.
    Device(DeviceError),
}

impl From<TaskError> for Error {
    fn from(error: TaskError) -> Self {
        Self::Task(error)
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

impl From<DeviceError> for Error {
    fn from(error: DeviceError) -> Self {
        Self::Device(error)
    }
}
