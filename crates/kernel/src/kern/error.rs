// SPDX-License-Identifier: CMU-Mach
// SPDX-FileCopyrightText: 1991,1990,1989,1988,1987 Carnegie Mellon University
// SPDX-FileCopyrightText: 1993,1994 The University of Utah and the Computer Systems Laboratory (CSL)
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from GNU Mach (commit c5701c1c1c8f330f7a790a4a0bc6b3434213722b)
// original files: include/mach/kern_return.h

//! The errors the task, thread, processor and host operations report, and
//! the traps that short-circuit their RPCs.

use crate::arch::x86_64::error::Error as MachineError;
use crate::device::r#return::DeviceError;
use crate::ipc::error::Error as IpcError;
use crate::vm::error::Error as VmError;

/// A failed operation on a task, thread, processor, processor set or host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An argument does not apply to this call: a null or inactive object,
    /// or a flavor, priority or policy out of range.
    InvalidArgument,
    /// The object's current state does not allow the call.
    Failure,
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

/// Why a trap that short-circuits a kernel RPC failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RpcError {
    /// The name does not denote the kernel object the trap needs; the user
    /// stub sends the RPC as a message instead.
    NotKernelObject,
    /// A task or thread operation failed.
    Kern(Error),
    /// An operation on a right or a space failed.
    Ipc(IpcError),
    /// A virtual-memory operation failed.
    Vm(VmError),
    /// A device operation failed.
    Device(DeviceError),
}

impl From<Error> for RpcError {
    fn from(error: Error) -> Self {
        Self::Kern(error)
    }
}

impl From<IpcError> for RpcError {
    fn from(error: IpcError) -> Self {
        Self::Ipc(error)
    }
}

impl From<VmError> for RpcError {
    fn from(error: VmError) -> Self {
        Self::Vm(error)
    }
}

impl From<DeviceError> for RpcError {
    fn from(error: DeviceError) -> Self {
        Self::Device(error)
    }
}
