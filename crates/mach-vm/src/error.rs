// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The errors the virtual-memory system reports.

/// A failed virtual-memory operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The address is not valid in the target map.
    InvalidAddress,
    /// The memory is valid, but does not permit the access asked for.
    ProtectionFailure,
    /// No free range of the size asked for could be found.
    NoSpace,
    /// An argument does not apply to this call.
    InvalidArgument,
    /// The call could not be performed.
    Failure,
    /// A kernel resource could not be allocated.
    ResourceShortage,
    /// The access restriction asked for is not allowed.
    NoAccess,
    /// The memory object could not return the data.
    MemoryError,
    /// A port the call needs is not valid.
    InvalidName,
    /// The target map, or the proxy call's IPC space, is null.
    InvalidTask,
    /// The host argument is not the host.
    InvalidHost,
    /// The data supply found the page already present.
    MemoryPresent,
    /// The entry asks for `VM_PROT_NOTIFY` and the fault is a write.
    WriteProtectionFailure,
    /// An object copy waiting for a pager was interrupted.
    Interrupted,
}
