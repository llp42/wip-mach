// SPDX-License-Identifier: CMU-Mach
// SPDX-FileCopyrightText: 1991,1990,1989 Carnegie Mellon University
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from GNU Mach (commit c5701c1c1c8f330f7a790a4a0bc6b3434213722b)
// original files: include/device/device_types.h

//! The results of device operations.

use crate::vm::error::Error as VmError;

/// A failed device operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceError {
    /// The hardware reported an IO error.
    IoError,
    /// The operation would block, and the caller asked it not to.
    WouldBlock,
    /// There is no such device, or it is not open.
    NoSuchDevice,
    /// The device is open for exclusive use.
    AlreadyOpen,
    /// The device has been shut down.
    DeviceDown,
    /// The device does not support the operation.
    InvalidOperation,
    /// The record number is out of range.
    InvalidRecnum,
    /// The IO size is out of range.
    InvalidSize,
    /// The request could not be allocated.
    NoMemory,
    /// The device cannot be written to.
    ReadOnly,
    /// A kernel resource the operation needs could not be allocated.
    ResourceShortage,
    /// An argument does not apply to this call.
    InvalidArgument,
    /// A value is out of range for this call.
    InvalidValue,
    /// The request's buffer could not be allocated or mapped.
    Vm(VmError),
}

/// How a driver finished an operation it did not fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceSuccess {
    /// The operation completed, and the caller owns the result.
    Success,
    /// The request is queued and the driver completes it, so the caller must
    /// not.
    IoQueued,
}

/// The result of a driver operation.
pub type IoResult = Result<DeviceSuccess, DeviceError>;

/// Whether a device call answers through its own reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The call finished, and its reply carries the outcome.
    Now,
    /// The call sends no reply of its own: the completion of a queued request
    /// sends it, it already went out, or the reply port is not valid.
    Withheld,
}

/// The result of a device call.
pub type ReplyResult = Result<Reply, DeviceError>;
