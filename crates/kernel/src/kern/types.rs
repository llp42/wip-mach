// SPDX-License-Identifier: CMU-Mach
// Derived from include/mach/kern_return.h:
//   Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University.
//   Copyright (c) 1993,1994 The University of Utah and the Computer
//   Systems Laboratory (CSL).
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Kernel error codes.

/// A failure a kernel operation can report.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernError {
    /// The address is not currently valid.
    InvalidAddress = 1,
    /// The memory is valid, but does not allow the required forms of access.
    ProtectionFailure = 2,
    /// The address range is already in use, or no range of the requested size
    /// could be found.
    NoSpace = 3,
    /// The operation was not applicable to this type of argument.
    InvalidArgument = 4,
    /// The operation could not be performed.
    Failure = 5,
    /// A system resource could not be allocated to fulfill the request.
    ResourceShortage = 6,
    /// The task does not hold receive rights for the port argument.
    NotReceiver = 7,
    /// The access restriction is invalid.
    NoAccess = 8,
    /// During a page fault, the target address refers to a memory object that
    /// has been destroyed.
    MemoryFailure = 9,
    /// During a page fault, the memory object could not return the data.
    MemoryError = 10,
    /// The receive right is not a member of a port set.
    NotInSet = 12,
    /// The name already denotes a right in the task.
    NameExists = 13,
    /// The operation was aborted.
    Aborted = 14,
    /// The name does not denote a right in the task.
    InvalidName = 15,
    /// The target task is not an active task.
    InvalidTask = 16,
    /// The name denotes a right, but not one appropriate here.
    InvalidRight = 17,
    /// A blatant range error.
    InvalidValue = 18,
    /// The operation would overflow the limit on user references.
    UrefsOverflow = 19,
    /// The supplied port capability is improper.
    InvalidCapability = 20,
    /// The task already has send or receive rights for the port under another
    /// name.
    RightExists = 21,
    /// The target host is not a host.
    InvalidHost = 22,
    /// An attempt was made to supply precious data for memory already present
    /// in a memory object.
    MemoryPresent = 23,
    /// A page was marked `VM_PROT_NOTIFY` and an attempt was made to write it.
    WriteProtectionFailure = 24,
    /// The object has been terminated and is no longer available.
    Terminated = 26,
    /// The kernel operation timed out.
    Timedout = 27,
    /// The kernel operation was interrupted.
    Interrupted = 28,
}

impl KernError {
    /// The discriminant as a byte.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The error a byte stands for.
    ///
    /// # Errors
    ///
    /// Returns the error the byte names, or [`Self::Failure`] for a byte
    /// that names no error.
    pub const fn from_u8(code: u8) -> Result<(), Self> {
        match code {
            0 => Ok(()),
            1 => Err(Self::InvalidAddress),
            2 => Err(Self::ProtectionFailure),
            3 => Err(Self::NoSpace),
            4 => Err(Self::InvalidArgument),
            6 => Err(Self::ResourceShortage),
            7 => Err(Self::NotReceiver),
            8 => Err(Self::NoAccess),
            9 => Err(Self::MemoryFailure),
            10 => Err(Self::MemoryError),
            12 => Err(Self::NotInSet),
            13 => Err(Self::NameExists),
            14 => Err(Self::Aborted),
            15 => Err(Self::InvalidName),
            16 => Err(Self::InvalidTask),
            17 => Err(Self::InvalidRight),
            18 => Err(Self::InvalidValue),
            19 => Err(Self::UrefsOverflow),
            20 => Err(Self::InvalidCapability),
            21 => Err(Self::RightExists),
            22 => Err(Self::InvalidHost),
            23 => Err(Self::MemoryPresent),
            24 => Err(Self::WriteProtectionFailure),
            26 => Err(Self::Terminated),
            27 => Err(Self::Timedout),
            28 => Err(Self::Interrupted),
            _ => Err(Self::Failure),
        }
    }
}
