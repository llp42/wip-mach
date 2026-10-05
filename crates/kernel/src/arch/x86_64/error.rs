// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The errors the `x86_64` machine layer reports.

use crate::vm::error::Error as VmError;

/// A failed machine-dependent operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A state flavor, count, selector, address or range the machine does
    /// not accept.
    InvalidArgument,
    /// The machine has no floating-point unit, or not the save format the
    /// flavor needs.
    NoFpu,
    /// The I/O range overlaps the PCI configuration ports the kernel took.
    PortsTaken,
    /// The machine does not implement the operation.
    NotSupported,
    /// Every user GDT slot is in use.
    NoSpace,
    /// A table, record or port could not be allocated.
    ResourceShortage,
    /// A VM map operation failed.
    Vm(VmError),
}
