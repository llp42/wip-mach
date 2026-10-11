// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The ACPI static-table reader: the root system description pointer,
//! the root table it names, the MADT and the HPET description table.
//!
//! The reader never touches memory itself. A caller supplies a
//! [`PhysicalMemory`] that maps physical ranges; [`find_rsdp`] finds the
//! root pointer in the BIOS areas, [`Root`] lists the tables, and
//! [`Madt`] and [`Hpet`] decode the two this kernel reads. Every table is
//! mapped whole and checksummed before a field of it is read.
//!
//! | item | purpose |
//! |---|---|
//! | [`PhysicalMemory`] | the caller's mapper of physical ranges |
//! | [`find_rsdp`] | find the root pointer in the EBDA or the BIOS area |
//! | [`Rsdp`] | where the root table is, and whether it is an XSDT |
//! | [`Root`] | the RSDT or XSDT, searched by signature |
//! | [`Madt`] | the local-APIC address and the interrupt controllers |
//! | [`MadtEntries`] | the iterator over the MADT's entries |
//! | [`MadtEntry`] | one decoded MADT entry |
//! | [`Hpet`] | the HPET register block's address |
//! | [`Error`] | why a table was rejected |

#![no_std]
#![forbid(unsafe_code)]

mod hpet;
mod madt;
mod root;
mod rsdp;
mod sdt;

use core::fmt;
use core::ops::Deref;

pub use hpet::Hpet;
pub use madt::{Madt, MadtEntries, MadtEntry};
pub use root::Root;
pub use rsdp::{Rsdp, find_rsdp};

/// Why a table was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No valid root system description pointer in the BIOS areas.
    NoRsdp,
    /// [`PhysicalMemory::map`] refused a range a table needs.
    Unmapped,
    /// A table does not carry the signature it was looked up by.
    BadSignature,
    /// A table's bytes do not sum to zero.
    BadChecksum,
    /// A table's length or one of its entries does not fit its layout.
    Corrupted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRsdp => f.write_str("no ACPI root pointer"),
            Self::Unmapped => f.write_str("ACPI table not mappable"),
            Self::BadSignature => f.write_str("ACPI table signature mismatch"),
            Self::BadChecksum => f.write_str("ACPI table checksum mismatch"),
            Self::Corrupted => f.write_str("corrupted ACPI table"),
        }
    }
}

/// The caller's view of physical memory.
///
/// The ranges mapped are firmware tables, which nothing writes while the
/// reader holds them.
pub trait PhysicalMemory {
    /// A mapped range; dropping it may unmap it.
    type Region<'a>: Deref<Target = [u8]> + fmt::Debug
    where
        Self: 'a;

    /// Maps the `len` bytes at physical address `phys`, or returns `None`
    /// when they cannot be mapped.
    ///
    /// The region holds exactly `len` bytes.
    fn map(&self, phys: u64, len: usize) -> Option<Self::Region<'_>>;
}
