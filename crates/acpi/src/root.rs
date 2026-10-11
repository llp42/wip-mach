// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The root table: the RSDT with 32-bit table addresses, or the XSDT with
//! 64-bit ones.

use crate::sdt::{self, HEADER_LEN, read_bytes, read_u32, read_u64};
use crate::{Error, PhysicalMemory, Rsdp};

/// The RSDT or XSDT a root pointer named, mapped and checksummed.
#[derive(Debug)]
pub struct Root<'a, M: PhysicalMemory> {
    memory: &'a M,
    table: M::Region<'a>,
    extended: bool,
}

impl<'a, M: PhysicalMemory> Root<'a, M> {
    /// Maps the root table `rsdp` names.
    ///
    /// # Errors
    ///
    /// As a table lookup: [`Error::Unmapped`], [`Error::BadSignature`]
    /// when the table is not the RSDT or XSDT the pointer promised,
    /// [`Error::Corrupted`] and [`Error::BadChecksum`].
    pub fn new(memory: &'a M, rsdp: Rsdp) -> Result<Self, Error> {
        let signature = if rsdp.is_extended() {
            *b"XSDT"
        } else {
            *b"RSDT"
        };
        let table = sdt::map_table(memory, rsdp.root(), signature)?;
        Ok(Self {
            memory,
            table,
            extended: rsdp.is_extended(),
        })
    }

    /// The number of tables the root lists.
    #[must_use]
    pub fn len(&self) -> usize {
        (self.table.len() - HEADER_LEN) / self.entry_len()
    }

    /// Whether the root lists no table.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The physical address of the first listed table whose header
    /// carries `signature`, or `None` when no listed table does.
    ///
    /// Only the header is read; the table's own checksum is checked when
    /// it is mapped whole.
    ///
    /// # Errors
    ///
    /// [`Error::Unmapped`] when a listed table's header cannot be mapped.
    pub fn find(&self, signature: [u8; 4]) -> Result<Option<u64>, Error> {
        for index in 0..self.len() {
            let offset = HEADER_LEN + index * self.entry_len();
            let address = if self.extended {
                read_u64(&self.table, offset)
            } else {
                u64::from(read_u32(&self.table, offset))
            };
            let header = self
                .memory
                .map(address, HEADER_LEN)
                .ok_or(Error::Unmapped)?;
            if read_bytes::<4>(&header, 0) == signature {
                return Ok(Some(address));
            }
        }
        Ok(None)
    }

    /// The bytes of one listed table address.
    const fn entry_len(&self) -> usize {
        if self.extended { 8 } else { 4 }
    }
}
