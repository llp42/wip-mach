// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The HPET description table: where the timer block's registers are.

use crate::sdt::{self, HEADER_LEN, read_u8, read_u64};
use crate::{Error, PhysicalMemory};

/// The bytes of the table: the header, the event-timer block ID, the base
/// address, the HPET number, the minimum tick and the page protection.
const TABLE_LEN: usize = HEADER_LEN + 20;
/// The offset of the base address, a generic address structure.
const BASE_ADDRESS: usize = HEADER_LEN + 4;
/// The generic-address space ID of system memory.
const SYSTEM_MEMORY: u8 = 0;

/// The HPET description, checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hpet {
    base_address: u64,
}

impl Hpet {
    /// Reads the HPET table at `address`, as [`crate::Root::find`]
    /// reports it.
    ///
    /// # Errors
    ///
    /// As a table lookup: [`Error::Unmapped`], [`Error::BadSignature`],
    /// [`Error::BadChecksum`], and [`Error::Corrupted`] for a table too
    /// short for its layout or a register block outside system memory.
    pub fn new<M: PhysicalMemory>(
        memory: &M,
        address: u64,
    ) -> Result<Self, Error> {
        let table = sdt::map_table(memory, address, *b"HPET")?;
        if table.len() < TABLE_LEN
            || read_u8(&table, BASE_ADDRESS) != SYSTEM_MEMORY
        {
            return Err(Error::Corrupted);
        }
        Ok(Self {
            base_address: read_u64(&table, BASE_ADDRESS + 4),
        })
    }

    /// The physical address of the timer block's registers.
    #[must_use]
    pub const fn base_address(self) -> u64 {
        self.base_address
    }
}
