// SPDX-License-Identifier: MIT
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeMemory, table};
    use std::vec::Vec;

    /// An HPET body whose base address is `address` in address space
    /// `space`.
    fn body(space: u8, address: u64) -> Vec<u8> {
        let mut body = vec![0; TABLE_LEN - HEADER_LEN];
        body[..4].copy_from_slice(&0x8086_a201u32.to_le_bytes());
        body[4] = space;
        body[8..16].copy_from_slice(&address.to_le_bytes());
        body
    }

    #[test]
    fn reads_the_base_address() {
        let mut memory = FakeMemory::new();
        memory.place(0x7ffe_22d5, table(*b"HPET", &body(0, 0xfed0_0000)));
        let hpet = Hpet::new(&memory, 0x7ffe_22d5).unwrap();
        assert_eq!(hpet.base_address(), 0xfed0_0000);
    }

    #[test]
    fn rejects_a_register_block_in_io_space() {
        let mut memory = FakeMemory::new();
        memory.place(0x1000, table(*b"HPET", &body(1, 0x40)));
        assert_eq!(Hpet::new(&memory, 0x1000), Err(Error::Corrupted));
    }

    #[test]
    fn rejects_a_short_table() {
        let mut memory = FakeMemory::new();
        let mut short = body(0, 0xfed0_0000);
        short.truncate(19);
        memory.place(0x1000, table(*b"HPET", &short));
        assert_eq!(Hpet::new(&memory, 0x1000), Err(Error::Corrupted));
    }

    #[test]
    fn a_table_lookup_error_reaches_the_caller() {
        let mut memory = FakeMemory::new();
        memory.place(0x1000, table(*b"APIC", &body(0, 0xfed0_0000)));
        assert_eq!(Hpet::new(&memory, 0x1000), Err(Error::BadSignature));
    }
}
