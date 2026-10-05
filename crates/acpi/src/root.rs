// SPDX-License-Identifier: MIT
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeMemory, rsdt, table, xsdt};

    /// A root pointer at a fixed place naming `root`.
    fn pointer(root: u64, extended: bool) -> Rsdp {
        Rsdp::new(0xf_5320, root, extended)
    }

    #[test]
    fn finds_a_table_through_the_rsdt() {
        let mut memory = FakeMemory::new();
        memory.place(0x7ffe_2335, rsdt(&[0x7ffe_21e9, 0x7ffe_225d]));
        memory.place(0x7ffe_21e9, table(*b"FACP", &[0; 80]));
        memory.place(0x7ffe_225d, table(*b"APIC", &[0; 8]));
        let root = Root::new(&memory, pointer(0x7ffe_2335, false)).unwrap();
        assert_eq!(root.len(), 2);
        assert!(!root.is_empty());
        assert_eq!(root.find(*b"APIC"), Ok(Some(0x7ffe_225d)));
        assert_eq!(root.find(*b"HPET"), Ok(None));
    }

    #[test]
    fn finds_a_table_through_the_xsdt() {
        let mut memory = FakeMemory::new();
        memory.place(0x1_0000_0004, xsdt(&[0x1_0000_1000, 0x2000]));
        memory.place(0x1_0000_1000, table(*b"HPET", &[0; 20]));
        memory.place(0x2000, table(*b"HPET", &[0; 20]));
        let root = Root::new(&memory, pointer(0x1_0000_0004, true)).unwrap();
        assert_eq!(root.len(), 2);
        assert_eq!(root.find(*b"HPET"), Ok(Some(0x1_0000_1000)));
    }

    #[test]
    fn an_empty_root_finds_nothing() {
        let mut memory = FakeMemory::new();
        memory.place(0x1000, rsdt(&[]));
        let root = Root::new(&memory, pointer(0x1000, false)).unwrap();
        assert!(root.is_empty());
        assert_eq!(root.find(*b"APIC"), Ok(None));
    }

    #[test]
    fn a_partial_entry_is_not_listed() {
        let mut memory = FakeMemory::new();
        memory.place(0x1000, table(*b"RSDT", &[0x00, 0x20, 0x00]));
        let root = Root::new(&memory, pointer(0x1000, false)).unwrap();
        assert!(root.is_empty());
    }

    #[test]
    fn rejects_a_root_of_the_other_width() {
        let mut memory = FakeMemory::new();
        memory.place(0x1000, rsdt(&[]));
        assert_eq!(
            Root::new(&memory, pointer(0x1000, true)).unwrap_err(),
            Error::BadSignature
        );
    }

    #[test]
    fn an_unmapped_listed_table_is_an_error() {
        let mut memory = FakeMemory::new();
        memory.place(0x1000, rsdt(&[0x2000]));
        let root = Root::new(&memory, pointer(0x1000, false)).unwrap();
        assert_eq!(root.find(*b"APIC"), Err(Error::Unmapped));
    }
}
