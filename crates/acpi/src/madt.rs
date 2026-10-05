// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The multiple APIC description table: the local-APIC address and one
//! entry per interrupt controller.

use crate::sdt::{self, HEADER_LEN, read_u8, read_u16, read_u32};
use crate::{Error, PhysicalMemory};

/// The bytes before the first entry: the header, the local-APIC address
/// and the flags.
const ENTRIES_OFFSET: usize = HEADER_LEN + 8;

/// The entry type of a processor's local APIC.
const LOCAL_APIC: u8 = 0;
/// The entry type of an I/O APIC.
const IO_APIC: u8 = 1;
/// The entry type of an interrupt source override.
const INTERRUPT_OVERRIDE: u8 = 2;

/// A local-APIC flag: the processor is usable now.
const LOCAL_APIC_ENABLED: u32 = 1 << 0;
/// A local-APIC flag: a disabled processor can be enabled at run time.
const LOCAL_APIC_ONLINE_CAPABLE: u32 = 1 << 1;

/// The MADT, mapped and checksummed.
#[derive(Debug)]
pub struct Madt<'a, M: PhysicalMemory + 'a> {
    table: M::Region<'a>,
}

impl<'a, M: PhysicalMemory> Madt<'a, M> {
    /// Maps the MADT at `address`, as [`crate::Root::find`] reports it.
    ///
    /// # Errors
    ///
    /// As a table lookup: [`Error::Unmapped`], [`Error::BadSignature`],
    /// [`Error::BadChecksum`], and [`Error::Corrupted`] for a table too
    /// short for the local-APIC address and flags.
    pub fn new(memory: &'a M, address: u64) -> Result<Self, Error> {
        let table = sdt::map_table(memory, address, *b"APIC")?;
        if table.len() < ENTRIES_OFFSET {
            return Err(Error::Corrupted);
        }
        Ok(Self { table })
    }

    /// The physical address of every processor's local APIC.
    #[must_use]
    pub fn local_apic_address(&self) -> u32 {
        read_u32(&self.table, HEADER_LEN)
    }

    /// The entries, in table order.
    #[must_use]
    pub fn entries(&self) -> MadtEntries<'_> {
        MadtEntries {
            rest: self.table.get(ENTRIES_OFFSET..).unwrap_or_default(),
        }
    }
}

/// One MADT entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MadtEntry {
    /// A processor's local APIC.
    LocalApic {
        /// The local APIC's ID.
        apic_id: u8,
        /// The processor is usable now.
        enabled: bool,
        /// The processor is disabled but can be enabled at run time.
        online_capable: bool,
    },
    /// An I/O APIC.
    IoApic {
        /// The I/O APIC's ID.
        id: u8,
        /// The physical address of its register window.
        address: u32,
        /// The first global system interrupt its pins deliver.
        gsi_base: u32,
    },
    /// An ISA interrupt delivered on another global system interrupt.
    InterruptOverride {
        /// The bus, 0 for ISA.
        bus: u8,
        /// The bus-relative interrupt.
        source: u8,
        /// The global system interrupt it is delivered on.
        gsi: u32,
        /// The polarity and trigger-mode flags.
        flags: u16,
    },
    /// An entry of a type this reader does not decode.
    Other {
        /// The entry type.
        kind: u8,
    },
}

/// The iterator over a MADT's entries.
///
/// An entry whose length is under two bytes, runs past the table, or is
/// shorter than its type's layout yields one [`Error::Corrupted`] and
/// ends the iteration.
#[derive(Clone, Debug)]
pub struct MadtEntries<'t> {
    rest: &'t [u8],
}

impl Iterator for MadtEntries<'_> {
    type Item = Result<MadtEntry, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let length = usize::from(read_u8(self.rest, 1));
        let entry = match self.rest.split_at_checked(length) {
            Some((entry, rest)) => {
                self.rest = rest;
                decode(entry)
            }
            None => Err(Error::Corrupted),
        };
        if entry.is_err() {
            self.rest = &[];
        }
        Some(entry)
    }
}

/// The entry `bytes` holds, or [`Error::Corrupted`] when they are fewer
/// than its type's layout needs; every layout opens with the two bytes
/// of type and length, so a zero-length entry is corrupted too.
fn decode(bytes: &[u8]) -> Result<MadtEntry, Error> {
    let kind = read_u8(bytes, 0);
    let layout_len = match kind {
        LOCAL_APIC => 8,
        IO_APIC => 12,
        INTERRUPT_OVERRIDE => 10,
        _ => 2,
    };
    if bytes.len() < layout_len {
        return Err(Error::Corrupted);
    }

    Ok(match kind {
        LOCAL_APIC => {
            let flags = read_u32(bytes, 4);
            MadtEntry::LocalApic {
                apic_id: read_u8(bytes, 3),
                enabled: flags & LOCAL_APIC_ENABLED != 0,
                online_capable: flags & LOCAL_APIC_ONLINE_CAPABLE != 0,
            }
        }
        IO_APIC => MadtEntry::IoApic {
            id: read_u8(bytes, 2),
            address: read_u32(bytes, 4),
            gsi_base: read_u32(bytes, 8),
        },
        INTERRUPT_OVERRIDE => MadtEntry::InterruptOverride {
            bus: read_u8(bytes, 2),
            source: read_u8(bytes, 3),
            gsi: read_u32(bytes, 4),
            flags: read_u16(bytes, 8),
        },
        _ => MadtEntry::Other { kind },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeMemory, table};
    use std::vec::Vec;

    /// A MADT naming the local APIC at 0xfee00000, with `entries` after
    /// its flags.
    fn madt(entries: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::from(0xfee0_0000u32.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        for entry in entries {
            body.extend_from_slice(entry);
        }
        table(*b"APIC", &body)
    }

    /// The entries of `bytes` placed as a MADT.
    fn entries_of(bytes: Vec<u8>) -> Vec<Result<MadtEntry, Error>> {
        let mut memory = FakeMemory::new();
        memory.place(0x7ffe_225d, bytes);
        let madt = Madt::new(&memory, 0x7ffe_225d).unwrap();
        madt.entries().collect()
    }

    #[test]
    fn decodes_the_entries_of_a_two_cpu_machine() {
        let mut memory = FakeMemory::new();
        memory.place(
            0x7ffe_225d,
            madt(&[
                &[0, 8, 0, 0, 1, 0, 0, 0],
                &[0, 8, 1, 1, 2, 0, 0, 0],
                &[1, 12, 0, 0, 0, 0, 0xc0, 0xfe, 0, 0, 0, 0],
                &[2, 10, 0, 0, 2, 0, 0, 0, 0, 0],
                &[2, 10, 0, 9, 9, 0, 0, 0, 0x0d, 0],
                &[4, 6, 0xff, 0, 0, 1],
            ]),
        );
        let madt = Madt::new(&memory, 0x7ffe_225d).unwrap();
        assert_eq!(madt.local_apic_address(), 0xfee0_0000);
        let entries: Vec<_> = madt.entries().collect();
        assert_eq!(
            entries,
            [
                Ok(MadtEntry::LocalApic {
                    apic_id: 0,
                    enabled: true,
                    online_capable: false,
                }),
                Ok(MadtEntry::LocalApic {
                    apic_id: 1,
                    enabled: false,
                    online_capable: true,
                }),
                Ok(MadtEntry::IoApic {
                    id: 0,
                    address: 0xfec0_0000,
                    gsi_base: 0,
                }),
                Ok(MadtEntry::InterruptOverride {
                    bus: 0,
                    source: 0,
                    gsi: 2,
                    flags: 0,
                }),
                Ok(MadtEntry::InterruptOverride {
                    bus: 0,
                    source: 9,
                    gsi: 9,
                    flags: 0x0d,
                }),
                Ok(MadtEntry::Other { kind: 4 }),
            ]
        );
    }

    #[test]
    fn a_zero_length_entry_ends_the_walk() {
        assert_eq!(
            entries_of(madt(&[
                &[0, 0, 0, 0, 1, 0, 0, 0],
                &[4, 6, 0, 0, 0, 1]
            ])),
            [Err(Error::Corrupted)]
        );
    }

    #[test]
    fn an_entry_past_the_table_ends_the_walk() {
        assert_eq!(
            entries_of(madt(&[&[4, 6, 0, 0, 0, 1], &[1, 12, 0, 0]])),
            [Ok(MadtEntry::Other { kind: 4 }), Err(Error::Corrupted)]
        );
    }

    #[test]
    fn a_lone_trailing_byte_ends_the_walk() {
        assert_eq!(entries_of(madt(&[&[0]])), [Err(Error::Corrupted)]);
    }

    #[test]
    fn an_entry_shorter_than_its_layout_ends_the_walk() {
        assert_eq!(
            entries_of(madt(&[
                &[2, 8, 0, 0, 2, 0, 0, 0],
                &[4, 6, 0, 0, 0, 1]
            ])),
            [Err(Error::Corrupted)]
        );
    }

    #[test]
    fn a_table_without_the_apic_fields_is_corrupted() {
        let mut memory = FakeMemory::new();
        memory.place(0x1000, table(*b"APIC", &[0; 7]));
        assert_eq!(Madt::new(&memory, 0x1000).unwrap_err(), Error::Corrupted);
    }

    #[test]
    fn a_table_lookup_error_reaches_the_caller() {
        let memory = FakeMemory::new();
        assert_eq!(Madt::new(&memory, 0x1000).unwrap_err(), Error::Unmapped);
    }
}
