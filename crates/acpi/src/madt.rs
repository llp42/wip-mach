// SPDX-License-Identifier: GPL-2.0-or-later
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

bitflags::bitflags! {
    /// The flags of a local-APIC entry.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct LocalApicFlags: u32 {
        /// The processor is usable now.
        const ENABLED = 1 << 0;
        /// A disabled processor can be enabled at run time.
        const ONLINE_CAPABLE = 1 << 1;
        // The bits the specification reserves.
        const _ = !0;
    }
}

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
            let flags = LocalApicFlags::from_bits_retain(read_u32(bytes, 4));
            MadtEntry::LocalApic {
                apic_id: read_u8(bytes, 3),
                enabled: flags.contains(LocalApicFlags::ENABLED),
                online_capable: flags.contains(LocalApicFlags::ONLINE_CAPABLE),
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
