// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The root system description pointer, and its search in the BIOS
//! areas a legacy-booted machine leaves it in.

use crate::sdt::{read_bytes, read_u8, read_u16, read_u32, read_u64};
use crate::{Error, PhysicalMemory, sdt};

/// The bytes an ACPI 1.0 root pointer covers with its checksum.
const V1_LEN: usize = 20;
/// The bytes an ACPI 2.0 root pointer covers with its extended checksum.
const V2_LEN: usize = 36;
/// The root pointer starts on a 16-byte boundary.
const ALIGN: usize = 16;
/// The word in the BIOS data area holding the EBDA's real-mode segment.
const EBDA_SEGMENT: u64 = 0x40e;
/// The EBDA bytes searched.
const EBDA_SEARCH_LEN: usize = 1024;
/// The BIOS read-only area searched, up to 1 MiB.
const BIOS_AREA: u64 = 0xe_0000;
/// The bytes of the BIOS read-only area.
const BIOS_AREA_LEN: usize = 0x2_0000;

/// A validated root pointer: where it sits, and the root table it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rsdp {
    address: u64,
    root: u64,
    extended: bool,
}

impl Rsdp {
    /// A root pointer at `address` naming the root table at `root`, an
    /// XSDT when `extended`.
    pub(crate) const fn new(address: u64, root: u64, extended: bool) -> Self {
        Self {
            address,
            root,
            extended,
        }
    }

    /// The physical address of the root pointer itself.
    #[must_use]
    pub const fn address(self) -> u64 {
        self.address
    }

    /// The physical address of the root table.
    #[must_use]
    pub const fn root(self) -> u64 {
        self.root
    }

    /// Whether the root table is an XSDT, with 64-bit entries, rather
    /// than an RSDT.
    #[must_use]
    pub const fn is_extended(self) -> bool {
        self.extended
    }
}

/// Finds the root pointer in the first KiB of the EBDA, then in the BIOS
/// read-only area below 1 MiB.
///
/// A revision 0 pointer names an RSDT and is checked over its 20 bytes;
/// a revision 2 pointer names an XSDT and is checked over 20 and 36
/// bytes. A candidate of any other revision is passed over.
///
/// # Errors
///
/// [`Error::Unmapped`] when a search area cannot be mapped, and
/// [`Error::NoRsdp`] when neither area holds a valid root pointer.
pub fn find_rsdp<M: PhysicalMemory>(memory: &M) -> Result<Rsdp, Error> {
    let segment = memory.map(EBDA_SEGMENT, 2).ok_or(Error::Unmapped)?;
    let ebda = u64::from(read_u16(&segment, 0)) << 4;
    drop(segment);

    if ebda != 0
        && let Some(rsdp) = search(memory, ebda, EBDA_SEARCH_LEN)?
    {
        return Ok(rsdp);
    }
    search(memory, BIOS_AREA, BIOS_AREA_LEN)?.ok_or(Error::NoRsdp)
}

/// The first valid root pointer in the `len` bytes at `base`.
fn search<M: PhysicalMemory>(
    memory: &M,
    base: u64,
    len: usize,
) -> Result<Option<Rsdp>, Error> {
    let area = memory.map(base, len).ok_or(Error::Unmapped)?;
    Ok((0..len).step_by(ALIGN).find_map(|offset| {
        let (root, extended) = area.get(offset..).and_then(decode)?;
        Some(Rsdp::new(base + offset as u64, root, extended))
    }))
}

/// The root table a root pointer at the start of `bytes` names, and
/// whether it is an XSDT; `None` unless the signature, the revision and
/// the checksums are good.
fn decode(bytes: &[u8]) -> Option<(u64, bool)> {
    if read_bytes::<8>(bytes, 0) != *b"RSD PTR " {
        return None;
    }
    let v1 = bytes.get(..V1_LEN)?;
    if !sdt::sums_to_zero(v1) {
        return None;
    }
    match read_u8(bytes, 15) {
        0 => Some((u64::from(read_u32(bytes, 16)), false)),
        2 => {
            let v2 = bytes.get(..V2_LEN)?;
            sdt::sums_to_zero(v2).then(|| (read_u64(bytes, 24), true))
        }
        _ => None,
    }
}
