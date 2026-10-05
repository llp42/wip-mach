// SPDX-License-Identifier: MIT
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeMemory, fix_checksum, rsdp_v1, rsdp_v2};
    use std::vec::Vec;

    /// A BIOS data area whose EBDA segment word names `ebda`.
    fn bda(ebda: u64) -> Vec<u8> {
        let segment = u16::try_from(ebda >> 4).unwrap();
        segment.to_le_bytes().to_vec()
    }

    /// Memory with an EBDA at 0x9fc00 and a BIOS area, each holding
    /// `in_ebda` and `in_bios` at the given offsets.
    fn machine(
        in_ebda: &[(usize, &[u8])],
        in_bios: &[(usize, &[u8])],
    ) -> FakeMemory {
        let mut ebda = vec![0; EBDA_SEARCH_LEN];
        for (offset, bytes) in in_ebda {
            ebda[*offset..*offset + bytes.len()].copy_from_slice(bytes);
        }
        let mut bios = vec![0; BIOS_AREA_LEN];
        for (offset, bytes) in in_bios {
            bios[*offset..*offset + bytes.len()].copy_from_slice(bytes);
        }
        let mut memory = FakeMemory::new();
        memory.place(EBDA_SEGMENT, bda(0x9_fc00));
        memory.place(0x9_fc00, ebda);
        memory.place(BIOS_AREA, bios);
        memory
    }

    #[test]
    fn finds_a_v1_pointer_in_the_ebda() {
        let pointer = rsdp_v1(0x7ffe_2335);
        let memory = machine(&[(0x40, &pointer)], &[]);
        let rsdp = find_rsdp(&memory).unwrap();
        assert_eq!(rsdp.address(), 0x9_fc40);
        assert_eq!(rsdp.root(), 0x7ffe_2335);
        assert!(!rsdp.is_extended());
    }

    #[test]
    fn finds_a_v2_pointer_in_the_bios_area() {
        let pointer = rsdp_v2(0x1_2345_6780);
        let memory = machine(&[], &[(0x1_5320, &pointer)]);
        let rsdp = find_rsdp(&memory).unwrap();
        assert_eq!(rsdp.address(), 0xf_5320);
        assert_eq!(rsdp.root(), 0x1_2345_6780);
        assert!(rsdp.is_extended());
    }

    #[test]
    fn the_ebda_is_searched_first() {
        let first = rsdp_v1(0x1000);
        let second = rsdp_v1(0x2000);
        let memory = machine(&[(0x3e0, &first)], &[(0, &second)]);
        assert_eq!(find_rsdp(&memory).unwrap().root(), 0x1000);
    }

    #[test]
    fn a_zero_ebda_segment_skips_the_ebda() {
        let pointer = rsdp_v1(0x2000);
        let mut memory = FakeMemory::new();
        memory.place(EBDA_SEGMENT, bda(0));
        let mut bios = vec![0; BIOS_AREA_LEN];
        bios[..20].copy_from_slice(&pointer);
        memory.place(BIOS_AREA, bios);
        assert_eq!(find_rsdp(&memory).unwrap().root(), 0x2000);
    }

    #[test]
    fn only_16_byte_boundaries_are_searched() {
        let pointer = rsdp_v1(0x1000);
        let memory = machine(&[(0x48, &pointer)], &[]);
        assert_eq!(find_rsdp(&memory), Err(Error::NoRsdp));
    }

    #[test]
    fn rejects_a_bad_v1_checksum() {
        let mut pointer = rsdp_v1(0x1000);
        pointer[8] ^= 1;
        let memory = machine(&[(0, &pointer)], &[]);
        assert_eq!(find_rsdp(&memory), Err(Error::NoRsdp));
    }

    #[test]
    fn rejects_a_bad_v2_checksum() {
        let mut pointer = rsdp_v2(0x1000);
        pointer[32] ^= 1;
        let memory = machine(&[(0, &pointer)], &[]);
        assert_eq!(find_rsdp(&memory), Err(Error::NoRsdp));
    }

    #[test]
    fn passes_over_an_unknown_revision() {
        let mut unknown = rsdp_v1(0x1000);
        unknown[15] = 1;
        fix_checksum(&mut unknown, V1_LEN, 8);
        let good = rsdp_v1(0x2000);
        let memory = machine(&[(0, &unknown), (0x20, &good)], &[]);
        assert_eq!(find_rsdp(&memory).unwrap().root(), 0x2000);
    }

    #[test]
    fn a_pointer_cut_off_by_the_area_end_is_not_found() {
        let v1 = rsdp_v1(0x1000);
        let v2 = rsdp_v2(0x2000);
        let memory = machine(
            &[(EBDA_SEARCH_LEN - 16, &v1[..16])],
            &[(BIOS_AREA_LEN - 32, &v2[..32])],
        );
        assert_eq!(find_rsdp(&memory), Err(Error::NoRsdp));
    }

    #[test]
    fn an_unmapped_area_is_an_error() {
        let memory = FakeMemory::new();
        assert_eq!(find_rsdp(&memory), Err(Error::Unmapped));

        let mut memory = FakeMemory::new();
        memory.place(EBDA_SEGMENT, bda(0x9_fc00));
        assert_eq!(find_rsdp(&memory), Err(Error::Unmapped));

        let mut memory = FakeMemory::new();
        memory.place(EBDA_SEGMENT, bda(0x9_fc00));
        memory.place(0x9_fc00, vec![0; EBDA_SEARCH_LEN]);
        assert_eq!(find_rsdp(&memory), Err(Error::Unmapped));
    }
}
