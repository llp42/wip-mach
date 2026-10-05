// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! A sparse physical memory over host buffers, and builders for the
//! tables the tests place in it.

use crate::PhysicalMemory;
use crate::sdt::HEADER_LEN;
use std::vec::Vec;

/// Physical memory made of separate buffers; a range maps only when one
/// buffer holds all of it.
#[derive(Debug)]
pub struct FakeMemory {
    regions: Vec<(u64, Vec<u8>)>,
}

impl FakeMemory {
    pub(crate) const fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    /// Places `bytes` at physical address `address`.
    pub(crate) fn place(&mut self, address: u64, bytes: Vec<u8>) {
        self.regions.push((address, bytes));
    }
}

impl PhysicalMemory for FakeMemory {
    type Region<'a> = &'a [u8];

    fn map(&self, phys: u64, len: usize) -> Option<&[u8]> {
        self.regions.iter().find_map(|(base, bytes)| {
            let start = phys
                .checked_sub(*base)
                .and_then(|offset| usize::try_from(offset).ok())?;
            bytes.get(start..start.checked_add(len)?)
        })
    }
}

/// Sets byte `at` so that `bytes[..len]` sums to zero.
pub fn fix_checksum(bytes: &mut [u8], len: usize, at: usize) {
    bytes[at] = 0;
    let sum = bytes[..len]
        .iter()
        .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
    bytes[at] = sum.wrapping_neg();
}

/// A table with `signature`, a valid length and checksum, and `body`
/// after its header.
pub fn table(signature: [u8; 4], body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; HEADER_LEN];
    bytes[..4].copy_from_slice(&signature);
    let length = u32::try_from(HEADER_LEN + body.len()).unwrap();
    bytes[4..8].copy_from_slice(&length.to_le_bytes());
    bytes[8] = 1;
    bytes[10..16].copy_from_slice(b"WIPMCH");
    bytes.extend_from_slice(body);
    let len = bytes.len();
    fix_checksum(&mut bytes, len, 9);
    bytes
}

/// An ACPI 1.0 root pointer naming the RSDT at `rsdt`.
pub fn rsdp_v1(rsdt: u32) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[..8].copy_from_slice(b"RSD PTR ");
    bytes[9..15].copy_from_slice(b"WIPMCH");
    bytes[16..20].copy_from_slice(&rsdt.to_le_bytes());
    fix_checksum(&mut bytes, 20, 8);
    bytes
}

/// An ACPI 2.0 root pointer naming the XSDT at `xsdt`.
pub fn rsdp_v2(xsdt: u64) -> Vec<u8> {
    let mut bytes = vec![0; 36];
    bytes[..8].copy_from_slice(b"RSD PTR ");
    bytes[9..15].copy_from_slice(b"WIPMCH");
    bytes[15] = 2;
    bytes[20..24].copy_from_slice(&36u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&xsdt.to_le_bytes());
    fix_checksum(&mut bytes, 20, 8);
    fix_checksum(&mut bytes, 36, 32);
    bytes
}

/// An RSDT listing the 32-bit table addresses `tables`.
pub fn rsdt(tables: &[u32]) -> Vec<u8> {
    let body: Vec<u8> = tables.iter().flat_map(|t| t.to_le_bytes()).collect();
    table(*b"RSDT", &body)
}

/// An XSDT listing the 64-bit table addresses `tables`.
pub fn xsdt(tables: &[u64]) -> Vec<u8> {
    let body: Vec<u8> = tables.iter().flat_map(|t| t.to_le_bytes()).collect();
    table(*b"XSDT", &body)
}

mod tests {
    use super::*;

    #[test]
    fn maps_only_inside_one_region() {
        let mut memory = FakeMemory::new();
        memory.place(0x1000, vec![1, 2, 3, 4]);
        assert_eq!(memory.map(0x1001, 2), Some(&[2, 3][..]));
        assert_eq!(memory.map(0x1002, 3), None);
        assert_eq!(memory.map(0x0fff, 1), None);
        assert_eq!(memory.map(0x1001, usize::MAX), None);
    }
}
