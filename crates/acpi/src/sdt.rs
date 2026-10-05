// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The header every system description table opens with, and the
//! little-endian field reads the tables share.

use crate::{Error, PhysicalMemory};

/// The bytes of the header: signature, length, revision, checksum, OEM
/// and creator identification.
pub const HEADER_LEN: usize = 36;

/// Maps the whole table at `address` once its header carries
/// `signature`, and checks its checksum.
///
/// # Errors
///
/// [`Error::Unmapped`] when the header or the table cannot be mapped,
/// [`Error::BadSignature`] for another table, [`Error::Corrupted`] for a
/// length shorter than the header, and [`Error::BadChecksum`].
pub fn map_table<M: PhysicalMemory>(
    memory: &M,
    address: u64,
    signature: [u8; 4],
) -> Result<M::Region<'_>, Error> {
    let header = memory.map(address, HEADER_LEN).ok_or(Error::Unmapped)?;
    if read_bytes::<4>(&header, 0) != signature {
        return Err(Error::BadSignature);
    }
    let length = read_u32(&header, 4) as usize;
    drop(header);
    if length < HEADER_LEN {
        return Err(Error::Corrupted);
    }

    let table = memory.map(address, length).ok_or(Error::Unmapped)?;
    if !sums_to_zero(&table) {
        return Err(Error::BadChecksum);
    }
    Ok(table)
}

/// Whether `bytes` add up to zero modulo 256, as every ACPI checksum
/// makes them.
pub fn sums_to_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)) == 0
}

/// The `N` bytes at `offset`; bytes past `bytes` read as zero.
pub fn read_bytes<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0; N];
    for (to, from) in out.iter_mut().zip(bytes.iter().skip(offset)) {
        *to = *from;
    }
    out
}

/// The byte at `offset`, or zero past `bytes`.
pub fn read_u8(bytes: &[u8], offset: usize) -> u8 {
    u8::from_le_bytes(read_bytes(bytes, offset))
}

/// The little-endian `u16` at `offset`.
pub fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(read_bytes(bytes, offset))
}

/// The little-endian `u32` at `offset`.
pub fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(read_bytes(bytes, offset))
}

/// The little-endian `u64` at `offset`.
pub fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(read_bytes(bytes, offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeMemory, table};

    #[test]
    fn reads_little_endian_fields() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u8(&bytes, 1), 0x02);
        assert_eq!(read_u16(&bytes, 0), 0x0201);
        assert_eq!(read_u32(&bytes, 0), 0x0403_0201);
        assert_eq!(read_u64(&bytes, 0), 0x0807_0605_0403_0201);
    }

    #[test]
    fn bytes_past_the_slice_read_as_zero() {
        let bytes = [0x11, 0x22];
        assert_eq!(read_u32(&bytes, 1), 0x22);
        assert_eq!(read_u8(&bytes, 2), 0);
        assert_eq!(read_u64(&bytes, 9), 0);
    }

    #[test]
    fn maps_a_table_whole() {
        let mut memory = FakeMemory::new();
        let bytes = table(*b"TEST", &[1, 2, 3]);
        memory.place(0x10_0000, bytes.clone());
        let mapped = map_table(&memory, 0x10_0000, *b"TEST").unwrap();
        assert_eq!(mapped, &bytes[..]);
    }

    #[test]
    fn rejects_an_unmapped_header() {
        let memory = FakeMemory::new();
        assert_eq!(
            map_table(&memory, 0x10_0000, *b"TEST").unwrap_err(),
            Error::Unmapped
        );
    }

    #[test]
    fn rejects_another_signature() {
        let mut memory = FakeMemory::new();
        memory.place(0x10_0000, table(*b"TEST", &[]));
        assert_eq!(
            map_table(&memory, 0x10_0000, *b"APIC").unwrap_err(),
            Error::BadSignature
        );
    }

    #[test]
    fn rejects_a_length_shorter_than_the_header() {
        let mut memory = FakeMemory::new();
        let mut bytes = table(*b"TEST", &[]);
        bytes[4..8].copy_from_slice(&35u32.to_le_bytes());
        memory.place(0x10_0000, bytes);
        assert_eq!(
            map_table(&memory, 0x10_0000, *b"TEST").unwrap_err(),
            Error::Corrupted
        );
    }

    #[test]
    fn rejects_a_table_longer_than_its_mapping() {
        let mut memory = FakeMemory::new();
        let mut bytes = table(*b"TEST", &[0; 4]);
        bytes.truncate(HEADER_LEN);
        memory.place(0x10_0000, bytes);
        assert_eq!(
            map_table(&memory, 0x10_0000, *b"TEST").unwrap_err(),
            Error::Unmapped
        );
    }

    #[test]
    fn rejects_a_bad_checksum() {
        let mut memory = FakeMemory::new();
        let mut bytes = table(*b"TEST", &[7]);
        bytes[HEADER_LEN] = 8;
        memory.place(0x10_0000, bytes);
        assert_eq!(
            map_table(&memory, 0x10_0000, *b"TEST").unwrap_err(),
            Error::BadChecksum
        );
    }
}
