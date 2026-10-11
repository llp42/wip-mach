// SPDX-License-Identifier: GPL-2.0-or-later
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
