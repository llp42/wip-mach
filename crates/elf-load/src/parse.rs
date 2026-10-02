// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Integer reads from a fixed-size on-disk record.

/// The byte order of an on-disk integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Endianness {
    /// Little-endian.
    Little,
    /// Big-endian.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only little-endian images are loaded; the parser \
                      still reads both byte orders"
        )
    )]
    Big,
}

/// Reads the `u16` at `offset` in `endian`. Bytes past `raw` read as
/// zero.
pub(crate) fn read_u16<const N: usize>(
    raw: &[u8; N],
    offset: usize,
    endian: Endianness,
) -> u16 {
    let b0 = raw.get(offset).copied().unwrap_or(0);
    let b1 = raw.get(offset + 1).copied().unwrap_or(0);

    match endian {
        Endianness::Little => u16::from_le_bytes([b0, b1]),
        Endianness::Big => u16::from_be_bytes([b0, b1]),
    }
}

/// Reads the `u32` at `offset` in `endian`. Bytes past `raw` read as
/// zero.
pub(crate) fn read_u32<const N: usize>(
    raw: &[u8; N],
    offset: usize,
    endian: Endianness,
) -> u32 {
    let b0 = raw.get(offset).copied().unwrap_or(0);
    let b1 = raw.get(offset + 1).copied().unwrap_or(0);
    let b2 = raw.get(offset + 2).copied().unwrap_or(0);
    let b3 = raw.get(offset + 3).copied().unwrap_or(0);

    match endian {
        Endianness::Little => u32::from_le_bytes([b0, b1, b2, b3]),
        Endianness::Big => u32::from_be_bytes([b0, b1, b2, b3]),
    }
}

/// Reads the `u64` at `offset` in `endian`. Bytes past `raw` read as
/// zero.
pub(crate) fn read_u64<const N: usize>(
    raw: &[u8; N],
    offset: usize,
    endian: Endianness,
) -> u64 {
    let b0 = raw.get(offset).copied().unwrap_or(0);
    let b1 = raw.get(offset + 1).copied().unwrap_or(0);
    let b2 = raw.get(offset + 2).copied().unwrap_or(0);
    let b3 = raw.get(offset + 3).copied().unwrap_or(0);
    let b4 = raw.get(offset + 4).copied().unwrap_or(0);
    let b5 = raw.get(offset + 5).copied().unwrap_or(0);
    let b6 = raw.get(offset + 6).copied().unwrap_or(0);
    let b7 = raw.get(offset + 7).copied().unwrap_or(0);

    match endian {
        Endianness::Little => {
            u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7])
        }
        Endianness::Big => {
            u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_both_byte_orders() {
        let raw = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(
            read_u16(&raw, 0, Endianness::Little),
            u16::from_le_bytes([0x01, 0x02])
        );
        assert_eq!(
            read_u16(&raw, 0, Endianness::Big),
            u16::from_be_bytes([0x01, 0x02])
        );
        assert_eq!(
            read_u32(&raw, 0, Endianness::Little),
            u32::from_le_bytes([0x01, 0x02, 0x03, 0x04])
        );
        assert_eq!(
            read_u32(&raw, 0, Endianness::Big),
            u32::from_be_bytes([0x01, 0x02, 0x03, 0x04])
        );
        assert_eq!(
            read_u64(&raw, 0, Endianness::Little),
            u64::from_le_bytes([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
            ])
        );
        assert_eq!(
            read_u64(&raw, 0, Endianness::Big),
            u64::from_be_bytes([
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
            ])
        );
    }

    #[test]
    fn bytes_past_the_record_read_as_zero() {
        let raw = [0x11, 0x22];
        assert_eq!(read_u16(&raw, 1, Endianness::Little), 0x22);
        assert_eq!(read_u32(&raw, 1, Endianness::Little), 0x22);
        assert_eq!(read_u64(&raw, 1, Endianness::Little), 0x22);
        assert_eq!(read_u16(&raw, 2, Endianness::Little), 0);
        assert_eq!(read_u32(&raw, 2, Endianness::Little), 0);
        assert_eq!(read_u64(&raw, 2, Endianness::Little), 0);
        assert_eq!(read_u16(&raw, 8, Endianness::Little), 0);
        assert_eq!(read_u32(&raw, 8, Endianness::Little), 0);
        assert_eq!(read_u64(&raw, 8, Endianness::Little), 0);
    }
}
