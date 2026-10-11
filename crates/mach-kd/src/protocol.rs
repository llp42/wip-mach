// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The packet protocols a mouse speaks.

/// The protocols a mouse device's minor number selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// Five-byte Mouse Systems packets, on a serial line.
    MouseSystems,
    /// Three-byte Microsoft packets, on an 8-bit serial line.
    Microsoft,
    /// Three-byte PS/2 packets, through the keyboard controller.
    Ps2,
    /// Microsoft packets with a fourth byte for the middle button, on a
    /// 7-bit serial line.
    LogitechTrackman,
    /// Microsoft packets, on a 7-bit serial line.
    Microsoft7,
}

impl Protocol {
    /// The protocol bits 3 to 7 of the minor number `dev` select.
    #[must_use]
    pub const fn from_minor(dev: u16) -> Option<Self> {
        match (dev & 0xf8) >> 3 {
            0 => Some(Self::MouseSystems),
            1 => Some(Self::Microsoft),
            2 => Some(Self::Ps2),
            4 => Some(Self::LogitechTrackman),
            5 => Some(Self::Microsoft7),
            _ => None,
        }
    }

    /// The bytes of one packet.
    pub(super) const fn packet_len(self) -> usize {
        match self {
            Self::MouseSystems => 5,
            _ => 3,
        }
    }
}
