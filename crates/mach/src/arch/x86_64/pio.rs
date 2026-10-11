// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Port I/O.

use x86_64::instructions::port::{PortRead, PortWrite};

/// An x86 I/O port address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Port(u16);

impl Port {
    #[must_use]
    /// The port at `address`.
    pub const fn new(address: u16) -> Self {
        Self(address)
    }

    /// Read one byte.
    #[must_use]
    pub fn read_u8(self) -> u8 {
        // SAFETY: the kernel names only the ports of the devices it drives,
        // and none of them reaches memory on a port access.
        unsafe { u8::read_from_port(self.0) }
    }

    /// Write one byte.
    pub fn write_u8(self, value: u8) {
        // SAFETY: the kernel names only the ports of the devices it drives,
        // and none of them reaches memory on a port access.
        unsafe { u8::write_to_port(self.0, value) }
    }
}
