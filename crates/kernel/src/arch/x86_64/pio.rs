// SPDX-License-Identifier: BSD-2-Clause
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Port I/O.

use core::arch::asm;

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
        let value: u8;
        // SAFETY: `in` reads the port in `dx` into `al`; it touches no memory,
        // changes no flag and uses no stack.
        unsafe {
            asm!(
                "in al, dx",
                in("dx") self.0,
                out("al") value,
                options(nostack, nomem, preserves_flags),
            );
        }
        value
    }

    /// Read one word.
    #[must_use]
    pub fn read_u16(self) -> u16 {
        let value: u16;
        // SAFETY: `in` reads the port in `dx` into `al`; it touches no memory,
        // changes no flag and uses no stack; with `ax` as the
        // destination.
        unsafe {
            asm!(
                "in ax, dx",
                in("dx") self.0,
                out("ax") value,
                options(nostack, nomem, preserves_flags),
            );
        }
        value
    }

    /// Read one long.
    #[must_use]
    pub fn read_u32(self) -> u32 {
        let value: u32;
        // SAFETY: `in` reads the port in `dx` into `al`; it touches no memory,
        // changes no flag and uses no stack; with `eax` as the
        // destination.
        unsafe {
            asm!(
                "in eax, dx",
                in("dx") self.0,
                out("eax") value,
                options(nostack, nomem, preserves_flags),
            );
        }
        value
    }

    /// Write one byte.
    pub fn write_u8(self, value: u8) {
        // SAFETY: `out` writes `al` to the port in `dx`; it touches no memory,
        // changes no flag and uses no stack.
        unsafe {
            asm!(
                "out dx, al",
                in("dx") self.0,
                in("al") value,
                options(nostack, nomem, preserves_flags),
            );
        }
    }

    /// Write one word.
    pub fn write_u16(self, value: u16) {
        // SAFETY: `out` writes `al` to the port in `dx`; it touches no memory,
        // changes no flag and uses no stack; with `ax` as the source.
        unsafe {
            asm!(
                "out dx, ax",
                in("dx") self.0,
                in("ax") value,
                options(nostack, nomem, preserves_flags),
            );
        }
    }

    /// Write one long.
    pub fn write_u32(self, value: u32) {
        // SAFETY: `out` writes `al` to the port in `dx`; it touches no memory,
        // changes no flag and uses no stack; with `eax` as the source.
        unsafe {
            asm!(
                "out dx, eax",
                in("dx") self.0,
                in("eax") value,
                options(nostack, nomem, preserves_flags),
            );
        }
    }
}
