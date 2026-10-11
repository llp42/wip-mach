// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The bytes a key types.

use crate::keymap::{CELL, DONE};

/// The bytes of one key-map cell, up to its first terminator.
#[derive(Clone, Copy, Debug)]
pub struct Chars {
    bytes: [u8; CELL],
    len: usize,
}

impl Chars {
    /// The bytes of `cell` before its first [`DONE`].
    pub(super) fn from_cell(cell: [u8; CELL]) -> Self {
        let len = cell.iter().take_while(|&&b| b != DONE).count();
        Self { bytes: cell, len }
    }

    /// The bytes, in typing order.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

/// Two cells type the same characters whatever follows their terminators.
impl PartialEq for Chars {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Chars {}
