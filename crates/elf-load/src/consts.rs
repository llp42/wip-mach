// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The numbers the ELF format defines, shared by every reader.

/// `EI_NIDENT`: the identification bytes that start every ELF image.
pub(crate) const EI_NIDENT: usize = 16;
/// `EI_CLASS`: offset of the class byte.
pub(crate) const EI_CLASS: usize = 4;
/// `EI_DATA`: offset of the data-encoding byte.
pub(crate) const EI_DATA: usize = 5;

/// The four magic bytes that open every ELF image.
pub(crate) const ELFMAG: [u8; 4] = *b"\x7fELF";
