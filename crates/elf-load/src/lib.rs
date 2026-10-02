// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The ELF executable parser: recognition, the segments an image asks
//! to have placed, and the stack protection it asks for.
//!
//! The parser never touches memory itself. A caller supplies an
//! [`ElfImage`] that can read file bytes; [`parse`] walks the program
//! headers and reports what it found, and the caller places each
//! [`Segment`] from [`ExecInfo::segments`].
//!
//! The 64-bit reader lives in `x86_64`. [`parse`] recognizes the
//! little-endian `ELFCLASS64` images this crate has a reader for and
//! hands them over; the reader owns the machine check, the
//! program-header walk and the segment iterator.
//!
//! | item | purpose |
//! |---|---|
//! | [`parse`] | recognize an image and report the segments to place |
//! | [`ElfImage`] | the caller's source of file bytes |
//! | [`ExecInfo`] | entry point, stack protection, and segment iterator |
//! | [`Segment`] | one `PT_LOAD` segment to place |
//! | [`Segments`] | the iterator over an image's loadable segments |
//! | [`ExecSectype`] | what a segment wants: read/write/execute, allocate, load |
//! | [`Prot`] | the protection bits a segment or the stack wants |
//! | [`ElfParserError`] | why an image was rejected |

#![cfg_attr(not(test), no_std)]

mod consts;
mod parse;
mod types;
mod x86_64;

use consts::EI_NIDENT;
use core::fmt;
use types::{Class, Data, Ident, ProgramFlags};
use x86_64::ProgramHeaders;

pub use x86_64::{Segment, Segments};

/// Why [`parse`] rejected an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfParserError {
    /// The bytes are not an ELF image.
    NotElf,
    /// A valid ELF image, but not one this parser has a reader for.
    WrongArch,
    /// A recognized ELF image, but mangled.
    Corrupted,
}

impl fmt::Display for ElfParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotElf => f.write_str("not an ELF image"),
            Self::WrongArch => f.write_str("wrong architecture"),
            Self::Corrupted => f.write_str("corrupted ELF image"),
        }
    }
}

/// The protection a segment or the stack allows.
///
/// A caller that speaks another protection type converts at its own
/// boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Prot(u32);

impl Prot {
    /// Nothing is allowed.
    pub const NONE: Self = Self(0);
    /// The region may be read.
    pub const READ: Self = Self(0x1);
    /// The region may be written.
    pub const WRITE: Self = Self(0x2);
    /// The region may be executed.
    pub const EXECUTE: Self = Self(0x4);
    /// Read, write and execute.
    pub const ALL: Self = Self(Self::READ.0 | Self::WRITE.0 | Self::EXECUTE.0);

    /// The raw bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// A protection value from raw bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Whether every bit of `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for Prot {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for Prot {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl core::ops::BitAnd for Prot {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

/// What one segment of an image wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ExecSectype(u32);

impl ExecSectype {
    /// The section is readable.
    pub const READ: Self = Self(Prot::READ.bits());
    /// The section is writable.
    pub const WRITE: Self = Self(Prot::WRITE.bits());
    /// The section is executable.
    pub const EXECUTE: Self = Self(Prot::EXECUTE.bits());
    /// The section needs memory allocated for it.
    pub const ALLOC: Self = Self(0x0100);
    /// The section's contents come from the file.
    pub const LOAD: Self = Self(0x0200);

    /// Whether every bit of `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The [`Prot`] bits of `self`.
    #[must_use]
    pub const fn protection(self) -> Prot {
        Prot::from_bits(self.0 & Prot::ALL.bits())
    }
}

impl core::ops::BitOr for ExecSectype {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for ExecSectype {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// The image [`parse`] recognized, after every program header has been
/// read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecInfo {
    entry: usize,
    stack_prot: Prot,
    phdrs: ProgramHeaders,
}

impl ExecInfo {
    /// The entry point the image wants, already rebased for a
    /// position-independent image.
    #[must_use]
    pub const fn entry(self) -> usize {
        self.entry
    }

    /// The protection the image wants on its stack.
    #[must_use]
    pub const fn stack_prot(self) -> Prot {
        self.stack_prot
    }

    /// The image's loadable segments, in program-header order.
    #[must_use]
    pub const fn segments<'a, I: ElfImage>(
        &self,
        image: &'a I,
    ) -> Segments<'a, I> {
        Segments::new(image, self.phdrs)
    }

    /// Builds the record [`parse`] returns.
    pub(crate) const fn new(
        entry: usize,
        stack_prot: Prot,
        phdrs: ProgramHeaders,
    ) -> Self {
        Self {
            entry,
            stack_prot,
            phdrs,
        }
    }
}

/// The source of ELF file bytes.
pub trait ElfImage {
    /// Reads up to `buf.len()` bytes at `offset` into `buf`.
    ///
    /// Same buffer-filling shape as `FileExt::read_at`: returns how
    /// many bytes were actually read. A short read is not an error; the
    /// parser classifies it as [`ElfParserError::NotElf`] or
    /// [`ElfParserError::Corrupted`]. `0` past the end of the image is
    /// the normal way to report exhaustion.
    fn read_at(&self, buf: &mut [u8], offset: usize) -> usize;
}

/// Parses an ELF executable through `image` and reports its entry
/// point, stack protection and loadable segments.
///
/// [`parse`] reads the `e_ident` bytes and rejects anything that is not
/// a little-endian `ELFCLASS64` ELF image. The 64-bit reader then owns
/// the machine and program-header checks, so a mangled program header
/// is found before any caller places a segment.
///
/// # Errors
///
/// Returns [`ElfParserError::NotElf`] when the bytes are not an ELF
/// image, [`ElfParserError::WrongArch`] when they are an image of
/// another machine, class or byte order, and
/// [`ElfParserError::Corrupted`] when a recognized image is mangled.
pub fn parse<I: ElfImage>(image: &I) -> Result<ExecInfo, ElfParserError> {
    let mut raw = [0u8; EI_NIDENT];
    if image.read_at(&mut raw, 0) < EI_NIDENT {
        return Err(ElfParserError::NotElf);
    }

    let e_ident = Ident::try_from(raw)?;

    if e_ident.data()? != Data::ELFDATA2LSB {
        return Err(ElfParserError::WrongArch);
    }

    match e_ident.class()? {
        Class::ELFCLASS64 => x86_64::parse(image),
        Class::ELFCLASS32 => Err(ElfParserError::WrongArch),
    }
}

/// Where a position-independent image (`ET_DYN` or `ET_REL`) is placed.
///
/// The first gibibyte stays free for the process's own mappings before
/// a position-independent image.
pub(crate) const PIE_LOAD_BASE: usize = 0x4000_0000;

/// The [`ExecSectype`] a `PF_R`/`PF_W`/`PF_X` segment asks for.
pub(crate) fn section_type(flags: ProgramFlags) -> ExecSectype {
    let mut type_ = ExecSectype::ALLOC | ExecSectype::LOAD;
    if flags.contains(ProgramFlags::PF_R) {
        type_ |= ExecSectype::READ;
    }
    if flags.contains(ProgramFlags::PF_W) {
        type_ |= ExecSectype::WRITE;
    }
    if flags.contains(ProgramFlags::PF_X) {
        type_ |= ExecSectype::EXECUTE;
    }
    type_
}

/// The protection a `PT_GNU_STACK` segment asks for.
pub(crate) fn stack_prot(flags: ProgramFlags) -> Prot {
    let mut prot = Prot::NONE;
    if flags.contains(ProgramFlags::PF_R) {
        prot |= Prot::READ;
    }
    if flags.contains(ProgramFlags::PF_W) {
        prot |= Prot::WRITE;
    }
    if flags.contains(ProgramFlags::PF_X) {
        prot |= Prot::EXECUTE;
    }
    prot
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use core::cell::Cell;
    use std::vec::Vec;

    /// An in-memory image both test modules share, so `parse` is
    /// monomorphized once and every dispatch arm is covered.
    pub(crate) struct MemImage {
        pub bytes: Vec<u8>,
        /// Set to make every read come back short, so the segment
        /// iterator's error arm is reachable after `parse` succeeded.
        pub fail: Cell<bool>,
    }

    impl MemImage {
        pub(crate) fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                fail: Cell::new(false),
            }
        }
    }

    impl ElfImage for MemImage {
        fn read_at(&self, buf: &mut [u8], offset: usize) -> usize {
            if self.fail.get() {
                return 0;
            }
            let Some(src) = self.bytes.get(offset..) else {
                return 0;
            };
            let n = src.len().min(buf.len());
            buf[..n].copy_from_slice(&src[..n]);
            n
        }
    }

    #[test]
    fn rejects_unknown_class() {
        let mut bytes = Vec::from(*b"\x7fELF\x03\x01\0\0\0\0\0\0\0\0\0\0");
        bytes.resize(64, 0);
        let image = MemImage::new(bytes);
        assert_eq!(parse(&image), Err(ElfParserError::WrongArch));
    }

    #[test]
    fn rejects_before_a_class_byte() {
        let image = MemImage::new(b"\x7fELF".to_vec());
        assert_eq!(parse(&image), Err(ElfParserError::NotElf));
    }

    #[test]
    fn rejects_bad_magic_and_endian() {
        // Class 32, but not an ELF.
        let mut bytes = Vec::from(*b"\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0");
        bytes.resize(64, 0);
        let image = MemImage::new(bytes);
        assert_eq!(parse(&image), Err(ElfParserError::NotElf));
        // Class 32, big-endian.
        let mut bytes = Vec::from(*b"\x7fELF\x01\x02\0\0\0\0\0\0\0\0\0\0");
        bytes.resize(64, 0);
        let image = MemImage::new(bytes);
        assert_eq!(parse(&image), Err(ElfParserError::WrongArch));
        // Class 64, not an ELF.
        let mut bytes = Vec::from(*b"\0\0\0\0\x02\x01\0\0\0\0\0\0\0\0\0\0");
        bytes.resize(64, 0);
        let image = MemImage::new(bytes);
        assert_eq!(parse(&image), Err(ElfParserError::NotElf));
        // Truncated identification after a valid magic.
        let image = MemImage::new(
            b"\x7fELF\x01\x01\0\0\0\0\0\0\0\0\0\0"[..5].to_vec(),
        );
        assert_eq!(parse(&image), Err(ElfParserError::NotElf));
    }

    #[test]
    fn rejects_unknown_data_encoding() {
        let mut bytes = Vec::from(*b"\x7fELF\x01\x03\0\0\0\0\0\0\0\0\0\0");
        bytes.resize(64, 0);
        let image = MemImage::new(bytes);
        assert_eq!(parse(&image), Err(ElfParserError::WrongArch));
    }

    #[test]
    fn rejects_elfclass32() {
        let mut bytes = Vec::from(*b"\x7fELF\x01\x01\0\0\0\0\0\0\0\0\0\0");
        bytes.resize(64, 0);
        let image = MemImage::new(bytes);
        assert_eq!(parse(&image), Err(ElfParserError::WrongArch));
    }

    #[test]
    fn prot_bits_and_contains() {
        assert_eq!(Prot::NONE.bits(), 0);
        assert_eq!(Prot::ALL.bits(), 7);
        assert!(Prot::ALL.contains(Prot::READ));
        assert!(!Prot::READ.contains(Prot::WRITE));
        assert_eq!(Prot::from_bits(3), Prot::READ | Prot::WRITE);
    }

    #[test]
    fn prot_bitor_assign() {
        let mut prot = Prot::NONE;
        prot |= Prot::EXECUTE;
        assert_eq!(prot, Prot::EXECUTE);
        assert_eq!(prot & Prot::READ, Prot::NONE);
    }

    #[test]
    fn sectype_contains_and_protection() {
        let rw = ExecSectype::READ | ExecSectype::WRITE;
        assert!(rw.contains(ExecSectype::READ));
        assert!(!rw.contains(ExecSectype::EXECUTE));
        assert_eq!(rw.protection(), Prot::READ | Prot::WRITE);
        assert_eq!(
            (ExecSectype::ALLOC | ExecSectype::LOAD).protection(),
            Prot::NONE
        );
    }

    #[test]
    fn sectype_bitor_assign() {
        let mut sectype = ExecSectype::ALLOC;
        sectype |= ExecSectype::LOAD;
        assert!(sectype.contains(ExecSectype::LOAD));
    }

    #[test]
    fn elf_parser_error_display() {
        assert_eq!(ElfParserError::NotElf.to_string(), "not an ELF image");
        assert_eq!(
            ElfParserError::WrongArch.to_string(),
            "wrong architecture"
        );
        assert_eq!(
            ElfParserError::Corrupted.to_string(),
            "corrupted ELF image"
        );
    }

    #[test]
    fn section_type_maps_flags() {
        assert_eq!(
            section_type(
                ProgramFlags::PF_R | ProgramFlags::PF_W | ProgramFlags::PF_X
            ),
            ExecSectype::ALLOC
                | ExecSectype::LOAD
                | ExecSectype::READ
                | ExecSectype::WRITE
                | ExecSectype::EXECUTE
        );
        assert_eq!(
            section_type(ProgramFlags::from(0)),
            ExecSectype::ALLOC | ExecSectype::LOAD
        );
    }

    #[test]
    fn stack_prot_maps_flags() {
        assert_eq!(
            stack_prot(ProgramFlags::PF_R | ProgramFlags::PF_X),
            Prot::READ | Prot::EXECUTE
        );
        assert_eq!(stack_prot(ProgramFlags::from(0)), Prot::NONE);
    }
}
