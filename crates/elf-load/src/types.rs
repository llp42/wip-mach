// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The ELF format's class-independent types: the identification bytes,
//! the object file type and the machine.

use crate::ElfParserError;
use crate::consts::{EI_CLASS, EI_DATA, EI_NIDENT, ELFMAG};

/// The `e_ident` bytes that start every ELF image.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ident([u8; EI_NIDENT]);

impl TryFrom<[u8; EI_NIDENT]> for Ident {
    type Error = ElfParserError;

    fn try_from(bytes: [u8; EI_NIDENT]) -> Result<Self, Self::Error> {
        if !bytes.starts_with(&ELFMAG) {
            return Err(ElfParserError::NotElf);
        }
        Ok(Self(bytes))
    }
}

impl Ident {
    /// `EI_CLASS`: the class, or capacity, of the image.
    ///
    /// # Errors
    ///
    /// [`ElfParserError::WrongArch`] when `EI_CLASS` is not one of the
    /// defined values.
    pub(crate) fn class(&self) -> Result<Class, ElfParserError> {
        Class::try_from(self.0[EI_CLASS])
    }

    /// `EI_DATA`: the encoding of the image's data structures.
    ///
    /// # Errors
    ///
    /// [`ElfParserError::WrongArch`] when `EI_DATA` is not one of the
    /// defined values.
    pub(crate) fn data(&self) -> Result<Data, ElfParserError> {
        Data::try_from(self.0[EI_DATA])
    }
}

/// `EI_CLASS`: the class, or capacity, of an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Class {
    /// `ELFCLASS32` (`1`).
    ELFCLASS32 = 1,
    /// `ELFCLASS64` (`2`).
    ELFCLASS64 = 2,
}

impl TryFrom<u8> for Class {
    type Error = ElfParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ELFCLASS32),
            2 => Ok(Self::ELFCLASS64),
            _ => Err(ElfParserError::WrongArch),
        }
    }
}

/// `EI_DATA`: the encoding of the data structures in an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Data {
    /// `ELFDATA2LSB` (`1`), little-endian.
    ELFDATA2LSB = 1,
    /// `ELFDATA2MSB` (`2`), big-endian.
    ELFDATA2MSB = 2,
}

impl TryFrom<u8> for Data {
    type Error = ElfParserError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ELFDATA2LSB),
            2 => Ok(Self::ELFDATA2MSB),
            _ => Err(ElfParserError::WrongArch),
        }
    }
}

/// `e_type`: the object file type.
#[expect(
    non_camel_case_types,
    reason = "the ET_* variants are the names the ELF format defines"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum Type {
    ET_NONE = 0,
    ET_REL = 1,
    ET_EXEC = 2,
    ET_DYN = 3,
    ET_CORE = 4,
    ET_LOOS = 0xfe00,
    ET_HIOS = 0xfeff,
    ET_LOPROC = 0xff00,
    ET_HIPROC = 0xffff,
}

impl Type {
    /// The object file type `value` names, or `None` when the ELF
    /// format does not name it. An unnamed type is still a valid image
    /// and is not position-independent.
    pub(crate) const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::ET_NONE),
            1 => Some(Self::ET_REL),
            2 => Some(Self::ET_EXEC),
            3 => Some(Self::ET_DYN),
            4 => Some(Self::ET_CORE),
            0xfe00 => Some(Self::ET_LOOS),
            0xfeff => Some(Self::ET_HIOS),
            0xff00 => Some(Self::ET_LOPROC),
            0xffff => Some(Self::ET_HIPROC),
            _ => None,
        }
    }

    /// Whether an image of this type is position-independent.
    pub(crate) const fn is_pie(self) -> bool {
        matches!(self, Self::ET_DYN | Self::ET_REL)
    }
}

/// `e_machine`: the machine an image is for.
#[expect(
    non_camel_case_types,
    reason = "the EM_* variants are the names the ELF format defines"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum Machine {
    EM_386 = 3,
    EM_X86_64 = 62,
}

impl TryFrom<u16> for Machine {
    type Error = ElfParserError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            3 => Ok(Self::EM_386),
            62 => Ok(Self::EM_X86_64),
            _ => Err(ElfParserError::WrongArch),
        }
    }
}

/// `p_type`: the type of one program header.
///
/// Only the types the loader reads are named; every other value is
/// ignored.
#[expect(
    non_camel_case_types,
    reason = "the PT_* variants are the names the ELF format defines"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(crate) enum ProgramType {
    PT_LOAD = 1,
    PT_GNU_STACK = 0x6474_e551,
}

impl ProgramType {
    /// The segment type `value` names, or `None` when it is not one
    /// this loader reads.
    pub(crate) const fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::PT_LOAD),
            0x6474_e551 => Some(Self::PT_GNU_STACK),
            _ => None,
        }
    }
}

/// `p_flags`: the permission bits of one program header.
///
/// The bits combine: a segment may set any of them at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct ProgramFlags(u32);

impl ProgramFlags {
    /// `PF_X` (`0x1`): the segment is executable.
    pub(crate) const PF_X: Self = Self(0x1);
    /// `PF_W` (`0x2`): the segment is writable.
    pub(crate) const PF_W: Self = Self(0x2);
    /// `PF_R` (`0x4`): the segment is readable.
    pub(crate) const PF_R: Self = Self(0x4);
    /// `PF_MASKOS` (`0x0ff0_0000`): the OS-specific bits.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the loader reads the permission bits; the mask \
                      is part of the format"
        )
    )]
    pub(crate) const PF_MASKOS: Self = Self(0x0ff0_0000);
    /// `PF_MASKPROC` (`0xf000_0000`): the processor-specific bits.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the loader reads the permission bits; the mask \
                      is part of the format"
        )
    )]
    pub(crate) const PF_MASKPROC: Self = Self(0xf000_0000);

    /// Whether every bit of `other` is set in `self`.
    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl From<u32> for ProgramFlags {
    fn from(bits: u32) -> Self {
        Self(bits)
    }
}

impl From<ProgramFlags> for u32 {
    fn from(flags: ProgramFlags) -> Self {
        flags.0
    }
}

impl core::ops::BitOr for ProgramFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident() -> [u8; EI_NIDENT] {
        let mut raw = [0u8; EI_NIDENT];
        raw[..ELFMAG.len()].copy_from_slice(&ELFMAG);
        raw[EI_CLASS] = Class::ELFCLASS32 as u8;
        raw[EI_DATA] = Data::ELFDATA2LSB as u8;
        raw
    }

    #[test]
    fn ident_rejects_bad_magic() {
        assert!(Ident::try_from(ident()).is_ok());
        for index in 0..ELFMAG.len() {
            let mut raw = ident();
            raw[index] = 0;
            assert_eq!(
                Ident::try_from(raw).unwrap_err(),
                ElfParserError::NotElf
            );
        }
    }

    #[test]
    fn class_reads_the_class_byte() {
        assert_eq!(
            Ident::try_from(ident()).unwrap().class(),
            Ok(Class::ELFCLASS32)
        );
        let mut raw = ident();
        raw[EI_CLASS] = Class::ELFCLASS64 as u8;
        assert_eq!(
            Ident::try_from(raw).unwrap().class(),
            Ok(Class::ELFCLASS64)
        );
        raw[EI_CLASS] = 3;
        assert_eq!(
            Ident::try_from(raw).unwrap().class(),
            Err(ElfParserError::WrongArch)
        );
    }

    #[test]
    fn data_reads_the_data_byte() {
        assert_eq!(
            Ident::try_from(ident()).unwrap().data(),
            Ok(Data::ELFDATA2LSB)
        );
        let mut raw = ident();
        raw[EI_DATA] = Data::ELFDATA2MSB as u8;
        assert_eq!(
            Ident::try_from(raw).unwrap().data(),
            Ok(Data::ELFDATA2MSB)
        );
        raw[EI_DATA] = 0;
        assert_eq!(
            Ident::try_from(raw).unwrap().data(),
            Err(ElfParserError::WrongArch)
        );
    }

    #[test]
    fn type_from_u16() {
        assert_eq!(Type::from_u16(0), Some(Type::ET_NONE));
        assert_eq!(Type::from_u16(1), Some(Type::ET_REL));
        assert_eq!(Type::from_u16(2), Some(Type::ET_EXEC));
        assert_eq!(Type::from_u16(3), Some(Type::ET_DYN));
        assert_eq!(Type::from_u16(4), Some(Type::ET_CORE));
        assert_eq!(Type::from_u16(0xfe00), Some(Type::ET_LOOS));
        assert_eq!(Type::from_u16(0xfeff), Some(Type::ET_HIOS));
        assert_eq!(Type::from_u16(0xff00), Some(Type::ET_LOPROC));
        assert_eq!(Type::from_u16(0xffff), Some(Type::ET_HIPROC));
        assert_eq!(Type::from_u16(5), None);
        assert_eq!(Type::from_u16(0xfe01), None);
        assert_eq!(Type::from_u16(0xff01), None);
    }

    #[test]
    fn type_is_pie() {
        assert!(Type::ET_DYN.is_pie());
        assert!(Type::ET_REL.is_pie());
        assert!(!Type::ET_EXEC.is_pie());
        assert!(!Type::ET_CORE.is_pie());
    }

    #[test]
    fn machine_try_from() {
        assert_eq!(Machine::try_from(3), Ok(Machine::EM_386));
        assert_eq!(Machine::try_from(62), Ok(Machine::EM_X86_64));
        assert_eq!(Machine::try_from(0), Err(ElfParserError::WrongArch));
        assert_eq!(Machine::try_from(99), Err(ElfParserError::WrongArch));
    }

    #[test]
    fn program_type_from_u32() {
        assert_eq!(ProgramType::from_u32(1), Some(ProgramType::PT_LOAD));
        assert_eq!(
            ProgramType::from_u32(0x6474_e551),
            Some(ProgramType::PT_GNU_STACK)
        );
        assert_eq!(ProgramType::from_u32(0), None);
        assert_eq!(ProgramType::from_u32(4), None);
        assert_eq!(ProgramType::from_u32(0x6000_0000), None);
    }

    #[test]
    fn program_flags_contains() {
        let rw = ProgramFlags::PF_R | ProgramFlags::PF_W;
        assert!(rw.contains(ProgramFlags::PF_R));
        assert!(!rw.contains(ProgramFlags::PF_X));
        assert_eq!(
            ProgramFlags::from(3),
            ProgramFlags::PF_X | ProgramFlags::PF_W
        );
        assert_eq!(u32::from(ProgramFlags::PF_R | ProgramFlags::PF_X), 0x5);
        assert_eq!(ProgramFlags::from(0x0ff0_0000), ProgramFlags::PF_MASKOS);
        assert_eq!(ProgramFlags::from(0xf000_0000), ProgramFlags::PF_MASKPROC);
    }
}
