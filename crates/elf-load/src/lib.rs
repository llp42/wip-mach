// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The ELF executable loader's view of an image: recognition, the segments
//! an image asks to have placed, and the stack protection it asks for.
//!
//! The parsing is the `elf` crate's: [`parse`] hands it the image bytes,
//! which it reads in place, and keeps what a loader needs. The loader
//! never touches memory itself; the caller places each [`Segment`] from
//! [`ExecInfo::segments`].
//!
//! | item | purpose |
//! |---|---|
//! | [`parse`] | recognize an image and report the segments to place |
//! | [`ExecInfo`] | entry point, stack protection, and segment iterator |
//! | [`Segment`] | one `PT_LOAD` segment to place |
//! | [`Segments`] | the iterator over an image's loadable segments |
//! | [`ExecSectype`] | what a segment wants: read/write/execute, allocate, load |
//! | [`Prot`] | the protection bits a segment or the stack wants |
//! | [`ElfParserError`] | why an image was rejected |

#![no_std]

use elf::ElfBytes;
use elf::abi;
use elf::endian::LittleEndian;
use elf::file::Class;
use elf::parse::ParsingIterator;
use elf::segment::{ProgramHeader, SegmentTable};

/// Where a position-independent image (`ET_DYN` or `ET_REL`) is placed.
///
/// The first gibibyte stays free for the process's own mappings before
/// a position-independent image.
const PIE_LOAD_BASE: usize = 0x4000_0000;

const _: () = assert!(size_of::<usize>() >= size_of::<u64>());

/// Why [`parse`] rejected an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfParserError {
    /// The bytes are not an ELF image.
    NotElf,
    /// A valid ELF image, but not one this loader can run: another
    /// machine, class or byte order.
    WrongArch,
    /// A recognized ELF image, but mangled.
    Corrupted,
}

impl From<elf::ParseError> for ElfParserError {
    fn from(error: elf::ParseError) -> Self {
        match error {
            elf::ParseError::BadMagic(_) => Self::NotElf,
            elf::ParseError::UnsupportedElfClass(_)
            | elf::ParseError::UnsupportedElfEndianness(_) => Self::WrongArch,
            _ => Self::Corrupted,
        }
    }
}

bitflags::bitflags! {
    /// The protection a segment or the stack allows.
    ///
    /// A caller that speaks another protection type converts at its own
    /// boundary.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Prot: u32 {
        /// The region may be read.
        const READ = 0x1;
        /// The region may be written.
        const WRITE = 0x2;
        /// The region may be executed.
        const EXECUTE = 0x4;
    }
}

bitflags::bitflags! {
    /// What one segment of an image wants.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct ExecSectype: u32 {
        /// The section is readable.
        const READ = Prot::READ.bits();
        /// The section is writable.
        const WRITE = Prot::WRITE.bits();
        /// The section is executable.
        const EXECUTE = Prot::EXECUTE.bits();
        /// The section needs memory allocated for it.
        const ALLOC = 0x0100;
        /// The section's contents come from the file.
        const LOAD = 0x0200;
    }
}

impl ExecSectype {
    /// The [`Prot`] bits of `self`.
    #[must_use]
    pub const fn protection(self) -> Prot {
        Prot::from_bits_truncate(self.bits())
    }
}

/// The protection the `PF_R`/`PF_W`/`PF_X` bits of `p_flags` ask for.
const fn protection(p_flags: u32) -> Prot {
    let mut prot = Prot::empty();
    if p_flags & abi::PF_R != 0 {
        prot = prot.union(Prot::READ);
    }
    if p_flags & abi::PF_W != 0 {
        prot = prot.union(Prot::WRITE);
    }
    if p_flags & abi::PF_X != 0 {
        prot = prot.union(Prot::EXECUTE);
    }
    prot
}

/// The image [`parse`] recognized.
#[derive(Clone, Copy, Debug)]
pub struct ExecInfo<'a> {
    entry: usize,
    stack_prot: Prot,
    phdrs: Option<SegmentTable<'a, LittleEndian>>,
    base: usize,
}

impl<'a> ExecInfo<'a> {
    /// The entry point the image wants, already rebased for a
    /// position-independent image.
    #[must_use]
    pub const fn entry(&self) -> usize {
        self.entry
    }

    /// The protection the image wants on its stack.
    #[must_use]
    pub const fn stack_prot(&self) -> Prot {
        self.stack_prot
    }

    /// The image's loadable segments, in program-header order.
    #[must_use]
    pub fn segments(&self) -> Segments<'a> {
        Segments {
            phdrs: self.phdrs.map(|table| table.iter()),
            base: self.base,
        }
    }
}

/// One `PT_LOAD` segment: where its bytes are in the image, where it goes,
/// and what it wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    offset: usize,
    file_len: usize,
    addr: usize,
    mem_len: usize,
    sectype: ExecSectype,
}

impl Segment {
    /// The segment's offset in the image.
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// The bytes the image holds for the segment.
    #[must_use]
    pub const fn file_len(self) -> usize {
        self.file_len
    }

    /// Where the segment goes, rebased for a position-independent image.
    #[must_use]
    pub const fn addr(self) -> usize {
        self.addr
    }

    /// The bytes the segment takes in memory, its file bytes and the zeroes
    /// past them.
    #[must_use]
    pub const fn mem_len(self) -> usize {
        self.mem_len
    }

    /// What the segment wants.
    #[must_use]
    pub const fn sectype(self) -> ExecSectype {
        self.sectype
    }
}

/// The iterator over an image's loadable segments.
#[derive(Debug)]
pub struct Segments<'a> {
    phdrs: Option<ParsingIterator<'a, LittleEndian, ProgramHeader>>,
    base: usize,
}

impl Iterator for Segments<'_> {
    type Item = Segment;

    #[expect(
        clippy::cast_possible_truncation,
        reason = "every supported target holds a 64-bit pointer"
    )]
    fn next(&mut self) -> Option<Segment> {
        let phdrs = self.phdrs.as_mut()?;
        phdrs.find(|phdr| phdr.p_type == abi::PT_LOAD).map(|phdr| {
            let prot = protection(phdr.p_flags);
            Segment {
                offset: phdr.p_offset as usize,
                file_len: phdr.p_filesz as usize,
                addr: (phdr.p_vaddr as usize).wrapping_add(self.base),
                mem_len: phdr.p_memsz as usize,
                sectype: ExecSectype::ALLOC
                    | ExecSectype::LOAD
                    | ExecSectype::from_bits_truncate(prot.bits()),
            }
        })
    }
}

/// Parses the ELF executable `data` and reports its entry point, stack
/// protection and loadable segments.
///
/// The header and the program-header table are checked against `data`
/// before this returns, so a mangled image is rejected before a caller
/// places any segment.
///
/// # Errors
///
/// Returns [`ElfParserError::NotElf`] when the bytes are not an ELF
/// image, [`ElfParserError::WrongArch`] when they are an image of another
/// machine, class or byte order, and [`ElfParserError::Corrupted`] when a
/// recognized image is mangled.
#[expect(
    clippy::cast_possible_truncation,
    reason = "every supported target holds a 64-bit pointer"
)]
pub fn parse(data: &[u8]) -> Result<ExecInfo<'_>, ElfParserError> {
    if data.len() < abi::EI_NIDENT {
        return Err(ElfParserError::NotElf);
    }

    let file = ElfBytes::<LittleEndian>::minimal_parse(data)?;
    if file.ehdr.class != Class::ELF64 || file.ehdr.e_machine != abi::EM_X86_64
    {
        return Err(ElfParserError::WrongArch);
    }

    let base = match file.ehdr.e_type {
        abi::ET_DYN | abi::ET_REL => PIE_LOAD_BASE,
        _ => 0,
    };
    let phdrs = file.segments();

    let stack_prot = phdrs
        .and_then(|table| {
            table
                .iter()
                .filter(|phdr| phdr.p_type == abi::PT_GNU_STACK)
                .last()
        })
        .map_or(Prot::all(), |phdr| protection(phdr.p_flags));

    Ok(ExecInfo {
        entry: (file.ehdr.e_entry as usize).wrapping_add(base),
        stack_prot,
        phdrs,
        base,
    })
}
