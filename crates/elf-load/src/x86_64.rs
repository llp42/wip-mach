// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The 64-bit ELF reader (`ELFCLASS64` / `EM_X86_64`).
//!
//! This module owns the on-disk header layouts, the program-header
//! walk and the loadable segments it yields. The 32-bit headers differ
//! in field order, so nothing here is shared with them.

use core::mem::size_of;

use super::parse::{Endianness, read_u16, read_u32, read_u64};
use super::{
    ElfImage, ElfParserError, ExecInfo, ExecSectype, PIE_LOAD_BASE, Prot,
    section_type,
};
use crate::types::{Machine, ProgramFlags, ProgramType, Type};

/// `Elf64_Ehdr`: the 64-bit ELF header as little-endian bytes.
#[derive(Clone, Copy, Debug)]
struct Header([u8; 64]);

impl Header {
    /// Reads the 64-bit header from `image`.
    ///
    /// # Errors
    ///
    /// [`ElfParserError::Corrupted`] when the image ends inside the
    /// header.
    fn from_image<I: ElfImage>(image: &I) -> Result<Self, ElfParserError> {
        let mut raw = [0u8; 64];
        if image.read_at(&mut raw, 0) < raw.len() {
            return Err(ElfParserError::Corrupted);
        }
        Ok(Self(raw))
    }

    /// `e_type`.
    fn e_type(&self) -> Option<Type> {
        Type::from_u16(read_u16(&self.0, 16, Endianness::Little))
    }

    /// Whether the image is position-independent.
    fn is_pie(&self) -> bool {
        self.e_type().is_some_and(Type::is_pie)
    }

    /// `e_machine`.
    fn e_machine(&self) -> Result<Machine, ElfParserError> {
        Machine::try_from(read_u16(&self.0, 18, Endianness::Little))
    }

    /// `e_entry`.
    fn e_entry(&self) -> u64 {
        read_u64(&self.0, 24, Endianness::Little)
    }

    /// `e_phoff`.
    fn e_phoff(&self) -> u64 {
        read_u64(&self.0, 32, Endianness::Little)
    }

    /// `e_phentsize`.
    fn e_phentsize(&self) -> u16 {
        read_u16(&self.0, 54, Endianness::Little)
    }

    /// `e_phnum`.
    fn e_phnum(&self) -> u16 {
        read_u16(&self.0, 56, Endianness::Little)
    }
}

/// `Elf64_Phdr`: the 64-bit program header as little-endian bytes.
///
/// `p_flags` sits next to `p_type`, unlike the 32-bit header.
#[derive(Clone, Copy, Debug)]
struct ProgramHeader([u8; 56]);

impl ProgramHeader {
    /// Reads the program header at `offset`.
    ///
    /// # Errors
    ///
    /// [`ElfParserError::Corrupted`] when the image ends inside the
    /// header.
    fn from_image<I: ElfImage>(
        image: &I,
        offset: usize,
    ) -> Result<Self, ElfParserError> {
        let mut raw = [0u8; 56];
        if image.read_at(&mut raw, offset) < raw.len() {
            return Err(ElfParserError::Corrupted);
        }
        Ok(Self(raw))
    }

    /// `p_type`.
    fn p_type(&self) -> Option<ProgramType> {
        ProgramType::from_u32(read_u32(&self.0, 0, Endianness::Little))
    }
    /// `p_flags`.
    fn p_flags(&self) -> ProgramFlags {
        ProgramFlags::from(read_u32(&self.0, 4, Endianness::Little))
    }
    /// `p_offset`.
    fn p_offset(&self) -> u64 {
        read_u64(&self.0, 8, Endianness::Little)
    }
    /// `p_vaddr`.
    fn p_vaddr(&self) -> u64 {
        read_u64(&self.0, 16, Endianness::Little)
    }
    /// `p_filesz`.
    fn p_filesz(&self) -> u64 {
        read_u64(&self.0, 32, Endianness::Little)
    }
    /// `p_memsz`.
    fn p_memsz(&self) -> u64 {
        read_u64(&self.0, 40, Endianness::Little)
    }
}

/// Where an image's program headers are, and where it is placed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProgramHeaders {
    offset: usize,
    stride: usize,
    count: u16,
    base: usize,
}

impl ProgramHeaders {
    /// The file offset of program header `index`.
    const fn offset_of(self, index: usize) -> usize {
        self.offset.wrapping_add(index.wrapping_mul(self.stride))
    }
}

/// One `PT_LOAD` segment an image asks to have placed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    offset: usize,
    file_len: usize,
    addr: usize,
    mem_len: usize,
    sectype: ExecSectype,
}

impl Segment {
    /// The file offset of the segment's initialized bytes.
    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }

    /// How many bytes come from the file.
    #[must_use]
    pub const fn file_len(self) -> usize {
        self.file_len
    }

    /// Where the segment lands, already rebased for a
    /// position-independent image.
    #[must_use]
    pub const fn addr(self) -> usize {
        self.addr
    }

    /// How many bytes the segment spans in memory. When it is larger
    /// than [`file_len`](Self::file_len), the trailing bytes read as
    /// zero.
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

/// The loadable segments of an image, in program-header order.
///
/// Created by [`ExecInfo::segments`]. Only `PT_LOAD` headers yield a
/// segment; a program header the image does not cover yields one
/// [`ElfParserError::Corrupted`] and ends the iteration.
#[derive(Debug)]
pub struct Segments<'a, I: ElfImage> {
    image: &'a I,
    phdrs: ProgramHeaders,
    index: u16,
}

impl<'a, I: ElfImage> Segments<'a, I> {
    /// Walks `image`'s program headers from the first.
    pub(crate) const fn new(image: &'a I, phdrs: ProgramHeaders) -> Self {
        Self {
            image,
            phdrs,
            index: 0,
        }
    }
}

impl<I: ElfImage> Iterator for Segments<'_, I> {
    type Item = Result<Segment, ElfParserError>;

    #[expect(
        clippy::cast_possible_truncation,
        reason = "every supported target holds a 64-bit pointer"
    )]
    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.phdrs.count {
            let phdr = match ProgramHeader::from_image(
                self.image,
                self.phdrs.offset_of(usize::from(self.index)),
            ) {
                Ok(phdr) => phdr,
                Err(error) => {
                    self.index = self.phdrs.count;
                    return Some(Err(error));
                }
            };
            self.index += 1;
            if phdr.p_type() == Some(ProgramType::PT_LOAD) {
                return Some(Ok(Segment {
                    offset: phdr.p_offset() as usize,
                    file_len: phdr.p_filesz() as usize,
                    addr: (phdr.p_vaddr() as usize)
                        .wrapping_add(self.phdrs.base),
                    mem_len: phdr.p_memsz() as usize,
                    sectype: section_type(phdr.p_flags()),
                }));
            }
        }
        None
    }
}

/// Reads a 64-bit image: check the machine, walk every program header,
/// and report what the loadable ones ask for.
#[expect(
    clippy::cast_possible_truncation,
    reason = "every supported target holds a 64-bit pointer"
)]
pub(super) fn parse<I: ElfImage>(
    image: &I,
) -> Result<ExecInfo, ElfParserError> {
    // Every address this crate writes is a `usize`, so the platform
    // has to hold a 64-bit ELF address.
    const _: () = assert!(size_of::<usize>() >= size_of::<u64>());

    let header = Header::from_image(image)?;
    if header.e_machine()? != Machine::EM_X86_64 {
        return Err(ElfParserError::WrongArch);
    }

    if header.e_phnum() != 0
        && usize::from(header.e_phentsize()) < size_of::<ProgramHeader>()
    {
        return Err(ElfParserError::Corrupted);
    }

    let load_base = if header.is_pie() { PIE_LOAD_BASE } else { 0 };
    let phdrs = ProgramHeaders {
        offset: header.e_phoff() as usize,
        stride: usize::from(header.e_phentsize()),
        count: header.e_phnum(),
        base: load_base,
    };

    let mut stack_prot = Prot::ALL;
    for index in 0..usize::from(phdrs.count) {
        let phdr = ProgramHeader::from_image(image, phdrs.offset_of(index))?;
        if phdr.p_type() == Some(ProgramType::PT_GNU_STACK) {
            stack_prot = super::stack_prot(phdr.p_flags());
        }
    }

    Ok(ExecInfo::new(
        (header.e_entry() as usize).wrapping_add(load_base),
        stack_prot,
        phdrs,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{EI_CLASS, EI_DATA, EI_NIDENT, ELFMAG};
    use crate::tests::MemImage;
    use crate::types::{Class, Data, ProgramFlags};
    use std::vec::Vec;

    fn ident() -> [u8; EI_NIDENT] {
        let mut ident = [0u8; EI_NIDENT];
        ident[..ELFMAG.len()].copy_from_slice(&ELFMAG);
        ident[EI_CLASS] = Class::ELFCLASS64 as u8;
        ident[EI_DATA] = Data::ELFDATA2LSB as u8;
        ident
    }

    /// Builds a 64-bit image with `phdrs` stored at `e_phentsize` stride.
    fn image(
        e_type: u16,
        e_entry: u64,
        e_phentsize: u16,
        phdrs: &[[u8; 56]],
        size: usize,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ident());
        bytes.extend_from_slice(&e_type.to_le_bytes());
        bytes.extend_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&e_entry.to_le_bytes());
        bytes.extend_from_slice(&64u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&64u16.to_le_bytes());
        bytes.extend_from_slice(&e_phentsize.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(phdrs.len()).unwrap().to_le_bytes(),
        );
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        for phdr in phdrs {
            let start = bytes.len();
            bytes.extend_from_slice(phdr);
            let stride =
                usize::from(e_phentsize).max(size_of::<ProgramHeader>());
            bytes.resize(start + stride, 0);
        }
        bytes.resize(size, 0);
        bytes
    }

    fn phdr(
        p_type: u32,
        p_offset: u64,
        p_vaddr: u64,
        p_filesz: u64,
        p_memsz: u64,
        p_flags: ProgramFlags,
    ) -> [u8; 56] {
        let mut raw = [0u8; 56];
        raw[0..4].copy_from_slice(&p_type.to_le_bytes());
        raw[4..8].copy_from_slice(&u32::from(p_flags).to_le_bytes());
        raw[8..16].copy_from_slice(&p_offset.to_le_bytes());
        raw[16..24].copy_from_slice(&p_vaddr.to_le_bytes());
        raw[24..32].copy_from_slice(&p_vaddr.to_le_bytes()); // p_paddr
        raw[32..40].copy_from_slice(&p_filesz.to_le_bytes());
        raw[40..48].copy_from_slice(&p_memsz.to_le_bytes());
        raw[48..56].copy_from_slice(&1u64.to_le_bytes()); // p_align
        raw
    }

    fn segments(info: &ExecInfo, image: &MemImage) -> Vec<Segment> {
        info.segments(image).collect::<Result<Vec<_>, _>>().unwrap()
    }

    #[test]
    fn loads_et_exec() {
        let one = phdr(
            ProgramType::PT_LOAD as u32,
            80,
            0x0040_0000,
            8,
            8,
            ProgramFlags::PF_R,
        );
        let bytes =
            image(2, 0x0040_0000, 56, core::slice::from_ref(&one), 160);
        let image = MemImage::new(bytes);
        let info = crate::parse(&image).unwrap();
        assert_eq!(info.entry(), 0x0040_0000);
        let segments = segments(&info, &image);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].offset(), 80);
        assert_eq!(segments[0].file_len(), 8);
        assert_eq!(segments[0].addr(), 0x0040_0000);
        assert_eq!(segments[0].mem_len(), 8);
        assert_eq!(
            segments[0].sectype(),
            ExecSectype::ALLOC | ExecSectype::LOAD | ExecSectype::READ
        );
    }

    #[test]
    fn loads_et_rel_with_base() {
        let one = phdr(
            ProgramType::PT_LOAD as u32,
            80,
            0x2000,
            4,
            4,
            ProgramFlags::PF_R | ProgramFlags::PF_X,
        );
        let bytes = image(1, 0x2000, 56, core::slice::from_ref(&one), 160);
        let image = MemImage::new(bytes);
        let info = crate::parse(&image).unwrap();
        assert_eq!(info.entry(), 0x2000 + PIE_LOAD_BASE);
        assert_eq!(segments(&info, &image)[0].addr(), 0x2000 + PIE_LOAD_BASE);
    }

    #[test]
    fn unknown_e_type_is_not_pie() {
        let one = phdr(
            ProgramType::PT_LOAD as u32,
            80,
            0x2000,
            4,
            4,
            ProgramFlags::PF_R,
        );
        let bytes = image(99, 0x2000, 56, core::slice::from_ref(&one), 160);
        let image = MemImage::new(bytes);
        let info = crate::parse(&image).unwrap();
        assert_eq!(info.entry(), 0x2000);
        assert_eq!(segments(&info, &image)[0].addr(), 0x2000);
    }

    #[test]
    fn empty_image_reads_no_segments() {
        let bytes = image(2, 0x0040_0000, 56, &[], 64);
        let image = MemImage::new(bytes);
        let info = crate::parse(&image).unwrap();
        assert_eq!(info.entry(), 0x0040_0000);
        assert!(info.segments(&image).next().is_none());
    }

    #[test]
    fn gnu_stack_and_other_types() {
        let note = phdr(4, 0, 0, 0, 0, ProgramFlags::from(0));
        let stack = phdr(
            ProgramType::PT_GNU_STACK as u32,
            0,
            0,
            0,
            0,
            ProgramFlags::PF_R | ProgramFlags::PF_W | ProgramFlags::PF_X,
        );
        let bytes = image(2, 0x0040_0000, 56, &[note, stack], 64 + 112);
        let image = MemImage::new(bytes);
        let info = crate::parse(&image).unwrap();
        assert_eq!(info.stack_prot(), Prot::ALL);
        assert!(segments(&info, &image).is_empty());
    }

    #[test]
    fn segments_keep_load_order() {
        let note = phdr(4, 0, 0, 0, 0, ProgramFlags::from(0));
        let stack = phdr(
            ProgramType::PT_GNU_STACK as u32,
            0,
            0,
            0,
            0,
            ProgramFlags::PF_R,
        );
        let first = phdr(
            ProgramType::PT_LOAD as u32,
            80,
            0x4000,
            4,
            4,
            ProgramFlags::PF_R,
        );
        let second = phdr(
            ProgramType::PT_LOAD as u32,
            96,
            0x5000,
            4,
            8,
            ProgramFlags::PF_R | ProgramFlags::PF_W,
        );
        let bytes =
            image(2, 0x4000, 56, &[note, stack, first, second], 64 + 4 * 56);
        let image = MemImage::new(bytes);
        let info = crate::parse(&image).unwrap();
        let segments = segments(&info, &image);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].offset(), 80);
        assert_eq!(segments[1].offset(), 96);
        assert_eq!(segments[1].mem_len(), 8);
        assert_eq!(
            segments[1].sectype(),
            ExecSectype::ALLOC
                | ExecSectype::LOAD
                | ExecSectype::READ
                | ExecSectype::WRITE
        );
    }

    #[test]
    fn segments_end_after_a_short_read() {
        let one = phdr(
            ProgramType::PT_LOAD as u32,
            80,
            0x4000,
            4,
            4,
            ProgramFlags::PF_R,
        );
        let bytes = image(2, 0x4000, 56, core::slice::from_ref(&one), 160);
        let image = MemImage::new(bytes);
        let info = crate::parse(&image).unwrap();
        image.fail.set(true);
        let mut segments = info.segments(&image);
        assert_eq!(segments.next(), Some(Err(ElfParserError::Corrupted)));
        assert_eq!(segments.next(), None);
    }

    #[test]
    fn rejects_wrong_machine() {
        for machine in [3u16, 99] {
            let mut bytes = image(2, 0x0040_0000, 56, &[], 64);
            bytes[18..20].copy_from_slice(&machine.to_le_bytes());
            let image = MemImage::new(bytes);
            assert_eq!(crate::parse(&image), Err(ElfParserError::WrongArch));
        }
    }

    #[test]
    fn rejects_short_phentsize() {
        let one = phdr(
            ProgramType::PT_LOAD as u32,
            0,
            0x4000,
            4,
            4,
            ProgramFlags::PF_R,
        );
        let bytes = image(2, 0x4000, 16, core::slice::from_ref(&one), 128);
        let image = MemImage::new(bytes);
        assert_eq!(crate::parse(&image), Err(ElfParserError::Corrupted));
    }

    #[test]
    fn short_header_is_corrupted() {
        let image = MemImage::new(ident().to_vec());
        assert_eq!(crate::parse(&image), Err(ElfParserError::Corrupted));
    }

    #[test]
    fn phdr_past_end_is_corrupt() {
        let mut bytes = image(2, 0x0040_0000, 56, &[], 64);
        bytes[32..40].copy_from_slice(&4096u64.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        let image = MemImage::new(bytes);
        assert_eq!(crate::parse(&image), Err(ElfParserError::Corrupted));
    }

    #[test]
    fn elf_header_getters_read_spec_offsets() {
        let mut raw = [0u8; 64];
        raw[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type
        raw[18..20].copy_from_slice(&62u16.to_le_bytes()); // e_machine
        raw[24..32].copy_from_slice(&0x0040_0000u64.to_le_bytes()); // e_entry
        raw[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        raw[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        raw[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        let h = Header(raw);
        assert_eq!(h.e_type(), Some(Type::ET_EXEC));
        assert_eq!(h.e_machine(), Ok(Machine::EM_X86_64));
        assert_eq!(h.e_entry(), 0x0040_0000);
        assert_eq!(h.e_phoff(), 64);
        assert_eq!(h.e_phentsize(), 56);
        assert_eq!(h.e_phnum(), 1);
        raw[18..20].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(Header(raw).e_machine(), Err(ElfParserError::WrongArch));
        raw[16..18].copy_from_slice(&99u16.to_le_bytes());
        assert_eq!(Header(raw).e_type(), None);
    }

    #[test]
    fn program_header_getters_read_spec_offsets() {
        let raw = phdr(
            ProgramType::PT_LOAD as u32,
            80,
            0x4000,
            8,
            16,
            ProgramFlags::PF_R,
        );
        let p = ProgramHeader(raw);
        assert_eq!(p.p_type(), Some(ProgramType::PT_LOAD));
        assert_eq!(p.p_flags(), ProgramFlags::PF_R);
        assert_eq!(p.p_offset(), 80);
        assert_eq!(p.p_vaddr(), 0x4000);
        assert_eq!(p.p_filesz(), 8);
        assert_eq!(p.p_memsz(), 16);
    }
}
