// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The 32-bit ELF reader (`ELFCLASS32` / `EM_386`).
//!
//! This path owns its header and program-header walk. The 64-bit
//! reader in [`super::x86_64`] is a separate module: the two on-disk
//! program headers differ in field order, and a shared walk would put
//! a class test at every access.

use super::{
    ElfImage, ExecError, ExecInfo, IDENT_LEN, PIE_LOAD_BASE, PT_GNU_STACK,
    PT_LOAD, Prot, is_pie, read_pod, section_type,
};
use core::mem::size_of;

/// `EM_386`.
const EM_386: u16 = 3;

/// The 32-bit ELF header (`Elf32_Ehdr`).
///
/// Field names are the on-disk `e_*` members.
#[repr(C)]
struct FileHeader {
    e_ident: [u8; IDENT_LEN],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u32,
    e_phoff: u32,
    e_shoff: u32,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// The 32-bit program header (`Elf32_Phdr`).
///
/// Field names are the on-disk `p_*` members.
#[repr(C)]
struct ProgramHeader {
    p_type: u32,
    p_offset: u32,
    p_vaddr: u32,
    p_paddr: u32,
    p_filesz: u32,
    p_memsz: u32,
    p_flags: u32,
    p_align: u32,
}

/// The `usize` of a 32-bit on-disk word. `usize` is at least 32 bits
/// on every target this crate supports (ADR 0003).
const fn width(value: u32) -> usize {
    value as usize
}

/// Loads a 32-bit image: walk the program headers, place `PT_LOAD`
/// segments, and remember the stack protection.
pub(super) fn load<I: ElfImage>(
    image: &mut I,
) -> Result<ExecInfo, ExecError<I::Error>> {
    let ident = crate::read_ident(image)?;
    crate::check_ident(&ident, crate::EiClass::X86)?;
    let header = read_pod::<FileHeader, _>(
        image,
        0,
        ExecError::<I::Error>::NotExecutable,
    )?;
    if header.e_machine != EM_386 {
        return Err(ExecError::WrongArch);
    }

    let load_base = if is_pie(header.e_type) {
        PIE_LOAD_BASE
    } else {
        0
    };
    let mut stack_prot = Prot::ALL;
    let entry = width(header.e_entry).wrapping_add(load_base);

    if header.e_phnum != 0
        && usize::from(header.e_phentsize) < size_of::<ProgramHeader>()
    {
        return Err(ExecError::Corrupt);
    }

    let phoff = width(header.e_phoff);
    let stride = usize::from(header.e_phentsize);
    for index in 0..usize::from(header.e_phnum) {
        let offset = phoff.wrapping_add(index.wrapping_mul(stride));
        let phdr = read_pod::<ProgramHeader, _>(
            image,
            offset as u64,
            ExecError::<I::Error>::Corrupt,
        )?;
        match phdr.p_type {
            PT_LOAD => {
                let type_ = section_type(phdr.p_flags);
                image
                    .place(
                        u64::from(phdr.p_offset),
                        width(phdr.p_filesz),
                        width(phdr.p_vaddr).wrapping_add(load_base),
                        width(phdr.p_memsz),
                        type_,
                    )
                    .map_err(ExecError::Image)?;
            }
            PT_GNU_STACK => {
                stack_prot = super::stack_prot(phdr.p_flags);
            }
            _ => {}
        }
    }

    Ok(ExecInfo::new(entry, stack_prot))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::MemImage;
    use crate::{ET_DYN, ExecError, ExecSectype, PF_R, PF_W, PF_X};
    use std::vec::Vec;

    pub(crate) fn ident() -> [u8; IDENT_LEN] {
        let mut ident = [0u8; IDENT_LEN];
        ident[..4].copy_from_slice(b"\x7fELF");
        ident[4] = 1;
        ident[5] = crate::DATA_LSB;
        ident
    }

    /// Builds a 32-bit image with `phdrs` stored at `phentsize` stride.
    fn image(
        e_type: u16,
        e_entry: u32,
        e_phentsize: u16,
        phdrs: &[ProgramHeader],
        size: usize,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ident());
        bytes.extend_from_slice(&e_type.to_le_bytes());
        bytes.extend_from_slice(&EM_386.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&e_entry.to_le_bytes());
        bytes.extend_from_slice(&52u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&52u16.to_le_bytes());
        bytes.extend_from_slice(&e_phentsize.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(phdrs.len()).unwrap().to_le_bytes(),
        );
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        for phdr in phdrs {
            let start = bytes.len();
            bytes.extend_from_slice(&phdr.p_type.to_le_bytes());
            bytes.extend_from_slice(&phdr.p_offset.to_le_bytes());
            bytes.extend_from_slice(&phdr.p_vaddr.to_le_bytes());
            bytes.extend_from_slice(&phdr.p_paddr.to_le_bytes());
            bytes.extend_from_slice(&phdr.p_filesz.to_le_bytes());
            bytes.extend_from_slice(&phdr.p_memsz.to_le_bytes());
            bytes.extend_from_slice(&phdr.p_flags.to_le_bytes());
            bytes.extend_from_slice(&phdr.p_align.to_le_bytes());
            let stride =
                usize::from(e_phentsize).max(size_of::<ProgramHeader>());
            bytes.resize(start + stride, 0);
        }
        bytes.resize(size, 0);
        bytes
    }

    fn phdr(
        p_type: u32,
        p_offset: u32,
        p_vaddr: u32,
        p_filesz: u32,
        p_memsz: u32,
        p_flags: u32,
    ) -> ProgramHeader {
        ProgramHeader {
            p_type,
            p_offset,
            p_vaddr,
            p_paddr: p_vaddr,
            p_filesz,
            p_memsz,
            p_flags,
            p_align: 1,
        }
    }

    #[test]
    fn loads_et_exec() {
        let one = phdr(PT_LOAD, 64, 0x4000, 8, 16, PF_R | PF_X);
        let bytes = image(2, 0x4010, 32, core::slice::from_ref(&one), 128);
        let mut image = MemImage::new(bytes);
        let info = crate::load(&mut image).unwrap();
        assert_eq!(info.entry(), 0x4010);
        assert_eq!(info.stack_prot(), Prot::ALL);
        assert_eq!(
            image.loads[0],
            (
                64,
                8,
                0x4000,
                16,
                ExecSectype::ALLOC
                    | ExecSectype::LOAD
                    | ExecSectype::READ
                    | ExecSectype::EXECUTE
            )
        );
    }

    #[test]
    fn loads_et_dyn_with_base() {
        let one = phdr(PT_LOAD, 64, 0x1000, 4, 4, PF_R | PF_W);
        let bytes =
            image(ET_DYN, 0x1000, 32, core::slice::from_ref(&one), 128);
        let mut image = MemImage::new(bytes);
        let info = crate::load(&mut image).unwrap();
        assert_eq!(info.entry(), 0x1000 + PIE_LOAD_BASE);
        assert_eq!(image.loads[0].2, 0x1000 + PIE_LOAD_BASE);
    }

    #[test]
    fn places_two_loads_in_order() {
        let a = phdr(PT_LOAD, 64, 0x1000, 4, 4, PF_R);
        let b = phdr(PT_LOAD, 68, 0x2000, 4, 8, PF_W);
        let bytes = image(2, 0x1000, 32, &[a, b], 128);
        let mut image = MemImage::new(bytes);
        let _ = crate::load(&mut image).unwrap();
        assert_eq!(image.loads.len(), 2);
        assert_eq!(image.loads[0].2, 0x1000);
        assert_eq!(image.loads[1].2, 0x2000);
    }

    #[test]
    fn gnu_stack_sets_prot_and_ignores_other_types() {
        let load = phdr(PT_LOAD, 64, 0x1000, 4, 4, PF_R);
        let note = phdr(4, 0, 0, 0, 0, 0);
        let stack = phdr(PT_GNU_STACK, 0, 0, 0, 0, PF_R | PF_X);
        let bytes = image(2, 0x1000, 32, &[load, note, stack], 256);
        let mut image = MemImage::new(bytes);
        let info = crate::load(&mut image).unwrap();
        assert_eq!(info.stack_prot(), Prot::READ | Prot::EXECUTE);
        assert_eq!(image.loads.len(), 1);
    }

    #[test]
    fn gnu_stack_last_wins_and_can_be_none() {
        let a = phdr(PT_GNU_STACK, 0, 0, 0, 0, PF_R);
        let b = phdr(PT_GNU_STACK, 0, 0, 0, 0, 0);
        let bytes = image(2, 0x1000, 32, &[a, b], 128);
        let mut image = MemImage::new(bytes);
        let info = crate::load(&mut image).unwrap();
        assert_eq!(info.stack_prot(), Prot::NONE);
    }

    #[test]
    fn rejects_wrong_machine() {
        let bytes = image(2, 0x4000, 32, &[], 64);
        let mut mut_bytes = bytes;
        mut_bytes[18] = 99;
        let mut image = MemImage::new(mut_bytes);
        assert_eq!(crate::load(&mut image), Err(ExecError::<u8>::WrongArch));
    }

    #[test]
    fn rejects_short_phentsize() {
        let one = phdr(PT_LOAD, 0, 0x4000, 4, 4, PF_R);
        let bytes = image(2, 0x4000, 16, core::slice::from_ref(&one), 128);
        let mut image = MemImage::new(bytes);
        assert_eq!(crate::load(&mut image), Err(ExecError::<u8>::Corrupt));
    }

    #[test]
    fn allows_short_phentsize_without_phdrs() {
        let bytes = image(2, 0x4000, 0, &[], 64);
        let mut image = MemImage::new(bytes);
        let info = crate::load(&mut image).unwrap();
        assert_eq!(info.entry(), 0x4000);
        assert!(image.loads.is_empty());
    }

    #[test]
    fn walks_padded_stride() {
        let a = phdr(PT_LOAD, 160, 0x1000, 4, 4, PF_R);
        let b = phdr(PT_GNU_STACK, 0, 0, 0, 0, PF_R | PF_X);
        let bytes = image(2, 0x1000, 48, &[a, b], 256);
        let mut image = MemImage::new(bytes);
        let info = crate::load(&mut image).unwrap();
        assert_eq!(info.stack_prot(), Prot::READ | Prot::EXECUTE);
        assert_eq!(image.loads.len(), 1);
    }

    #[test]
    fn short_header_is_not_executable() {
        let mut image = MemImage::new(ident().to_vec());
        assert_eq!(
            crate::load(&mut image),
            Err(ExecError::<u8>::NotExecutable)
        );
    }

    #[test]
    fn short_phdr_is_corrupt() {
        let mut bytes = image(2, 0x4000, 32, &[], 52 + 8);
        bytes[44..46].copy_from_slice(&1u16.to_le_bytes());
        let mut image = MemImage::new(bytes);
        assert_eq!(crate::load(&mut image), Err(ExecError::<u8>::Corrupt));
    }

    #[test]
    fn phdr_past_end_is_corrupt() {
        let mut bytes = image(2, 0x4000, 32, &[], 64);
        bytes[28..32].copy_from_slice(&1024u32.to_le_bytes());
        bytes[44..46].copy_from_slice(&1u16.to_le_bytes());
        let mut image = MemImage::new(bytes);
        assert_eq!(crate::load(&mut image), Err(ExecError::<u8>::Corrupt));
    }

    #[test]
    fn image_errors_surface() {
        let one = phdr(PT_LOAD, 64, 0x4000, 4, 4, PF_R);
        let bytes = image(2, 0x4000, 32, core::slice::from_ref(&one), 128);
        let mut image = MemImage::new(bytes.clone());
        image.fail_read = true;
        assert_eq!(crate::load(&mut image), Err(ExecError::Image(1u8)));
        let mut image = MemImage::new(bytes.clone());
        // Peek succeeds; the identification read then fails.
        image.fail_after_reads = Some(1);
        assert_eq!(crate::load(&mut image), Err(ExecError::Image(1u8)));
        let mut image = MemImage::new(bytes.clone());
        // Peek and identification succeed; the header read then fails.
        image.fail_after_reads = Some(2);
        assert_eq!(crate::load(&mut image), Err(ExecError::Image(1u8)));
        let mut image = MemImage::new(bytes);
        image.fail_place = true;
        assert_eq!(crate::load(&mut image), Err(ExecError::Image(4u8)));
    }

    #[test]
    fn zero_phnum_with_tiny_entsize_is_ok() {
        let bytes = image(2, 0x4000, 0, &[], 64);
        let mut image = MemImage::new(bytes);
        let info = crate::load(&mut image).unwrap();
        assert_eq!(info.entry(), 0x4000);
    }
}
