// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The 64-bit ELF reader (`ELFCLASS64` / `EM_X86_64`).
//!
//! This path owns its header and program-header walk. The 32-bit
//! reader in [`super::x86`] is a separate module: the two on-disk
//! program headers differ in field order, and a shared walk would put
//! a class test at every access.

use super::{
    ElfImage, ExecError, ExecInfo, IDENT_LEN, PIE_LOAD_BASE, PT_GNU_STACK,
    PT_LOAD, Prot, is_pie, read_pod, section_type,
};
use core::mem::size_of;

/// `EM_X86_64`.
const EM_X86_64: u16 = 62;

/// The 64-bit ELF header (`Elf64_Ehdr`).
///
/// Field names are the on-disk `e_*` members.
#[repr(C)]
struct FileHeader {
    e_ident: [u8; IDENT_LEN],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

/// The 64-bit program header (`Elf64_Phdr`).
///
/// Field names are the on-disk `p_*` members. Note that `p_flags`
/// sits next to `p_type`, unlike the 32-bit header.
#[repr(C)]
struct ProgramHeader {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

/// The `usize` of a 64-bit on-disk word. The crate asserts `usize` is
/// at least 64 bits (ADR 0003), so this cannot truncate.
#[expect(
    clippy::cast_possible_truncation,
    reason = "usize is at least 64 bits (ADR 0003)"
)]
const fn width(value: u64) -> usize {
    value as usize
}

/// Loads a 64-bit image: walk the program headers, place `PT_LOAD`
/// segments, and remember the stack protection.
pub(super) fn load<I: ElfImage>(
    image: &mut I,
) -> Result<ExecInfo, ExecError<I::Error>> {
    // Every address this crate writes is a `usize`, so the platform
    // has to hold a 64-bit ELF address (ADR 0003).
    const _: () = assert!(size_of::<usize>() >= size_of::<u64>());

    let ident = crate::read_ident(image)?;
    crate::check_ident(&ident, crate::EiClass::X86_64)?;
    let header = read_pod::<FileHeader, _>(
        image,
        0,
        ExecError::<I::Error>::NotExecutable,
    )?;
    if header.e_machine != EM_X86_64 {
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
                        phdr.p_offset,
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
    use crate::{ET_REL, ExecError, ExecSectype, PF_R, PF_W, PF_X};
    use std::vec::Vec;

    fn ident() -> [u8; IDENT_LEN] {
        let mut ident = [0u8; IDENT_LEN];
        ident[..4].copy_from_slice(b"\x7fELF");
        ident[4] = 2;
        ident[5] = crate::DATA_LSB;
        ident
    }

    /// Builds a 64-bit image with `phdrs` stored at `phentsize` stride.
    fn image(
        e_type: u16,
        e_entry: u64,
        e_phentsize: u16,
        phdrs: &[ProgramHeader],
        size: usize,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ident());
        bytes.extend_from_slice(&e_type.to_le_bytes());
        bytes.extend_from_slice(&EM_X86_64.to_le_bytes());
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
            bytes.extend_from_slice(&phdr.p_type.to_le_bytes());
            bytes.extend_from_slice(&phdr.p_flags.to_le_bytes());
            bytes.extend_from_slice(&phdr.p_offset.to_le_bytes());
            bytes.extend_from_slice(&phdr.p_vaddr.to_le_bytes());
            bytes.extend_from_slice(&phdr.p_paddr.to_le_bytes());
            bytes.extend_from_slice(&phdr.p_filesz.to_le_bytes());
            bytes.extend_from_slice(&phdr.p_memsz.to_le_bytes());
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
        p_offset: u64,
        p_vaddr: u64,
        p_filesz: u64,
        p_memsz: u64,
        p_flags: u32,
    ) -> ProgramHeader {
        ProgramHeader {
            p_type,
            p_flags,
            p_offset,
            p_vaddr,
            p_paddr: p_vaddr,
            p_filesz,
            p_memsz,
            p_align: 1,
        }
    }

    #[test]
    fn loads_et_exec() {
        let one = phdr(PT_LOAD, 80, 0x0040_0000, 8, 8, PF_R);
        let bytes =
            image(2, 0x0040_0000, 56, core::slice::from_ref(&one), 160);
        let mut image = MemImage::new(bytes);
        let info = crate::load(&mut image).unwrap();
        assert_eq!(info.entry(), 0x0040_0000);
        assert_eq!(image.loads.len(), 1);
        assert_eq!(
            image.loads[0],
            (
                80,
                8,
                0x0040_0000,
                8,
                ExecSectype::ALLOC | ExecSectype::LOAD | ExecSectype::READ
            )
        );
    }

    #[test]
    fn loads_et_rel_with_base() {
        let one = phdr(PT_LOAD, 80, 0x2000, 4, 4, PF_R | PF_X);
        let bytes =
            image(ET_REL, 0x2000, 56, core::slice::from_ref(&one), 160);
        let mut image = MemImage::new(bytes);
        let info = crate::load(&mut image).unwrap();
        assert_eq!(info.entry(), 0x2000 + PIE_LOAD_BASE);
        assert_eq!(image.loads[0].2, 0x2000 + PIE_LOAD_BASE);
    }

    #[test]
    fn gnu_stack_and_other_types() {
        let note = phdr(4, 0, 0, 0, 0, 0);
        let stack = phdr(PT_GNU_STACK, 0, 0, 0, 0, PF_R | PF_W | PF_X);
        let bytes = image(2, 0x0040_0000, 56, &[note, stack], 64 + 112);
        let mut image = MemImage::new(bytes);
        let info = crate::load(&mut image).unwrap();
        assert_eq!(info.stack_prot(), Prot::ALL);
        assert!(image.loads.is_empty());
    }

    #[test]
    fn rejects_wrong_machine() {
        let mut bytes = image(2, 0x0040_0000, 56, &[], 64);
        bytes[18] = 99;
        let mut image = MemImage::new(bytes);
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
    fn short_header_is_not_executable() {
        let mut image = MemImage::new(ident().to_vec());
        assert_eq!(
            crate::load(&mut image),
            Err(ExecError::<u8>::NotExecutable)
        );
    }

    #[test]
    fn phdr_past_end_is_corrupt() {
        let mut bytes = image(2, 0x0040_0000, 56, &[], 64);
        bytes[32..40].copy_from_slice(&4096u64.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        let mut image = MemImage::new(bytes);
        assert_eq!(crate::load(&mut image), Err(ExecError::<u8>::Corrupt));
    }

    #[test]
    fn image_errors_surface() {
        let one = phdr(PT_LOAD, 80, 0x4000, 4, 4, PF_R);
        let bytes = image(2, 0x4000, 56, core::slice::from_ref(&one), 160);
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
}
