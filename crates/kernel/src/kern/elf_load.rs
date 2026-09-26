// SPDX-License-Identifier: HPND
// Derived from kern/elf-load.c:
//   Copyright (c) 1995, 1994, 1993, 1992, 1991, 1990 Open Software
//   Foundation, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The ELF executable loader, which `kern/elf-load.c` used to define.

#![allow(non_camel_case_types)]

use crate::arch::types::{VmOffset, VmSize};
use crate::vm::types::VmProt;
use core::ffi::{c_int, c_void};
use core::mem::{MaybeUninit, size_of};

/// `exec_sectype_t` of <mach/exec/exec.h>: a set of bits.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct ExecSectype(c_int);

impl ExecSectype {
    /// `EXEC_SECTYPE_READ`: the section is readable.
    pub const READ: Self = Self(VmProt::READ.bits());
    /// `EXEC_SECTYPE_WRITE`: the section is writable.
    pub const WRITE: Self = Self(VmProt::WRITE.bits());
    /// `EXEC_SECTYPE_EXECUTE`: the section is executable.
    pub const EXECUTE: Self = Self(VmProt::EXECUTE.bits());
    /// `EXEC_SECTYPE_ALLOC`: the section needs memory allocated for it.
    pub const ALLOC: Self = Self(0x0100);
    /// `EXEC_SECTYPE_LOAD`: the section's contents come from the file.
    pub const LOAD: Self = Self(0x0200);

    /// Whether every bit of `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The `EXEC_SECTYPE_PROT_MASK` bits as a [`VmProt`].
    #[must_use]
    pub const fn protection(self) -> VmProt {
        VmProt::from_bits(self.0 & VmProt::ALL.bits())
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

/// `exec_read_func_t` of <mach/exec/exec.h>: reads raw file bytes for the
/// loader.
///
/// # Safety
///
/// A function stored as a `ReadFn` must be callable for the `handle` the
/// loader passes it, for as long as the `exec_load()` call runs. It must
/// copy up to `size` bytes starting at `file_ofs` in the image `handle`
/// names into `buf`, which must be writable for `size` bytes, write the
/// number of bytes actually copied through `out_actual`, and return zero
/// on success or a nonzero code the loader reports back to its caller.
pub type ReadFn = unsafe fn(
    handle: *mut c_void,
    file_ofs: VmOffset,
    buf: *mut c_void,
    size: VmSize,
    out_actual: *mut VmSize,
) -> c_int;

/// `exec_read_exec_func_t` of <mach/exec/exec.h>: maps or copies one loadable
/// section into the image being built.
///
/// # Safety
///
/// A function stored as a `ReadExecFn` must be callable for the `handle`
/// the loader passes it, for as long as the `exec_load()` call runs. It
/// must place the `file_size` bytes at `file_ofs` in the image `handle`
/// names at `mem_addr` in the loaded image, honoring `section_type`, leave
/// the trailing `mem_size - file_size` bytes reading as zero when
/// `mem_size` is larger, and return zero on success or a nonzero code the
/// loader reports back to its caller.
pub type ReadExecFn = unsafe fn(
    handle: *mut c_void,
    file_ofs: VmOffset,
    file_size: VmSize,
    mem_addr: VmOffset,
    mem_size: VmSize,
    section_type: ExecSectype,
) -> c_int;

/// `exec_info_t` of <mach/exec/exec.h>: the recognized image handed back to
/// `exec_load()`'s caller.
///
/// `exec_load()` zeroes the struct once the image is recognized and writes
/// `entry` and `stack_prot` only after the whole image has loaded.
#[repr(C)]
#[allow(dead_code)]
#[allow(missing_docs)]
pub struct ExecInfo {
    format: c_int,
    entry: VmOffset,
    init_dp: VmOffset,
    interp: VmOffset,
    stack_prot: VmProt,
}

impl ExecInfo {
    /// `exec_info_t.stack_prot`: the protection the image wants on its stack.
    pub(crate) const fn stack_prot(&self) -> VmProt {
        self.stack_prot
    }
}

/// The ELF scalar types of <mach/exec/elf.h>, which its `Ehdr` and `Phdr`
/// structures use.
type Elf32_Half = u16;
type Elf32_Word = u32;
type Elf32_Addr = u32;
type Elf32_Off = u32;
type Elf64_Half = u16;
type Elf64_Word = u32;
type Elf64_Addr = u64;
type Elf64_Off = u64;
type Elf64_Xword = u64;

/// `Elf32_Ehdr` of <mach/exec/elf.h>, field for field.
#[repr(C)]
#[allow(dead_code)]
// The field names are the ELF `Ehdr`'s `e_*` members.
#[allow(clippy::struct_field_names)]
struct Elf32_Ehdr {
    e_ident: [u8; EI_NIDENT],
    e_type: Elf32_Half,
    e_machine: Elf32_Half,
    e_version: Elf32_Word,
    e_entry: Elf32_Addr,
    e_phoff: Elf32_Off,
    e_shoff: Elf32_Off,
    e_flags: Elf32_Word,
    e_ehsize: Elf32_Half,
    e_phentsize: Elf32_Half,
    e_phnum: Elf32_Half,
    e_shentsize: Elf32_Half,
    e_shnum: Elf32_Half,
    e_shstrndx: Elf32_Half,
}

/// `Elf64_Ehdr` of <mach/exec/elf.h>, field for field.
#[repr(C)]
#[allow(dead_code)]
// The field names are the ELF `Ehdr`'s `e_*` members.
#[allow(clippy::struct_field_names)]
struct Elf64_Ehdr {
    e_ident: [u8; EI_NIDENT],
    e_type: Elf64_Half,
    e_machine: Elf64_Half,
    e_version: Elf64_Word,
    e_entry: Elf64_Addr,
    e_phoff: Elf64_Off,
    e_shoff: Elf64_Off,
    e_flags: Elf64_Word,
    e_ehsize: Elf64_Half,
    e_phentsize: Elf64_Half,
    e_phnum: Elf64_Half,
    e_shentsize: Elf64_Half,
    e_shnum: Elf64_Half,
    e_shstrndx: Elf64_Half,
}

/// `Elf32_Phdr` of <mach/exec/elf.h>, field for field.
#[repr(C)]
#[allow(dead_code)]
// The field names are the ELF `Phdr`'s `p_*` members.
#[allow(clippy::struct_field_names)]
struct Elf32_Phdr {
    p_type: Elf32_Word,
    p_offset: Elf32_Off,
    p_vaddr: Elf32_Addr,
    p_paddr: Elf32_Addr,
    p_filesz: Elf32_Word,
    p_memsz: Elf32_Word,
    p_flags: Elf32_Word,
    p_align: Elf32_Word,
}

/// `Elf64_Phdr` of <mach/exec/elf.h>, field for field.
#[repr(C)]
#[allow(dead_code)]
// The field names are the ELF `Phdr`'s `p_*` members.
#[allow(clippy::struct_field_names)]
struct Elf64_Phdr {
    p_type: Elf64_Word,
    p_flags: Elf64_Word,
    p_offset: Elf64_Off,
    p_vaddr: Elf64_Addr,
    p_paddr: Elf64_Addr,
    p_filesz: Elf64_Xword,
    p_memsz: Elf64_Xword,
    p_align: Elf64_Xword,
}

const EI_NIDENT: usize = 16;
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFMAG: [u8; 4] = *b"\x7fELF";
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EM_386: u16 = 3;
const EM_X86_64: u16 = 62;
const ET_REL: u16 = 1;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
const PF_R: u32 = 0x4;

/// The errors `exec_load()` reports: the `EX_*` codes of <mach/exec/exec.h>,
/// or a callback's own result passed through.
#[derive(Clone, Copy)]
enum ExecError {
    /// `EX_NOT_EXECUTABLE`: not a recognized executable format.
    NotExecutable,
    /// `EX_WRONG_ARCH`: valid executable, but wrong architecture.
    WrongArch,
    /// `EX_CORRUPT`: recognized executable, but mangled.
    Corrupt,
    /// Whatever `read` or `read_exec` returned, passed through.
    Callback(c_int),
}

impl ExecError {
    #[inline]
    const fn code(self) -> c_int {
        match self {
            Self::NotExecutable => 6000,
            Self::WrongArch => 6001,
            Self::Corrupt => 6002,
            Self::Callback(code) => code,
        }
    }
}

/// `exec_load()` converts it back into the caller's struct once the whole
/// image has loaded.
#[derive(Clone, Copy)]
struct LoadInfo {
    entry: VmOffset,
    stack_prot: VmProt,
}

/// Read the `size_of::<T>()` bytes at `offset` as a `T`, or `too_short` if the
/// callback reports fewer.
///
/// # Safety
///
/// `read` must be valid for `handle`, as the caller of `exec_load()` promises,
/// and `T` must be valid for every bit pattern: the callback reports how much
/// it wrote, and that report is trusted.
#[inline]
unsafe fn read_struct<T>(
    read: ReadFn,
    handle: *mut c_void,
    offset: VmOffset,
    too_short: ExecError,
) -> Result<T, ExecError> {
    let mut value = MaybeUninit::<T>::uninit();
    let mut actual: VmSize = 0;

    let result = unsafe {
        read(
            handle,
            offset,
            value.as_mut_ptr().cast(),
            size_of::<T>(),
            &raw mut actual,
        )
    };
    if result != 0 {
        return Err(ExecError::Callback(result));
    }
    if actual < size_of::<T>() {
        return Err(too_short);
    }

    // SAFETY: the read reported the whole value, and `T` is valid for every
    // bit pattern.
    Ok(unsafe { value.assume_init() })
}

/// Read `e_ident`, the identification bytes at the start of the file.
///
/// # Safety
///
/// `read` must be valid for `handle`, as the caller of `exec_load()` promises.
#[inline]
unsafe fn read_ident(
    read: ReadFn,
    handle: *mut c_void,
) -> Result<[u8; EI_NIDENT], ExecError> {
    // SAFETY: the caller promises `read` is valid for `handle`, and `[u8;
    // EI_NIDENT]` is valid for every bit pattern.
    unsafe { read_struct(read, handle, 0, ExecError::NotExecutable) }
}

/// Reject what cannot be an ELF this loader understands: the magic and the
/// byte order.
#[inline]
fn check_ident(ident: &[u8; EI_NIDENT]) -> Result<(), ExecError> {
    if ident[..4] != ELFMAG {
        return Err(ExecError::NotExecutable);
    }
    if ident[EI_DATA] != ELFDATA2LSB {
        return Err(ExecError::WrongArch);
    }
    Ok(())
}

/// Room to leave for mmaps and the like before a PIE image.
#[inline]
const fn load_base(e_type: u16) -> VmOffset {
    if e_type == ET_DYN || e_type == ET_REL {
        128 << 20
    } else {
        0
    }
}

/// The `EXEC_SECTYPE_*` bits a loadable segment asks for.
#[inline]
fn section_type(p_flags: u32) -> ExecSectype {
    let mut type_ = ExecSectype::ALLOC | ExecSectype::LOAD;
    if p_flags & PF_R != 0 {
        type_ |= ExecSectype::READ;
    }
    if p_flags & PF_W != 0 {
        type_ |= ExecSectype::WRITE;
    }
    if p_flags & PF_X != 0 {
        type_ |= ExecSectype::EXECUTE;
    }
    type_
}

/// The `vm_prot_t` a `PT_GNU_STACK` segment asks for.
#[inline]
fn stack_prot(p_flags: u32) -> VmProt {
    let mut prot = VmProt::NONE;
    if p_flags & PF_R != 0 {
        prot |= VmProt::READ;
    }
    if p_flags & PF_W != 0 {
        prot |= VmProt::WRITE;
    }
    if p_flags & PF_X != 0 {
        prot |= VmProt::EXECUTE;
    }
    prot
}

/// Read the 32-bit ELF header.
///
/// # Safety
///
/// `read` must be valid for `handle`, as the caller of `exec_load()` promises.
#[inline]
unsafe fn read_header32(
    read: ReadFn,
    handle: *mut c_void,
) -> Result<Elf32_Ehdr, ExecError> {
    unsafe { read_struct(read, handle, 0, ExecError::NotExecutable) }
}

/// Read program header `i` of a 32-bit image.
///
/// # Safety
///
/// `read` must be valid for `handle`, as the caller of `exec_load()` promises.
#[inline]
unsafe fn read_phdr32(
    read: ReadFn,
    handle: *mut c_void,
    x: &Elf32_Ehdr,
    i: usize,
) -> Result<Elf32_Phdr, ExecError> {
    let offset = (x.e_phoff as VmOffset)
        .wrapping_add(i.wrapping_mul(x.e_phentsize as usize));
    unsafe { read_struct(read, handle, offset, ExecError::Corrupt) }
}

/// Apply one 32-bit program header: load a `PT_LOAD` segment, or record the
/// `PT_GNU_STACK` protection.
///
/// # Safety
///
/// `read_exec` must be valid for `handle`, as the caller of `exec_load()`
/// promises.
#[inline]
unsafe fn apply_phdr32(
    read_exec: ReadExecFn,
    handle: *mut c_void,
    ph: &Elf32_Phdr,
    loadbase: VmOffset,
    info: LoadInfo,
) -> Result<LoadInfo, ExecError> {
    match ph.p_type {
        PT_LOAD => {
            let type_ = section_type(ph.p_flags);
            let result = unsafe {
                read_exec(
                    handle,
                    ph.p_offset as VmOffset,
                    ph.p_filesz as VmSize,
                    (ph.p_vaddr as VmOffset).wrapping_add(loadbase),
                    ph.p_memsz as VmSize,
                    type_,
                )
            };
            if result != 0 {
                Err(ExecError::Callback(result))
            } else {
                Ok(info)
            }
        }
        PT_GNU_STACK => Ok(LoadInfo {
            stack_prot: stack_prot(ph.p_flags),
            ..info
        }),
        _ => Ok(info),
    }
}

/// Load an ELF32 image.
///
/// # Safety
///
/// `read` and `read_exec` must be valid for `handle`, as the caller of
/// `exec_load()` promises.
#[inline]
unsafe fn exec_load32(
    read: ReadFn,
    read_exec: ReadExecFn,
    handle: *mut c_void,
) -> Result<LoadInfo, ExecError> {
    let x = unsafe { read_header32(read, handle) }?;
    if x.e_ident[EI_CLASS] != ELFCLASS32
        || x.e_ident[EI_DATA] != ELFDATA2LSB
        || x.e_machine != EM_386
    {
        return Err(ExecError::WrongArch);
    }
    let loadbase = load_base(x.e_type);
    let mut info = LoadInfo {
        entry: (x.e_entry as VmOffset).wrapping_add(loadbase),
        stack_prot: VmProt::ALL,
    };

    if x.e_phnum != 0 && (x.e_phentsize as usize) < size_of::<Elf32_Phdr>() {
        return Err(ExecError::Corrupt);
    }

    for i in 0..x.e_phnum as usize {
        let ph = unsafe { read_phdr32(read, handle, &x, i) }?;
        info =
            unsafe { apply_phdr32(read_exec, handle, &ph, loadbase, info) }?;
    }

    Ok(info)
}

/// Read the 64-bit ELF header.
///
/// # Safety
///
/// `read` must be valid for `handle`, as the caller of `exec_load()` promises.
#[inline]
unsafe fn read_header64(
    read: ReadFn,
    handle: *mut c_void,
) -> Result<Elf64_Ehdr, ExecError> {
    unsafe { read_struct(read, handle, 0, ExecError::NotExecutable) }
}

/// Read program header `i` of a 64-bit image.
///
/// # Safety
///
/// `read` must be valid for `handle`, as the caller of `exec_load()` promises.
#[inline]
unsafe fn read_phdr64(
    read: ReadFn,
    handle: *mut c_void,
    x: &Elf64_Ehdr,
    i: usize,
) -> Result<Elf64_Phdr, ExecError> {
    let offset = (x.e_phoff as VmOffset)
        .wrapping_add(i.wrapping_mul(x.e_phentsize as usize));
    unsafe { read_struct(read, handle, offset, ExecError::Corrupt) }
}

/// Apply one 64-bit program header: load a `PT_LOAD` segment, or record the
/// `PT_GNU_STACK` protection.
///
/// # Safety
///
/// `read_exec` must be valid for `handle`, as the caller of `exec_load()`
/// promises.
#[inline]
unsafe fn apply_phdr64(
    read_exec: ReadExecFn,
    handle: *mut c_void,
    ph: &Elf64_Phdr,
    loadbase: VmOffset,
    info: LoadInfo,
) -> Result<LoadInfo, ExecError> {
    match ph.p_type {
        PT_LOAD => {
            let type_ = section_type(ph.p_flags);
            let result = unsafe {
                read_exec(
                    handle,
                    ph.p_offset as VmOffset,
                    ph.p_filesz as VmSize,
                    (ph.p_vaddr as VmOffset).wrapping_add(loadbase),
                    ph.p_memsz as VmSize,
                    type_,
                )
            };
            if result != 0 {
                Err(ExecError::Callback(result))
            } else {
                Ok(info)
            }
        }
        PT_GNU_STACK => Ok(LoadInfo {
            stack_prot: stack_prot(ph.p_flags),
            ..info
        }),
        _ => Ok(info),
    }
}

/// Load an ELF64 image.
///
/// # Safety
///
/// `read` and `read_exec` must be valid for `handle`, as the caller of
/// `exec_load()` promises.
#[inline]
unsafe fn exec_load64(
    read: ReadFn,
    read_exec: ReadExecFn,
    handle: *mut c_void,
) -> Result<LoadInfo, ExecError> {
    if size_of::<VmOffset>() < size_of::<Elf64_Addr>() {
        return Err(ExecError::WrongArch);
    }

    let x = unsafe { read_header64(read, handle) }?;
    if x.e_ident[EI_CLASS] != ELFCLASS64
        || x.e_ident[EI_DATA] != ELFDATA2LSB
        || x.e_machine != EM_X86_64
    {
        return Err(ExecError::WrongArch);
    }
    let loadbase = load_base(x.e_type);
    let mut info = LoadInfo {
        entry: (x.e_entry as VmOffset).wrapping_add(loadbase),
        stack_prot: VmProt::ALL,
    };

    if x.e_phnum != 0 && (x.e_phentsize as usize) < size_of::<Elf64_Phdr>() {
        return Err(ExecError::Corrupt);
    }

    for i in 0..x.e_phnum as usize {
        let ph = unsafe { read_phdr64(read, handle, &x, i) }?;
        info =
            unsafe { apply_phdr64(read_exec, handle, &ph, loadbase, info) }?;
    }

    Ok(info)
}

/// Load an ELF executable through the caller's `read` and `read_exec`.
///
/// # Safety
///
/// `read` and `read_exec` must be valid function pointers, callable with
/// `handle` for the duration of the call.
pub(crate) unsafe fn exec_load(
    read: ReadFn,
    read_exec: ReadExecFn,
    handle: *mut c_void,
    out_info: *mut ExecInfo,
) -> c_int {
    let ident = match unsafe { read_ident(read, handle) } {
        Ok(ident) => ident,
        Err(err) => return err.code(),
    };
    if let Err(err) = check_ident(&ident) {
        return err.code();
    }

    unsafe { out_info.write_bytes(0, 1) };

    let result = match ident[EI_CLASS] {
        ELFCLASS32 => unsafe { exec_load32(read, read_exec, handle) },
        ELFCLASS64 => unsafe { exec_load64(read, read_exec, handle) },
        _ => Err(ExecError::WrongArch),
    };

    match result {
        Ok(info) => {
            unsafe {
                (*out_info).entry = info.entry;
                (*out_info).stack_prot = info.stack_prot;
            }
            0
        }
        Err(err) => err.code(),
    }
}
