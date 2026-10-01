// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The ELF executable loader: recognition, segment placement, and the
//! stack protection an image asks for.
//!
//! The loader never touches memory itself. A caller supplies an
//! [`ElfImage`] that can read file bytes and place one loadable segment;
//! [`load`] walks the program headers and reports what it found.
//!
//! The 32-bit and 64-bit readers are separate modules (`x86` and
//! `x86_64`). Their on-disk program headers differ in field order, not
//! just width, so each path owns its own walk and the only class test
//! is the dispatch in [`load`].
//!
//! | item | purpose |
//! |---|---|
//! | [`load`] | recognize an image and place its `PT_LOAD` segments |
//! | [`ElfImage`] | the caller's source of file bytes and segment sink |
//! | [`ExecInfo`] | entry point and stack protection the image asks for |
//! | [`ExecSectype`] | what a segment wants: read/write/execute, allocate, load |
//! | [`Prot`] | the protection bits a segment or the stack wants |
//! | [`ExecError`] | why an image was rejected, or the caller's own error |

#![cfg_attr(not(test), no_std)]

mod x86;
mod x86_64;

use core::fmt;
use core::mem::{MaybeUninit, size_of};

/// How many identification bytes start every ELF image.
pub(crate) const IDENT_LEN: usize = 16;

/// The image is little-endian, the only byte order this loader takes.
pub(crate) const DATA_LSB: u8 = 1;

/// Offset of the class byte in the identification bytes.
const EI_CLASS_OFFSET: usize = 4;

/// Offset of the data byte in the identification bytes.
const EI_DATA_OFFSET: usize = 5;

/// `EI_CLASS`: the image class, `1` or `2`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EiClass {
    /// `ELFCLASS32` (`1`), the `x86` reader.
    X86,
    /// `ELFCLASS64` (`2`), the `x86_64` reader.
    X86_64,
}

impl EiClass {
    /// The class an `EI_CLASS` byte names, if this loader has a reader
    /// for it.
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::X86),
            2 => Some(Self::X86_64),
            _ => None,
        }
    }
}

/// The `EX_*` errors an image can fail with, or the caller's own error.
///
/// The numeric `EX_*` codes live at the ABI boundary, not here (ADR 0015).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecError<E> {
    /// The bytes are not a recognized executable format.
    NotExecutable,
    /// A valid executable, but not one this loader will load.
    WrongArch,
    /// A recognized executable, but mangled.
    Corrupt,
    /// Whatever the [`ElfImage`] returned, passed through.
    Image(E),
}

impl<E: fmt::Debug> fmt::Display for ExecError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotExecutable => f.write_str("not an executable"),
            Self::WrongArch => f.write_str("wrong architecture"),
            Self::Corrupt => f.write_str("corrupt executable"),
            Self::Image(err) => write!(f, "image error: {err:?}"),
        }
    }
}

/// A protection value: the `vm_prot_t` bits an image uses.
///
/// The bit values are `VM_PROT_READ`/`WRITE`/`EXECUTE`. A caller that
/// speaks another protection type converts at its own boundary.
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

/// What one section of an image wants: the `EXEC_SECTYPE_*` bits.
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

/// The image [`load`] recognized, after every segment has been
/// placed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecInfo {
    entry: usize,
    stack_prot: Prot,
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

    /// Builds the record [`load`] would return.
    pub(crate) const fn new(entry: usize, stack_prot: Prot) -> Self {
        Self { entry, stack_prot }
    }
}

/// The source of ELF file bytes and the sink for loadable segments.
///
/// One object plays both roles: [`load`] reads headers and program
/// headers through [`read_at`](Self::read_at), and asks the same
/// object to place each `PT_LOAD` segment through [`place`](Self::place).
pub trait ElfImage {
    /// The caller's own error type.
    type Error;

    /// Reads up to `buf.len()` bytes at `offset` into `buf`.
    ///
    /// Same shape as `FileExt::read_at`: returns how many bytes were
    /// actually read. A short read is not an error (the loader
    /// classifies it as an unrecognized or corrupt image). `0` past the
    /// end of the image is the normal way to report exhaustion.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] when the image cannot be read at all.
    fn read_at(
        &self,
        buf: &mut [u8],
        offset: u64,
    ) -> Result<usize, Self::Error>;

    /// Places one segment of the image into the loaded picture.
    ///
    /// The `file_len` bytes at `offset` land at `addr`. When
    /// `mem_len` is larger, the trailing `mem_len - file_len` bytes
    /// read as zero. `sectype` says what the segment wants: whether it
    /// comes from the file at all ([`ExecSectype::LOAD`]), whether it
    /// needs memory ([`ExecSectype::ALLOC`]), and the
    /// [`protection`](ExecSectype::protection) bits.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] when the segment cannot be placed.
    fn place(
        &mut self,
        offset: u64,
        file_len: usize,
        addr: usize,
        mem_len: usize,
        sectype: ExecSectype,
    ) -> Result<(), Self::Error>;
}

/// Loads an ELF executable through `image`, placing its segments and
/// reporting the entry point and stack protection.
///
/// [`load`] reads `EI_CLASS` first and hands the image to the
/// matching reader immediately. Each path then owns its magic,
/// byte-order, machine and program-header checks.
///
/// # Errors
///
/// Returns [`ExecError::NotExecutable`] when the bytes are not an
/// image this loader recognizes, [`ExecError::WrongArch`] when they are
/// an image of another machine or byte order, [`ExecError::Corrupt`]
/// when a recognized image is mangled, and [`ExecError::Image`] when
/// `image` itself fails.
pub fn load<I: ElfImage>(
    image: &mut I,
) -> Result<ExecInfo, ExecError<I::Error>> {
    // `EI_CLASS` is the first thing that picks a reader.
    let mut class = [0u8; 1];
    let n = image
        .read_at(&mut class, EI_CLASS_OFFSET as u64)
        .map_err(ExecError::Image)?;
    if n < 1 {
        return Err(ExecError::NotExecutable);
    }
    match EiClass::from_u8(class[0]).ok_or(ExecError::WrongArch)? {
        EiClass::X86 => x86::load(image),
        EiClass::X86_64 => x86_64::load(image),
    }
}

/// Reads the identification bytes at the start of the file.
pub(crate) fn read_ident<I: ElfImage>(
    image: &I,
) -> Result<[u8; IDENT_LEN], ExecError<I::Error>> {
    let mut ident = [0u8; IDENT_LEN];
    let n = image.read_at(&mut ident, 0).map_err(ExecError::Image)?;
    if n < IDENT_LEN {
        return Err(ExecError::NotExecutable);
    }
    Ok(ident)
}

/// Accepts only the magic, the little-endian byte order, and the
/// class this path owns.
pub(crate) fn check_ident<E>(
    ident: &[u8],
    class: EiClass,
) -> Result<(), ExecError<E>> {
    let Some((magic, rest)) = ident.split_first_chunk::<4>() else {
        return Err(ExecError::NotExecutable);
    };
    if *magic != *b"\x7fELF" {
        return Err(ExecError::NotExecutable);
    }
    match ident
        .get(EI_CLASS_OFFSET)
        .copied()
        .and_then(EiClass::from_u8)
    {
        Some(found) if found == class => {}
        Some(_) => return Err(ExecError::WrongArch),
        None => return Err(ExecError::NotExecutable),
    }
    match rest.get(EI_DATA_OFFSET - 4) {
        Some(&DATA_LSB) => Ok(()),
        Some(_) => Err(ExecError::WrongArch),
        None => Err(ExecError::NotExecutable),
    }
}

/// Reads `offset` as a `T`, or reports why the image is unusable.
///
/// Both arch readers use this one generic; each instantiates it with
/// its own on-disk header type.
pub(crate) fn read_pod<T, I: ElfImage>(
    image: &I,
    offset: u64,
    too_short: ExecError<I::Error>,
) -> Result<T, ExecError<I::Error>> {
    let mut slot = MaybeUninit::<T>::uninit();
    // SAFETY: `slot` is writable for `size_of::<T>()` bytes and the
    // temporary slice does not outlive it.
    let buf = unsafe {
        core::slice::from_raw_parts_mut(
            slot.as_mut_ptr().cast::<u8>(),
            size_of::<T>(),
        )
    };
    let n = image.read_at(buf, offset).map_err(ExecError::Image)?;
    if n < size_of::<T>() {
        return Err(too_short);
    }
    // SAFETY: `T` is an integer-POD on-disk record, valid for every
    // bit pattern, and `read_at` wrote the whole value.
    Ok(unsafe { slot.assume_init() })
}

/// The room left for mmaps and the like before a position-independent
/// image (`ET_DYN` or `ET_REL`).
pub(crate) const PIE_LOAD_BASE: usize = 128 << 20;

/// The `EXEC_SECTYPE_*` bits a `PF_R`/`PF_W`/`PF_X` segment asks for.
pub(crate) fn section_type(flags: u32) -> ExecSectype {
    let mut type_ = ExecSectype::ALLOC | ExecSectype::LOAD;
    if flags & PF_R != 0 {
        type_ |= ExecSectype::READ;
    }
    if flags & PF_W != 0 {
        type_ |= ExecSectype::WRITE;
    }
    if flags & PF_X != 0 {
        type_ |= ExecSectype::EXECUTE;
    }
    type_
}

/// The protection a `PT_GNU_STACK` segment asks for.
pub(crate) fn stack_prot(flags: u32) -> Prot {
    let mut prot = Prot::NONE;
    if flags & PF_R != 0 {
        prot |= Prot::READ;
    }
    if flags & PF_W != 0 {
        prot |= Prot::WRITE;
    }
    if flags & PF_X != 0 {
        prot |= Prot::EXECUTE;
    }
    prot
}

/// `PF_R`.
pub(crate) const PF_R: u32 = 0x4;
/// `PF_W`.
pub(crate) const PF_W: u32 = 0x2;
/// `PF_X`.
pub(crate) const PF_X: u32 = 0x1;

/// `ET_REL`.
pub(crate) const ET_REL: u16 = 1;
/// `ET_DYN`.
pub(crate) const ET_DYN: u16 = 3;

/// `PT_LOAD`.
pub(crate) const PT_LOAD: u32 = 1;
/// `PT_GNU_STACK`.
pub(crate) const PT_GNU_STACK: u32 = 0x6474_e551;

/// `true` when `e_type` is a position-independent image.
pub(crate) const fn is_pie(e_type: u16) -> bool {
    e_type == ET_DYN || e_type == ET_REL
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::vec::Vec;

    /// An in-memory image both arch test modules share, so `load`
    /// is monomorphized once and every dispatch arm is covered.
    pub(crate) struct MemImage {
        pub bytes: Vec<u8>,
        pub loads: Vec<(u64, usize, usize, usize, ExecSectype)>,
        pub fail_read: bool,
        pub fail_place: bool,
        /// Fail `read` after this many successful calls.
        pub fail_after_reads: Option<usize>,
        reads: core::cell::Cell<usize>,
    }

    impl MemImage {
        pub(crate) fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                loads: Vec::new(),
                fail_read: false,
                fail_place: false,
                fail_after_reads: None,
                reads: core::cell::Cell::new(0),
            }
        }
    }

    impl ElfImage for MemImage {
        type Error = u8;

        fn read_at(
            &self,
            buf: &mut [u8],
            offset: u64,
        ) -> Result<usize, Self::Error> {
            if self.fail_read {
                return Err(1);
            }
            if self
                .fail_after_reads
                .is_some_and(|limit| self.reads.get() >= limit)
            {
                self.reads.set(self.reads.get() + 1);
                return Err(1);
            }
            self.reads.set(self.reads.get() + 1);
            let Some(src) = self
                .bytes
                .get(usize::try_from(offset).unwrap_or(usize::MAX)..)
            else {
                return Ok(0);
            };
            let n = src.len().min(buf.len());
            buf[..n].copy_from_slice(&src[..n]);
            Ok(n)
        }

        fn place(
            &mut self,
            offset: u64,
            file_len: usize,
            addr: usize,
            mem_len: usize,
            sectype: ExecSectype,
        ) -> Result<(), Self::Error> {
            if self.fail_place {
                return Err(4);
            }
            self.loads.push((offset, file_len, addr, mem_len, sectype));
            Ok(())
        }
    }

    #[test]
    fn rejects_unknown_class() {
        let mut bytes = Vec::from(*b"\x7fELF\x03\x01\0\0\0\0\0\0\0\0\0\0");
        bytes.resize(64, 0);
        let mut image = MemImage::new(bytes);
        assert_eq!(load(&mut image), Err(ExecError::<u8>::WrongArch));
    }

    #[test]
    fn rejects_before_a_class_byte() {
        let mut image = MemImage::new(b"\x7fELF".to_vec());
        assert_eq!(load(&mut image), Err(ExecError::<u8>::NotExecutable));
    }

    #[test]
    fn rejects_bad_magic_and_endian_in_paths() {
        // Class 32, but not an ELF: the x86 path rejects it.
        let mut bytes = Vec::from(*b"\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0");
        bytes.resize(64, 0);
        let mut image = MemImage::new(bytes);
        assert_eq!(load(&mut image), Err(ExecError::<u8>::NotExecutable));
        // Class 32, big-endian.
        let mut bytes = Vec::from(*b"\x7fELF\x01\x02\0\0\0\0\0\0\0\0\0\0");
        bytes.resize(64, 0);
        let mut image = MemImage::new(bytes);
        assert_eq!(load(&mut image), Err(ExecError::<u8>::WrongArch));
        // Class 64, not an ELF.
        let mut bytes = Vec::from(*b"\0\0\0\0\x02\x01\0\0\0\0\0\0\0\0\0\0");
        bytes.resize(64, 0);
        let mut image = MemImage::new(bytes);
        assert_eq!(load(&mut image), Err(ExecError::<u8>::NotExecutable));
        // Truncated identification after a valid class byte.
        let mut image = MemImage::new(
            b"\x7fELF\x01\x01\0\0\0\0\0\0\0\0\0\0"[..5].to_vec(),
        );
        assert_eq!(load(&mut image), Err(ExecError::<u8>::NotExecutable));
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
    fn exec_info_accessors() {
        let info = ExecInfo::new(0x4000, Prot::READ | Prot::WRITE);
        assert_eq!(info.entry(), 0x4000);
        assert_eq!(info.stack_prot(), Prot::READ | Prot::WRITE);
    }

    #[test]
    fn exec_error_display() {
        assert_eq!(
            ExecError::<u8>::NotExecutable.to_string(),
            "not an executable"
        );
        assert_eq!(
            ExecError::<u8>::WrongArch.to_string(),
            "wrong architecture"
        );
        assert_eq!(ExecError::<u8>::Corrupt.to_string(), "corrupt executable");
        assert_eq!(ExecError::Image(7u8).to_string(), "image error: 7");
    }

    #[test]
    fn section_type_maps_flags() {
        assert_eq!(
            section_type(PF_R | PF_W | PF_X),
            ExecSectype::ALLOC
                | ExecSectype::LOAD
                | ExecSectype::READ
                | ExecSectype::WRITE
                | ExecSectype::EXECUTE
        );
        assert_eq!(section_type(0), ExecSectype::ALLOC | ExecSectype::LOAD);
    }

    #[test]
    fn stack_prot_maps_flags() {
        assert_eq!(stack_prot(PF_R | PF_X), Prot::READ | Prot::EXECUTE);
        assert_eq!(stack_prot(0), Prot::NONE);
    }

    #[test]
    fn pie_types() {
        assert!(is_pie(ET_DYN));
        assert!(is_pie(ET_REL));
        assert!(!is_pie(2));
    }

    #[test]
    fn ei_class_from_u8() {
        assert_eq!(EiClass::from_u8(1), Some(EiClass::X86));
        assert_eq!(EiClass::from_u8(2), Some(EiClass::X86_64));
        assert_eq!(EiClass::from_u8(0), None);
        assert_eq!(EiClass::from_u8(9), None);
    }

    #[test]
    fn check_ident_paths() {
        assert_eq!(
            check_ident::<u8>(&[0x7f, b'E', b'L'], EiClass::X86),
            Err(ExecError::NotExecutable)
        );
        assert_eq!(
            check_ident::<u8>(&[0; 4], EiClass::X86),
            Err(ExecError::NotExecutable)
        );
        let mut ident = *b"\x7fELF\x01\x02\0\0\0\0\0\0\0\0\0\0";
        assert_eq!(
            check_ident::<u8>(&ident, EiClass::X86),
            Err(ExecError::WrongArch)
        );
        ident[5] = DATA_LSB;
        assert_eq!(
            check_ident::<u8>(&ident[..5], EiClass::X86),
            Err(ExecError::NotExecutable)
        );
        assert_eq!(
            check_ident::<u8>(&ident, EiClass::X86_64),
            Err(ExecError::WrongArch)
        );
        assert_eq!(check_ident::<u8>(&ident, EiClass::X86), Ok(()));
        // Magic is fine, but `EI_CLASS` is not 1 or 2.
        assert_eq!(
            check_ident::<u8>(b"\x7fELF\x09", EiClass::X86),
            Err(ExecError::NotExecutable)
        );
    }
}
