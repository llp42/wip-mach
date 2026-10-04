// SPDX-License-Identifier: LicenseRef-Utah-CSL AND GPL-2.0-or-later
// SPDX-FileCopyrightText: 1995-1994 The University of Utah and the Computer Systems Laboratory of the University of Utah (CSL)
// SPDX-FileContributor: Bryan Ford
// SPDX-FileCopyrightText: 2010, 2012 Richard Braun
// SPDX-FileCopyrightText: 2024 Free Software Foundation, Inc.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from GNU Mach (commit c5701c1c1c8f330f7a790a4a0bc6b3434213722b)
// original files: i386/include/mach/i386/multiboot.h

//! The Multiboot layout the boot loader hands the kernel: its information
//! block, the module records, the memory map entries, and the flags saying
//! which fields are live.
//!
//! [`load_modules`] copies the loader's module table and command lines out
//! of its memory, so the boot code past that point works on owned Rust
//! data.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::PAGE_SIZE;
use crate::kern::kheap::Kalloc;
use crate::vm::vm_kern::VM_MIN_KERNEL_ADDRESS;
use crate::vm::vm_page;
use core::ffi::{CStr, c_char, c_void};
use core::mem::{offset_of, size_of};
use core::ptr::with_exposed_provenance;
use kmem::{AllocError, KCString, KVec};

/// The flags the loader set in the information block, saying which fields
/// are live.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(crate) struct MultibootLoaderFlags(u32);

impl MultibootLoaderFlags {
    /// The loader set the memory-size fields.
    #[allow(dead_code)]
    pub(crate) const MEMORY: Self = Self(0x01);

    /// The loader set the command line field.
    pub(crate) const CMDLINE: Self = Self(0x04);

    /// The loader set the module table fields.
    pub(crate) const MODULES: Self = Self(0x08);

    /// The loader set the ELF section header fields.
    pub(crate) const SHDR: Self = Self(0x20);

    /// The loader set the memory map fields.
    pub(crate) const MMAP: Self = Self(0x40);

    /// The flags the raw `bits` word holds.
    #[must_use]
    pub(crate) const fn from_raw(bits: u32) -> Self {
        Self(bits)
    }

    /// Whether every flag in `other` is set.
    #[must_use]
    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// One module the loader placed: the physical bounds of its image and the
/// physical address of its command line, all 32-bit on either target.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub(crate) struct MultibootRawModule {
    pub mod_start: u32,
    pub mod_end: u32,
    pub string: u32,
    pub reserved: u32,
}

const _: () = {
    assert!(size_of::<MultibootRawModule>() == 16);
    assert!(offset_of!(MultibootRawModule, mod_start) == 0);
    assert!(offset_of!(MultibootRawModule, mod_end) == 4);
    assert!(offset_of!(MultibootRawModule, string) == 8);
    assert!(offset_of!(MultibootRawModule, reserved) == 12);
};

/// The two shapes of the video fields: an indexed palette or direct color
/// bit fields.
///
/// The union is as large as its palette arm, whose trailing 16-bit field
/// still pads the arm to four bytes; the whole video record is 30 bytes,
/// not the 28 their field widths add up to.  The loader and `/dev/mbinfo`
/// both speak that layout, so keep it.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub(crate) union MultibootFramebufferFields {
    pub palette: MultibootFramebufferPalette,
    pub rgb: MultibootFramebufferRgb,
}

/// The indexed arm of [`MultibootFramebufferFields`].
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub(crate) struct MultibootFramebufferPalette {
    pub framebuffer_palette_addr: u32,
    pub framebuffer_palette_num_colors: u16,
}

/// The direct-color arm of [`MultibootFramebufferFields`].
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
#[allow(clippy::struct_field_names)]
pub(crate) struct MultibootFramebufferRgb {
    pub framebuffer_red_field_position: u8,
    pub framebuffer_red_mask_size: u8,
    pub framebuffer_green_field_position: u8,
    pub framebuffer_green_mask_size: u8,
    pub framebuffer_blue_field_position: u8,
    pub framebuffer_blue_mask_size: u8,
}

/// The video mode the loader selected.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub(crate) struct MultibootFramebufferInfo {
    pub framebuffer_addr: u64,
    pub framebuffer_pitch: u32,
    pub framebuffer_width: u32,
    pub framebuffer_height: u32,
    pub framebuffer_bpp: u8,
    pub framebuffer_type: u8,
    pub framebuffer: MultibootFramebufferFields,
}

const _: () = {
    assert!(size_of::<MultibootFramebufferInfo>() == 30);
    assert!(offset_of!(MultibootFramebufferInfo, framebuffer_addr) == 0);
    assert!(offset_of!(MultibootFramebufferInfo, framebuffer_pitch) == 8);
    assert!(offset_of!(MultibootFramebufferInfo, framebuffer_width) == 12);
    assert!(offset_of!(MultibootFramebufferInfo, framebuffer_height) == 16);
    assert!(offset_of!(MultibootFramebufferInfo, framebuffer_bpp) == 20);
    assert!(offset_of!(MultibootFramebufferInfo, framebuffer_type) == 21);
    assert!(offset_of!(MultibootFramebufferInfo, framebuffer) == 22);
};

/// The information block the loader leaves in low memory: the command
/// line, the module table, the section headers and the memory map.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub(crate) struct MultibootRawInfo {
    pub flags: u32,
    pub mem_lower: u32,
    pub mem_upper: u32,
    pub unused0: u32,
    pub cmdline: u32,
    pub mods_count: u32,
    pub mods_addr: u32,
    pub shdr_num: u32,
    pub shdr_size: u32,
    pub shdr_addr: u32,
    pub shdr_strndx: u32,
    pub mmap_length: u32,
    pub mmap_addr: u32,
    pub unused1: [u32; 9],
    pub fb_info: MultibootFramebufferInfo,
}

const _: () = {
    assert!(size_of::<MultibootRawInfo>() == 118);
    assert!(offset_of!(MultibootRawInfo, flags) == 0);
    assert!(offset_of!(MultibootRawInfo, mem_lower) == 4);
    assert!(offset_of!(MultibootRawInfo, mem_upper) == 8);
    assert!(offset_of!(MultibootRawInfo, cmdline) == 16);
    assert!(offset_of!(MultibootRawInfo, mods_count) == 20);
    assert!(offset_of!(MultibootRawInfo, mods_addr) == 24);
    assert!(offset_of!(MultibootRawInfo, shdr_num) == 28);
    assert!(offset_of!(MultibootRawInfo, shdr_size) == 32);
    assert!(offset_of!(MultibootRawInfo, shdr_addr) == 36);
    assert!(offset_of!(MultibootRawInfo, shdr_strndx) == 40);
    assert!(offset_of!(MultibootRawInfo, mmap_length) == 44);
    assert!(offset_of!(MultibootRawInfo, mmap_addr) == 48);
    assert!(offset_of!(MultibootRawInfo, unused1) == 52);
    assert!(offset_of!(MultibootRawInfo, fb_info) == 88);
};

/// One entry of the loader's memory map: `size` gives the stride to the
/// next entry, which is 4 bytes past this record's start plus `size`.
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(missing_docs)]
pub(crate) struct MultibootRawMmapEntry {
    pub size: u32,
    pub base_addr: u64,
    pub length: u64,
    pub type_: u32,
}

const _: () = {
    assert!(size_of::<MultibootRawMmapEntry>() == 24);
    assert!(offset_of!(MultibootRawMmapEntry, size) == 0);
    assert!(offset_of!(MultibootRawMmapEntry, base_addr) == 4);
    assert!(offset_of!(MultibootRawMmapEntry, length) == 12);
    assert!(offset_of!(MultibootRawMmapEntry, type_) == 20);
};

/// One module the loader left, copied out of the loader's memory: the
/// copied image and its command line.
pub(crate) struct MultibootModule {
    image: ModuleImage,
    command_line: KCString<Kalloc>,
}

impl MultibootModule {
    /// The module's command line.
    #[must_use]
    pub(crate) fn command_line(&self) -> &CStr {
        &self.command_line
    }

    /// The copied image bytes at `file_ofs`, or `None` when the module
    /// does not cover `size` bytes there.
    #[must_use]
    pub(crate) const fn image_at(
        &self,
        file_ofs: VmOffset,
        size: VmSize,
    ) -> Option<*const c_void> {
        if self.image.start.wrapping_add(file_ofs).wrapping_add(size)
            > self.image.end
        {
            return None;
        }
        Some(kv_ptr::<c_void>(
            phystokv(self.image.start).wrapping_add(file_ofs),
        ))
    }
}

/// The copied pages of one module image, returned to the page allocator
/// when the module is dropped.
struct ModuleImage {
    start: VmOffset,
    end: VmOffset,
}

impl Drop for ModuleImage {
    fn drop(&mut self) {
        let mut start = self.start;
        while start < self.end {
            if let Some(page) = vm_page::lookup_pa(start) {
                // SAFETY: the copied pages are the module's, and this is
                // the one reference that hands them back.
                unsafe { vm_page::manage(page.as_ptr()) };
            }
            start = start.wrapping_add(PAGE_SIZE);
        }
    }
}

/// Loads `count` module records at `address` into owned modules; each
/// command line is copied and each image range is adopted.
///
/// # Errors
///
/// [`AllocError`] when the heap cannot hold the list or a command line.
///
/// # Safety
///
/// `count` live module records must sit at `address`, mapped, and every
/// record's image and command line must be mapped, the line
/// NUL-terminated.
pub(crate) unsafe fn load_modules(
    address: u32,
    count: u32,
) -> Result<KVec<MultibootModule, Kalloc>, AllocError> {
    let records =
        kv_ptr::<MultibootRawModule>(phystokv(address_value(address)));
    let mut modules = KVec::try_with_capacity(count as usize, Kalloc)?;
    for index in 0..count as usize {
        let record = unsafe { records.add(index).read() };
        let line = kv_ptr::<c_char>(phystokv(address_value(record.string)));
        let line = unsafe { CStr::from_ptr(line) };
        modules.try_push(MultibootModule {
            image: ModuleImage {
                start: address_value(record.mod_start),
                end: address_value(record.mod_end),
            },
            command_line: KCString::try_from_c_str(line, Kalloc)?,
        })?;
    }
    Ok(modules)
}

/// A physical address in the kernel's direct map.
const fn phystokv(pa: VmOffset) -> VmOffset {
    pa.wrapping_add(VM_MIN_KERNEL_ADDRESS)
}

/// The pointer-width address a 32-bit module field holds; the widening is
/// lossless on both targets.
const fn address_value(value: u32) -> VmOffset {
    value as VmOffset
}

/// The kernel pointer a direct-map address denotes.
const fn kv_ptr<T>(address: VmOffset) -> *const T {
    with_exposed_provenance(address)
}
