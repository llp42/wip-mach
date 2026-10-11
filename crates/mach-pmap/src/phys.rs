// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The kernel virtual-to-physical lookup and the physical-page zero and
//! copy.

use crate::param::{VM_PAGE_DIRECTMAP_LIMIT, phystokv};
use crate::platform::Platform;
use crate::pmap::{kernel_pmap_ptr, pte_of};
use crate::pte::{Pte, pa_to_pte};
use crate::types::PmapMapwindow;
use crate::window::{pmap_get_mapwindow, pmap_put_mapwindow};
use core::ptr::{
    self, NonNull, with_exposed_provenance, with_exposed_provenance_mut,
};
use mach_page::param::{PAGE_MASK, PAGE_SIZE, VmOffset};

/// The offset within a page.
const OFFMASK: VmOffset = 0xfff;

/// `INTEL_PTE_PFN`: the physical-page-number field of a page table entry.
const PFN_MASK: VmOffset = 0xffff_ffff_ffff_f000;

/// The entry a writable temporary mapping is made with.
const fn pte_writable(pa: VmOffset) -> Pte {
    Pte::VALID
        .union(Pte::WRITE)
        .union(Pte::REF)
        .union(Pte::MOD)
        .union(pa_to_pte(pa))
}

/// The entry a read-only temporary mapping is made with.
const fn pte_readable(pa: VmOffset) -> Pte {
    Pte::VALID.union(Pte::REF).union(pa_to_pte(pa))
}

/// The physical address the kernel address `addr` maps to, or zero.
#[must_use]
pub fn kvtophys(addr: VmOffset) -> VmOffset {
    // SAFETY: `kernel_pmap_ptr()` is the kernel's live pmap after the pmap
    // bootstrap, and `pte_of()` returns null rather than something invalid
    // for an address without a mapping.
    let pte = unsafe { pte_of(kernel_pmap_ptr(), addr) };
    let Some(pte) = NonNull::new(pte) else {
        return 0;
    };
    // SAFETY: `pte_of()` returned a non-null pointer to a live page table
    // entry, which the C dereferenced the same way.
    let entry = unsafe { *pte.as_ptr() };
    (entry.bits() & PFN_MASK) | (addr & OFFMASK)
}

/// A physical page's kernel-visible address, holding a temporary map window
/// open while the page lies above [`VM_PAGE_DIRECTMAP_LIMIT`].
struct Mapping {
    /// The map window covering `pa`, or null for the direct map.
    window: *mut PmapMapwindow,
    /// The physical address the C passed.
    pa: VmOffset,
}

impl Mapping {
    /// The mapping of `pa` for a write.
    ///
    /// # Safety
    ///
    /// As [`Mapping::read`], and no other access may write the frame while
    /// this mapping is live.
    unsafe fn write<P: Platform>(pa: VmOffset) -> Self {
        unsafe { Self::new::<P>(pa, pte_writable(pa)) }
    }

    /// # Safety
    ///
    /// `pa` must name a real page frame, and `entry` exactly the
    /// [`pte_writable`] or [`pte_readable`] entry of that frame.
    unsafe fn new<P: Platform>(pa: VmOffset, entry: Pte) -> Self {
        if pa < VM_PAGE_DIRECTMAP_LIMIT {
            return Self {
                window: ptr::null_mut(),
                pa,
            };
        }
        let window = unsafe { pmap_get_mapwindow::<P>(entry) };
        Self { window, pa }
    }

    /// The address the C computed: the direct-map address, or the window
    /// with the in-page offset added.
    fn address(&self) -> VmOffset {
        if self.window.is_null() {
            phystokv(self.pa)
        } else {
            // SAFETY: the mapping holds the window live until `drop()` runs.
            unsafe { (*self.window).vaddr + (self.pa & PAGE_MASK) }
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        if !self.window.is_null() {
            // SAFETY: `self.window` is the window `pmap_get_mapwindow()`
            // returned, and a `Mapping` is dropped once.
            unsafe { pmap_put_mapwindow(self.window) };
        }
    }
}

/// Zeroes one physical page.
///
/// # Safety
///
/// `pa` must be the page-aligned address of a real physical frame.
pub unsafe fn zero_page<P: Platform>(pa: VmOffset) {
    let mapping = unsafe { Mapping::write::<P>(pa) };
    let page = with_exposed_provenance_mut::<u8>(mapping.address());
    // SAFETY: the mapping covers the page at `pa` for the whole write.
    unsafe { ptr::write_bytes(page, 0, PAGE_SIZE) };
}

/// Copies one physical page to another.
///
/// # Safety
///
/// `src` and `dst` must be the page-aligned addresses of real physical
/// frames, and the two frames must not overlap.
pub unsafe fn copy_page<P: Platform>(src: VmOffset, dst: VmOffset) {
    let src_map = unsafe { Mapping::new::<P>(src, pte_readable(src)) };
    let dst_map = unsafe { Mapping::write::<P>(dst) };
    // SAFETY: both mappings cover a page, and the caller promises the frames
    // do not overlap.
    unsafe {
        ptr::copy_nonoverlapping(
            with_exposed_provenance::<u8>(src_map.address()),
            with_exposed_provenance_mut::<u8>(dst_map.address()),
            PAGE_SIZE,
        );
    };
}
