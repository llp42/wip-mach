// SPDX-License-Identifier: CMU-Mach
// Derived from i386/i386/phys.c:
//   Copyright (c) 1991,1990,1989 Carnegie Mellon University.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel virtual-to-physical lookup and the physical-page copy
//! entries, which `i386/i386/phys.c` used to define and
//! `i386/intel/pmap.h` declares.

use crate::arch::types::VmOffset;
use crate::arch::vm_param::{PAGE_MASK, PAGE_SIZE};
use crate::arch::x86_64::biosmem::VM_PAGE_DIRECTMAP_LIMIT;
use crate::arch::x86_64::pmap::{self, PmapMapwindow};
use core::ptr::{
    self, NonNull, with_exposed_provenance, with_exposed_provenance_mut,
};

/// `INTEL_OFFMASK` of `i386/intel/pmap.h`: the offset within a page.
const OFFMASK: VmOffset = 0xfff;

/// `INTEL_PTE_PFN`: the physical-page-number field of a page table entry.
const PFN_MASK: VmOffset = 0xffff_ffff_ffff_f000;

/// `INTEL_PTE_W()` of `i386/i386/phys.c`: the entry a writable temporary
/// mapping is made with.
const fn pte_writable(pa: VmOffset) -> VmOffset {
    pmap::INTEL_PTE_VALID
        | pmap::INTEL_PTE_WRITE
        | pmap::INTEL_PTE_REF
        | pmap::INTEL_PTE_MOD
        | pmap::pa_to_pte(pa)
}

/// `INTEL_PTE_R()` of `i386/i386/phys.c`: the entry a read-only temporary
/// mapping is made with.
const fn pte_readable(pa: VmOffset) -> VmOffset {
    pmap::INTEL_PTE_VALID | pmap::INTEL_PTE_REF | pmap::pa_to_pte(pa)
}

/// `kvtophys()` of `i386/intel/pmap.h`, which `i386/i386/phys.c` defined.
pub(crate) fn kvtophys(addr: VmOffset) -> VmOffset {
    // SAFETY: `kernel_pmap` is the kernel's live pmap after
    // `pmap_bootstrap()`, and `pmap_pte()` returns null rather than something
    // invalid for an address without a mapping, as the C check relies on.
    let pte = unsafe { pmap::pmap_pte(pmap::kernel_pmap_ptr(), addr) };
    let Some(pte) = NonNull::new(pte) else {
        return 0;
    };
    // SAFETY: `pmap_pte()` returned a non-null pointer to a live page table
    // entry, which the C dereferenced the same way.
    let entry = unsafe { *pte.as_ptr() };
    (entry & PFN_MASK) | (addr & OFFMASK)
}

/// A physical page's kernel-visible address, holding a temporary map window
/// open while the page lies above [`VM_PAGE_DIRECTMAP_LIMIT`].
struct Mapping {
    /// The `pmap_mapwindow_t` covering `pa`, or null for the direct map.
    window: *mut PmapMapwindow,
    /// The physical address the C passed.
    pa: VmOffset,
}

impl Mapping {
    /// The mapping of `pa` for a read, as `INTEL_PTE_R()` built it.
    ///
    /// # Safety
    ///
    /// `pa` must name a real page frame, and the direct map or the mapwindow
    /// pool must cover it.
    unsafe fn read(pa: VmOffset) -> Self {
        unsafe { Self::new(pa, pte_readable(pa)) }
    }

    /// The mapping of `pa` for a write.
    ///
    /// # Safety
    ///
    /// As [`Mapping::read`], and no other access may write the frame while
    /// this mapping is live.
    unsafe fn write(pa: VmOffset) -> Self {
        unsafe { Self::new(pa, pte_writable(pa)) }
    }

    /// # Safety
    ///
    /// `pa` must name a real page frame, and `entry` exactly the
    /// `INTEL_PTE_W()`/`INTEL_PTE_R()` template of that frame.
    unsafe fn new(pa: VmOffset, entry: VmOffset) -> Self {
        if pa < VM_PAGE_DIRECTMAP_LIMIT {
            return Self {
                window: ptr::null_mut(),
                pa,
            };
        }
        let window = unsafe { pmap::pmap_get_mapwindow(entry) };
        Self { window, pa }
    }

    /// The address the C computed: the direct-map address, or the window
    /// with the in-page offset added.
    fn address(&self) -> VmOffset {
        if self.window.is_null() {
            pmap::phystokv(self.pa)
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
            unsafe { pmap::pmap_put_mapwindow(self.window) };
        }
    }
}

/// `pmap_zero_page()` of `i386/i386/phys.c`: zero one physical page.
///
/// # Safety
///
/// `pa` must be the page-aligned address of a real physical frame.
pub(crate) unsafe fn zero_page(pa: VmOffset) {
    let mapping = unsafe { Mapping::write(pa) };
    let page = with_exposed_provenance_mut::<u8>(mapping.address());
    // SAFETY: the mapping covers the page at `pa` for the whole write.
    unsafe { ptr::write_bytes(page, 0, PAGE_SIZE) };
}

/// `pmap_copy_page()` of `i386/i386/phys.c`: copy one physical page to
/// another.
///
/// # Safety
///
/// `src` and `dst` must be the page-aligned addresses of real physical
/// frames, and the two frames must not overlap.
pub(crate) unsafe fn copy_page(src: VmOffset, dst: VmOffset) {
    let src_map = unsafe { Mapping::read(src) };
    let dst_map = unsafe { Mapping::write(dst) };
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
