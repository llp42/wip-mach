// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The page-table entry, at every level of the tree.

use crate::param::phystokv;
use mach_page::param::{PAGE_SIZE, VmOffset};

/// The offset within a page.
pub(crate) const INTEL_OFFMASK: VmOffset = 0xfff;

/// `INTEL_PTE_PFN`: the page-frame field of a page table entry, whose width
/// follows the `phys_addr_t` the entry is.
pub(crate) const INTEL_PTE_PFN: VmOffset = 0xffff_ffff_ffff_f000;

bitflags::bitflags! {
    /// A page table entry at any level: its flags, with the page-frame
    /// field in the bits [`INTEL_PTE_PFN`] covers.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Pte: VmOffset {
        /// The entry maps something.
        const VALID = 0x0000_0001;
        /// The mapping is writable.
        const WRITE = 0x0000_0002;
        /// User mode may use the mapping.
        const USER = 0x0000_0004;
        /// Writes go through the cache.
        const WTHRU = 0x0000_0008;
        /// The mapping is not cached.
        const NCACHE = 0x0000_0010;
        /// The page has been read or written.
        const REF = 0x0000_0020;
        /// The page has been written.
        const MOD = 0x0000_0040;
        /// A large-page directory entry.
        const PS = 0x0000_0080;
        /// The mapping survives an address-space switch.
        const GLOBAL = 0x0000_0100;
        /// Software: the mapping is wired.
        const WIRED = 0x0000_0200;
        // The page-frame field and the bits the kernel leaves clear.
        const _ = !0;
    }
}

impl Pte {
    /// The same entry for the page after this one.
    pub(crate) const fn next_page(self) -> Self {
        Self::from_bits_retain(self.bits().wrapping_add(PAGE_SIZE))
    }
}

/// The page-table entry bits of the physical address `pa`.
pub(crate) const fn pa_to_pte(pa: VmOffset) -> Pte {
    Pte::from_bits_retain(pa & INTEL_PTE_PFN)
}

/// The physical address in the entry `pte`.
pub(crate) const fn pte_to_pa(pte: Pte) -> VmOffset {
    pte.bits() & INTEL_PTE_PFN
}

/// The kernel virtual address of the table the entry `pte` points at.
pub(crate) const fn ptetokv(pte: Pte) -> *mut Pte {
    phystokv(pte_to_pa(pte)) as *mut Pte
}
