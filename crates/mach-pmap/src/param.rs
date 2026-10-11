// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The layout of the address space the page tables map, and the
//! conversions between its kernel virtual, linear and physical addresses.

use core::mem::size_of;
use mach_page::param::{PAGE_SIZE, VM_MIN_KERNEL_ADDRESS, VmOffset};
use mach_page::smp::MAX_NCPUS;

/// The invalidation requests one CPU can queue before the last becomes a
/// whole-address-space flush.
pub(crate) const UPDATE_LIST_SIZE: usize = 4;

/// The temporary map windows per CPU.
pub(crate) const PMAP_NMAPWINDOWS: usize = 2;

/// `MAPWINDOW_SIZE`: the virtual space the map windows take from the kernel
/// map's tail.
pub(crate) const MAPWINDOW_SIZE: VmOffset =
    PMAP_NMAPWINDOWS * MAX_NCPUS * PAGE_SIZE;

/// One hardware entry per VM page.
pub(crate) const PTES_PER_VM_PAGE: usize = 1;

/// The entries in one page table.
pub(crate) const NPTES: usize = PAGE_SIZE / size_of::<VmOffset>();

/// The protected page directories at the kernel end of the address space.
pub(crate) const PDPNUM_KERNEL: usize =
    ((VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS) >> PDPSHIFT) + 1;

/// The page directories [`pmap_create`](crate::pmap::pmap_create)
/// allocates, the same count
/// [`pmap_bootstrap`](crate::bootstrap::pmap_bootstrap) writes at the
/// kernel end.
pub(crate) const PDPNUM: usize = PDPNUM_KERNEL;

/// The lowest linear kernel address.
const LINEAR_MIN_KERNEL_ADDRESS: VmOffset = VM_MIN_KERNEL_ADDRESS;

/// The highest linear kernel address.
const LINEAR_MAX_KERNEL_ADDRESS: VmOffset = usize::MAX;

pub use mach_page::param::{
    VM_KERNEL_MAP_SIZE, VM_MAX_KERNEL_ADDRESS, VM_PAGE_DIRECTMAP_LIMIT,
};

// The kernel's top address is the linear one, moved to the kernel base.
const _: () = assert!(
    VM_MAX_KERNEL_ADDRESS
        == LINEAR_MAX_KERNEL_ADDRESS - LINEAR_MIN_KERNEL_ADDRESS
            + VM_MIN_KERNEL_ADDRESS
);

/// The top of a user map.
pub(crate) const VM_MAX_USER_ADDRESS: VmOffset = 0x8000_0000_0000;

/// The lowest user address.
pub(crate) const VM_MIN_USER_ADDRESS: VmOffset = 0;

/// The page-directory-pointer shift.
const PDPSHIFT: u32 = 30;

const PDESHIFT: u32 = 21;

/// `PDE_MAPPED_SIZE`: the virtual memory one page-directory entry covers.
pub(crate) const PDE_MAPPED_SIZE: VmOffset = 1 << PDESHIFT;

/// The page-directory index of `addr`.
pub(crate) const fn lin2pdenum(addr: VmOffset) -> usize {
    (addr >> PDESHIFT) & 0x1ff
}

/// The page-directory index of `addr`, including the directory-pointer index
/// when the directories are contiguous.
pub(crate) const fn lin2pdenum_cont(addr: VmOffset) -> usize {
    (addr >> PDESHIFT) & 0x3ff
}

/// The page-table index of `addr`.
pub(crate) const fn ptenum(addr: VmOffset) -> usize {
    (addr >> 12) & 0x1ff
}

/// The level-4 index of `addr`.
pub(crate) const fn lin2l4num(addr: VmOffset) -> usize {
    (addr >> 39) & 0x1ff
}

/// The directory-pointer index of `addr`.
pub(crate) const fn lin2pdpnum(addr: VmOffset) -> usize {
    (addr >> 30) & 0x1ff
}

/// The linear address of a page, from its indices.
pub(crate) const fn pagenum2lin(
    l4: usize,
    l3: usize,
    l2: usize,
    l1: usize,
) -> VmOffset {
    ((l4) << 39) + ((l3) << 30) + ((l2) << 21) + ((l1) << 12)
}

/// The kernel virtual address of the physical address `pa`.
pub(crate) const fn phystokv(pa: VmOffset) -> VmOffset {
    pa.wrapping_add(VM_MIN_KERNEL_ADDRESS)
}

/// The physical address of the kernel virtual address `va`, before paging is
/// up.
pub(crate) const fn kvtophys_early(va: VmOffset) -> VmOffset {
    va.wrapping_sub(VM_MIN_KERNEL_ADDRESS)
}

/// The linear address of the kernel virtual address `va`: an identity here
/// because the linear and kernel virtual bases coincide.
pub(crate) const fn kvtolin(va: VmOffset) -> VmOffset {
    va.wrapping_sub(VM_MIN_KERNEL_ADDRESS)
        .wrapping_add(LINEAR_MIN_KERNEL_ADDRESS)
}

/// The kernel virtual address of the linear address `lin`.
pub(crate) const fn lintokv(lin: VmOffset) -> VmOffset {
    lin.wrapping_sub(LINEAR_MIN_KERNEL_ADDRESS)
        .wrapping_add(VM_MIN_KERNEL_ADDRESS)
}
