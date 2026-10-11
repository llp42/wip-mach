// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The machine values the physical pages are built for.
//!
//! `x86_64`'s scalar widths, page geometry and kernel base, and the CPU cap
//! that sizes the per-CPU page pools.  The kernel asserts that its own
//! definitions agree.

use core::sync::atomic::AtomicUsize;

/// `vm_offset_t`: a type-neutral pointer, the width of an address.
pub type VmOffset = usize;

/// `vm_size_t`: the difference between two `vm_offset_t`s, likewise the width
/// of an address.
pub type VmSize = usize;

/// A [`VmOffset`] shared between CPUs without a lock.
pub type AtomicVmOffset = AtomicUsize;

/// The number of bits to shift for pages.
pub const PAGE_SHIFT: u32 = 12;

/// `PAGE_SIZE`: one page, `1 << PAGE_SHIFT`.
pub const PAGE_SIZE: VmSize = 1 << PAGE_SHIFT;

/// `PAGE_MASK`: the in-page offset bits, `PAGE_SIZE - 1`.
pub const PAGE_MASK: VmSize = PAGE_SIZE - 1;

/// The lowest kernel virtual address, where the kernel map begins.
///
/// A kernel-object offset is linear in the kernel virtual address, so a
/// kernel mapping is stored at `addr - VM_MIN_KERNEL_ADDRESS`, and the direct
/// map adds it back to a physical address.
pub const VM_MIN_KERNEL_ADDRESS: VmOffset = 0xffff_ffff_8000_0000;

/// The highest kernel virtual address: the linear and kernel virtual bases
/// coincide, so the kernel's addresses run to the top.
pub const VM_MAX_KERNEL_ADDRESS: VmOffset = usize::MAX;

/// The room reserved for the kernel map.
pub const VM_KERNEL_MAP_SIZE: VmOffset = 1000 * 1024 * 1024;

/// The physical memory the direct map covers, up to where the kernel map's
/// room begins.
pub const VM_PAGE_DIRECTMAP_LIMIT: VmOffset =
    VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS - VM_KERNEL_MAP_SIZE + 1;

pub use crate::smp::MAX_NCPUS;

/// The page number of the byte address `addr`.
#[must_use]
pub const fn atop(addr: VmOffset) -> usize {
    addr >> PAGE_SHIFT
}

/// The byte address of page number `page`.
#[must_use]
pub const fn ptoa(page: usize) -> VmOffset {
    page << PAGE_SHIFT
}

/// Truncates `addr` down to a page boundary.
#[must_use]
pub const fn trunc_page(addr: VmOffset) -> VmOffset {
    addr & !(PAGE_SIZE - 1)
}

/// Rounds `addr` up to a page boundary.
#[must_use]
pub const fn round_page(addr: VmOffset) -> VmOffset {
    addr.wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}
