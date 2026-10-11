// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! What the slab allocator asks of the kernel.

use crate::state::SlabState;
use core::fmt;
use mach_page::param::{VmOffset, VmSize};

/// The kernel services the slab allocator needs.
///
/// The slab sits below VM and the pmap's neighbours, so its pages come
/// through here: a directly mapped page from VM's free pages, wired kernel
/// virtual memory from VM's kernel map, and the physical address behind a
/// kernel address.
///
/// # Safety
///
/// Each item must keep the contract its documentation states.
pub unsafe trait Platform: Sized + 'static {
    /// The lock platform of the cache list's spin lock.
    type Lock: lock::Platform;

    /// The slab state the kernel holds.
    fn slab_state() -> &'static SlabState<Self>;

    /// Takes one free directly mapped page, returning its physical address,
    /// or `None` when none is free.
    ///
    /// # Safety
    ///
    /// The caller holds no cache lock, so the allocation may block on the
    /// page queues.
    unsafe fn alloc_physmem_page() -> Option<VmOffset>;

    /// Returns the page at `pa`, which [`Self::alloc_physmem_page`] gave.
    ///
    /// # Safety
    ///
    /// `pa` must be such a page, which nothing uses any more.
    unsafe fn free_physmem_page(pa: VmOffset);

    /// Blocks until a free page may be available.
    ///
    /// # Safety
    ///
    /// The caller holds no cache lock and may block.
    unsafe fn wait_for_page();

    /// Allocates `size` bytes of wired kernel virtual memory, page-rounded,
    /// aligned to `align` when it exceeds a page, or `None`.
    fn alloc_virtual(size: VmSize, align: VmSize) -> Option<VmOffset>;

    /// Frees the `size` bytes at `addr`, returning whether the kernel map
    /// held them.
    ///
    /// # Safety
    ///
    /// `addr..addr + size` must be a region [`Self::alloc_virtual`] gave,
    /// which nothing uses any more.
    unsafe fn free_virtual(addr: VmOffset, size: VmSize) -> bool;

    /// The kernel virtual range wired allocations come from.
    fn kernel_virtual_range() -> (VmOffset, VmOffset);

    /// The physical address of the kernel virtual address `addr`.
    fn kvtophys(addr: VmOffset) -> VmOffset;

    /// Writes `args` to the console.
    fn print(args: fmt::Arguments<'_>);
}
