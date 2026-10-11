// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! Where slabs get their pages: single directly mapped pages, or wired
//! kernel virtual memory, both through the platform.

use crate::platform::Platform;
use crate::types::CacheFlags;
use core::ptr::{NonNull, with_exposed_provenance_mut};
use mach_page::param::{VM_MIN_KERNEL_ADDRESS, VmOffset, VmSize, round_page};

/// A direct-mapped page, blocking until one is free.
pub(crate) fn pagealloc_physmem<P: Platform>(_size: VmSize) -> NonNull<u8> {
    loop {
        // SAFETY: no cache lock is held, so the allocation may block on the
        // page queues.
        if let Some(pa) = unsafe { P::alloc_physmem_page() } {
            // SAFETY: the mapped address is non-null.
            return unsafe {
                NonNull::new_unchecked(with_exposed_provenance_mut(
                    VM_MIN_KERNEL_ADDRESS.wrapping_add(pa),
                ))
            };
        }

        // SAFETY: no cache lock is held, so the wait may block.
        unsafe { P::wait_for_page() };
    }
}

/// Allocates `size` bytes of wired kernel virtual memory aligned to `align`.
pub(crate) fn pagealloc_virtual<P: Platform>(
    size: VmSize,
    align: VmSize,
) -> Option<NonNull<u8>> {
    let addr = P::alloc_virtual(round_page(size), align)?;

    // SAFETY: a successful allocation is a non-null kernel address.
    Some(unsafe { NonNull::new_unchecked(with_exposed_provenance_mut(addr)) })
}

/// Frees a direct-mapped page.
///
/// # Safety
///
/// `addr` must be a page [`pagealloc_physmem`] returned.
pub(crate) unsafe fn pagefree_physmem<P: Platform>(
    addr: VmOffset,
    _size: VmSize,
) {
    let pa = P::kvtophys(addr);
    // The caller promises the page was allocated here, so the lookup finds
    // it.
    assert!(
        mach_page::table::lookup_pa::<()>(pa).is_some(),
        "kmem_pagefree_physmem: kmem_pagefree_physmem: missing page"
    );

    // SAFETY: the page is live, as the lookup showed, and came from
    // `alloc_physmem_page`.
    unsafe { P::free_physmem_page(pa) };
}

/// Frees `size` bytes of kernel virtual memory.
///
/// # Safety
///
/// `addr..addr + size` must be a region [`pagealloc_virtual`] returned.
pub(crate) unsafe fn pagefree_virtual<P: Platform>(
    addr: VmOffset,
    size: VmSize,
) {
    let (start, end) = P::kernel_virtual_range();

    assert!(
        addr >= start && addr.wrapping_add(size) <= end,
        "kmem_pagefree_virtual: kmem_pagefree_virtual({:x}-{:x}) falls in physical memory area!\n",
        addr,
        addr.wrapping_add(size)
    );

    // SAFETY: the region came from `alloc_virtual`, as the caller promises.
    let freed = unsafe { P::free_virtual(addr, round_page(size)) };
    assert!(freed, "kmem_free: kmem_free");
}

/// Allocates a slab's memory, from physical or virtual memory as the cache's
/// flags say.
pub(crate) fn pagealloc<P: Platform>(
    size: VmSize,
    align: VmSize,
    flags: CacheFlags,
) -> Option<NonNull<u8>> {
    if flags.contains(CacheFlags::PHYSMEM) {
        Some(pagealloc_physmem::<P>(size))
    } else {
        pagealloc_virtual::<P>(size, align)
    }
}

/// Frees a slab's memory, to physical or virtual memory as the cache's flags
/// say.
///
/// # Safety
///
/// `addr` must be a region the matching [`pagealloc`] returned.
pub(crate) unsafe fn pagefree<P: Platform>(
    addr: VmOffset,
    size: VmSize,
    flags: CacheFlags,
) {
    if flags.contains(CacheFlags::PHYSMEM) {
        unsafe { pagefree_physmem::<P>(addr, size) };
    } else {
        unsafe { pagefree_virtual::<P>(addr, size) };
    }
}
