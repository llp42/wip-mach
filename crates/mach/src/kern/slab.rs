// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The slab allocator's platform: the pages its slabs take from VM's free
//! pages and kernel map, and the slab state the kernel holds.

use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::vm_platform::VM_STATE;
use crate::kern::console;
use crate::vm::VmMap;
use core::fmt;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
use mach_host::time as host_time;
use mach_page::param::{VmOffset, VmSize};
use mach_pmap::bootstrap::{KERNEL_VIRTUAL_END, KERNEL_VIRTUAL_START};
use mach_pmap::phys;
use mach_slab::{Platform, SlabState};
use mach_vm::param::PAGE_SIZE;
use mach_vm::types::PageSelect;
use mach_vm::{vm_kern, vm_page, vm_resident};

pub use mach_slab::types::{CacheInfo, CacheInitFlags, KMEM_ALIGN_MIN};
pub use mach_slab::{kalloc_ready, nr_caches};

/// A slab cache of the kernel's.
pub type KmemCache = mach_slab::KmemCache<MachPlatform>;

/// The slab allocator's state.
static SLAB_STATE: SlabState<MachPlatform> = SlabState::new();

/// Allocates `size` bytes from the general-purpose caches, or from the kernel
/// map past the largest one.
pub(crate) fn kalloc(size: usize) -> Option<NonNull<u8>> {
    mach_slab::kalloc::<MachPlatform>(size)
}

/// Frees `size` bytes [`kalloc`] allocated.
///
/// # Safety
///
/// `data` must be a live allocation of `size` bytes from [`kalloc`] that
/// nothing uses.
pub(crate) unsafe fn kfree(data: NonNull<u8>, size: usize) {
    // SAFETY: the caller's promises are the allocator's.
    unsafe { mach_slab::kfree::<MachPlatform>(data, size) };
}

/// Returns the free slabs of every cache to the system, at most once per
/// collection interval.
pub(crate) fn slab_collect() {
    // The tick rate is positive once the clock is probed.
    let hz = usize::try_from(mach_sched::sched::CLOCK_HZ).unwrap_or(0);
    mach_slab::slab_collect::<MachPlatform>(
        host_time::elapsed_ticks::<MachPlatform>(),
        hz,
    );
}

// SAFETY: each function forwards to the kernel routine the slab called before
// the seam, whose contract the trait restates.
unsafe impl Platform for MachPlatform {
    type Lock = Self;

    fn slab_state() -> &'static SlabState<Self> {
        &SLAB_STATE
    }

    unsafe fn alloc_physmem_page() -> Option<VmOffset> {
        // SAFETY: the caller holds no cache lock, so the allocation may
        // block on the page queues.
        let page =
            unsafe { vm_resident::grab::<Self>(PageSelect::DIRECTMAP) }?;
        // SAFETY: the page is live and direct-mapped.
        Some(unsafe { (*page.as_ptr()).phys_addr })
    }

    unsafe fn free_physmem_page(pa: VmOffset) {
        let Some(page) = vm_page::lookup_pa(pa) else {
            panic!(
                "kmem_pagefree_physmem: kmem_pagefree_physmem: missing page"
            );
        };
        // SAFETY: the page is live, and the release takes the page-queues
        // lock itself.
        unsafe { vm_resident::release::<Self>(page, false, false) };
    }

    unsafe fn wait_for_page() {
        // SAFETY: the wait takes no continuation, so it returns here.
        unsafe { vm_page::wait::<Self>(None) };
    }

    fn alloc_virtual(size: VmSize, align: VmSize) -> Option<VmOffset> {
        // SAFETY: `kernel_map` is the live kernel map.
        let map = unsafe {
            NonNull::new_unchecked(VM_STATE.kernel_map().cast::<VmMap>())
        };

        if align <= PAGE_SIZE {
            vm_kern::kmem_alloc_wired(map, size).ok()
        } else {
            vm_kern::kmem_alloc_aligned(map, size).ok()
        }
    }

    unsafe fn free_virtual(addr: VmOffset, size: VmSize) -> bool {
        // SAFETY: `kernel_map` is the live kernel map.
        let map = unsafe { &mut *VM_STATE.kernel_map().cast::<VmMap>() };
        vm_kern::kmem_free(map, addr, size).is_ok()
    }

    fn kernel_virtual_range() -> (VmOffset, VmOffset) {
        (
            KERNEL_VIRTUAL_START.load(Ordering::Relaxed),
            KERNEL_VIRTUAL_END.load(Ordering::Relaxed),
        )
    }

    fn kvtophys(addr: VmOffset) -> VmOffset {
        phys::kvtophys(addr)
    }

    fn print(args: fmt::Arguments<'_>) {
        console::write_fmt(args);
    }
}
