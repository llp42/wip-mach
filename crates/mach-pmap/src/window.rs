// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The per-CPU windows that map a physical page outside the direct map.

use crate::cell::SyncCell;
use crate::param::PMAP_NMAPWINDOWS;
use crate::platform::Platform;
use crate::pmap::kernel_pmap_ptr;
use crate::pte::Pte;
use crate::shootdown::invalidate_tlb;
use crate::types::PmapMapwindow;
use core::cell::UnsafeCell;
use core::ptr::{self};
use mach_page::param::PAGE_SIZE;
use mach_page::smp::MAX_NCPUS;

/// The per-CPU temporary mappings; a CPU uses only its own run of them.
pub static MAPWINDOWS: SyncCell<
    [PmapMapwindow; PMAP_NMAPWINDOWS * MAX_NCPUS],
> = SyncCell(UnsafeCell::new(
    [PmapMapwindow {
        entry: ptr::null_mut(),
        vaddr: 0,
    }; PMAP_NMAPWINDOWS * MAX_NCPUS],
));

/// Maps a physical page in the calling CPU's temporary window.
///
/// # Safety
///
/// `entry` must be a page-table template the caller intends to map now.
///
/// # Panics
///
/// Halts when both of the CPU's windows are busy, a state the two nested
/// users cannot reach.
pub unsafe fn pmap_get_mapwindow<P: Platform>(
    entry: Pte,
) -> *mut PmapMapwindow {
    // SAFETY: `kernel_pmap_ptr()` is live from `pmap_bootstrap()` on, and a
    // `CpuId` indexes the `MAX_NCPUS` window runs.
    unsafe {
        let cpu = P::current_cpu().as_usize();
        let windows = MAPWINDOWS.0.get().cast::<PmapMapwindow>();
        let start = windows.wrapping_add(cpu * PMAP_NMAPWINDOWS);
        let end = windows.wrapping_add((cpu + 1) * PMAP_NMAPWINDOWS);
        let mut map = start;
        while map < end {
            let slot = (*map).entry;
            if slot.is_null() || (*slot).is_empty() {
                break;
            }
            map = map.wrapping_add(1);
        }
        assert!(map != end, "pmap_get_mapwindow: no free map window");
        *(*map).entry = entry;
        invalidate_tlb(
            kernel_pmap_ptr(),
            (*map).vaddr,
            (*map).vaddr.wrapping_add(PAGE_SIZE),
        );
        map
    }
}

/// Drops a temporary mapping.
///
/// # Safety
///
/// `map` must be a window `pmap_get_mapwindow()` returned and not yet
/// released.
pub unsafe fn pmap_put_mapwindow(map: *mut PmapMapwindow) {
    unsafe {
        *(*map).entry = Pte::empty();
        invalidate_tlb(
            kernel_pmap_ptr(),
            (*map).vaddr,
            (*map).vaddr.wrapping_add(PAGE_SIZE),
        );
    }
}
