// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The physical map's platform: what the pmap asks of the `x86_64` machine,
//! and the pmap's state and caches the kernel holds.

use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::{model_dep, mp_desc, per_cpu, spl};
use crate::kern::console;
use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::vm::VmMap;
use core::ffi::c_int;
use core::fmt;
use core::ptr::NonNull;
use core::sync::atomic::Ordering;
use mach_host::machine::slot as machine_slot;
use mach_page::param::{VmOffset, VmSize};
use mach_page::smp::CpuId;
use mach_pmap::platform::Platform;
use mach_pmap::pmap::Pmap;
use mach_pmap::state::PmapState;
use mach_pmap::types::PmapCache;
use mach_vm::vm_page;

const _: () = assert!(PmapCache::PvEntry as usize + 1 == PmapCache::COUNT);

/// The physical map's state.
pub static PMAP_STATE: PmapState<MachPlatform> = PmapState::new();

/// The slab cache behind each of the pmap's [`PmapCache`]s.
static PMAP_CACHES: [KmemCache; PmapCache::COUNT] =
    [const { KmemCache::zeroed() }; PmapCache::COUNT];

/// The slab cache behind `cache`.
fn pmap_cache(cache: PmapCache) -> &'static KmemCache {
    &PMAP_CACHES[cache as usize]
}

// SAFETY: each function forwards to the kernel routine the pmap called
// before the seam, whose contract the trait restates.
unsafe impl Platform for MachPlatform {
    type Lock = Self;

    fn pmap_state() -> &'static PmapState<Self> {
        &PMAP_STATE
    }

    fn current_cpu() -> CpuId {
        per_cpu::cpu_id()
    }

    unsafe fn current_pmap() -> Option<NonNull<Pmap>> {
        let thread = per_cpu::thread();
        if thread.is_null() {
            return None;
        }
        // SAFETY: the running thread is live, and its task has a map, as the
        // caller promises.
        unsafe {
            let map = (*(*thread).task).map.cast::<VmMap>();
            NonNull::new((*map).pmap)
        }
    }

    fn cpu_type() -> c_int {
        machine_slot(per_cpu::cpu_id())
            .cpu_type
            .load(Ordering::Relaxed)
    }

    unsafe fn splvm() -> c_int {
        // SAFETY: the caller hands the level back to `splx`.
        unsafe { spl::splvm() }
    }

    unsafe fn splx(s: c_int) {
        // SAFETY: `s` came from an spl call, as the caller promises.
        unsafe { spl::splx(s) };
    }

    unsafe fn wait_for_page() {
        // SAFETY: the caller holds no page lock and may block.
        unsafe { vm_page::wait::<Self>(None) };
    }

    fn interrupt_processor(cpu: CpuId) {
        mp_desc::interrupt_processor(cpu);
    }

    fn boot_alloc(size: VmSize) -> Option<VmOffset> {
        model_dep::alloc_aligned(size)
    }

    unsafe fn pmap_cache_init(
        cache: PmapCache,
        name: &'static [u8],
        size: usize,
        align: usize,
        physmem: bool,
    ) {
        let flags = if physmem {
            CacheInitFlags::PHYSMEM
        } else {
            CacheInitFlags::empty()
        };
        pmap_cache(cache).init(name, size, align, None, flags);
    }

    unsafe fn pmap_cache_alloc(cache: PmapCache) -> Option<NonNull<u8>> {
        pmap_cache(cache).alloc()
    }

    unsafe fn pmap_cache_free(cache: PmapCache, record: NonNull<u8>) {
        // SAFETY: the record came from this cache, as the caller promises.
        unsafe { pmap_cache(cache).free(record) };
    }

    fn print(args: fmt::Arguments<'_>) {
        console::write_fmt(args);
    }
}
