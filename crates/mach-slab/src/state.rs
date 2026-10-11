// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! `SlabState`: the caches and the cache list the kernel holds, and the
//! counters that name no platform.

use crate::cache::{CacheList, KmemCache};
use crate::platform::Platform;
use crate::types::{Caches, KALLOC_NR_CACHES};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize};
use lock::TicketLock;

/// The slab allocator's state that names the platform: the cache of
/// off-slab data, the general-purpose caches and the list of every cache.
///
/// A Rust `static` cannot be generic, so the kernel declares the one
/// `SlabState` and returns it from [`Platform::slab_state`].
pub struct SlabState<P: Platform> {
    slab_cache: KmemCache<P>,
    kalloc_caches: [KmemCache<P>; KALLOC_NR_CACHES],
    pub(crate) cache_list: TicketLock<Caches<P>>,
}

impl<P: Platform> SlabState<P> {
    /// The state before `slab_init()`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slab_cache: KmemCache::zeroed(),
            kalloc_caches: [const { KmemCache::zeroed() }; KALLOC_NR_CACHES],
            cache_list: TicketLock::new(Caches(CacheList::new())),
        }
    }

    /// The off-slab data cache; live from `slab_init()` on.
    pub(crate) const fn slab_cache(&self) -> &KmemCache<P> {
        &self.slab_cache
    }

    /// The first of the general-purpose caches, from 32 bytes to 128 KiB,
    /// one doubling per entry.
    pub(crate) const fn kalloc_caches(
        &self,
    ) -> &[KmemCache<P>; KALLOC_NR_CACHES] {
        &self.kalloc_caches
    }
}

impl<P: Platform> Default for SlabState<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// How many caches the cache list holds.
pub(crate) static KMEM_NR_CACHES: AtomicU32 = AtomicU32::new(0);

/// Whether `kalloc_init()` has built the general-purpose caches, so
/// `kalloc` may be called.
pub(crate) static KALLOC_READY: AtomicBool = AtomicBool::new(false);

/// The tick of the last garbage collection.
pub(crate) static KMEM_GC_LAST_TICK: AtomicUsize = AtomicUsize::new(0);
