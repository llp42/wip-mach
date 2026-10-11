// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The general-purpose caches behind `kalloc`, and the operations over every
//! cache: initialization, collection and the `host_slab_info()` snapshot.

use crate::cache::{CacheList, KmemCache};
use crate::pages::{
    pagealloc_physmem, pagealloc_virtual, pagefree_physmem, pagefree_virtual,
};
use crate::platform::Platform;
use crate::slab::{KmemSlab, SlabList};
use crate::state::{KALLOC_READY, KMEM_GC_LAST_TICK, KMEM_NR_CACHES};
use crate::types::{
    CacheError, CacheFlags, CacheInfo, CacheInitFlags, KALLOC_FIRST_SHIFT,
    KALLOC_NR_CACHES, KMEM_CACHE_NAME_SIZE, KMEM_GC_TICKS, KMEM_REDZONE_BYTE,
};
use core::mem::size_of;
use core::pin::pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::Ordering;
use mach_page::param::PAGE_SIZE;

/// The index of the [`kalloc`] cache for `size` bytes; the caller passes a
/// size greater than zero.
const fn kalloc_index(size: usize) -> usize {
    let size = (size - 1) >> KALLOC_FIRST_SHIFT;

    if size == 0 {
        0
    } else {
        // The bit width is a `u32`, and `usize` is at least as wide.
        size.bit_width() as usize
    }
}

/// The `index`th general-purpose cache.
fn kalloc_cache<P: Platform>(index: usize) -> &'static KmemCache<P> {
    &P::slab_state().kalloc_caches()[index]
}

/// Fills the slack past the requested `size` of a buffer [`kalloc`] hands out
/// with the redzone byte.
///
/// # Safety
///
/// `buf` must hold `cache.obj_size` writable bytes.
unsafe fn kalloc_verify<P: Platform>(
    cache: &KmemCache<P>,
    buf: NonNull<u8>,
    size: usize,
) {
    let redzone = buf.as_ptr().wrapping_add(size);
    let redzone_size = cache.layout().obj_size - size;
    unsafe { ptr::write_bytes(redzone, KMEM_REDZONE_BYTE, redzone_size) };
}

/// Checks the redzone past `size` of a buffer [`kfree`] gets back.
///
/// # Safety
///
/// `buf` must hold `cache.obj_size` readable bytes previously filled with
/// [`KMEM_REDZONE_BYTE`] past `size`.
unsafe fn kfree_verify<P: Platform>(
    cache: &KmemCache<P>,
    buf: NonNull<u8>,
    size: usize,
) {
    let mut redzone_byte = buf.as_ptr().wrapping_add(size);
    let redzone_end = buf.as_ptr().wrapping_add(cache.layout().obj_size);

    while redzone_byte < redzone_end {
        if unsafe { *redzone_byte } != KMEM_REDZONE_BYTE {
            cache.error(
                buf.as_ptr(),
                CacheError::Redzone,
                redzone_byte.cast(),
            );
        }
        redzone_byte = unsafe { redzone_byte.add(1) };
    }
}

/// Allocates `size` bytes from the general-purpose caches, or from the kernel
/// map past the largest one.
#[must_use]
pub fn kalloc<P: Platform>(size: usize) -> Option<NonNull<u8>> {
    if size == 0 {
        return None;
    }

    let index = kalloc_index(size);

    if index < KALLOC_NR_CACHES {
        let cache = kalloc_cache::<P>(index);
        let buf = cache.alloc()?;

        if cache.layout().flags.contains(CacheFlags::VERIFY) {
            // SAFETY: the buffer is a live allocation of the cache's object
            // size.
            unsafe { kalloc_verify(cache, buf, size) };
        }

        Some(buf)
    } else if size <= PAGE_SIZE {
        Some(pagealloc_physmem::<P>(PAGE_SIZE))
    } else {
        pagealloc_virtual::<P>(size, 0)
    }
}

/// Frees `size` bytes [`kalloc`] allocated.
///
/// # Safety
///
/// `data` must be a live allocation of `size` bytes from [`kalloc`] that
/// nothing uses.
pub unsafe fn kfree<P: Platform>(data: NonNull<u8>, size: usize) {
    if size == 0 {
        return;
    }

    let index = kalloc_index(size);

    if index < KALLOC_NR_CACHES {
        let cache = kalloc_cache::<P>(index);

        if cache.layout().flags.contains(CacheFlags::VERIFY) {
            // SAFETY: `data` is a live allocation of this cache.
            unsafe { kfree_verify(cache, data, size) };
        }

        // SAFETY: `data` is a live allocation of this cache that nothing
        // else uses.
        unsafe { cache.free(data) };
    } else if size <= PAGE_SIZE {
        // SAFETY: the allocator returned a direct-mapped page for it.
        unsafe { pagefree_physmem::<P>(data.as_ptr().addr(), PAGE_SIZE) };
    } else {
        unsafe { pagefree_virtual::<P>(data.as_ptr().addr(), size) };
    }
}

/// Initializes the cache of off-slab data.
pub fn slab_init<P: Platform>() {
    P::slab_state().slab_cache().init(
        b"kmem_slab",
        size_of::<KmemSlab<P>>(),
        0,
        None,
        CacheInitFlags::NOOFFSLAB,
    );
}

/// Initializes the general-purpose caches.
pub fn kalloc_init<P: Platform>() {
    let mut size = 1 << KALLOC_FIRST_SHIFT;

    for index in 0..KALLOC_NR_CACHES {
        let name = kalloc_name(size);
        let cache = kalloc_cache::<P>(index);

        cache.init(&name, size, 0, None, CacheInitFlags::empty());
        size <<= 1;
    }

    // Publish the initialized caches to `kalloc_ready()`'s `Acquire` load.
    KALLOC_READY.store(true, Ordering::Release);
}

/// Whether [`kalloc`] may be called: `kalloc_init()` has run.
#[must_use]
pub fn kalloc_ready() -> bool {
    KALLOC_READY.load(Ordering::Acquire)
}

/// The name of the [`kalloc`] cache for `value` bytes, `kalloc_<value>`.
fn kalloc_name(value: usize) -> [u8; KMEM_CACHE_NAME_SIZE] {
    let mut name = [0u8; KMEM_CACHE_NAME_SIZE];
    let mut digits = itoa::Buffer::new();
    let spelling = b"kalloc_".iter().chain(digits.format(value).as_bytes());
    for (slot, byte) in name.iter_mut().zip(spelling) {
        *slot = *byte;
    }
    name
}

/// Returns the free slabs of every cache to the system, at most once per
/// collection interval.
///
/// `now` is the tick count since boot, and `hz` the ticks in a second.
pub fn slab_collect<P: Platform>(now: usize, hz: usize) {
    let interval = hz * KMEM_GC_TICKS;

    if now
        <= KMEM_GC_LAST_TICK
            .load(Ordering::Relaxed)
            .wrapping_add(interval)
    {
        return;
    }

    // `Relaxed` is enough: the collector only needs the value back, and a
    // stale one merely reaps a tick early or late.
    KMEM_GC_LAST_TICK.store(now, Ordering::Relaxed);

    let mut dead_slabs = pin!(SlabList::<P>::new());

    for_each_cache(&P::slab_state().cache_list.lock().0, |cache| {
        cache.reap(dead_slabs.as_mut());
    });

    while let Some(slab) =
        dead_slabs.as_mut().cursor_front_mut().remove_current()
    {
        // SAFETY: the slab is off every list and nothing holds it.
        unsafe {
            let slab = NonNull::from(slab);
            KmemSlab::<P>::destroy(slab, &*(*slab.as_ptr()).cache);
        }
    }
}

/// The number of caches on the global list, read without synchronization.
#[must_use]
pub fn nr_caches() -> u32 {
    KMEM_NR_CACHES.load(Ordering::Relaxed)
}

/// The `host_slab_info()` snapshot: fill `out` with every cache.
///
/// Returns [`None`] when the cache count changed under the caller, who
/// retries with a fresh allocation, as the C's `retry` label did.
pub fn collect<P: Platform>(
    expected: u32,
    out: &mut [CacheInfo],
) -> Option<u32> {
    if out.len() < expected as usize {
        return None;
    }

    let caches = P::slab_state().cache_list.lock();

    if KMEM_NR_CACHES.load(Ordering::Relaxed) != expected {
        drop(caches);
        return None;
    }

    let mut count = 0usize;

    for_each_cache(&caches.0, |cache| {
        let Some(info) = out.get_mut(count) else {
            return;
        };
        cache.fill_info(info);
        count += 1;
    });

    drop(caches);

    // `count` never exceeds the list's length, `expected`, which is a `u32`.
    Some(count as u32)
}

/// Runs `f` on every cache of `caches`, the locked global list.
///
/// No callback may remove a cache from the list.
fn for_each_cache<P: Platform>(
    caches: &CacheList<P>,
    mut f: impl FnMut(&mut KmemCache<P>),
) {
    let mut cursor = caches.cursor_front();
    while let Some(cache) = cursor.current_ptr() {
        cursor.move_next();
        // SAFETY: `KmemCache<P>::init()` linked this cache, which is static
        // storage for the kernel's lifetime; the walk mutates nothing.
        f(unsafe { &mut *cache.as_ptr() });
    }
}
