// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! The slab allocator's flags, records and constants.

use crate::cache::CacheList;
use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::mem::{align_of, offset_of, size_of};
use mach_page::param::{PAGE_SIZE, VmSize};

/// The length of a cache name, chosen so the mirror fits in two 64-byte cache
/// lines.
pub const KMEM_CACHE_NAME_SIZE: usize = 24;

/// The length of a cache name in the slab report.
pub(crate) const CACHE_NAME_MAX_LEN: usize = 32;

/// The alignment every [`kalloc`](crate::kalloc::kalloc) buffer has, whatever
/// its size.
pub const KMEM_ALIGN_MIN: usize = 8;

/// The buffer size below which a cache keeps its slab data on the slab.
pub(crate) const KMEM_BUF_SIZE_THRESHOLD: usize = PAGE_SIZE / 8;

/// The shift of the smallest [`kalloc`] cache: 32 bytes.
pub(crate) const KALLOC_FIRST_SHIFT: usize = 5;

/// The number of [`kalloc`] caches.
pub(crate) const KALLOC_NR_CACHES: usize = 13;

/// How many seconds of ticks pass between two garbage collections.
pub(crate) const KMEM_GC_TICKS: usize = 5;

/// The byte a verify cache fills redzones with.
pub(crate) const KMEM_REDZONE_BYTE: u8 = 0xbb;

/// The word a verify cache stamps in a buffer's redzone, little-endian.
pub(crate) const KMEM_REDZONE_WORD: c_ulong = 0xcefa_edfe_cefa_edfe;

/// The pattern a verify cache fills free buffers with, little-endian.
pub(crate) const KMEM_FREE_PATTERN: u64 = 0xefbe_adde_efbe_adde;

/// The pattern a verify cache fills unconstructed buffers with, little-endian.
pub(crate) const KMEM_UNINIT_PATTERN: u64 = 0xfeca_ddba_feca_ddba;

/// The buffer tag of an allocated buffer, little-endian.
pub(crate) const KMEM_BUFTAG_ALLOC: c_ulong = 0xedc8_10a1_edc8_10a1;

/// The buffer tag of a free buffer, little-endian.
pub(crate) const KMEM_BUFTAG_FREE: c_ulong = 0x0cb1_eef4_0cb1_eef4;

bitflags::bitflags! {
    /// The flags that reach [`KmemCache::init`].
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct CacheInitFlags: c_int {
        /// Do not allocate external slab data.
        const NOOFFSLAB = 0x1;
        /// Allocate from physical memory.
        const PHYSMEM = 0x2;
        /// Use the debugging facilities.
        const VERIFY = 0x4;
    }
}

bitflags::bitflags! {
    /// The flags a cache records.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct CacheFlags: c_int {
        /// The slab data is off the slab.
        const SLAB_EXTERNAL = 0x01;
        /// The slabs come from physical memory.
        const PHYSMEM = 0x02;
        /// The buffers map to their slab by address alone.
        const DIRECT = 0x04;
        /// Every page of a slab carries the slab in its `priv_` field (see
        /// `tag_pages`).  Bit 0x08 is reserved: `host_slab_info()`
        /// reports the flags, so the other values do not move.
        const USE_PAGE = 0x10;
        /// The cache uses the debugging facilities.
        const VERIFY = 0x20;
    }
}

/// The `KMEM_ERR_*` codes `kmem_cache_error()` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CacheError {
    /// The buffer is not one the cache handed out.
    Invalid,
    /// The buffer was freed twice.
    DoubleFree,
    /// The buffer tag is corrupt.
    Buftag,
    /// A free buffer was written after its free.
    Modified,
    /// A buffer's redzone was overwritten.
    Redzone,
}

/// The free-list link a free buffer carries, or the redzone word of a
/// verify-mode buffer.
#[repr(C)]
pub(crate) union KmemBufctl {
    pub(crate) next: *mut KmemBufctl,
    pub(crate) redzone: c_ulong,
}

const _: () = {
    assert!(size_of::<KmemBufctl>() == size_of::<*mut KmemBufctl>());
    assert!(align_of::<KmemBufctl>() == align_of::<*mut KmemBufctl>());
};

/// The allocated/free state a verify cache stamps on each buffer.
#[repr(C)]
pub(crate) struct KmemBuftag {
    pub(crate) state: c_ulong,
}

const _: () = {
    assert!(size_of::<KmemBuftag>() == 8);
    assert!(align_of::<KmemBuftag>() == 8);
    assert!(offset_of!(KmemBuftag, state) == 0);
};

/// The constructor a cache may hold.
///
/// [`KmemCache::alloc`](crate::cache::KmemCache::alloc) invokes it with a
/// fresh, otherwise-uninitialized
/// buffer of the cache's `buf_size`, on every allocation; it must build the
/// object in place and never fail.
pub type KmemCacheCtor = Option<unsafe fn(*mut c_void)>;

/// `cache_info_t`: the record `host_slab_info()` copies out for each cache.
#[repr(C)]
#[allow(missing_docs)]
pub struct CacheInfo {
    /// The `KMEM_CF_*` bits.
    pub flags: c_int,
    pub cpu_pool_size: VmSize,
    pub obj_size: VmSize,
    pub align: VmSize,
    pub buf_size: VmSize,
    pub slab_size: VmSize,
    pub bufs_per_slab: c_ulong,
    pub nr_objs: c_ulong,
    pub nr_bufs: c_ulong,
    pub nr_slabs: c_ulong,
    pub nr_free_slabs: c_ulong,
    pub name: [c_char; CACHE_NAME_MAX_LEN],
}

const _: () = {
    assert!(size_of::<CacheInfo>() == 120);
    assert!(align_of::<CacheInfo>() == 8);
    assert!(offset_of!(CacheInfo, flags) == 0);
    assert!(offset_of!(CacheInfo, cpu_pool_size) == 8);
    assert!(offset_of!(CacheInfo, obj_size) == 16);
    assert!(offset_of!(CacheInfo, align) == 24);
    assert!(offset_of!(CacheInfo, buf_size) == 32);
    assert!(offset_of!(CacheInfo, slab_size) == 40);
    assert!(offset_of!(CacheInfo, bufs_per_slab) == 48);
    assert!(offset_of!(CacheInfo, nr_objs) == 56);
    assert!(offset_of!(CacheInfo, nr_bufs) == 64);
    assert!(offset_of!(CacheInfo, nr_slabs) == 72);
    assert!(offset_of!(CacheInfo, nr_free_slabs) == 80);
    assert!(offset_of!(CacheInfo, name) == 88);
};

/// Every cache, in initialization order.
pub(crate) struct Caches<P: 'static>(pub(crate) CacheList<P>);

// SAFETY: the list links cache records, which every CPU shares.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "the linked caches are shared between CPUs, which their type \
              does not say"
)]
unsafe impl<P: 'static> Send for Caches<P> {}
