// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from kern/slab.c and kern/slab.h:
//   Copyright (c) 2011 Free Software Foundation.
//   Copyright (c) 2010, 2011 Richard Braun.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The object-caching memory allocator, which `kern/slab.c` used to define,
//! and the `struct kmem_cache` mirror of `kern/slab.h`.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::PAGE_SIZE;
use crate::arch::x86_64::phys::kvtophys;
use crate::arch::x86_64::pmap::KERNEL_VIRTUAL_END;
use crate::arch::x86_64::pmap::KERNEL_VIRTUAL_START;
use crate::kern::console::{CStrArg, kprint};
use crate::kern::debug::kpanic;
use crate::kern::lock::SimpleLock;
use crate::kern::machine;
use crate::kern::host_time;
use crate::utils::cell::SyncCell;
use crate::vm::vm_kern::KERNEL_MAP;
use crate::vm::vm_kern::{self, VM_MIN_KERNEL_ADDRESS};
use crate::vm::vm_map::VmMap;
use crate::vm::vm_map::round_page;
use crate::vm::vm_page;
use crate::vm::vm_resident::{self, VM_PAGE_DIRECTMAP};
use collections::simple_queue::{self, SimpleQueue};
use collections::tail_queue::{self, TailQueue};
use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ops;
use core::pin::{Pin, pin};
use core::ptr::{self, NonNull, addr_of_mut, with_exposed_provenance_mut};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use intrusive_collections::{Bound, RBTree, RBTreeLink, UnsafeRef};

/// `KMEM_CACHE_NAME_SIZE` of <kern/slab.h>: the length of a cache name,
/// chosen so the mirror fits in two 64-byte cache lines.
pub const KMEM_CACHE_NAME_SIZE: usize = 24;

/// `CACHE_NAME_MAX_LEN` of <`mach_debug/slab_info.h`>.
const CACHE_NAME_MAX_LEN: usize = 32;

/// `KMEM_ALIGN_MIN` of kern/slab.c: the alignment every [`kalloc`] buffer
/// has, whatever its size.
pub(crate) const KMEM_ALIGN_MIN: usize = 8;

/// `KMEM_BUF_SIZE_THRESHOLD` of kern/slab.c.
const KMEM_BUF_SIZE_THRESHOLD: usize = PAGE_SIZE / 8;

/// `KALLOC_FIRST_SHIFT` of kern/slab.c.
const KALLOC_FIRST_SHIFT: usize = 5;

/// `KALLOC_NR_CACHES` of kern/slab.c.
const KALLOC_NR_CACHES: usize = 13;

/// `KMEM_GC_INTERVAL` of kern/slab.c: the multiplier of the `hz` tick rate.
const KMEM_GC_TICKS: usize = 5;

/// `KMEM_REDZONE_BYTE` of kern/slab.c.
const KMEM_REDZONE_BYTE: u8 = 0xbb;

/// `KMEM_REDZONE_WORD` of kern/slab.c, little-endian.
const KMEM_REDZONE_WORD: c_ulong = 0xcefa_edfe_cefa_edfe;

/// `KMEM_FREE_PATTERN` of kern/slab.c, little-endian.
const KMEM_FREE_PATTERN: u64 = 0xefbe_adde_efbe_adde;

/// `KMEM_UNINIT_PATTERN` of kern/slab.c, little-endian.
const KMEM_UNINIT_PATTERN: u64 = 0xfeca_ddba_feca_ddba;

/// `KMEM_BUFTAG_ALLOC` of kern/slab.c, little-endian.
const KMEM_BUFTAG_ALLOC: c_ulong = 0xedc8_10a1_edc8_10a1;

/// `KMEM_BUFTAG_FREE` of kern/slab.c, little-endian.
const KMEM_BUFTAG_FREE: c_ulong = 0x0cb1_eef4_0cb1_eef4;

/// The `KMEM_CACHE_*` flags of <kern/slab.h> that reach
/// [`KmemCache::init`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct CacheInitFlags(c_int);

impl CacheInitFlags {
    /// `KMEM_CACHE_NOOFFSLAB`: don't allocate external slab data.
    pub const NOOFFSLAB: Self = Self(0x1);
    /// `KMEM_CACHE_PHYSMEM`: allocate from physical memory.
    pub const PHYSMEM: Self = Self(0x2);
    /// `KMEM_CACHE_VERIFY`: use the debugging facilities.
    pub const VERIFY: Self = Self(0x4);
    /// The C callers' literal `0`.
    pub const EMPTY: Self = Self(0);

    /// The C `int` the initializer was called with.
    pub(crate) const fn from_bits(bits: c_int) -> Self {
        Self(bits)
    }

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl ops::BitOr for CacheInitFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// The `KMEM_CF_*` flags of kern/slab.c, the `flags` field of a cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
struct CacheFlags(c_int);

impl CacheFlags {
    /// `KMEM_CF_SLAB_EXTERNAL`.
    const SLAB_EXTERNAL: Self = Self(0x01);
    /// `KMEM_CF_PHYSMEM`.
    const PHYSMEM: Self = Self(0x02);
    /// `KMEM_CF_DIRECT`.
    const DIRECT: Self = Self(0x04);
    /// `KMEM_CF_USE_TREE`.
    const USE_TREE: Self = Self(0x08);
    /// `KMEM_CF_USE_PAGE`.
    const USE_PAGE: Self = Self(0x10);
    /// `KMEM_CF_VERIFY`.
    const VERIFY: Self = Self(0x20);

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    const fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// The `KMEM_ERR_*` codes `kmem_cache_error()` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CacheError {
    /// `KMEM_ERR_INVALID`.
    Invalid,
    /// `KMEM_ERR_DOUBLEFREE`.
    DoubleFree,
    /// `KMEM_ERR_BUFTAG`.
    Buftag,
    /// `KMEM_ERR_MODIFIED`.
    Modified,
    /// `KMEM_ERR_REDZONE`.
    Redzone,
}

/// `union kmem_bufctl` of <kern/slab.h>: the free-list link a free buffer
/// carries, or the redzone word of a verify-mode buffer.
#[repr(C)]
#[allow(missing_docs)]
union KmemBufctl {
    next: *mut KmemBufctl,
    redzone: c_ulong,
}

const _: () = {
    assert!(size_of::<KmemBufctl>() == size_of::<*mut KmemBufctl>());
    assert!(align_of::<KmemBufctl>() == align_of::<*mut KmemBufctl>());
};

/// `struct kmem_buftag` of <kern/slab.h>: the allocated/free state a verify
/// cache stamps on each buffer.
#[repr(C)]
#[allow(missing_docs)]
struct KmemBuftag {
    state: c_ulong,
}

const _: () = {
    assert!(size_of::<KmemBuftag>() == 8);
    assert!(align_of::<KmemBuftag>() == 8);
    assert!(offset_of!(KmemBuftag, state) == 0);
};

/// `struct kmem_slab` of <kern/slab.h>: a page-aligned collection of
/// unconstructed buffers.
#[repr(C)]
#[allow(missing_docs)]
pub(crate) struct KmemSlab {
    cache: *mut KmemCache,
    list_node: tail_queue::Link,
    tree_node: RBTreeLink,
    nr_refs: c_ulong,
    first_free: *mut KmemBufctl,
    addr: *mut u8,
}

const _: () = {
    assert!(size_of::<KmemSlab>() == 72);
    assert!(align_of::<KmemSlab>() == 8);
    assert!(offset_of!(KmemSlab, cache) == 0);
    assert!(offset_of!(KmemSlab, list_node) == 8);
    assert!(offset_of!(KmemSlab, tree_node) == 24);
    assert!(offset_of!(KmemSlab, nr_refs) == 48);
    assert!(offset_of!(KmemSlab, first_free) == 56);
    assert!(offset_of!(KmemSlab, addr) == 64);
};

// The macro-emitted items stay undocumented (`NEW`, `new()`) and hand-roll
// `Clone` on a `Copy` type, so the lints are off around the expansion.
#[allow(missing_docs, clippy::expl_impl_clone_on_copy)]
mod tree_adapter {
    use super::{KmemSlab, RBTreeLink, UnsafeRef, VmOffset};
    use intrusive_collections::KeyAdapter;
    use intrusive_collections::intrusive_adapter;

    intrusive_adapter!(
        /// The adapter for a slab's `tree_node` in [`KmemCache::active_slabs`],
        /// keyed by the slab's buffer base.
        pub(crate) KmemSlabTreeAdapter = UnsafeRef<KmemSlab>: KmemSlab {
            tree_node => RBTreeLink
        }
    );

    impl<'a> KeyAdapter<'a> for KmemSlabTreeAdapter {
        type Key = VmOffset;

        fn get_key(&self, value: &'a KmemSlab) -> VmOffset {
            value.addr.addr()
        }
    }
}

use tree_adapter::KmemSlabTreeAdapter;

tail_queue::adapter!(
    /// The adapter for a slab's `list_node` in the free, partial and dead
    /// lists of its cache.
    pub(crate) KmemSlabListAdapter = KmemSlab { list_node }
);

simple_queue::adapter!(
    /// The adapter for a cache's `node` in `KMEM_CACHE_LIST`.
    pub(crate) KmemCacheListAdapter = KmemCache { node }
);

/// A list of one cache's slabs: they join at either end and leave from the
/// middle.
type SlabList = TailQueue<'static, KmemSlabListAdapter>;

/// Every cache, in initialization order; nothing ever leaves it.
type CacheList = SimpleQueue<'static, KmemCacheListAdapter>;

// The links and heads have the sizes the offsets above and below rely on.
const _: () = assert!(size_of::<RBTreeLink>() == 24);
const _: () = assert!(align_of::<RBTreeLink>() == 8);
const _: () = assert!(size_of::<tail_queue::Link>() == 16);
const _: () = assert!(size_of::<simple_queue::Link>() == 8);
const _: () = assert!(size_of::<SlabList>() == 16);
const _: () = assert!(size_of::<CacheList>() == 16);
const _: () = assert!(size_of::<RBTree<KmemSlabTreeAdapter>>() == 8);

/// The constructor a cache may hold; `kmem_cache_ctor_t` of <kern/slab.h>.
///
/// [`KmemCache::alloc`] invokes it with a fresh, otherwise-uninitialized
/// buffer of the cache's `buf_size`, on every allocation; it must build the
/// object in place and never fail.
pub type KmemCacheCtor = Option<unsafe fn(*mut c_void)>;

/// `struct kmem_cache` of <kern/slab.h>: a cache of objects.
///
/// The layout is the C record's, `__cacheline_aligned` (`1 << CPU_L1_SHIFT`,
/// 64 bytes) included; the field order is the C's, which put every hot field
/// in the first cache line.
#[repr(C, align(64))]
#[allow(missing_docs)]
pub struct KmemCache {
    lock: SimpleLock,
    node: simple_queue::Link,
    partial_slabs: SlabList,
    free_slabs: SlabList,
    active_slabs: RBTree<KmemSlabTreeAdapter>,
    flags: CacheFlags,
    bufctl_dist: usize,
    slab_size: usize,
    bufs_per_slab: c_ulong,
    nr_objs: c_ulong,
    nr_free_slabs: c_ulong,
    ctor: KmemCacheCtor,
    obj_size: usize,
    align: usize,
    buf_size: usize,
    color: usize,
    color_max: usize,
    nr_bufs: c_ulong,
    nr_slabs: c_ulong,
    name: [c_char; KMEM_CACHE_NAME_SIZE],
    buftag_dist: usize,
    redzone_pad: usize,
}

const _: () = {
    assert!(size_of::<KmemCache>() == 256);
    assert!(align_of::<KmemCache>() == 64);
    assert!(offset_of!(KmemCache, lock) == 0);
    assert!(offset_of!(KmemCache, node) == 8);
    assert!(offset_of!(KmemCache, partial_slabs) == 16);
    assert!(offset_of!(KmemCache, free_slabs) == 32);
    assert!(offset_of!(KmemCache, active_slabs) == 48);
    assert!(offset_of!(KmemCache, flags) == 56);
    assert!(offset_of!(KmemCache, bufctl_dist) == 64);
    assert!(offset_of!(KmemCache, slab_size) == 72);
    assert!(offset_of!(KmemCache, bufs_per_slab) == 80);
    assert!(offset_of!(KmemCache, nr_objs) == 88);
    assert!(offset_of!(KmemCache, nr_free_slabs) == 96);
    assert!(offset_of!(KmemCache, ctor) == 104);
    assert!(offset_of!(KmemCache, obj_size) == 112);
    assert!(offset_of!(KmemCache, align) == 120);
    assert!(offset_of!(KmemCache, buf_size) == 128);
    assert!(offset_of!(KmemCache, color) == 136);
    assert!(offset_of!(KmemCache, color_max) == 144);
    assert!(offset_of!(KmemCache, nr_bufs) == 152);
    assert!(offset_of!(KmemCache, nr_slabs) == 160);
    assert!(offset_of!(KmemCache, name) == 168);
    assert!(offset_of!(KmemCache, buftag_dist) == 192);
    assert!(offset_of!(KmemCache, redzone_pad) == 200);
};

/// `cache_info_t` of <`mach_debug/slab_info.h`>, the record `host_slab_info()`
/// copies out.
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

/// `kmem_slab_cache` of kern/slab.c: the cache for off-slab data.
static KMEM_SLAB_CACHE: SyncCell<KmemCache> =
    SyncCell(UnsafeCell::new(KmemCache::zeroed()));

/// `kalloc_caches` of kern/slab.c: the general-purpose caches, from 32 bytes
/// to 128 KiB, one doubling per entry.
static KALLOC_CACHES: SyncCell<[KmemCache; KALLOC_NR_CACHES]> = SyncCell(
    UnsafeCell::new([const { KmemCache::zeroed() }; KALLOC_NR_CACHES]),
);

/// `kmem_cache_list` of kern/slab.c: every cache, in initialization order.
static KMEM_CACHE_LIST: SyncCell<CacheList> =
    SyncCell(UnsafeCell::new(CacheList::new()));

/// `kmem_nr_caches` of kern/slab.c.
static KMEM_NR_CACHES: AtomicU32 = AtomicU32::new(0);

/// `kmem_cache_list_lock` of kern/slab.c.
static KMEM_CACHE_LIST_LOCK: SimpleLock = SimpleLock::new();

/// Whether `kalloc_init()` has built the general-purpose caches, so
/// [`kalloc`] may be called.
static KALLOC_READY: AtomicBool = AtomicBool::new(false);

/// `kmem_gc_last_tick` of kern/slab.c.
static KMEM_GC_LAST_TICK: AtomicUsize = AtomicUsize::new(0);

/// The global cache list head.
///
/// # Safety
///
/// The caller must hold `KMEM_CACHE_LIST_LOCK` for as long as it uses the
/// list.
unsafe fn cache_list() -> Pin<&'static mut CacheList> {
    // SAFETY: the static never moves, and the lock the caller holds keeps
    // anything else from reaching the list.
    unsafe { Pin::new_unchecked(&mut *KMEM_CACHE_LIST.0.get()) }
}

/// The off-slab data cache; live from `slab_init()` on.
fn slab_cache() -> *mut KmemCache {
    KMEM_SLAB_CACHE.0.get()
}

/// `P2ROUND()` of <kern/macros.h>.
const fn round_up(value: usize, align: usize) -> usize {
    value.wrapping_add(align - 1) & !(align - 1)
}

impl KmemCache {
    /// The slabs with some buffers in use and some free, pinned.
    ///
    /// # Safety
    ///
    /// The cache lives in static storage and never moves, and the caller
    /// must hold its lock for as long as it uses the list.
    const unsafe fn partial_list(&mut self) -> Pin<&mut SlabList> {
        // SAFETY: the cache never moves, and the lock the caller holds keeps
        // anything else from reaching the list.
        unsafe { Pin::new_unchecked(&mut self.partial_slabs) }
    }

    /// The slabs with no buffer in use, pinned.
    ///
    /// # Safety
    ///
    /// Same contract as [`KmemCache::partial_list()`].
    const unsafe fn free_list(&mut self) -> Pin<&mut SlabList> {
        // SAFETY: the cache never moves, and the lock the caller holds keeps
        // anything else from reaching the list.
        unsafe { Pin::new_unchecked(&mut self.free_slabs) }
    }

    /// The zero image a C `static` began with; [`KmemCache::init`] completes
    /// it.
    pub(crate) const fn zeroed() -> Self {
        Self {
            lock: SimpleLock::new(),
            node: simple_queue::Link::new(),
            partial_slabs: SlabList::new(),
            free_slabs: SlabList::new(),
            active_slabs: RBTree::new(KmemSlabTreeAdapter::new()),
            flags: CacheFlags(0),
            bufctl_dist: 0,
            slab_size: 0,
            bufs_per_slab: 0,
            nr_objs: 0,
            nr_free_slabs: 0,
            ctor: None,
            obj_size: 0,
            align: 0,
            buf_size: 0,
            color: 0,
            color_max: 0,
            nr_bufs: 0,
            nr_slabs: 0,
            name: [0; KMEM_CACHE_NAME_SIZE],
            buftag_dist: 0,
            redzone_pad: 0,
        }
    }

    /// `kmem_cache_init()` in C.
    pub(crate) fn init(
        &mut self,
        name: &[u8],
        obj_size: usize,
        align: usize,
        ctor: KmemCacheCtor,
        flags: CacheInitFlags,
    ) {
        self.flags = CacheFlags(0);

        if flags.contains(CacheInitFlags::VERIFY) {
            self.flags.insert(CacheFlags::VERIFY);
        }

        let align = align.max(KMEM_ALIGN_MIN);
        let mut buf_size = round_up(obj_size, align);

        self.lock.init();
        // The C's `list_init()` calls: empty heads.
        self.partial_slabs = SlabList::new();
        self.free_slabs = SlabList::new();
        self.active_slabs.fast_clear();
        self.obj_size = obj_size;
        self.align = align;
        self.buf_size = buf_size;
        self.bufctl_dist = buf_size - size_of::<KmemBufctl>();
        self.color = 0;
        self.nr_objs = 0;
        self.nr_bufs = 0;
        self.nr_slabs = 0;
        self.nr_free_slabs = 0;
        self.ctor = ctor;
        self.name.fill(0);
        let len = name.len().min(KMEM_CACHE_NAME_SIZE - 1);
        for (dst, byte) in self.name.iter_mut().zip(&name[..len]) {
            *dst = c_char::from_ne_bytes([*byte]);
        }
        self.buftag_dist = 0;
        self.redzone_pad = 0;

        if self.flags.contains(CacheFlags::VERIFY) {
            self.bufctl_dist = buf_size;
            self.buftag_dist = self.bufctl_dist + size_of::<KmemBufctl>();
            self.redzone_pad = self.bufctl_dist - self.obj_size;
            buf_size += size_of::<KmemBufctl>() + size_of::<KmemBuftag>();
            buf_size = round_up(buf_size, align);
            self.buf_size = buf_size;
        }

        self.compute_properties(flags);

        KMEM_CACHE_LIST_LOCK.lock();
        // SAFETY: each cache is initialized once, lives in static storage
        // for the kernel's lifetime, and the list lock serializes the
        // insertion.
        unsafe { cache_list().push_back_ptr(NonNull::from(&mut *self)) };
        // `Relaxed` is enough: the list lock orders the insertion, and the
        // count is only a size hint outside the lock.
        KMEM_NR_CACHES.fetch_add(1, Ordering::Relaxed);
        KMEM_CACHE_LIST_LOCK.unlock();
    }

    /// `kmem_cache_compute_properties()` in C.
    fn compute_properties(&mut self, flags: CacheInitFlags) {
        let flags = if self.buf_size < KMEM_BUF_SIZE_THRESHOLD {
            flags | CacheInitFlags::NOOFFSLAB
        } else {
            flags
        };

        let mut slab_size = PAGE_SIZE;
        let mut embed;

        loop {
            if flags.contains(CacheInitFlags::NOOFFSLAB) {
                embed = true;
            } else {
                let waste = slab_size % self.buf_size;
                embed = size_of::<KmemSlab>() <= waste;
            }

            let mut size = slab_size;

            if embed {
                size -= size_of::<KmemSlab>();
            }

            if size >= self.buf_size {
                self.slab_size = slab_size;
                // The C divided two `size_t`s into a `long_natural_t`; both
                // are `unsigned long` on x86_64.
                self.bufs_per_slab = (size / self.buf_size) as c_ulong;
                self.color_max = size % self.buf_size;
                break;
            }

            slab_size += PAGE_SIZE;
        }

        if self.color_max >= PAGE_SIZE {
            self.color_max = 0;
        }

        if !embed {
            self.flags.insert(CacheFlags::SLAB_EXTERNAL);
        }

        if flags.contains(CacheInitFlags::PHYSMEM)
            || self.slab_size == PAGE_SIZE
        {
            self.flags.insert(CacheFlags::PHYSMEM);

            if self.slab_size != PAGE_SIZE {
                kpanic!(
                    "kmem_cache_compute_properties",
                    "slab: invalid cache parameters"
                );
            }
        }

        if self.flags.contains(CacheFlags::VERIFY) {
            self.flags.insert(CacheFlags::USE_TREE);
        }

        if self.flags.contains(CacheFlags::SLAB_EXTERNAL) {
            if self.flags.contains(CacheFlags::PHYSMEM) {
                self.flags.insert(CacheFlags::USE_PAGE);
            } else {
                self.flags.insert(CacheFlags::USE_TREE);
            }
        } else if self.slab_size == PAGE_SIZE {
            self.flags.insert(CacheFlags::DIRECT);
        } else {
            self.flags.insert(CacheFlags::USE_TREE);
        }
    }

    /// `kmem_buf_to_bufctl()` in C.
    const fn bufctl_of(&self, buf: *mut u8) -> *mut KmemBufctl {
        // SAFETY: the bufctl of a buffer of this cache lies inside the
        // buffer's `buf_size` bytes.
        unsafe { buf.add(self.bufctl_dist).cast() }
    }

    /// `kmem_buf_to_buftag()` in C.
    const fn buftag_of(&self, buf: *mut u8) -> *mut KmemBuftag {
        // SAFETY: the buftag of a buffer of this cache lies inside the
        // buffer's `buf_size` bytes.
        unsafe { buf.add(self.buftag_dist).cast() }
    }

    /// `kmem_bufctl_to_buf()` in C.
    const fn buf_of(&self, bufctl: *mut KmemBufctl) -> NonNull<u8> {
        // SAFETY: the bufctl lies inside a buffer of this cache, so the
        // subtraction stays inside that allocation.
        unsafe {
            NonNull::new_unchecked(bufctl.cast::<u8>().sub(self.bufctl_dist))
        }
    }

    /// `kmem_cache_empty()` in C.
    const fn is_empty(&self) -> bool {
        self.nr_objs == self.nr_bufs
    }

    /// `kmem_cache_alloc()` in C.
    pub(crate) fn alloc(&mut self) -> Option<NonNull<u8>> {
        loop {
            self.lock.lock();
            let buf = self.alloc_from_slab();
            self.lock.unlock();

            let Some(buf) = buf else {
                if !self.grow() {
                    return None;
                }
                continue;
            };

            if self.flags.contains(CacheFlags::VERIFY) {
                self.alloc_verify(buf);
            }

            if let Some(ctor) = self.ctor {
                // SAFETY: the constructor contract is the C typedef's: it
                // builds the object in place and never fails.
                unsafe { ctor(buf.as_ptr().cast()) };
            }

            return Some(buf);
        }
    }

    /// `kmem_cache_alloc_from_slab()` in C; the cache lock must be held.
    fn alloc_from_slab(&mut self) -> Option<NonNull<u8>> {
        let (slab, from_free) =
            match self.partial_slabs.cursor_front().current_ptr() {
                Some(slab) => (slab, false),
                None => (self.free_slabs.cursor_front().current_ptr()?, true),
            };
        let slab_ref = slab;

        // SAFETY: the cursor named the first slab of a live list, and the
        // cache lock serializes its fields.
        let slab = unsafe { &mut *slab.as_ptr() };

        let bufctl = slab.first_free;
        // SAFETY: a listed slab has a free-buffer chain, so `first_free` is
        // a live bufctl.
        slab.first_free = unsafe { (*bufctl).next };
        slab.nr_refs += 1;
        self.nr_objs += 1;

        if slab.nr_refs == self.bufs_per_slab {
            // SAFETY: the slab is linked in the list it was taken from, and
            // the cache lock keeps it live and unmoved.
            unsafe {
                if from_free {
                    self.free_list().remove_ptr(slab_ref);
                } else {
                    self.partial_list().remove_ptr(slab_ref);
                }
            }

            if slab.nr_refs == 1 {
                self.nr_free_slabs -= 1;
            }
        } else if slab.nr_refs == 1 {
            // The slab becomes partial, and the tail insertion keeps the
            // lists consistent.
            // SAFETY: the slab is linked in `free_slabs`, and the cache
            // lock keeps it live and unmoved while the lists link it.
            unsafe {
                self.free_list().remove_ptr(slab_ref);
                self.partial_list().push_back_ptr(slab_ref);
            }
            self.nr_free_slabs -= 1;
        }

        if slab.nr_refs == 1 && self.flags.contains(CacheFlags::USE_TREE) {
            // SAFETY: `Slab::create` left the tree node unlinked and keyed
            // by this slab, and the cache lock keeps the slab live and
            // unmoved while the tree links it.
            self.active_slabs
                .insert(unsafe { UnsafeRef::from_raw(slab_ref.as_ptr()) });
        }

        Some(self.buf_of(bufctl))
    }

    /// `kmem_cache_grow()` in C.
    fn grow(&mut self) -> bool {
        self.lock.lock();

        if !self.is_empty() {
            self.lock.unlock();
            return true;
        }

        let color = self.color;
        self.color += self.align;

        if self.color > self.color_max {
            self.color = 0;
        }

        self.lock.unlock();

        let slab = KmemSlab::create(self, color);

        self.lock.lock();

        if let Some(slab) = slab {
            // SAFETY: the fresh slab is not on any list, and the cache lock
            // keeps it live and unmoved while the list links it.
            unsafe { self.free_list().push_front_ptr(slab) };
            self.nr_bufs += self.bufs_per_slab;
            self.nr_slabs += 1;
            self.nr_free_slabs += 1;
        }

        let empty = self.is_empty();

        self.lock.unlock();

        !empty
    }

    /// `kmem_cache_free()` in C.
    ///
    /// # Safety
    ///
    /// `obj` must be a live allocation from this cache that nothing uses.
    pub(crate) unsafe fn free(&mut self, obj: NonNull<u8>) {
        if self.flags.contains(CacheFlags::VERIFY) {
            unsafe { self.free_verify(obj) };
        }

        self.lock.lock();
        unsafe { self.free_to_slab(obj) };
        self.lock.unlock();
    }

    /// `kmem_cache_free_to_slab()` in C; the cache lock must be held.
    ///
    /// # Safety
    ///
    /// `buf` must be a live allocation from this cache.
    unsafe fn free_to_slab(&mut self, buf: NonNull<u8>) {
        let slab = if self.flags.contains(CacheFlags::DIRECT) {
            // SAFETY: a direct-mapped slab sits at the end of the page range
            // containing the buffer.
            unsafe { slab_from_direct(buf, self.slab_size) }
        } else if self.flags.contains(CacheFlags::USE_PAGE) {
            let page = vm_page::lookup_pa(kvtophys(buf.as_ptr().addr()));
            let Some(page) = page else {
                self.error(buf.as_ptr(), CacheError::Invalid, ptr::null_mut());
            };
            // SAFETY: the page is live and this cache owns its private
            // field.
            unsafe { (*page.as_ptr()).priv_ }.cast::<KmemSlab>()
        } else {
            let slab = self
                .active_slabs
                .upper_bound(Bound::Included(&buf.as_ptr().addr()))
                .get_ptr();
            let Some(slab) = slab else {
                self.error(buf.as_ptr(), CacheError::Invalid, ptr::null_mut());
            };
            slab.as_ptr()
        };

        // SAFETY: the slab and the bufctl are live, and the cache lock
        // serializes them.
        unsafe {
            let bufctl = self.bufctl_of(buf.as_ptr());
            (*bufctl).next = (*slab).first_free;
            (*slab).first_free = bufctl;
            (*slab).nr_refs -= 1;
        }
        self.nr_objs -= 1;

        // SAFETY: the slab fields and links are this cache's, and the lock
        // serializes them.
        unsafe {
            if (*slab).nr_refs == 0 {
                if self.flags.contains(CacheFlags::USE_TREE) {
                    // SAFETY: the slab is linked in this tree, and the
                    // cache lock keeps it live for the cursor.
                    self.active_slabs
                        .cursor_mut_from_ptr(slab.cast_const())
                        .remove();
                }

                if self.bufs_per_slab > 1 {
                    // SAFETY: with more than one buffer per slab, the last
                    // free leaves the slab in `partial_slabs`, and the
                    // cache lock keeps it live.
                    self.partial_list()
                        .remove_ptr(NonNull::new_unchecked(slab));
                }

                // SAFETY: the slab is unlinked from every list and the
                // cache lock keeps it live and unmoved while the list links
                // it.
                self.free_list()
                    .push_front_ptr(NonNull::new_unchecked(slab));
                self.nr_free_slabs += 1;
            } else if (*slab).nr_refs == self.bufs_per_slab - 1 {
                // SAFETY: the first free of a full slab, which is off every
                // list, and the cache lock keeps the slab live and unmoved
                // while the list links it.
                self.partial_list()
                    .push_front_ptr(NonNull::new_unchecked(slab));
            }
        }
    }

    /// `kmem_cache_reap()` in C.
    fn reap(&mut self, dead_slabs: Pin<&mut SlabList>) {
        self.lock.lock();

        // The nodes of `free_slabs` move to `dead_slabs` at its tail, as the
        // C's `list_concat()` did.
        // SAFETY: the cache lock is held.
        dead_slabs.append(unsafe { self.free_list() });

        self.nr_bufs -= self.bufs_per_slab * self.nr_free_slabs;
        self.nr_slabs -= self.nr_free_slabs;
        self.nr_free_slabs = 0;

        self.lock.unlock();
    }

    /// `kmem_cache_alloc_verify()` in C.
    ///
    /// The C's `construct` argument was `KMEM_AV_NOCONSTRUCT` at its only
    /// call site, so [`KmemCache::alloc`] calls the constructor itself.
    fn alloc_verify(&mut self, buf: NonNull<u8>) {
        let buftag = self.buftag_of(buf.as_ptr());

        // SAFETY: the buffer is live and holds its buftag.
        if unsafe { (*buftag).state } != KMEM_BUFTAG_FREE {
            self.error(buf.as_ptr(), CacheError::Buftag, buftag.cast());
        }

        // SAFETY: the buffer spans `bufctl_dist` readable and writable
        // bytes.
        let modified = unsafe {
            verify_fill(
                buf.as_ptr(),
                KMEM_FREE_PATTERN,
                KMEM_UNINIT_PATTERN,
                self.bufctl_dist,
            )
        };

        if let Some(addr) = modified {
            self.error(
                buf.as_ptr(),
                CacheError::Modified,
                addr.as_ptr().cast(),
            );
        }

        // SAFETY: `obj_size` plus `redzone_pad` is `bufctl_dist`, so the
        // write stays inside the buffer.
        unsafe {
            ptr::write_bytes(
                buf.as_ptr().add(self.obj_size),
                KMEM_REDZONE_BYTE,
                self.redzone_pad,
            );
        }

        let bufctl = self.bufctl_of(buf.as_ptr());
        // SAFETY: the buffer is live, so its bufctl and buftag are too.
        unsafe {
            (*bufctl).redzone = KMEM_REDZONE_WORD;
            (*buftag).state = KMEM_BUFTAG_ALLOC;
        }
    }

    /// `kmem_cache_free_verify()` in C.
    ///
    /// # Safety
    ///
    /// `buf` must be a live allocation from this verify cache.
    unsafe fn free_verify(&mut self, buf: NonNull<u8>) {
        self.lock.lock();
        let found = self
            .active_slabs
            .upper_bound(Bound::Included(&buf.as_ptr().addr()))
            .get_ptr();
        self.lock.unlock();

        let Some(found) = found else {
            self.error(buf.as_ptr(), CacheError::Invalid, ptr::null_mut());
        };

        // SAFETY: the cursor named an active slab of this cache.
        let slab = unsafe { &*found.as_ptr() };
        let slabend =
            slab.addr.addr().wrapping_add(self.slab_size) & !(PAGE_SIZE - 1);

        if buf.as_ptr().addr() >= slabend {
            self.error(buf.as_ptr(), CacheError::Invalid, ptr::null_mut());
        }

        let offset = buf.as_ptr().addr() - slab.addr.addr();

        if !offset.is_multiple_of(self.buf_size) {
            self.error(buf.as_ptr(), CacheError::Invalid, ptr::null_mut());
        }

        let buftag = self.buftag_of(buf.as_ptr());
        // SAFETY: the buffer is valid, so its buftag is too.
        let state = unsafe { (*buftag).state };

        if state != KMEM_BUFTAG_ALLOC {
            if state == KMEM_BUFTAG_FREE {
                self.error(
                    buf.as_ptr(),
                    CacheError::DoubleFree,
                    ptr::null_mut(),
                );
            }

            self.error(buf.as_ptr(), CacheError::Buftag, buftag.cast());
        }

        let bufctl = self.bufctl_of(buf.as_ptr());
        // SAFETY: `obj_size` is inside the buffer.
        let mut redzone_byte = unsafe { buf.as_ptr().add(self.obj_size) };

        while redzone_byte.cast::<KmemBufctl>() < bufctl {
            // SAFETY: the range between the object and its bufctl is inside
            // the buffer.
            if unsafe { *redzone_byte } != KMEM_REDZONE_BYTE {
                self.error(
                    buf.as_ptr(),
                    CacheError::Redzone,
                    redzone_byte.cast(),
                );
            }
            redzone_byte = unsafe { redzone_byte.add(1) };
        }

        // SAFETY: the bufctl is live.
        let redzone = unsafe { (*bufctl).redzone };

        if redzone != KMEM_REDZONE_WORD {
            let word = KMEM_REDZONE_WORD;
            // SAFETY: `redzone` is live and `word` has its size.
            if let Some(addr) = unsafe {
                verify_bytes(
                    ptr::from_ref(&redzone).cast(),
                    &word.to_ne_bytes(),
                )
            } {
                self.error(
                    buf.as_ptr(),
                    CacheError::Redzone,
                    addr.as_ptr().cast(),
                );
            }
        }

        // SAFETY: the buffer's bytes are live and writable.
        unsafe { fill(buf.as_ptr(), KMEM_FREE_PATTERN, self.bufctl_dist) };
        // SAFETY: the buftag is the buffer's.
        unsafe { (*buftag).state = KMEM_BUFTAG_FREE };
    }

    /// `kmem_cache_error()` in C: report and halt.
    fn error(&self, buf: *mut u8, error: CacheError, arg: *mut c_void) -> ! {
        // SAFETY: the name is NUL-terminated by `init()`.
        let name = unsafe { CStrArg::from_ptr(self.name.as_ptr()) };
        kprint!(
            "mem: warning: kmem_cache_error(): cache: {}, buffer: {:x}\n",
            name,
            buf.expose_provenance(),
        );

        // The C's `%td` reads a ptrdiff_t; the offset is inside one buffer,
        // far below `isize::MAX`.
        let offset = arg.addr().wrapping_sub(buf.addr());

        match error {
            CacheError::Invalid => kpanic!(
                "kmem_cache_error",
                "mem: error: kmem_cache_error(): freeing invalid address\n"
            ),
            CacheError::DoubleFree => kpanic!(
                "kmem_cache_error",
                "mem: error: kmem_cache_error(): attempting to free the same address twice\n"
            ),
            CacheError::Buftag => kpanic!(
                "kmem_cache_error",
                "mem: error: kmem_cache_error(): invalid buftag content, buftag state: {:x}\n",
                arg.expose_provenance()
            ),
            CacheError::Modified => kpanic!(
                "kmem_cache_error",
                "mem: error: kmem_cache_error(): free buffer modified, fault address: {:x}, offset in buffer: {}\n",
                arg.expose_provenance(),
                offset as isize
            ),
            CacheError::Redzone => kpanic!(
                "kmem_cache_error",
                "mem: error: kmem_cache_error(): write beyond end of buffer, fault address: {:x}, offset in buffer: {}\n",
                arg.expose_provenance(),
                offset as isize
            ),
        }
    }

    /// The per-cache copy `host_slab_info()` makes.
    fn fill_info(&self, info: &mut CacheInfo) {
        self.lock.lock();
        info.flags = self.flags.0;
        info.cpu_pool_size = 0;
        info.obj_size = self.obj_size;
        info.align = self.align;
        info.buf_size = self.buf_size;
        info.slab_size = self.slab_size;
        info.bufs_per_slab = self.bufs_per_slab;
        info.nr_objs = self.nr_objs;
        info.nr_bufs = self.nr_bufs;
        info.nr_slabs = self.nr_slabs;
        info.nr_free_slabs = self.nr_free_slabs;
        info.name.fill(0);
        let len = self
            .name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(KMEM_CACHE_NAME_SIZE);
        for (dst, src) in info.name.iter_mut().zip(&self.name[..len]) {
            *dst = *src;
        }
        self.lock.unlock();
    }
}

impl KmemSlab {
    /// `kmem_slab_create()` in C; the caller holds no cache lock.
    fn create(cache: &mut KmemCache, color: usize) -> Option<NonNull<Self>> {
        let slab_buf = pagealloc(cache.slab_size, cache.align, cache.flags)?;

        let slab = if cache.flags.contains(CacheFlags::SLAB_EXTERNAL) {
            // SAFETY: the slab cache was initialized before any cache could
            // grow.
            let external = unsafe { (*slab_cache()).alloc() };
            let Some(external) = external else {
                // SAFETY: the buffer is a live page allocation of this
                // cache.
                unsafe {
                    pagefree(
                        slab_buf.as_ptr().addr(),
                        cache.slab_size,
                        cache.flags,
                    );
                };
                return None;
            };

            if cache.flags.contains(CacheFlags::USE_PAGE) {
                let page =
                    vm_page::lookup_pa(kvtophys(slab_buf.as_ptr().addr()));
                let Some(page) = page else {
                    kpanic!(
                        "kmem_slab_create",
                        "kmem_slab_create: missing page"
                    )
                };
                // SAFETY: the page is live and this cache owns its private
                // field.
                unsafe { (*page.as_ptr()).priv_ = external.as_ptr().cast() };
            }

            external.cast::<Self>()
        } else {
            // SAFETY: the slab trailer fits the buffer, as
            // `compute_properties()` established.
            unsafe {
                NonNull::new_unchecked(with_exposed_provenance_mut(
                    slab_buf.as_ptr().addr() + cache.slab_size
                        - size_of::<Self>(),
                ))
            }
        };

        // SAFETY: the slab storage is fresh, so its fields are initialized
        // here before anything links it.
        unsafe {
            (*slab.as_ptr()).cache = cache;
            ptr::write(
                addr_of_mut!((*slab.as_ptr()).list_node),
                tail_queue::Link::new(),
            );
            ptr::write(
                addr_of_mut!((*slab.as_ptr()).tree_node),
                RBTreeLink::new(),
            );
            (*slab.as_ptr()).nr_refs = 0;
            (*slab.as_ptr()).first_free = ptr::null_mut();
            (*slab.as_ptr()).addr = slab_buf.as_ptr().add(color);
        }

        // SAFETY: `addr` is the buffer base the C used.
        let mut bufctl = cache.bufctl_of(unsafe { (*slab.as_ptr()).addr });

        for _ in 0..cache.bufs_per_slab {
            // SAFETY: each bufctl is inside the buffer, and the chain links
            // every buffer of the slab.
            unsafe {
                (*bufctl).next = (*slab.as_ptr()).first_free;
                (*slab.as_ptr()).first_free = bufctl;
                bufctl = bufctl.cast::<u8>().add(cache.buf_size).cast();
            }
        }

        if cache.flags.contains(CacheFlags::VERIFY) {
            // SAFETY: the slab is fresh and complete.
            unsafe { Self::create_verify(slab, cache) };
        }

        Some(slab)
    }

    /// `kmem_slab_create_verify()` in C.
    ///
    /// # Safety
    ///
    /// `slab` must be a fresh slab of `cache`.
    unsafe fn create_verify(slab: NonNull<Self>, cache: &KmemCache) {
        let buf_size = cache.buf_size;
        let mut buf = unsafe { (*slab.as_ptr()).addr };
        let mut buftag = cache.buftag_of(buf);

        for _ in 0..cache.bufs_per_slab {
            // SAFETY: `buf` is inside the slab, and `bufctl_dist` bytes are
            // writable from it.
            unsafe {
                fill(buf, KMEM_FREE_PATTERN, cache.bufctl_dist);
                (*buftag).state = KMEM_BUFTAG_FREE;
                buf = buf.add(buf_size);
            }
            buftag = cache.buftag_of(buf);
        }
    }

    /// `kmem_slab_destroy()` in C; the caller holds no cache lock.
    ///
    /// # Safety
    ///
    /// `slab` must be off every list, with nothing holding it.
    unsafe fn destroy(slab: NonNull<Self>, cache: &mut KmemCache) {
        if cache.flags.contains(CacheFlags::VERIFY) {
            unsafe { Self::destroy_verify(slab, cache) };
        }

        let slab_buf =
            unsafe { (*slab.as_ptr()).addr.addr() } & !(PAGE_SIZE - 1);

        if cache.flags.contains(CacheFlags::SLAB_EXTERNAL) {
            if cache.flags.contains(CacheFlags::USE_PAGE)
                && let Some(page) = vm_page::lookup_pa(kvtophys(slab_buf))
            {
                // SAFETY: the page is live, and the C cleared the field.
                unsafe { (*page.as_ptr()).priv_ = ptr::null_mut() };
            }

            // SAFETY: the slab came from the off-slab cache.
            unsafe {
                (*slab_cache())
                    .free(NonNull::new_unchecked(slab.as_ptr().cast::<u8>()));
            };
        }

        // SAFETY: the slab's buffer is the one `pagealloc()` returned.
        unsafe { pagefree(slab_buf, cache.slab_size, cache.flags) };
    }

    /// `kmem_slab_destroy_verify()` in C.
    ///
    /// # Safety
    ///
    /// `slab` must be a dead slab of `cache` whose buffers are all free.
    unsafe fn destroy_verify(slab: NonNull<Self>, cache: &KmemCache) {
        let buf_size = cache.buf_size;
        let mut buf = unsafe { (*slab.as_ptr()).addr };
        let mut buftag = cache.buftag_of(buf);

        for _ in 0..cache.bufs_per_slab {
            unsafe {
                if (*buftag).state != KMEM_BUFTAG_FREE {
                    cache.error(buf, CacheError::Buftag, buftag.cast());
                }

                if let Some(addr) =
                    verify(buf, KMEM_FREE_PATTERN, cache.bufctl_dist)
                {
                    cache.error(
                        buf,
                        CacheError::Modified,
                        addr.as_ptr().cast(),
                    );
                }

                buf = buf.add(buf_size);
            }
            buftag = cache.buftag_of(buf);
        }
    }
}

/// The slab at the end of the `slab_size` block holding `buf`, the C's
/// `P2END(buf, slab_size) - 1` for a direct-mapped cache.
///
/// # Safety
///
/// `buf` must come from a direct-mapped slab of `slab_size` bytes.
unsafe fn slab_from_direct(
    buf: NonNull<u8>,
    slab_size: usize,
) -> *mut KmemSlab {
    let end = buf.as_ptr().addr() & !(slab_size - 1);
    // The caller promises the slab trailer is at the block's end.
    with_exposed_provenance_mut(end + slab_size - size_of::<KmemSlab>())
}

/// `kmem_buf_verify_bytes()` in C.
///
/// # Safety
///
/// `buf` must hold `pattern.len()` readable bytes.
unsafe fn verify_bytes(buf: *const u8, pattern: &[u8]) -> Option<NonNull<u8>> {
    for (i, byte) in pattern.iter().enumerate() {
        if unsafe { *buf.add(i) } != *byte {
            // SAFETY: the mismatch byte is inside the range.
            return Some(unsafe {
                NonNull::new_unchecked(buf.add(i).cast_mut())
            });
        }
    }

    None
}

/// `kmem_buf_verify()` in C.
///
/// # Safety
///
/// `buf` must hold `size` readable bytes.
unsafe fn verify(
    buf: *const u8,
    pattern: u64,
    size: usize,
) -> Option<NonNull<u8>> {
    let end = buf.wrapping_add(size);
    let mut ptr = buf.cast::<u64>();

    while ptr.cast::<u8>() < end {
        if unsafe { ptr.read() } != pattern {
            return unsafe {
                verify_bytes(ptr.cast(), &pattern.to_ne_bytes())
            };
        }
        ptr = unsafe { ptr.add(1) };
    }

    None
}

/// `kmem_buf_fill()` in C.
///
/// # Safety
///
/// `buf` must hold `size` writable bytes.
unsafe fn fill(buf: *mut u8, pattern: u64, size: usize) {
    let end = buf.wrapping_add(size);
    let mut ptr = buf.cast::<u64>();

    while ptr.cast::<u8>() < end {
        unsafe { ptr.write(pattern) };
        ptr = unsafe { ptr.add(1) };
    }
}

/// `kmem_buf_verify_fill()` in C.
///
/// # Safety
///
/// `buf` must hold `size` readable and writable bytes.
unsafe fn verify_fill(
    buf: *mut u8,
    old: u64,
    new: u64,
    size: usize,
) -> Option<NonNull<u8>> {
    let end = buf.wrapping_add(size);
    let mut ptr = buf.cast::<u64>();

    while ptr.cast::<u8>() < end {
        if unsafe { ptr.read() } != old {
            return unsafe { verify_bytes(ptr.cast(), &old.to_ne_bytes()) };
        }
        unsafe { ptr.write(new) };
        ptr = unsafe { ptr.add(1) };
    }

    None
}

/// `kmem_pagealloc_physmem()` in C: a direct-mapped page, blocking until one
/// is free.
fn pagealloc_physmem(_size: VmSize) -> NonNull<u8> {
    loop {
        // SAFETY: no cache lock is held, so the allocation may block on the
        // page queues.
        let page = unsafe { vm_resident::grab(VM_PAGE_DIRECTMAP) };

        if let Some(page) = page {
            // SAFETY: the page is live and direct-mapped.
            let addr = unsafe { (*page.as_ptr()).phys_addr };
            // SAFETY: the mapped address is non-null.
            return unsafe {
                NonNull::new_unchecked(with_exposed_provenance_mut(
                    VM_MIN_KERNEL_ADDRESS.wrapping_add(addr),
                ))
            };
        }

        // SAFETY: the continuation is the C's `NULL`.
        unsafe { vm_page::wait(None) };
    }
}

/// `kmem_pagealloc_virtual()` in C.
fn pagealloc_virtual(size: VmSize, align: VmSize) -> Option<NonNull<u8>> {
    let size = round_page(size);
    // SAFETY: `kernel_map` is the live kernel map.
    let map = unsafe { NonNull::new_unchecked(KERNEL_MAP.cast::<VmMap>()) };

    let addr = if align <= PAGE_SIZE {
        vm_kern::kmem_alloc_wired(map, size).ok()?
    } else {
        vm_kern::kmem_alloc_aligned(map, size).ok()?
    };

    // SAFETY: a successful allocation is a non-null kernel address.
    Some(unsafe { NonNull::new_unchecked(with_exposed_provenance_mut(addr)) })
}

/// `kmem_pagefree_physmem()` in C.
///
/// # Safety
///
/// `addr` must be a page [`pagealloc_physmem`] returned.
unsafe fn pagefree_physmem(addr: VmOffset, _size: VmSize) {
    // The caller promises the page was allocated here, so the lookup finds
    // it.
    let page = vm_page::lookup_pa(kvtophys(addr));
    let Some(page) = page else {
        kpanic!(
            "kmem_pagefree_physmem",
            "kmem_pagefree_physmem: missing page"
        )
    };

    // SAFETY: the page is live, and the release takes the page-queues lock
    // itself.
    unsafe { vm_resident::release(page, false, false) };
}

/// `kmem_pagefree_virtual()` in C.
///
/// # Safety
///
/// `addr..addr + size` must be a region [`pagealloc_virtual`] returned.
unsafe fn pagefree_virtual(addr: VmOffset, size: VmSize) {
    // SAFETY: the boot globals are live for the kernel's lifetime.
    let start = unsafe { KERNEL_VIRTUAL_START };
    let end = unsafe { KERNEL_VIRTUAL_END };

    if addr < start || addr.wrapping_add(size) > end {
        kpanic!(
            "kmem_pagefree_virtual",
            "kmem_pagefree_virtual({:x}-{:x}) falls in physical memory area!\n",
            addr,
            addr.wrapping_add(size)
        );
    }

    let size = round_page(size);
    // SAFETY: `kernel_map` is the live kernel map.
    let map = unsafe { &mut *KERNEL_MAP.cast::<VmMap>() };

    if vm_kern::kmem_free(map, addr, size).is_err() {
        kpanic!("kmem_free", "kmem_free");
    }
}

/// `kmem_pagealloc()` in C.
fn pagealloc(
    size: VmSize,
    align: VmSize,
    flags: CacheFlags,
) -> Option<NonNull<u8>> {
    if flags.contains(CacheFlags::PHYSMEM) {
        Some(pagealloc_physmem(size))
    } else {
        pagealloc_virtual(size, align)
    }
}

/// `kmem_pagefree()` in C.
///
/// # Safety
///
/// `addr` must be a region the matching [`pagealloc`] returned.
unsafe fn pagefree(addr: VmOffset, size: VmSize, flags: CacheFlags) {
    if flags.contains(CacheFlags::PHYSMEM) {
        unsafe { pagefree_physmem(addr, size) };
    } else {
        unsafe { pagefree_virtual(addr, size) };
    }
}

/// `kalloc_get_index()` in C; the caller passes a size greater than zero.
const fn kalloc_index(size: usize) -> usize {
    let size = (size - 1) >> KALLOC_FIRST_SHIFT;

    if size == 0 {
        0
    } else {
        // Both operands are `u32`s and `usize` is at least as wide.
        (usize::BITS - size.leading_zeros()) as usize
    }
}

/// The `index`th general-purpose cache.
fn kalloc_cache(index: usize) -> *mut KmemCache {
    // SAFETY: the array is a static that never moves.
    let caches: *mut KmemCache = KALLOC_CACHES.0.get().cast();
    // SAFETY: every caller bounds-checks `index` against `KALLOC_NR_CACHES`.
    unsafe { caches.add(index) }
}

/// `kalloc_verify()` in C.
///
/// # Safety
///
/// `buf` must hold `cache.obj_size` writable bytes.
const unsafe fn kalloc_verify(
    cache: &KmemCache,
    buf: NonNull<u8>,
    size: usize,
) {
    let redzone = buf.as_ptr().wrapping_add(size);
    let redzone_size = cache.obj_size - size;
    unsafe { ptr::write_bytes(redzone, KMEM_REDZONE_BYTE, redzone_size) };
}

/// `kfree_verify()` in C.
///
/// # Safety
///
/// `buf` must hold `cache.obj_size` readable bytes previously filled with
/// [`KMEM_REDZONE_BYTE`] past `size`.
unsafe fn kfree_verify(cache: &KmemCache, buf: NonNull<u8>, size: usize) {
    let mut redzone_byte = buf.as_ptr().wrapping_add(size);
    let redzone_end = buf.as_ptr().wrapping_add(cache.obj_size);

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

/// `kalloc()` in C.
pub(crate) fn kalloc(size: usize) -> Option<NonNull<u8>> {
    if size == 0 {
        return None;
    }

    let index = kalloc_index(size);

    if index < KALLOC_NR_CACHES {
        let cache = kalloc_cache(index);
        // SAFETY: `kalloc_init()` built every cache before any allocation,
        // and the cache lock serializes the operation.
        let buf = unsafe { (*cache).alloc() }?;

        // SAFETY: the cache is initialized and its lock is free here.
        if unsafe { (*cache).flags.contains(CacheFlags::VERIFY) } {
            // SAFETY: the buffer is a live allocation of the cache's object
            // size.
            unsafe { kalloc_verify(&*cache, buf, size) };
        }

        Some(buf)
    } else if size <= PAGE_SIZE {
        Some(pagealloc_physmem(PAGE_SIZE))
    } else {
        pagealloc_virtual(size, 0)
    }
}

/// `kfree()` in C.
///
/// # Safety
///
/// `data` must be a live allocation of `size` bytes from [`kalloc`] that
/// nothing uses.
pub(crate) unsafe fn kfree(data: NonNull<u8>, size: usize) {
    if size == 0 {
        return;
    }

    let index = kalloc_index(size);

    if index < KALLOC_NR_CACHES {
        let cache = kalloc_cache(index);

        // SAFETY: the cache is initialized and its lock is free here.
        if unsafe { (*cache).flags.contains(CacheFlags::VERIFY) } {
            unsafe { kfree_verify(&*cache, data, size) };
        }

        unsafe { (*cache).free(data) };
    } else if size <= PAGE_SIZE {
        // SAFETY: the allocator returned a direct-mapped page for it.
        unsafe { pagefree_physmem(data.as_ptr().addr(), PAGE_SIZE) };
    } else {
        unsafe { pagefree_virtual(data.as_ptr().addr(), size) };
    }
}

/// `kmem_cache_init()` in C.
///
/// # Safety
///
/// `cache` must point at writable storage for a [`KmemCache`] that no other
/// thread can see yet, and `name` at a NUL-terminated string.
pub(crate) unsafe fn kmem_cache_init(
    cache: *mut KmemCache,
    name: *const c_char,
    obj_size: usize,
    align: usize,
    ctor: KmemCacheCtor,
    flags: c_int,
) {
    let Some(cache) = NonNull::new(cache) else {
        return;
    };
    let Some(name) = NonNull::new(name.cast_mut()) else {
        return;
    };

    let name = unsafe { CStr::from_ptr(name.as_ptr()) };

    unsafe {
        (*cache.as_ptr()).init(
            name.to_bytes(),
            obj_size,
            align,
            ctor,
            CacheInitFlags::from_bits(flags),
        );
    };
}

/// `kmem_cache_alloc()` in C.
///
/// # Safety
///
/// `cache` must point at a live cache that [`kmem_cache_init`] built.
pub(crate) unsafe fn kmem_cache_alloc(cache: *mut KmemCache) -> VmOffset {
    let Some(cache) = NonNull::new(cache) else {
        return 0;
    };

    let buf = unsafe { (*cache.as_ptr()).alloc() };

    buf.map_or(0, |buf| buf.as_ptr().addr())
}

/// `kmem_cache_free()` in C.
///
/// # Safety
///
/// `cache` must point at a live cache, and `obj` be a live allocation from
/// it that nothing uses.
pub(crate) unsafe fn kmem_cache_free(cache: *mut KmemCache, obj: VmOffset) {
    let Some(cache) = NonNull::new(cache) else {
        return;
    };
    let Some(obj) = NonNull::new(with_exposed_provenance_mut::<u8>(obj))
    else {
        return;
    };

    unsafe { (*cache.as_ptr()).free(obj) };
}

/// `slab_bootstrap()` in C.
pub(crate) fn slab_bootstrap() {
    KMEM_CACHE_LIST_LOCK.init();
}

/// `slab_init()` in C.
pub(crate) fn slab_init() {
    // SAFETY: `slab_bootstrap()` ran, and this is the off-slab cache's only
    // initializer.
    unsafe {
        (*slab_cache()).init(
            b"kmem_slab",
            size_of::<KmemSlab>(),
            0,
            None,
            CacheInitFlags::NOOFFSLAB,
        );
    };
}

/// `kalloc_init()` in C.
pub(crate) fn kalloc_init() {
    let mut size = 1 << KALLOC_FIRST_SHIFT;

    for index in 0..KALLOC_NR_CACHES {
        let name = kalloc_name(size);
        let cache = kalloc_cache(index);

        // SAFETY: `slab_init()` ran, and each cache is initialized once, in
        // order.
        unsafe {
            (*cache).init(&name, size, 0, None, CacheInitFlags::EMPTY);
        }
        size <<= 1;
    }

    // Publish the initialized caches to `kalloc_ready()`'s `Acquire` load.
    KALLOC_READY.store(true, Ordering::Release);
}

/// Whether [`kalloc`] may be called: `kalloc_init()` has run.
pub(crate) fn kalloc_ready() -> bool {
    KALLOC_READY.load(Ordering::Acquire)
}

/// The `sprintf(name, "kalloc_%lu", size)` of `kalloc_init()`, in place.
fn kalloc_name(mut value: usize) -> [u8; KMEM_CACHE_NAME_SIZE] {
    const PREFIX: &[u8] = b"kalloc_";

    let mut name = [0u8; KMEM_CACHE_NAME_SIZE];
    name[..PREFIX.len()].copy_from_slice(PREFIX);

    let mut digits = [0u8; KMEM_CACHE_NAME_SIZE];
    let mut len = 0;

    loop {
        digits[len] = b'0' + u8::try_from(value % 10).unwrap_or(0);
        value /= 10;
        len += 1;
        if value == 0 {
            break;
        }
    }

    for i in 0..len {
        name[PREFIX.len() + i] = digits[len - 1 - i];
    }

    name
}

/// `slab_collect()` in C.
pub(crate) fn slab_collect() {
    // SAFETY: `elapsed_ticks` is the live clock global, an `unsigned long`
    // the C kept in the target's `usize`.
    let now = host_time::elapsed_ticks();
    // The C read `hz` for `KMEM_GC_INTERVAL`, an `int` that is positive
    // after the probe sets it.
    let interval =
        usize::try_from(machine::CLOCK_HZ).unwrap_or(0) * KMEM_GC_TICKS;

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

    let mut dead_slabs = pin!(SlabList::new());

    KMEM_CACHE_LIST_LOCK.lock();
    for_each_cache(|cache| cache.reap(dead_slabs.as_mut()));
    KMEM_CACHE_LIST_LOCK.unlock();

    while let Some(slab) =
        dead_slabs.as_mut().cursor_front_mut().remove_current()
    {
        // SAFETY: the slab is off every list and nothing holds it.
        unsafe {
            let slab = NonNull::from(slab);
            KmemSlab::destroy(slab, &mut *(*slab.as_ptr()).cache);
        }
    }
}

/// The number of caches on the global list, the C's unsynchronized read of
/// `kmem_nr_caches`.
pub(crate) fn nr_caches() -> u32 {
    KMEM_NR_CACHES.load(Ordering::Relaxed)
}

/// The `host_slab_info()` snapshot: fill `out` with every cache.
///
/// Returns [`None`] when the cache count changed under the caller, who
/// retries with a fresh allocation, as the C's `retry` label did.
pub(crate) fn collect(expected: u32, out: &mut [CacheInfo]) -> Option<u32> {
    if out.len() < expected as usize {
        return None;
    }

    KMEM_CACHE_LIST_LOCK.lock();

    if KMEM_NR_CACHES.load(Ordering::Relaxed) != expected {
        KMEM_CACHE_LIST_LOCK.unlock();
        return None;
    }

    let mut count = 0usize;

    for_each_cache(|cache| {
        let Some(info) = out.get_mut(count) else {
            return;
        };
        cache.fill_info(info);
        count += 1;
    });

    KMEM_CACHE_LIST_LOCK.unlock();

    // `count` never exceeds the list's length, `expected`, which is a `u32`.
    Some(count as u32)
}

/// Run `f` on every cache of the global list.
///
/// The caller must hold `KMEM_CACHE_LIST_LOCK`; no callback may remove a
/// cache from the list.
fn for_each_cache(mut f: impl FnMut(&mut KmemCache)) {
    // SAFETY: the caller holds the list lock, so the head is a valid list
    // for the walk.
    let head = unsafe { cache_list() };

    let mut cursor = head.cursor_front();
    while let Some(cache) = cursor.current_ptr() {
        cursor.move_next();
        // SAFETY: `KmemCache::init()` linked this cache, which is static
        // storage for the kernel's lifetime; the walk mutates nothing.
        f(unsafe { &mut *cache.as_ptr() });
    }
}
