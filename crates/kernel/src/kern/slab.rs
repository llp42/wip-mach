// SPDX-License-Identifier: GPL-2.0-or-later
// Derived from kern/slab.c and kern/slab.h:
//   Copyright (c) 2011 Free Software Foundation.
//   Copyright (c) 2010, 2011 Richard Braun.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The object-caching memory allocator and its cache record.

use crate::arch::types::{VmOffset, VmSize};
use crate::arch::vm_param::PAGE_SIZE;
use crate::arch::x86_64::phys::kvtophys;
use crate::arch::x86_64::platform::MachPlatform;
use crate::arch::x86_64::pmap::KERNEL_VIRTUAL_END;
use crate::arch::x86_64::pmap::KERNEL_VIRTUAL_START;
use crate::kern::console::{CStrArg, kprint};
use crate::kern::debug::kpanic;
use crate::kern::host_time;
use crate::kern::lock::SimpleLock;
use crate::kern::machine;
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
use lock::SpinLock;

/// The length of a cache name, chosen so the mirror fits in two 64-byte cache
/// lines.
pub const KMEM_CACHE_NAME_SIZE: usize = 24;

/// The length of a cache name in the slab report.
const CACHE_NAME_MAX_LEN: usize = 32;

/// The alignment every [`kalloc`] buffer has, whatever its size.
pub(crate) const KMEM_ALIGN_MIN: usize = 8;

/// The buffer size below which a cache keeps its slab data on the slab.
const KMEM_BUF_SIZE_THRESHOLD: usize = PAGE_SIZE / 8;

/// The shift of the smallest [`kalloc`] cache: 32 bytes.
const KALLOC_FIRST_SHIFT: usize = 5;

/// The number of [`kalloc`] caches.
const KALLOC_NR_CACHES: usize = 13;

/// How many seconds of ticks pass between two garbage collections.
const KMEM_GC_TICKS: usize = 5;

/// The byte a verify cache fills redzones with.
const KMEM_REDZONE_BYTE: u8 = 0xbb;

/// The word a verify cache stamps in a buffer's redzone, little-endian.
const KMEM_REDZONE_WORD: c_ulong = 0xcefa_edfe_cefa_edfe;

/// The pattern a verify cache fills free buffers with, little-endian.
const KMEM_FREE_PATTERN: u64 = 0xefbe_adde_efbe_adde;

/// The pattern a verify cache fills unconstructed buffers with, little-endian.
const KMEM_UNINIT_PATTERN: u64 = 0xfeca_ddba_feca_ddba;

/// The buffer tag of an allocated buffer, little-endian.
const KMEM_BUFTAG_ALLOC: c_ulong = 0xedc8_10a1_edc8_10a1;

/// The buffer tag of a free buffer, little-endian.
const KMEM_BUFTAG_FREE: c_ulong = 0x0cb1_eef4_0cb1_eef4;

/// The flags that reach [`KmemCache::init`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct CacheInitFlags(c_int);

impl CacheInitFlags {
    /// Do not allocate external slab data.
    pub const NOOFFSLAB: Self = Self(0x1);
    /// Allocate from physical memory.
    pub const PHYSMEM: Self = Self(0x2);
    /// Use the debugging facilities.
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

/// The flags a cache records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
struct CacheFlags(c_int);

impl CacheFlags {
    /// The slab data is off the slab.
    const SLAB_EXTERNAL: Self = Self(0x01);
    /// The slabs come from physical memory.
    const PHYSMEM: Self = Self(0x02);
    /// The buffers map to their slab by address alone.
    const DIRECT: Self = Self(0x04);
    /// Every page of a slab carries the slab in its `priv_` field (see
    /// [`tag_pages`]).  Bit 0x08 is reserved: `host_slab_info()` reports the
    /// flags, so the other values do not move.
    const USE_PAGE: Self = Self(0x10);
    /// The cache uses the debugging facilities.
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
#[allow(missing_docs)]
union KmemBufctl {
    next: *mut KmemBufctl,
    redzone: c_ulong,
}

const _: () = {
    assert!(size_of::<KmemBufctl>() == size_of::<*mut KmemBufctl>());
    assert!(align_of::<KmemBufctl>() == align_of::<*mut KmemBufctl>());
};

/// The allocated/free state a verify cache stamps on each buffer.
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

/// A page-aligned collection of unconstructed buffers.
#[repr(C)]
#[allow(missing_docs)]
pub(crate) struct KmemSlab {
    cache: *mut KmemCache,
    list_node: tail_queue::Link,
    nr_refs: c_ulong,
    first_free: *mut KmemBufctl,
    addr: *mut u8,
}

const _: () = {
    assert!(size_of::<KmemSlab>() == 48);
    assert!(align_of::<KmemSlab>() == 8);
    assert!(offset_of!(KmemSlab, cache) == 0);
    assert!(offset_of!(KmemSlab, list_node) == 8);
    assert!(offset_of!(KmemSlab, nr_refs) == 24);
    assert!(offset_of!(KmemSlab, first_free) == 32);
    assert!(offset_of!(KmemSlab, addr) == 40);
};

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
const _: () = assert!(size_of::<tail_queue::Link>() == 16);
const _: () = assert!(size_of::<simple_queue::Link>() == 8);
const _: () = assert!(size_of::<SlabList>() == 16);
const _: () = assert!(size_of::<CacheList>() == 16);

/// The constructor a cache may hold.
///
/// [`KmemCache::alloc`] invokes it with a fresh, otherwise-uninitialized
/// buffer of the cache's `buf_size`, on every allocation; it must build the
/// object in place and never fail.
pub type KmemCacheCtor = Option<unsafe fn(*mut c_void)>;

/// A cache of objects.
///
/// The record is cache-line aligned, at 64 bytes.
#[repr(C, align(64))]
#[allow(missing_docs)]
pub struct KmemCache {
    lock: SimpleLock,
    node: simple_queue::Link,
    partial_slabs: SlabList,
    free_slabs: SlabList,
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
    assert!(offset_of!(KmemCache, flags) == 48);
    assert!(offset_of!(KmemCache, bufctl_dist) == 56);
    assert!(offset_of!(KmemCache, slab_size) == 64);
    assert!(offset_of!(KmemCache, bufs_per_slab) == 72);
    assert!(offset_of!(KmemCache, nr_objs) == 80);
    assert!(offset_of!(KmemCache, nr_free_slabs) == 88);
    assert!(offset_of!(KmemCache, ctor) == 96);
    assert!(offset_of!(KmemCache, obj_size) == 104);
    assert!(offset_of!(KmemCache, align) == 112);
    assert!(offset_of!(KmemCache, buf_size) == 120);
    assert!(offset_of!(KmemCache, color) == 128);
    assert!(offset_of!(KmemCache, color_max) == 136);
    assert!(offset_of!(KmemCache, nr_bufs) == 144);
    assert!(offset_of!(KmemCache, nr_slabs) == 152);
    assert!(offset_of!(KmemCache, name) == 160);
    assert!(offset_of!(KmemCache, buftag_dist) == 184);
    assert!(offset_of!(KmemCache, redzone_pad) == 192);
};

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

/// The cache for off-slab data.
static KMEM_SLAB_CACHE: SyncCell<KmemCache> =
    SyncCell(UnsafeCell::new(KmemCache::zeroed()));

/// The general-purpose caches, from 32 bytes to 128 KiB, one doubling per
/// entry.
static KALLOC_CACHES: SyncCell<[KmemCache; KALLOC_NR_CACHES]> = SyncCell(
    UnsafeCell::new([const { KmemCache::zeroed() }; KALLOC_NR_CACHES]),
);

/// Every cache, in initialization order.
struct Caches(CacheList);

// SAFETY: the list links cache records, which every CPU shares.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "the linked caches are shared between CPUs, which their type \
              does not say"
)]
unsafe impl Send for Caches {}

/// Every cache, in initialization order.
static KMEM_CACHE_LIST: SpinLock<Caches, MachPlatform> =
    SpinLock::new(Caches(CacheList::new()));

/// How many caches [`KMEM_CACHE_LIST`] holds.
static KMEM_NR_CACHES: AtomicU32 = AtomicU32::new(0);

/// Whether `kalloc_init()` has built the general-purpose caches, so
/// [`kalloc`] may be called.
static KALLOC_READY: AtomicBool = AtomicBool::new(false);

/// The tick of the last garbage collection.
static KMEM_GC_LAST_TICK: AtomicUsize = AtomicUsize::new(0);

/// The off-slab data cache; live from `slab_init()` on.
fn slab_cache() -> *mut KmemCache {
    KMEM_SLAB_CACHE.0.get()
}

/// Rounds `value` up to a multiple of the power of two `align`.
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

    /// Initializes the cache for objects of `obj_size` bytes aligned to
    /// `align`, built by `ctor`.
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
        // Empty slab lists.
        self.partial_slabs = SlabList::new();
        self.free_slabs = SlabList::new();
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

        let mut caches = KMEM_CACHE_LIST.lock();
        // SAFETY: the list is in `KMEM_CACHE_LIST`, a static, which never
        // moves; each cache is initialized once and lives in static storage
        // for the kernel's lifetime.
        unsafe {
            Pin::new_unchecked(&mut caches.0)
                .push_back_ptr(NonNull::from(&mut *self));
        }
        // `Relaxed` is enough: the list lock orders the insertion, and the
        // count is only a size hint outside the lock.
        KMEM_NR_CACHES.fetch_add(1, Ordering::Relaxed);
        drop(caches);
    }

    /// Chooses the cache's slab size, buffer layout and slab-data placement.
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

        // An embedded one-page slab is found by address arithmetic.  Every
        // other slab is found through its pages; a verify cache always
        // is, since it must reject an address that is in no slab.
        if !self.flags.contains(CacheFlags::SLAB_EXTERNAL)
            && self.slab_size == PAGE_SIZE
            && !self.flags.contains(CacheFlags::VERIFY)
        {
            self.flags.insert(CacheFlags::DIRECT);
        } else {
            self.flags.insert(CacheFlags::USE_PAGE);
        }
    }

    /// The free-list link of the buffer `buf`.
    const fn bufctl_of(&self, buf: *mut u8) -> *mut KmemBufctl {
        // SAFETY: the bufctl of a buffer of this cache lies inside the
        // buffer's `buf_size` bytes.
        unsafe { buf.add(self.bufctl_dist).cast() }
    }

    /// The buffer tag of the buffer `buf`.
    const fn buftag_of(&self, buf: *mut u8) -> *mut KmemBuftag {
        // SAFETY: the buftag of a buffer of this cache lies inside the
        // buffer's `buf_size` bytes.
        unsafe { buf.add(self.buftag_dist).cast() }
    }

    /// The buffer a free-list link belongs to.
    const fn buf_of(&self, bufctl: *mut KmemBufctl) -> NonNull<u8> {
        // SAFETY: the bufctl lies inside a buffer of this cache, so the
        // subtraction stays inside that allocation.
        unsafe {
            NonNull::new_unchecked(bufctl.cast::<u8>().sub(self.bufctl_dist))
        }
    }

    /// Whether the cache has no free buffer left.
    const fn is_empty(&self) -> bool {
        self.nr_objs == self.nr_bufs
    }

    /// Allocates a buffer from the cache, growing it when it is empty, and
    /// constructs it.
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

    /// Takes a buffer off the cache's first partial or free slab; the cache
    /// lock must be held.
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

        Some(self.buf_of(bufctl))
    }

    /// Adds a slab to the cache, returning whether it could.
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

    /// Returns the buffer `obj` to the cache.
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

    /// The slab holding the page of `addr`, read from the tag [`tag_pages`]
    /// left on it.
    ///
    /// The tag is what lets an address anywhere in a slab, not only a buffer
    /// start, find it.
    ///
    /// # Panics
    ///
    /// Halts through [`KmemCache::error`] as an invalid address when the page
    /// has no descriptor, no tag, or a tag from another cache.
    fn slab_of(&self, addr: *mut u8) -> NonNull<KmemSlab> {
        let slab =
            vm_page::lookup_pa(kvtophys(addr.addr())).and_then(|page| {
                // SAFETY: the page is live, and the tag is null or a live slab:
                // `tag_pages()` and `untag_pages()` are the only writers of
                // `priv_` outside the page allocator, which clears it.
                NonNull::new(
                    unsafe { (*page.as_ptr()).priv_ }.cast::<KmemSlab>(),
                )
            });

        // SAFETY: a tag names a slab that is live until `destroy()` clears
        // it, and `cache` never changes after `create()`.
        match slab {
            Some(slab) if ptr::eq(unsafe { (*slab.as_ptr()).cache }, self) => {
                slab
            }
            _ => self.error(addr, CacheError::Invalid, ptr::null_mut()),
        }
    }

    /// Returns the buffer `buf` to its slab; the cache lock must be held.
    ///
    /// # Safety
    ///
    /// `buf` must be a live allocation from this cache.
    unsafe fn free_to_slab(&mut self, buf: NonNull<u8>) {
        let slab = if self.flags.contains(CacheFlags::DIRECT) {
            // SAFETY: a direct-mapped slab sits at the end of the page range
            // containing the buffer.
            unsafe { slab_from_direct(buf, self.slab_size) }
        } else {
            self.slab_of(buf.as_ptr()).as_ptr()
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

    /// Moves the cache's free slabs to `dead_slabs`, for the caller to
    /// destroy.
    fn reap(&mut self, dead_slabs: Pin<&mut SlabList>) {
        self.lock.lock();

        // The free slabs move to the tail of `dead_slabs`.
        // SAFETY: the cache lock is held.
        dead_slabs.append(unsafe { self.free_list() });

        self.nr_bufs -= self.bufs_per_slab * self.nr_free_slabs;
        self.nr_slabs -= self.nr_free_slabs;
        self.nr_free_slabs = 0;

        self.lock.unlock();
    }

    /// Checks a buffer the cache is handing out, and stamps it allocated.
    ///
    /// [`KmemCache::alloc`] calls the constructor itself, so this check does
    /// not.
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

    /// Checks a buffer coming back to the cache, and stamps it free.
    ///
    /// # Safety
    ///
    /// `buf` must be a live allocation from this verify cache.
    unsafe fn free_verify(&mut self, buf: NonNull<u8>) {
        // The tag stays put while `buf` is a live buffer, so no lock is
        // needed; an address that is in no slab of this cache is rejected.
        let found = self.slab_of(buf.as_ptr());

        // SAFETY: `slab_of()` named a slab of this cache.
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

    /// Reports a buffer error and halts the kernel.
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
    /// Allocates and lays out a new slab for `cache`, at the `color` offset;
    /// the caller holds no cache lock.
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

        if cache.flags.contains(CacheFlags::USE_PAGE) {
            // SAFETY: the pages are the live allocation `pagealloc()` made,
            // and nothing else tags them.
            unsafe {
                tag_pages(
                    slab_buf.as_ptr().addr(),
                    cache.slab_size,
                    slab.as_ptr(),
                );
            };
        }

        Some(slab)
    }

    /// Fills the buffers of a new verify-mode slab with the free pattern and
    /// stamps them free.
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

    /// Frees a slab of `cache`; the caller holds no cache lock.
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

        if cache.flags.contains(CacheFlags::USE_PAGE) {
            // SAFETY: the pages are still mapped, so they can be named, and
            // `pagefree()` below has not released them yet.
            unsafe { untag_pages(slab_buf, cache.slab_size) };
        }

        if cache.flags.contains(CacheFlags::SLAB_EXTERNAL) {
            // SAFETY: the slab came from the off-slab cache.
            unsafe {
                (*slab_cache())
                    .free(NonNull::new_unchecked(slab.as_ptr().cast::<u8>()));
            };
        }

        // SAFETY: the slab's buffer is the one `pagealloc()` returned.
        unsafe { pagefree(slab_buf, cache.slab_size, cache.flags) };
    }

    /// Checks that every buffer of a verify-mode slab is free and untouched
    /// before the slab is freed.
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

/// Point the `priv_` field of every page of the slab buffer at `base` to
/// `slab`.
///
/// Every page is tagged, not only the first, so an address anywhere in the
/// slab finds it.  The slab's address lives in the page descriptor in place
/// of a search structure, the buffer-to-slab method of FreeBSD's UMA
/// allocator and of x15.
///
/// # Panics
///
/// Halts when a page of the range has no descriptor, or is already tagged:
/// a stale tag means an earlier slab was not untagged.
///
/// # Safety
///
/// `base..base + size` must be a mapped, page-aligned range of slab pages
/// that no other slab owns, and `slab` must be the slab that owns them.
unsafe fn tag_pages(base: VmOffset, size: VmSize, slab: *mut KmemSlab) {
    for addr in (base..base + size).step_by(PAGE_SIZE) {
        let page = page_of(addr);

        // SAFETY: the page is live, and the caller says this slab owns its
        // private field.
        unsafe {
            if !(*page.as_ptr()).priv_.is_null() {
                kpanic!("kmem_tag_pages", "slab: page already tagged");
            }

            (*page.as_ptr()).priv_ = slab.cast();
        }
    }
}

/// Clear the tag [`tag_pages`] left on every page of the slab buffer at
/// `base`.
///
/// # Panics
///
/// Halts when a page of the range has no descriptor.
///
/// # Safety
///
/// `base..base + size` must be the mapped range [`tag_pages`] tagged, and
/// the slab must be off every list with nothing holding it.
unsafe fn untag_pages(base: VmOffset, size: VmSize) {
    for addr in (base..base + size).step_by(PAGE_SIZE) {
        let page = page_of(addr);

        // SAFETY: the page is live, and the caller says its tag is this
        // slab's.
        unsafe { (*page.as_ptr()).priv_ = ptr::null_mut() };
    }
}

/// The descriptor of the page mapped at `addr`.
///
/// # Panics
///
/// Halts when `addr` names no page.
fn page_of(addr: VmOffset) -> NonNull<vm_page::VmPage> {
    let Some(page) = vm_page::lookup_pa(kvtophys(addr)) else {
        kpanic!("kmem_tag_pages", "slab: missing page");
    };

    page
}

/// The slab at the end of the `slab_size` block holding `buf`, for a
/// direct-mapped cache.
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

/// The first byte of `buf` that differs from `pattern`, or `None`.
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

/// The first word of the `size` bytes at `buf` that differs from `pattern`, or
/// `None`.
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

/// Fills the `size` bytes at `buf` with `pattern`.
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

/// Checks that the `size` bytes at `buf` hold `old` and refills them with
/// `new`, returning the first word that differs, or `None`.
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

/// A direct-mapped page, blocking until one is free.
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

        // SAFETY: the wait takes no continuation, so it returns here.
        unsafe { vm_page::wait(None) };
    }
}

/// Allocates `size` bytes of wired kernel virtual memory aligned to `align`.
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

/// Frees a direct-mapped page.
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

/// Frees `size` bytes of kernel virtual memory.
///
/// # Safety
///
/// `addr..addr + size` must be a region [`pagealloc_virtual`] returned.
unsafe fn pagefree_virtual(addr: VmOffset, size: VmSize) {
    let start = KERNEL_VIRTUAL_START.load(Ordering::Relaxed);
    let end = KERNEL_VIRTUAL_END.load(Ordering::Relaxed);

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

/// Allocates a slab's memory, from physical or virtual memory as the cache's
/// flags say.
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

/// Frees a slab's memory, to physical or virtual memory as the cache's flags
/// say.
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

/// The index of the [`kalloc`] cache for `size` bytes; the caller passes a
/// size greater than zero.
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

/// Fills the slack past the requested `size` of a buffer [`kalloc`] hands out
/// with the redzone byte.
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

/// Checks the redzone past `size` of a buffer [`kfree`] gets back.
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

/// Allocates `size` bytes from the general-purpose caches, or from the kernel
/// map past the largest one.
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

/// Frees `size` bytes [`kalloc`] allocated.
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

/// [`KmemCache::init`] over raw pointers.
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

/// [`KmemCache::alloc`] over a raw pointer: the buffer address, or 0.
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

/// [`KmemCache::free`] over a raw pointer and address.
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

/// Initializes the cache of off-slab data.
pub(crate) fn slab_init() {
    // SAFETY: this is the off-slab cache's only initializer.
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

/// Initializes the general-purpose caches.
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

/// The name of the [`kalloc`] cache for `value` bytes, `kalloc_<value>`.
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

/// Returns the free slabs of every cache to the system, at most once per
/// collection interval.
pub(crate) fn slab_collect() {
    // SAFETY: `elapsed_ticks` is the live clock global, an `unsigned long`
    // the C kept in the target's `usize`.
    let now = host_time::elapsed_ticks();
    // The tick rate is positive once the clock is probed.
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

    for_each_cache(&KMEM_CACHE_LIST.lock().0, |cache| {
        cache.reap(dead_slabs.as_mut());
    });

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

/// The number of caches on the global list, read without synchronization.
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

    let caches = KMEM_CACHE_LIST.lock();

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
fn for_each_cache(caches: &CacheList, mut f: impl FnMut(&mut KmemCache)) {
    let mut cursor = caches.cursor_front();
    while let Some(cache) = cursor.current_ptr() {
        cursor.move_next();
        // SAFETY: `KmemCache::init()` linked this cache, which is static
        // storage for the kernel's lifetime; the walk mutates nothing.
        f(unsafe { &mut *cache.as_ptr() });
    }
}
