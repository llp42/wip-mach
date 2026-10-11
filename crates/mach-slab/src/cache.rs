// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! `KmemCache`: a cache of objects of one size, carved from slabs.

use crate::platform::Platform;
use crate::slab::{KmemSlab, SlabList, slab_from_direct};
use crate::state::KMEM_NR_CACHES;
use crate::types::{
    CacheError, CacheFlags, CacheInfo, CacheInitFlags, KMEM_ALIGN_MIN,
    KMEM_BUF_SIZE_THRESHOLD, KMEM_BUFTAG_ALLOC, KMEM_BUFTAG_FREE,
    KMEM_CACHE_NAME_SIZE, KMEM_FREE_PATTERN, KMEM_REDZONE_BYTE,
    KMEM_REDZONE_WORD, KMEM_UNINIT_PATTERN, KmemBufctl, KmemBuftag,
    KmemCacheCtor,
};
use crate::verify::{fill, verify_bytes, verify_fill};
use collections::simple_queue::{self, SimpleQueue};
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_ulong, c_void};
use core::marker::PhantomData;
use core::mem::{align_of, offset_of, size_of};
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::sync::atomic::Ordering;
use mach_page::param::PAGE_SIZE;
use mach_page::simple_lock::SimpleLock;

/// A cache of objects.
///
/// The record is cache-line aligned, at 64 bytes. Its own lock guards the
/// lists and counts and is dropped before a new slab's memory is allocated or
/// freed, so those may wait; the configuration [`KmemCache::init`] fixes is
/// read freely once the cache is built.
#[repr(C, align(64))]
pub struct KmemCache<P: 'static> {
    /// Serializes the body's lists and counts.
    lock: SimpleLock,
    /// The link that joins the cache list, written once by [`Self::init`].
    node: UnsafeCell<simple_queue::Link>,
    /// The rest of the cache.
    body: UnsafeCell<CacheBody<P>>,
}

/// A cache's body: what [`KmemCache::init`] fixes at startup and what the
/// cache lock serializes.
#[repr(C)]
struct CacheBody<P: 'static> {
    /// The slabs with some buffers in use and some free.
    partial_slabs: SlabList<P>,
    /// The slabs with no buffer in use.
    free_slabs: SlabList<P>,
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
    platform: PhantomData<P>,
}

// SAFETY: a cache is shared by every CPU that allocates from it. Its own
// lock serializes the lists and counts, `init` runs before any of that and
// writes nothing afterwards, and the buffers it hands out are raw memory
// with no thread binding.
unsafe impl<P: Platform> Sync for KmemCache<P> {}

const _: () = {
    assert!(align_of::<KmemCache<()>>() == 64);
    assert!(offset_of!(KmemCache<()>, lock) == 0);
    assert!(offset_of!(KmemCache<()>, node) == 8);
    assert!(offset_of!(KmemCache<()>, body) == 16);
    assert!(offset_of!(CacheBody<()>, partial_slabs) == 0);
    assert!(offset_of!(CacheBody<()>, free_slabs) == 16);
    assert!(offset_of!(CacheBody<()>, flags) == 32);
    assert!(offset_of!(CacheBody<()>, obj_size) == 88);
    assert!(offset_of!(CacheBody<()>, name) == 144);
};

/// The adapter for a cache's `node` in the global cache list.
pub(crate) struct KmemCacheListAdapter<P: 'static>(PhantomData<P>);

// SAFETY: `node` is one field at a fixed offset of every cache, and each
// direction steps by that offset alone.
unsafe impl<P: 'static> simple_queue::Adapter for KmemCacheListAdapter<P> {
    type Node = KmemCache<P>;

    unsafe fn link(node: NonNull<Self::Node>) -> NonNull<simple_queue::Link> {
        // SAFETY: `node` is inside the cache it names, and the caller keeps
        // the cache live.
        unsafe { node.cast::<u8>().add(offset_of!(KmemCache<P>, node)).cast() }
    }

    unsafe fn node(link: NonNull<simple_queue::Link>) -> NonNull<Self::Node> {
        // SAFETY: `link` is the node field of a live cache, so stepping back
        // by its offset lands on the cache.
        unsafe { link.cast::<u8>().sub(offset_of!(KmemCache<P>, node)).cast() }
    }
}

/// The buffer and slab layout a cache's `init` fixed, copied out so that the
/// code running outside the cache lock can read it.
#[derive(Clone, Copy)]
pub(crate) struct CacheLayout {
    pub(crate) flags: CacheFlags,
    pub(crate) slab_size: usize,
    pub(crate) align: usize,
    pub(crate) buf_size: usize,
    pub(crate) bufctl_dist: usize,
    pub(crate) buftag_dist: usize,
    pub(crate) obj_size: usize,
    pub(crate) redzone_pad: usize,
    pub(crate) bufs_per_slab: c_ulong,
}

/// Every cache, in initialization order; nothing ever leaves it.
pub(crate) type CacheList<P> = SimpleQueue<'static, KmemCacheListAdapter<P>>;

const _: () = assert!(size_of::<simple_queue::Link>() == 8);
const _: () = assert!(size_of::<CacheList<()>>() == 16);

/// Rounds `value` up to a multiple of the power of two `align`.
const fn round_up(value: usize, align: usize) -> usize {
    value.wrapping_add(align - 1) & !(align - 1)
}

impl<P: Platform> KmemCache<P> {
    /// The body, which the cache lock serializes.
    ///
    /// # Safety
    ///
    /// The caller must hold `self.lock`, or be [`KmemCache::init`] before the
    /// cache is shared, and no other reference to the body may be live for as
    /// long as this one is.
    #[allow(
        clippy::mut_from_ref,
        reason = "the body is the cache's own storage; the caller keeps the                   accesses exclusive"
    )]
    unsafe fn body(&self) -> &mut CacheBody<P> {
        // SAFETY: the body is the cache's own storage, and the caller keeps
        // the accesses exclusive.
        unsafe { &mut *self.body.get() }
    }

    /// The buffer and slab layout [`KmemCache::init`] fixed. Nothing writes
    /// these fields after the cache is built, so the copy is safe to take at
    /// any point, and it is what code outside the cache lock reads.
    pub(crate) fn layout(&self) -> CacheLayout {
        // SAFETY: `init` wrote each of these before the cache was shared and
        // nothing writes them after; a read of one field takes only that
        // field, so it does not reach the lists the lock serializes.
        unsafe {
            let body = self.body.get();
            CacheLayout {
                flags: (*body).flags,
                slab_size: (*body).slab_size,
                align: (*body).align,
                buf_size: (*body).buf_size,
                bufctl_dist: (*body).bufctl_dist,
                buftag_dist: (*body).buftag_dist,
                obj_size: (*body).obj_size,
                redzone_pad: (*body).redzone_pad,
                bufs_per_slab: (*body).bufs_per_slab,
            }
        }
    }

    /// The slabs with some buffers in use and some free, pinned.
    ///
    /// # Safety
    ///
    /// The cache lives in static storage and never moves, and `this` must be
    /// the only way anyone reaches the body for as long as the list is used.
    const unsafe fn partial_list(
        this: &mut CacheBody<P>,
    ) -> Pin<&mut SlabList<P>> {
        // SAFETY: the cache never moves, and the borrow of the body keeps
        // anything else from reaching the list.
        unsafe { Pin::new_unchecked(&mut this.partial_slabs) }
    }

    /// The slabs with no buffer in use, pinned.
    ///
    /// # Safety
    ///
    /// Same contract as [`KmemCache::partial_list()`].
    const unsafe fn free_list(
        this: &mut CacheBody<P>,
    ) -> Pin<&mut SlabList<P>> {
        // SAFETY: the cache never moves, and the borrow of the body keeps
        // anything else from reaching the list.
        unsafe { Pin::new_unchecked(&mut this.free_slabs) }
    }

    /// The zero image a C `static` began with; [`KmemCache::init`] completes
    /// it.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            lock: SimpleLock::new(),
            node: UnsafeCell::new(simple_queue::Link::new()),
            body: UnsafeCell::new(CacheBody {
                partial_slabs: SlabList::new(),
                free_slabs: SlabList::new(),
                flags: CacheFlags::empty(),
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
                platform: PhantomData,
            }),
        }
    }

    /// Initializes the cache for objects of `obj_size` bytes aligned to
    /// `align`, built by `ctor`.
    pub fn init(
        &self,
        name: &[u8],
        obj_size: usize,
        align: usize,
        ctor: KmemCacheCtor,
        flags: CacheInitFlags,
    ) {
        // SAFETY: `init` runs once, at startup, before the cache is shared.
        let this = unsafe { self.body() };

        this.flags = CacheFlags::empty();

        if flags.contains(CacheInitFlags::VERIFY) {
            this.flags.insert(CacheFlags::VERIFY);
        }

        let align = align.max(KMEM_ALIGN_MIN);
        let mut buf_size = round_up(obj_size, align);

        self.lock.init();
        // Empty slab lists.
        this.partial_slabs = SlabList::new();
        this.free_slabs = SlabList::new();
        this.obj_size = obj_size;
        this.align = align;
        this.buf_size = buf_size;
        this.bufctl_dist = buf_size - size_of::<KmemBufctl>();
        this.color = 0;
        this.nr_objs = 0;
        this.nr_bufs = 0;
        this.nr_slabs = 0;
        this.nr_free_slabs = 0;
        this.ctor = ctor;
        this.name.fill(0);
        let len = name.len().min(KMEM_CACHE_NAME_SIZE - 1);
        for (dst, byte) in this.name.iter_mut().zip(&name[..len]) {
            *dst = c_char::from_ne_bytes([*byte]);
        }
        this.buftag_dist = 0;
        this.redzone_pad = 0;

        if this.flags.contains(CacheFlags::VERIFY) {
            this.bufctl_dist = buf_size;
            this.buftag_dist = this.bufctl_dist + size_of::<KmemBufctl>();
            this.redzone_pad = this.bufctl_dist - this.obj_size;
            buf_size += size_of::<KmemBufctl>() + size_of::<KmemBuftag>();
            buf_size = round_up(buf_size, align);
            this.buf_size = buf_size;
        }

        Self::compute_properties(this, flags);

        let mut caches = P::slab_state().cache_list.lock();
        // SAFETY: the list is in the slab state, a static, which never
        // moves; each cache is initialized once and lives in static storage
        // for the kernel's lifetime, and the queue only writes the cache's
        // `node`.
        unsafe {
            Pin::new_unchecked(&mut caches.0)
                .push_back_ptr(NonNull::from(self));
        }
        // `Relaxed` is enough: the list lock orders the insertion, and the
        // count is only a size hint outside the lock.
        KMEM_NR_CACHES.fetch_add(1, Ordering::Relaxed);
        drop(caches);
    }

    /// Chooses the cache's slab size, buffer layout and slab-data placement.
    fn compute_properties(this: &mut CacheBody<P>, flags: CacheInitFlags) {
        let flags = if this.buf_size < KMEM_BUF_SIZE_THRESHOLD {
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
                let waste = slab_size % this.buf_size;
                embed = size_of::<KmemSlab<P>>() <= waste;
            }

            let mut size = slab_size;

            if embed {
                size -= size_of::<KmemSlab<P>>();
            }

            if size >= this.buf_size {
                this.slab_size = slab_size;
                // The C divided two `size_t`s into a `long_natural_t`; both
                // are `unsigned long` on x86_64.
                this.bufs_per_slab = (size / this.buf_size) as c_ulong;
                this.color_max = size % this.buf_size;
                break;
            }

            slab_size += PAGE_SIZE;
        }

        if this.color_max >= PAGE_SIZE {
            this.color_max = 0;
        }

        if !embed {
            this.flags.insert(CacheFlags::SLAB_EXTERNAL);
        }

        if flags.contains(CacheInitFlags::PHYSMEM)
            || this.slab_size == PAGE_SIZE
        {
            this.flags.insert(CacheFlags::PHYSMEM);

            assert!(
                this.slab_size == PAGE_SIZE,
                "kmem_cache_compute_properties: slab: invalid cache parameters"
            );
        }

        // An embedded one-page slab is found by address arithmetic.  Every
        // other slab is found through its pages; a verify cache always
        // is, since it must reject an address that is in no slab.
        if !this.flags.contains(CacheFlags::SLAB_EXTERNAL)
            && this.slab_size == PAGE_SIZE
            && !this.flags.contains(CacheFlags::VERIFY)
        {
            this.flags.insert(CacheFlags::DIRECT);
        } else {
            this.flags.insert(CacheFlags::USE_PAGE);
        }
    }

    /// The free-list link of the buffer `buf`.
    pub(crate) fn bufctl_of(&self, buf: *mut u8) -> *mut KmemBufctl {
        // SAFETY: the bufctl of a buffer of this cache lies inside the
        // buffer's `buf_size` bytes.
        unsafe { buf.add(self.layout().bufctl_dist).cast() }
    }

    /// The buffer tag of the buffer `buf`.
    pub(crate) fn buftag_of(&self, buf: *mut u8) -> *mut KmemBuftag {
        // SAFETY: the buftag of a buffer of this cache lies inside the
        // buffer's `buf_size` bytes.
        unsafe { buf.add(self.layout().buftag_dist).cast() }
    }

    /// The buffer a free-list link belongs to.
    pub(crate) fn buf_of(&self, bufctl: *mut KmemBufctl) -> NonNull<u8> {
        // SAFETY: the bufctl lies inside a buffer of this cache, so the
        // subtraction stays inside that allocation.
        unsafe {
            NonNull::new_unchecked(
                bufctl.cast::<u8>().sub(self.layout().bufctl_dist),
            )
        }
    }

    /// Allocates a buffer from the cache, growing it when it is empty, and
    /// constructs it.
    pub fn alloc(&self) -> Option<NonNull<u8>> {
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

            let layout = self.layout();
            if layout.flags.contains(CacheFlags::VERIFY) {
                self.alloc_verify(buf, &layout);
            }

            // SAFETY: `init` wrote the constructor before the cache was
            // shared and nothing writes it after; the read takes that field
            // alone.
            if let Some(ctor) = unsafe { (*self.body.get()).ctor } {
                // SAFETY: the constructor contract is the C typedef's: it
                // builds the object in place and never fails.
                unsafe { ctor(buf.as_ptr().cast()) };
            }

            return Some(buf);
        }
    }

    /// Takes a buffer off the cache's first partial or free slab; the cache
    /// lock must be held.
    fn alloc_from_slab(&self) -> Option<NonNull<u8>> {
        // SAFETY: the caller holds the cache lock.
        let this = unsafe { self.body() };

        let (slab, from_free) =
            match this.partial_slabs.cursor_front().current_ptr() {
                Some(slab) => (slab, false),
                None => (this.free_slabs.cursor_front().current_ptr()?, true),
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
        this.nr_objs += 1;

        if slab.nr_refs == this.bufs_per_slab {
            // SAFETY: the slab is linked in the list it was taken from, and
            // the cache lock keeps it live and unmoved.
            unsafe {
                if from_free {
                    Self::free_list(this).remove_ptr(slab_ref);
                } else {
                    Self::partial_list(this).remove_ptr(slab_ref);
                }
            }

            if slab.nr_refs == 1 {
                this.nr_free_slabs -= 1;
            }
        } else if slab.nr_refs == 1 {
            // The slab becomes partial, and the tail insertion keeps the
            // lists consistent.
            // SAFETY: the slab is linked in `free_slabs`, and the cache
            // lock keeps it live and unmoved while the lists link it.
            unsafe {
                Self::free_list(this).remove_ptr(slab_ref);
                Self::partial_list(this).push_back_ptr(slab_ref);
            }
            this.nr_free_slabs -= 1;
        }

        Some(self.buf_of(bufctl))
    }

    /// Adds a slab to the cache, returning whether it could.
    fn grow(&self) -> bool {
        let layout = self.layout();

        self.lock.lock();

        let color = {
            // SAFETY: the lock above is held.
            let this = unsafe { self.body() };

            if this.nr_objs != this.nr_bufs {
                self.lock.unlock();
                return true;
            }

            let color = this.color;
            this.color += layout.align;

            if this.color > this.color_max {
                this.color = 0;
            }
            color
        };

        self.lock.unlock();

        let slab = KmemSlab::<P>::create(self, &layout, color);

        self.lock.lock();

        // SAFETY: the lock above is held.
        let this = unsafe { self.body() };

        if let Some(slab) = slab {
            // SAFETY: the fresh slab is not on any list, and the cache lock
            // keeps it live and unmoved while the list links it.
            unsafe { Self::free_list(this).push_front_ptr(slab) };
            this.nr_bufs += layout.bufs_per_slab;
            this.nr_slabs += 1;
            this.nr_free_slabs += 1;
        }

        let empty = this.nr_objs == this.nr_bufs;

        self.lock.unlock();

        !empty
    }

    /// Returns the buffer `obj` to the cache.
    ///
    /// # Safety
    ///
    /// `obj` must be a live allocation from this cache that nothing uses.
    pub unsafe fn free(&self, obj: NonNull<u8>) {
        let layout = self.layout();

        if layout.flags.contains(CacheFlags::VERIFY) {
            unsafe { self.free_verify(obj, &layout) };
        }

        self.lock.lock();
        // SAFETY: the lock above is held, and the caller gives up `obj`.
        unsafe { self.free_to_slab(obj, &layout) };
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
    fn slab_of(&self, addr: *mut u8) -> NonNull<KmemSlab<P>> {
        let slab = mach_page::table::lookup_pa::<()>(P::kvtophys(addr.addr()))
            .and_then(|page| {
                // SAFETY: the page is live, and the tag is null or a live slab:
                // `tag_pages()` and `untag_pages()` are the only writers of
                // `priv_` outside the page allocator, which clears it.
                NonNull::new(
                    unsafe { (*page.as_ptr()).priv_ }.cast::<KmemSlab<P>>(),
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
    unsafe fn free_to_slab(&self, buf: NonNull<u8>, layout: &CacheLayout) {
        // SAFETY: the caller holds the cache lock.
        let this = unsafe { self.body() };

        let slab = if layout.flags.contains(CacheFlags::DIRECT) {
            // SAFETY: a direct-mapped slab sits at the end of the page range
            // containing the buffer.
            unsafe { slab_from_direct(buf, layout.slab_size) }
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
        this.nr_objs -= 1;

        // SAFETY: the slab fields and links are this cache's, and the lock
        // serializes them.
        unsafe {
            if (*slab).nr_refs == 0 {
                if this.bufs_per_slab > 1 {
                    // SAFETY: with more than one buffer per slab, the last
                    // free leaves the slab in `partial_slabs`, and the
                    // cache lock keeps it live.
                    Self::partial_list(this)
                        .remove_ptr(NonNull::new_unchecked(slab));
                }

                // SAFETY: the slab is unlinked from every list and the
                // cache lock keeps it live and unmoved while the list links
                // it.
                Self::free_list(this)
                    .push_front_ptr(NonNull::new_unchecked(slab));
                this.nr_free_slabs += 1;
            } else if (*slab).nr_refs == this.bufs_per_slab - 1 {
                // SAFETY: the first free of a full slab, which is off every
                // list, and the cache lock keeps the slab live and unmoved
                // while the list links it.
                Self::partial_list(this)
                    .push_front_ptr(NonNull::new_unchecked(slab));
            }
        }
    }

    /// Moves the cache's free slabs to `dead_slabs`, for the caller to
    /// destroy.
    pub(crate) fn reap(&self, dead_slabs: Pin<&mut SlabList<P>>) {
        let layout = self.layout();

        self.lock.lock();

        // SAFETY: the lock above is held.
        let this = unsafe { self.body() };

        // The free slabs move to the tail of `dead_slabs`.
        // SAFETY: the cache lock is held.
        dead_slabs.append(unsafe { Self::free_list(this) });

        this.nr_bufs -= layout.bufs_per_slab * this.nr_free_slabs;
        this.nr_slabs -= this.nr_free_slabs;
        this.nr_free_slabs = 0;

        self.lock.unlock();
    }

    /// Checks a buffer the cache is handing out, and stamps it allocated.
    ///
    /// [`KmemCache::alloc`] calls the constructor itself, so this check does
    /// not.
    fn alloc_verify(&self, buf: NonNull<u8>, layout: &CacheLayout) {
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
                layout.bufctl_dist,
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
                buf.as_ptr().add(layout.obj_size),
                KMEM_REDZONE_BYTE,
                layout.redzone_pad,
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
    unsafe fn free_verify(&self, buf: NonNull<u8>, layout: &CacheLayout) {
        // The tag stays put while `buf` is a live buffer, so no lock is
        // needed; an address that is in no slab of this cache is rejected.
        let found = self.slab_of(buf.as_ptr());

        // SAFETY: `slab_of()` named a slab of this cache.
        let slab = unsafe { &*found.as_ptr() };
        let slabend =
            slab.addr.addr().wrapping_add(layout.slab_size) & !(PAGE_SIZE - 1);

        if buf.as_ptr().addr() >= slabend {
            self.error(buf.as_ptr(), CacheError::Invalid, ptr::null_mut());
        }

        let offset = buf.as_ptr().addr() - slab.addr.addr();

        if !offset.is_multiple_of(layout.buf_size) {
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
        let mut redzone_byte = unsafe { buf.as_ptr().add(layout.obj_size) };

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
        unsafe { fill(buf.as_ptr(), KMEM_FREE_PATTERN, layout.bufctl_dist) };
        // SAFETY: the buftag is the buffer's.
        unsafe { (*buftag).state = KMEM_BUFTAG_FREE };
    }

    /// Reports a buffer error and halts the kernel.
    pub(crate) fn error(
        &self,
        buf: *mut u8,
        error: CacheError,
        arg: *mut c_void,
    ) -> ! {
        P::print(format_args!(
            "mem: warning: kmem_cache_error(): cache: {}, buffer: {:x}\n",
            self.name(),
            buf.expose_provenance(),
        ));

        // The C's `%td` reads a ptrdiff_t; the offset is inside one buffer,
        // far below `isize::MAX`.
        let offset = arg.addr().wrapping_sub(buf.addr());

        match error {
            CacheError::Invalid => panic!(
                "kmem_cache_error: mem: error: kmem_cache_error(): freeing invalid address\n"
            ),
            CacheError::DoubleFree => panic!(
                "kmem_cache_error: mem: error: kmem_cache_error(): attempting to free the same address twice\n"
            ),
            CacheError::Buftag => panic!(
                "kmem_cache_error: mem: error: kmem_cache_error(): invalid buftag content, buftag state: {:x}\n",
                arg.expose_provenance()
            ),
            CacheError::Modified => panic!(
                "kmem_cache_error: mem: error: kmem_cache_error(): free buffer modified, fault address: {:x}, offset in buffer: {}\n",
                arg.expose_provenance(),
                offset as isize
            ),
            CacheError::Redzone => panic!(
                "kmem_cache_error: mem: error: kmem_cache_error(): write beyond end of buffer, fault address: {:x}, offset in buffer: {}\n",
                arg.expose_provenance(),
                offset as isize
            ),
        }
    }

    /// The cache's name, up to its NUL.
    fn name(&self) -> &str {
        // SAFETY: `init` wrote the name before the cache was shared and
        // nothing writes it after; the read takes that field alone.
        let name = unsafe { &(*self.body.get()).name };
        let len = name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(KMEM_CACHE_NAME_SIZE);
        // SAFETY: `c_char` and `u8` have the same layout, and `len` is inside
        // the array.
        let bytes = unsafe {
            core::slice::from_raw_parts(name.as_ptr().cast::<u8>(), len)
        };
        core::str::from_utf8(bytes).unwrap_or("?")
    }

    /// The per-cache copy `host_slab_info()` makes.
    pub(crate) fn fill_info(&self, info: &mut CacheInfo) {
        self.lock.lock();
        // SAFETY: the lock above is held.
        let this = unsafe { self.body() };
        info.flags = this.flags.bits();
        info.cpu_pool_size = 0;
        info.obj_size = this.obj_size;
        info.align = this.align;
        info.buf_size = this.buf_size;
        info.slab_size = this.slab_size;
        info.bufs_per_slab = this.bufs_per_slab;
        info.nr_objs = this.nr_objs;
        info.nr_bufs = this.nr_bufs;
        info.nr_slabs = this.nr_slabs;
        info.nr_free_slabs = this.nr_free_slabs;
        info.name.fill(0);
        let len = this
            .name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(KMEM_CACHE_NAME_SIZE);
        for (dst, src) in info.name.iter_mut().zip(&this.name[..len]) {
            *dst = *src;
        }
        self.lock.unlock();
    }
}
