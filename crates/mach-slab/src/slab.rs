// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Inspired by GNU Mach; see COPYRIGHT.

//! `KmemSlab`: a page-aligned run of a cache's buffers, and the page tags
//! that lead an address back to its slab.

use crate::cache::{CacheLayout, KmemCache};
use crate::pages::{pagealloc, pagefree};
use crate::platform::Platform;
use crate::types::{
    CacheError, CacheFlags, KMEM_BUFTAG_FREE, KMEM_FREE_PATTERN, KmemBufctl,
};
use crate::verify::{fill, verify};
use collections::tail_queue::{self, TailQueue};
use core::ffi::c_ulong;
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull, addr_of_mut, with_exposed_provenance_mut};
use mach_page::Page;
use mach_page::param::{PAGE_SIZE, VmOffset, VmSize};

/// A page-aligned collection of unconstructed buffers.
#[repr(C)]
pub(crate) struct KmemSlab<P: 'static> {
    pub(crate) cache: *const KmemCache<P>,
    pub(crate) list_node: tail_queue::Link,
    pub(crate) nr_refs: c_ulong,
    pub(crate) first_free: *mut KmemBufctl,
    pub(crate) addr: *mut u8,
}

const _: () = {
    assert!(size_of::<KmemSlab<()>>() == 48);
    assert!(align_of::<KmemSlab<()>>() == 8);
    assert!(offset_of!(KmemSlab<()>, cache) == 0);
    assert!(offset_of!(KmemSlab<()>, list_node) == 8);
    assert!(offset_of!(KmemSlab<()>, nr_refs) == 24);
    assert!(offset_of!(KmemSlab<()>, first_free) == 32);
    assert!(offset_of!(KmemSlab<()>, addr) == 40);
};

// SAFETY: a slab is shared by every CPU that allocates from its cache, which
// serializes its lists under the cache's lock; the slab's pointers are into
// memory the cache owns and nothing binds a slab to one thread.
unsafe impl<P: 'static> Send for KmemSlab<P> {}
unsafe impl<P: 'static> Sync for KmemSlab<P> {}

tail_queue::adapter!(
    /// The adapter for a slab's `list_node` in the free, partial and dead
    /// lists of its cache.
    pub(crate) KmemSlabListAdapter<P: 'static> = KmemSlab<P> { list_node }
);

/// A list of one cache's slabs: they join at either end and leave from the
/// middle.
pub(crate) type SlabList<P> = TailQueue<'static, KmemSlabListAdapter<P>>;

// The links and heads have the sizes the offsets above rely on.
const _: () = assert!(size_of::<tail_queue::Link>() == 16);
const _: () = assert!(size_of::<SlabList<()>>() == 16);

impl<P: Platform> KmemSlab<P> {
    /// Allocates and lays out a new slab for `cache`, at the `color` offset;
    /// the caller holds no cache lock.
    pub(crate) fn create(
        cache: &KmemCache<P>,
        layout: &CacheLayout,
        color: usize,
    ) -> Option<NonNull<Self>> {
        let slab_buf =
            pagealloc::<P>(layout.slab_size, layout.align, layout.flags)?;

        let slab = if layout.flags.contains(CacheFlags::SLAB_EXTERNAL) {
            // SAFETY: the slab cache was initialized before any cache could
            // grow.
            let external = P::slab_state().slab_cache().alloc();
            let Some(external) = external else {
                // SAFETY: the buffer is a live page allocation of this
                // cache.
                unsafe {
                    pagefree::<P>(
                        slab_buf.as_ptr().addr(),
                        layout.slab_size,
                        layout.flags,
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
                    slab_buf.as_ptr().addr() + layout.slab_size
                        - size_of::<Self>(),
                ))
            }
        };

        // SAFETY: the slab storage is fresh, so its fields are initialized
        // here before anything links it.
        unsafe {
            (*slab.as_ptr()).cache = ptr::from_ref(cache);
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

        for _ in 0..layout.bufs_per_slab {
            // SAFETY: each bufctl is inside the buffer, and the chain links
            // every buffer of the slab.
            unsafe {
                (*bufctl).next = (*slab.as_ptr()).first_free;
                (*slab.as_ptr()).first_free = bufctl;
                bufctl = bufctl.cast::<u8>().add(layout.buf_size).cast();
            }
        }

        if layout.flags.contains(CacheFlags::VERIFY) {
            // SAFETY: the slab is fresh and complete.
            unsafe { Self::create_verify(slab, cache, layout) };
        }

        if layout.flags.contains(CacheFlags::USE_PAGE) {
            // SAFETY: the pages are the live allocation `pagealloc()` made,
            // and nothing else tags them.
            unsafe {
                tag_pages(
                    slab_buf.as_ptr().addr(),
                    layout.slab_size,
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
    unsafe fn create_verify(
        slab: NonNull<Self>,
        cache: &KmemCache<P>,
        layout: &CacheLayout,
    ) {
        let buf_size = layout.buf_size;
        let mut buf = unsafe { (*slab.as_ptr()).addr };
        let mut buftag = cache.buftag_of(buf);

        for _ in 0..layout.bufs_per_slab {
            // SAFETY: `buf` is inside the slab, and `bufctl_dist` bytes are
            // writable from it.
            unsafe {
                fill(buf, KMEM_FREE_PATTERN, layout.bufctl_dist);
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
    pub(crate) unsafe fn destroy(slab: NonNull<Self>, cache: &KmemCache<P>) {
        let layout = cache.layout();

        if layout.flags.contains(CacheFlags::VERIFY) {
            unsafe { Self::destroy_verify(slab, cache, &layout) };
        }

        let slab_buf =
            unsafe { (*slab.as_ptr()).addr.addr() } & !(PAGE_SIZE - 1);

        if layout.flags.contains(CacheFlags::USE_PAGE) {
            // SAFETY: the pages are still mapped, so they can be named, and
            // `pagefree()` below has not released them yet.
            unsafe { untag_pages::<P>(slab_buf, layout.slab_size) };
        }

        if layout.flags.contains(CacheFlags::SLAB_EXTERNAL) {
            // SAFETY: the slab came from the off-slab cache.
            unsafe {
                (*P::slab_state().slab_cache())
                    .free(NonNull::new_unchecked(slab.as_ptr().cast::<u8>()));
            };
        }

        // SAFETY: the slab's buffer is the one `pagealloc()` returned.
        unsafe {
            pagefree::<P>(slab_buf, layout.slab_size, layout.flags);
        }
    }

    /// Checks that every buffer of a verify-mode slab is free and untouched
    /// before the slab is freed.
    ///
    /// # Safety
    ///
    /// `slab` must be a dead slab of `cache` whose buffers are all free.
    unsafe fn destroy_verify(
        slab: NonNull<Self>,
        cache: &KmemCache<P>,
        layout: &CacheLayout,
    ) {
        let buf_size = layout.buf_size;
        let mut buf = unsafe { (*slab.as_ptr()).addr };
        let mut buftag = cache.buftag_of(buf);

        for _ in 0..layout.bufs_per_slab {
            unsafe {
                if (*buftag).state != KMEM_BUFTAG_FREE {
                    cache.error(buf, CacheError::Buftag, buftag.cast());
                }

                if let Some(addr) =
                    verify(buf, KMEM_FREE_PATTERN, layout.bufctl_dist)
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

/// Points the `priv_` field of every page of the slab buffer at `base` to
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
unsafe fn tag_pages<P: Platform>(
    base: VmOffset,
    size: VmSize,
    slab: *mut KmemSlab<P>,
) {
    for addr in (base..base + size).step_by(PAGE_SIZE) {
        let page = page_of::<P>(addr);

        // SAFETY: the page is live, and the caller says this slab owns its
        // private field.
        unsafe {
            assert!(
                (*page.as_ptr()).priv_.is_null(),
                "kmem_tag_pages: slab: page already tagged"
            );

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
unsafe fn untag_pages<P: Platform>(base: VmOffset, size: VmSize) {
    for addr in (base..base + size).step_by(PAGE_SIZE) {
        let page = page_of::<P>(addr);

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
fn page_of<P: Platform>(addr: VmOffset) -> NonNull<Page<()>> {
    let Some(page) = mach_page::table::lookup_pa(P::kvtophys(addr)) else {
        panic!("kmem_tag_pages: slab: missing page");
    };

    page
}

/// The slab at the end of the `slab_size` block holding `buf`, for a
/// direct-mapped cache.
///
/// # Safety
///
/// `buf` must come from a direct-mapped slab of `slab_size` bytes.
pub(crate) unsafe fn slab_from_direct<P>(
    buf: NonNull<u8>,
    slab_size: usize,
) -> *mut KmemSlab<P> {
    let end = buf.as_ptr().addr() & !(slab_size - 1);
    // The caller promises the slab trailer is at the block's end.
    with_exposed_provenance_mut(end + slab_size - size_of::<KmemSlab<()>>())
}
