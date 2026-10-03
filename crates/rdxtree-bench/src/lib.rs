// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Times [`kmem::RadixTree`] against the `kern/rdxtree` it replaced.
//!
//! The old tree is `src/old/rdxtree.rs`, a verbatim snapshot of the
//! BSD-2-Clause `crates/kernel/src/kern/rdxtree.rs` that commit `c189c8b`
//! deleted: the bench cannot drift from what the kernel ran.  Its three
//! kernel dependencies are shimmed here as small host modules at the
//! paths the file imports (`kern::slab`, `utils::cell`, `vm::error`).
//!
//! Both contenders allocate nodes from the same kind of free list and
//! store the same `NonNull<c_void>` values, so a run measures the tree
//! walk and its bookkeeping, not the allocator.  Only relative numbers
//! are meaningful: this is a host process, not the kernel.

use core::ffi::c_void;
use core::ptr::NonNull;
use std::alloc::{Layout, alloc, dealloc};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, Once};

/// The kernel items `old/rdxtree.rs` imports, as host shims.
pub mod kern {
    /// A fixed-size node cache with a free list.
    pub mod slab {
        use core::cell::Cell;
        use core::ptr::NonNull;
        use std::alloc::{Layout, alloc, dealloc};
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Outstanding blocks across every `KmemCache`. The snapshot's
        /// node cache is a private `static`, so counting lives here.
        static LIVE: AtomicUsize = AtomicUsize::new(0);

        /// How many blocks the shims currently hold outstanding.
        #[must_use]
        pub fn live_blocks() -> usize {
            LIVE.load(Ordering::Relaxed)
        }

        /// `CacheInitFlags`; only `EMPTY` exists.
        #[derive(Clone, Copy)]
        pub struct CacheInitFlags;

        impl CacheInitFlags {
            /// `kmem_cache_init(..., 0)`.
            pub const EMPTY: Self = Self;
        }

        /// `KmemCache`: a free list of one block size over the host heap.
        pub struct KmemCache {
            size: Cell<usize>,
            align: Cell<usize>,
            free: Mutex<Vec<(NonNull<u8>, Layout)>>,
        }

        impl KmemCache {
            /// An uninitialised cache, as `KmemCache::zeroed()` left one.
            pub const fn zeroed() -> Self {
                Self {
                    size: Cell::new(0),
                    align: Cell::new(0),
                    free: Mutex::new(Vec::new()),
                }
            }

            /// Records the block size; `ctor` is unused here.
            pub fn init(
                &self,
                _name: &[u8],
                size: usize,
                align: usize,
                _ctor: Option<fn(*mut u8)>,
                _flags: CacheInitFlags,
            ) {
                self.size.set(size);
                self.align.set(if align == 0 {
                    core::mem::align_of::<usize>()
                } else {
                    align
                });
            }

            /// A block from the list, or a fresh host allocation.
            pub fn alloc(&self) -> Option<NonNull<u8>> {
                if let Some((block, _)) = self.free.lock().unwrap().pop() {
                    LIVE.fetch_add(1, Ordering::Relaxed);
                    return Some(block);
                }
                let size = self.size.get();
                if size == 0 {
                    return None;
                }
                let layout =
                    Layout::from_size_align(size, self.align.get()).ok()?;
                // SAFETY: `layout` is non-zero and matches the one every
                // later `free` of this block reuses.
                let block = unsafe { alloc(layout) };
                LIVE.fetch_add(1, Ordering::Relaxed);
                NonNull::new(block)
            }

            /// Returns a block to the list.
            pub fn free(&self, block: NonNull<u8>) {
                let layout =
                    Layout::from_size_align(self.size.get(), self.align.get())
                        .expect("the cache was initialised");
                self.free.lock().unwrap().push((block, layout));
                LIVE.fetch_sub(1, Ordering::Relaxed);
            }
        }

        impl Drop for KmemCache {
            fn drop(&mut self) {
                for (block, layout) in self.free.get_mut().unwrap().drain(..) {
                    // SAFETY: every block came from `alloc` with this
                    // layout and is not used again.
                    unsafe { dealloc(block.as_ptr(), layout) };
                }
            }
        }
    }
}

/// The kernel items `old/rdxtree.rs` imports, as host shims.
pub mod utils {
    /// The kernel's `UnsafeCell` wrapper.
    pub mod cell {
        use core::cell::UnsafeCell;

        /// A cell a `static` may hold.
        pub struct SyncCell<T>(pub UnsafeCell<T>);

        // SAFETY: the bench is single-threaded, and the cache guards its
        // own list with a mutex.
        unsafe impl<T> Sync for SyncCell<T> {}
    }
}

/// The kernel items `old/rdxtree.rs` imports, as host shims.
pub mod vm {
    /// The tree's error type.
    pub mod error {
        /// `vm::error::Error`, the two variants the tree uses.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Error {
            /// The key is already used.
            InvalidArgument,
            /// Memory is short.
            ResourceShortage,
        }
    }
}

// The snapshot keeps every line of the deleted kernel file,
// including the helpers this bench never calls.
#[allow(dead_code)]
#[path = "old/rdxtree.rs"]
mod rdxtree;

/// Both trees answer the same calls; the bench drives this trait.
pub trait Tree {
    /// An empty tree.
    fn new() -> Self;
    /// Stores `ptr` at the lowest free name, and hands back that name.
    fn insert_alloc(&mut self, ptr: NonNull<c_void>) -> u32;
    /// Stores `ptr` at `name`; false when the name is taken.
    fn insert_named(&mut self, name: u32, ptr: NonNull<c_void>) -> bool;
    /// The stored pointer as a checksum word, or zero.
    fn lookup(&self, name: u32) -> u64;
    /// Removes `name`; the removed pointer as a checksum word.
    fn remove(&mut self, name: u32) -> u64;
    /// Rewrites the value at `name`; the previous pointer as a
    /// checksum word, or zero when the name is empty.
    fn replace(&mut self, name: u32, ptr: NonNull<c_void>) -> u64;
    /// Walks every entry, folding names and pointers into a checksum.
    fn walk(&self) -> u64;
    /// Drops every entry.
    fn clear(&mut self);
}

/// `hash * 31 + value`, the mix the rb_tree bench uses.
pub const fn mix(hash: u64, value: u64) -> u64 {
    hash.wrapping_mul(31).wrapping_add(value)
}

/// The old `kern/rdxtree`, over its shimmed node cache.
pub struct OldTree {
    tree: rdxtree::Rdxtree,
}

impl OldTree {
    /// A tree, with the node cache initialised once per process.
    #[must_use]
    pub fn new() -> Self {
        static INIT: Once = Once::new();
        INIT.call_once(rdxtree::cache_init);
        let mut tree: rdxtree::Rdxtree = unsafe { core::mem::zeroed() };
        tree.init();
        Self { tree }
    }
}

impl Default for OldTree {
    fn default() -> Self {
        Self::new()
    }
}

impl Tree for OldTree {
    fn new() -> Self {
        OldTree::new()
    }

    fn insert_alloc(&mut self, ptr: NonNull<c_void>) -> u32 {
        self.tree
            .insert_alloc(ptr)
            .map(|(key, _)| key.into_raw())
            .expect("the host cache does not run dry")
    }

    fn insert_named(&mut self, name: u32, ptr: NonNull<c_void>) -> bool {
        self.tree
            .insert(rdxtree::RdxtreeKey::from_raw(name), ptr)
            .is_ok()
    }

    fn lookup(&self, name: u32) -> u64 {
        match self.tree.lookup(
            rdxtree::RdxtreeKey::from_raw(name),
            rdxtree::Lookup::Value,
        ) {
            Some(found) => found.address() as u64,
            None => 0,
        }
    }

    fn remove(&mut self, name: u32) -> u64 {
        match self.tree.remove(rdxtree::RdxtreeKey::from_raw(name)) {
            Some(ptr) => ptr.as_ptr() as u64,
            None => 0,
        }
    }

    fn replace(&mut self, name: u32, ptr: NonNull<c_void>) -> u64 {
        match self
            .tree
            .lookup(rdxtree::RdxtreeKey::from_raw(name), rdxtree::Lookup::Slot)
        {
            Some(rdxtree::Found::Slot(slot)) => {
                // SAFETY: `slot` points into this tree's live storage,
                // and the bench is single-threaded.
                let old =
                    unsafe { rdxtree::replace_slot(&mut *slot, ptr.as_ptr()) };
                old as u64
            }
            _ => 0,
        }
    }

    fn walk(&self) -> u64 {
        let mut iter = rdxtree::RdxtreeIter::new();
        let mut sum = 0_u64;
        while let Some(ptr) = self.tree.walk(&mut iter) {
            sum = mix(sum, ptr.as_ptr() as u64);
        }
        sum
    }

    fn clear(&mut self) {
        self.tree.remove_all();
    }
}

/// Outstanding blocks across every `HostAlloc`. `RadixTree` owns its
/// allocator, so counting lives here rather than on the tree.
static HOST_LIVE: AtomicUsize = AtomicUsize::new(0);

/// A host free list of node-sized blocks, standing in for the slab.
pub struct HostAlloc {
    free: Mutex<Vec<(NonNull<u8>, Layout)>>,
}

impl HostAlloc {
    /// An empty list.
    #[must_use]
    pub fn new() -> Self {
        Self {
            free: Mutex::new(Vec::new()),
        }
    }
}

/// How many blocks the host allocators currently hold outstanding.
#[must_use]
pub fn host_live_blocks() -> usize {
    HOST_LIVE.load(Ordering::Relaxed)
}

impl Default for HostAlloc {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: blocks stay valid until `free`, and the list is behind a mutex.
unsafe impl kmem::Alloc for HostAlloc {
    fn alloc(&self, layout: Layout) -> Result<NonNull<u8>, kmem::AllocError> {
        if let Some((block, _)) = self.free.lock().unwrap().pop() {
            HOST_LIVE.fetch_add(1, Ordering::Relaxed);
            return Ok(block);
        }
        // SAFETY: `layout` is non-zero at every call of a tree node, and
        // the matching `free` reuses it.
        let block = unsafe { alloc(layout) };
        HOST_LIVE.fetch_add(1, Ordering::Relaxed);
        NonNull::new(block).ok_or(kmem::AllocError)
    }

    unsafe fn free(&self, block: NonNull<u8>, layout: Layout) {
        self.free.lock().unwrap().push((block, layout));
        HOST_LIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for HostAlloc {
    fn drop(&mut self) {
        for (block, layout) in self.free.get_mut().unwrap().drain(..) {
            // SAFETY: every block came from `alloc` with this layout and
            // is not used again.
            unsafe { dealloc(block.as_ptr(), layout) };
        }
    }
}

/// `kmem::RadixTree`, the MIT rewrite.
pub struct NewTree {
    tree: kmem::RadixTree<NonNull<c_void>, HostAlloc>,
}

impl NewTree {
    /// A tree over a fresh host free list.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tree: kmem::RadixTree::new(HostAlloc::new()),
        }
    }
}

impl Default for NewTree {
    fn default() -> Self {
        Self::new()
    }
}

impl Tree for NewTree {
    fn new() -> Self {
        NewTree::new()
    }

    fn insert_alloc(&mut self, ptr: NonNull<c_void>) -> u32 {
        self.tree
            .insert_alloc(ptr)
            .map(|(key, _)| key.into_raw())
            .expect("the host cache does not run dry")
    }

    fn insert_named(&mut self, name: u32, ptr: NonNull<c_void>) -> bool {
        self.tree
            .insert(kmem::RadixKey::from_raw(name), ptr)
            .is_ok()
    }

    fn lookup(&self, name: u32) -> u64 {
        match self.tree.get(kmem::RadixKey::from_raw(name)) {
            Some(ptr) => ptr.as_ptr() as u64,
            None => 0,
        }
    }

    fn remove(&mut self, name: u32) -> u64 {
        match self.tree.remove(kmem::RadixKey::from_raw(name)) {
            Some(ptr) => ptr.as_ptr() as u64,
            None => 0,
        }
    }

    fn replace(&mut self, name: u32, ptr: NonNull<c_void>) -> u64 {
        match self.tree.replace(kmem::RadixKey::from_raw(name), ptr) {
            Ok(Some(old)) => old.as_ptr() as u64,
            Ok(None) | Err(_) => 0,
        }
    }

    fn walk(&self) -> u64 {
        let mut sum = 0_u64;
        for (_key, ptr) in self.tree.iter() {
            sum = mix(sum, ptr.as_ptr() as u64);
        }
        sum
    }

    fn clear(&mut self) {
        self.tree.clear();
    }
}
