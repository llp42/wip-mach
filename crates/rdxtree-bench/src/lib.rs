// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Times [`kmem::RadixTree`] against the C tree it replaced.
//!
//! The reference is `src/old`, a frozen copy of the C the kernel's tree
//! was translated from, compiled by `build.rs` (ADR 0052).  The
//! contender is [`kmem::RadixTree`], a port over `A: Alloc` of the same
//! author's later MIT release of that tree.  Both store the same
//! `NonNull<c_void>` values under the same 32-bit names.  The reference
//! is built with 32-bit keys, as the kernel built it; the contender takes
//! `u64` keys, but a tree is only as tall as its largest key needs, so
//! under 32-bit names both build the same levels and a run compares two
//! trees, not two key widths.
//!
//! Ids read `<tree>/<workload>/<entries>`, with `c` the reference and
//! `new` the port.  Every workload is an action the kernel performs on
//! the name table of an IPC space, or on the reverse map beside it:
//!
//! | workload | the kernel's action | where |
//! |---|---|---|
//! | `insert_alloc` | the lowest free name, on port creation | `ipc/ipc_entry.rs:240` |
//! | `insert_named` | an entry registered at a chosen name | `ipc/ipc_entry.rs:296` |
//! | `lookup` | name to entry | `ipc/ipc_entry.rs:279` |
//! | `remove` | release, which evicts once the free list is full | `ipc/ipc_entry.rs:183` |
//! | `replace` | a fresh entry written into a slot already held | `ipc/ipc_space.rs:98` |
//! | `walk` | `mach_port_names`, and set membership | `ipc/mach_port.rs:1112` |
//! | `clear` | space teardown | `ipc/ipc_space.rs:341` |
//! | `churn`, `ipc` | a live port population allocating and releasing | `ipc/ipc_entry.rs:240` |
//! | `reverse_map` | the second map every space keeps | `ipc/ipc_space.rs:120` |
//! | `*_sparse*` | keys spread over the whole domain, the worst descent | — |
//!
//! Only relative numbers mean anything: this is a host process, not the
//! kernel, and the reference is compiled by whatever `cc` the host has.
//! Three things are held equal so that a difference is the trees':
//!
//! - **The allocator.**  Both draw nodes from a process-global free list
//!   that survives between iterations, as the kernel's node cache does,
//!   so neither pays the host allocator for a node the other reuses.
//! - **The teardown.**  Each routine takes its tree by value, so its
//!   destructor runs inside the timed window; [`CTree`] drops through
//!   `rdxtree_remove_all` and [`NewTree`] through `RadixTree::drop`.
//! - **The assertions.**  The reference is built with `NDEBUG` because
//!   the contender's `debug_assert!`s are compiled out in this profile.
//!   The contender's alignment check on each stored pointer is part of
//!   its contract in every profile, so it stays inside the window.

use core::ffi::{c_int, c_void};
use core::mem::{MaybeUninit, offset_of, size_of};
use core::ptr::NonNull;
use std::alloc::{Layout, alloc};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, Once};

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

/// The reference's tree: a height and a root that is a node or a value.
///
/// `bridge.c` asserts every offset and size below, and the key's width
/// with them, so a mismatch is a build failure rather than a silent one.
#[repr(C)]
struct Rdxtree {
    height: u32,
    root: *mut c_void,
}

/// The reference's iterator: the node it last reached and its key.
#[repr(C)]
struct RdxtreeIter {
    node: *mut c_void,
    key: u32,
}

const _: () = {
    assert!(size_of::<Rdxtree>() == 16);
    assert!(offset_of!(Rdxtree, root) == 8);
    assert!(size_of::<RdxtreeIter>() == 16);
    assert!(offset_of!(RdxtreeIter, key) == 8);
};

// The reference's entry points.  The ones its headers declare `static
// inline` have no symbol of their own and are reached through the
// `_bench_` wrappers `bridge.c` defines.
unsafe extern "C" {
    /// Initializes the reference's node cache; once per process.
    fn rdxtree_cache_init();
    /// Removes `key`, answering the pointer it held.
    fn rdxtree_remove(tree: *mut Rdxtree, key: u32) -> *mut c_void;
    /// Drops every entry and frees every node.
    fn rdxtree_remove_all(tree: *mut Rdxtree);
    /// Writes `ptr` into `slot`, answering the pointer it displaced.
    fn rdxtree_replace_slot(
        slot: *mut *mut c_void,
        ptr: *mut c_void,
    ) -> *mut c_void;
    /// Steps the iterator to the next entry, or null at the end.
    fn rdxtree_walk(tree: *mut Rdxtree, iter: *mut RdxtreeIter)
    -> *mut c_void;

    /// `rdxtree_init()`.
    fn rdxtree_bench_init(tree: *mut Rdxtree);
    /// `rdxtree_insert()`: zero on success, non-zero when `key` is taken.
    fn rdxtree_bench_insert(
        tree: *mut Rdxtree,
        key: u32,
        ptr: *mut c_void,
    ) -> c_int;
    /// `rdxtree_insert_alloc()`: zero on success, with the key written
    /// through `keyp`.
    fn rdxtree_bench_insert_alloc(
        tree: *mut Rdxtree,
        ptr: *mut c_void,
        keyp: *mut u32,
    ) -> c_int;
    /// `rdxtree_lookup()`, or null when nothing is stored at `key`.
    fn rdxtree_bench_lookup(tree: *const Rdxtree, key: u32) -> *mut c_void;
    /// `rdxtree_lookup_slot()`, or null when nothing is stored at `key`.
    fn rdxtree_bench_lookup_slot(
        tree: *const Rdxtree,
        key: u32,
    ) -> *mut *mut c_void;
    /// `rdxtree_iter_init()`.
    fn rdxtree_bench_iter_init(iter: *mut RdxtreeIter);

    /// How many node blocks the reference's cache holds outstanding.
    fn rdxtree_bench_live_blocks() -> usize;
}

/// How many blocks the reference's trees currently hold.
///
/// The reference's cache is one process-wide cache, so this counts every
/// tree at once; read it around one tree's fill, as the node-count
/// example does.
#[must_use]
pub fn c_live_blocks() -> usize {
    // SAFETY: the counter is a plain global with no preconditions.
    unsafe { rdxtree_bench_live_blocks() }
}

/// The C tree the kernel's translation came from.
pub struct CTree {
    tree: Rdxtree,
}

impl CTree {
    /// A tree, with the node cache initialised once per process.
    #[must_use]
    pub fn new() -> Self {
        static INIT: Once = Once::new();
        // SAFETY: the cache is a process-wide global, and `Once` runs
        // this before any tree can allocate from it.
        INIT.call_once(|| unsafe { rdxtree_cache_init() });

        let mut tree = MaybeUninit::<Rdxtree>::uninit();
        // SAFETY: the initializer writes both words and reads nothing.
        unsafe { rdxtree_bench_init(tree.as_mut_ptr()) };
        // SAFETY: the call above initialised the whole structure.
        Self {
            tree: unsafe { tree.assume_init() },
        }
    }
}

impl Default for CTree {
    fn default() -> Self {
        Self::new()
    }
}

impl Tree for CTree {
    fn new() -> Self {
        CTree::new()
    }

    fn insert_alloc(&mut self, ptr: NonNull<c_void>) -> u32 {
        let mut key = 0_u32;
        // SAFETY: the tree is live and exclusively borrowed, and `key`
        // is writable; a stored value is never null, as `tree` asserts.
        let result = unsafe {
            rdxtree_bench_insert_alloc(
                &raw mut self.tree,
                ptr.as_ptr(),
                &raw mut key,
            )
        };
        assert_eq!(result, 0, "the host cache does not run dry");
        key
    }

    fn insert_named(&mut self, name: u32, ptr: NonNull<c_void>) -> bool {
        // SAFETY: the tree is live and exclusively borrowed; a stored
        // value is never null, as `tree` asserts.
        let result = unsafe {
            rdxtree_bench_insert(&raw mut self.tree, name, ptr.as_ptr())
        };
        result == 0
    }

    fn lookup(&self, name: u32) -> u64 {
        // SAFETY: the tree is live and shared, which is all a lookup
        // reads it through.
        let found = unsafe { rdxtree_bench_lookup(&self.tree, name) };
        found as u64
    }

    fn remove(&mut self, name: u32) -> u64 {
        // SAFETY: the tree is live and exclusively borrowed.
        let removed = unsafe { rdxtree_remove(&raw mut self.tree, name) };
        removed as u64
    }

    fn replace(&mut self, name: u32, ptr: NonNull<c_void>) -> u64 {
        // SAFETY: the tree is live and shared, which is all a lookup
        // reads it through.
        let slot = unsafe { rdxtree_bench_lookup_slot(&self.tree, name) };
        if slot.is_null() {
            return 0;
        }
        // SAFETY: a non-null slot points into this tree's live storage,
        // the tree is exclusively borrowed so no other writer reaches
        // it, and `replace_slot` only writes the one word.
        let old = unsafe { rdxtree_replace_slot(slot, ptr.as_ptr()) };
        old as u64
    }

    fn walk(&self) -> u64 {
        let mut iter = MaybeUninit::<RdxtreeIter>::uninit();
        // SAFETY: the initializer writes both fields and reads nothing.
        unsafe { rdxtree_bench_iter_init(iter.as_mut_ptr()) };
        // SAFETY: the call above initialised the whole structure.
        let mut iter = unsafe { iter.assume_init() };

        let mut sum = 0_u64;
        loop {
            // SAFETY: the tree is live; the walk writes only the
            // iterator, which this call owns exclusively, so sharing the
            // tree is sound even though the parameter is not `const`.
            let ptr = unsafe {
                rdxtree_walk(&raw const self.tree as *mut _, &raw mut iter)
            };
            if ptr.is_null() {
                return sum;
            }
            sum = mix(sum, ptr as u64);
        }
    }

    fn clear(&mut self) {
        // SAFETY: the tree is live and exclusively borrowed; every
        // stored value is a pointer the caller keeps, so nothing is
        // leaked by not running a destructor over them.
        unsafe { rdxtree_remove_all(&raw mut self.tree) };
    }
}

impl Drop for CTree {
    /// Frees every node, as the contender's `Drop` does.
    ///
    /// Each timed routine takes its tree by value, so this runs inside
    /// the measured window; a tree that skipped it would win every
    /// workload that fills one.
    fn drop(&mut self) {
        self.clear();
    }
}

/// Blocks handed out and not yet given back.
static HOST_LIVE: AtomicUsize = AtomicUsize::new(0);

/// The free list every tree's nodes come from.
///
/// One list for the process, as the kernel's node cache is one cache for
/// every tree: a per-tree list would return its blocks when the tree is
/// dropped, and the next iteration would call the host allocator for
/// every node while the reference reused its own.
static HOST_FREE: Mutex<FreeList> = Mutex::new(FreeList {
    layout: None,
    blocks: Vec::new(),
});

/// The blocks a [`HostAlloc`] has been given back, and the one block
/// size they all are.
struct FreeList {
    layout: Option<Layout>,
    blocks: Vec<NonNull<u8>>,
}

// SAFETY: the list owns the blocks it holds, and every access to it goes
// through its mutex.  A pointer is not `Send` because it may be shared
// with a thread that writes through it; these are not shared with
// anything until the list hands one out.
unsafe impl Send for FreeList {}

/// A host free list of node-sized blocks, standing in for the slab.
pub struct HostAlloc;

impl HostAlloc {
    /// A handle onto the process-wide list.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for HostAlloc {
    fn default() -> Self {
        Self::new()
    }
}

/// How many blocks the trees currently hold.
#[must_use]
pub fn host_live_blocks() -> usize {
    HOST_LIVE.load(Ordering::Relaxed)
}

/// Records the list's block size, and fails a second, different one.
fn hold_layout(cache: &mut FreeList, layout: Layout) {
    match cache.layout {
        Some(held) => assert_eq!(
            held, layout,
            "one free list holds one block size; a tree node is one layout"
        ),
        None => cache.layout = Some(layout),
    }
}

// SAFETY: blocks stay valid until they are given back, the list hands
// each one out once, and it is behind a mutex.
unsafe impl kmem::Alloc for HostAlloc {
    fn alloc(&self, layout: Layout) -> Result<NonNull<u8>, kmem::AllocError> {
        let mut cache = HOST_FREE.lock().unwrap();
        hold_layout(&mut cache, layout);

        if let Some(block) = cache.blocks.pop() {
            HOST_LIVE.fetch_add(1, Ordering::Relaxed);
            return Ok(block);
        }
        drop(cache);

        // SAFETY: `layout` is non-zero at every call of a tree node, and
        // the matching `free` reuses it.
        let block = unsafe { alloc(layout) };
        HOST_LIVE.fetch_add(1, Ordering::Relaxed);
        NonNull::new(block).ok_or(kmem::AllocError)
    }

    unsafe fn free(&self, block: NonNull<u8>, layout: Layout) {
        let mut cache = HOST_FREE.lock().unwrap();
        hold_layout(&mut cache, layout);
        cache.blocks.push(block);
        HOST_LIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

/// `kmem::RadixTree`, the contender.
pub struct NewTree {
    tree: kmem::RadixTree<c_void, HostAlloc>,
}

impl NewTree {
    /// A tree over the process's node free list.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tree: kmem::RadixTree::new(HostAlloc::new(), true),
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
        let key = self
            .tree
            .insert_alloc(ptr)
            .expect("the host cache does not run dry");
        u32::try_from(key).expect("a workload stays under 2^32 entries")
    }

    fn insert_named(&mut self, name: u32, ptr: NonNull<c_void>) -> bool {
        self.tree.insert(u64::from(name), ptr).is_ok()
    }

    fn lookup(&self, name: u32) -> u64 {
        match self.tree.get(u64::from(name)) {
            Some(ptr) => ptr.as_ptr() as u64,
            None => 0,
        }
    }

    fn remove(&mut self, name: u32) -> u64 {
        match self.tree.remove(u64::from(name)) {
            Some(ptr) => ptr.as_ptr() as u64,
            None => 0,
        }
    }

    fn replace(&mut self, name: u32, ptr: NonNull<c_void>) -> u64 {
        match self.tree.get_slot(u64::from(name)) {
            Some(mut slot) => slot.replace(ptr).as_ptr() as u64,
            None => 0,
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
