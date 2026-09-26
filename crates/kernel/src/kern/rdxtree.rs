// SPDX-License-Identifier: BSD-2-Clause
// Derived from kern/rdxtree.c, kern/rdxtree.h and kern/rdxtree_i.h:
//   Copyright (c) 2011-2015 Richard Braun.
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Radix tree, which `kern/rdxtree.c` used to define, and the
//! `struct rdxtree` and `struct rdxtree_iter` mirrors of <`kern/rdxtree_i.h`>.

use crate::kern::slab::{CacheInitFlags, KmemCache};
use crate::utils::cell::SyncCell;
use crate::vm::error::Error;
use core::cell::UnsafeCell;
use core::ffi::{c_uint, c_void};
use core::mem::{align_of, offset_of, size_of};
use core::ptr::{self, NonNull};

/// `RDXTREE_RADIX` of kern/rdxtree.c: the key bits a level selects.
const RDXTREE_RADIX: u32 = 6;

/// `RDXTREE_RADIX_SIZE`: the entries a node holds.
const RDXTREE_RADIX_SIZE: usize = 1 << RDXTREE_RADIX;

/// `RDXTREE_RADIX_MASK`.
const RDXTREE_RADIX_MASK: u32 = (1 << RDXTREE_RADIX) - 1;

/// `RDXTREE_ENTRY_ADDR_MASK`: the address bits an entry carries.
const RDXTREE_ENTRY_ADDR_MASK: usize = !0x3;

/// `RDXTREE_BM_FULL`: every entry of a fresh node is free.
const RDXTREE_BM_FULL: u64 = u64::MAX;

/// A slot index as the `unsigned int` a node field holds.
const fn field_index(index: usize) -> c_uint {
    // Every index is below `RDXTREE_RADIX_SIZE`, so the narrowing cannot
    // lose anything.
    index as c_uint
}

/// The slot index an `unsigned int` node field holds.
const fn slot_index(index: c_uint) -> usize {
    // The field always holds a value below `RDXTREE_RADIX_SIZE`, and
    // `usize` is 64 bits, so the widening is lossless.
    index as usize
}

/// `rdxtree_key_t` of <kern/rdxtree.h>: `uint32_t`, the key width the
/// build's `RDXTREE_KEY_32` selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub(crate) struct RdxtreeKey(u32);

impl RdxtreeKey {
    /// The first key, which a leaf keeps in its root.
    const ZERO: Self = Self(0);

    /// `(rdxtree_key_t)-1`, the key a fresh iterator holds.
    const LAST: Self = Self(u32::MAX);

    /// The key a C caller's integer stands for.
    pub(crate) const fn from_raw(bits: u32) -> Self {
        Self(bits)
    }

    /// The integer a C caller reads back.
    pub(crate) const fn into_raw(self) -> u32 {
        self.0
    }

    /// `rdxtree_max_key()` in C: the largest key a tree of `height` holds.
    const fn max_for_height(height: u32) -> Self {
        let shift = RDXTREE_RADIX * height;

        if shift < u32::BITS {
            Self((1 << shift) - 1)
        } else {
            Self(u32::MAX)
        }
    }

    /// The entry index this key selects at `shift`, `(key >> shift) & mask`.
    const fn index_at(self, shift: u32) -> usize {
        // The mask leaves a value below `RDXTREE_RADIX_SIZE`, which is
        // narrower than `usize`.
        ((self.0 >> shift) & RDXTREE_RADIX_MASK) as usize
    }

    /// `key | (index << shift)`, the key assembly of `insert_alloc()`.
    const fn with_index(self, index: usize, shift: u32) -> Self {
        Self(self.0 | ((field_index(index)) << shift))
    }

    const fn wrapping_add(self, rhs: u32) -> Self {
        Self(self.0.wrapping_add(rhs))
    }

    const fn wrapping_shr(self, shift: u32) -> Self {
        Self(self.0.wrapping_shr(shift))
    }

    const fn wrapping_shl(self, shift: u32) -> Self {
        Self(self.0.wrapping_shl(shift))
    }
}

/// `struct rdxtree` of <`kern/rdxtree_i.h`>.
#[repr(C)]
#[allow(missing_docs)]
pub struct Rdxtree {
    /// The number of nodes to traverse; 0 means `root` is a stored pointer.
    height: c_uint,
    /// A stored pointer, or a node tagged in its low bit.
    root: *mut c_void,
}

/// `struct rdxtree_iter` of <`kern/rdxtree_i.h`>.
#[repr(C)]
#[allow(missing_docs)]
pub struct RdxtreeIter {
    /// The node holding the current pointer, null before the first walk.
    node: *mut c_void,
    key: RdxtreeKey,
}

const _: () = {
    assert!(size_of::<Rdxtree>() == 16);
    assert!(align_of::<Rdxtree>() == 8);
    assert!(offset_of!(Rdxtree, height) == 0);
    assert!(offset_of!(Rdxtree, root) == 8);
    assert!(size_of::<RdxtreeIter>() == 16);
    assert!(align_of::<RdxtreeIter>() == 8);
    assert!(offset_of!(RdxtreeIter, node) == 0);
    assert!(offset_of!(RdxtreeIter, key) == 8);
};

/// `struct rdxtree_node` of kern/rdxtree.c: one level of a tree.
///
/// # Invariants
///
/// `index` is valid only while `parent` is not null, and `alloc_bm` has bit
/// `i` set when the entry `i` denotes, or one of its children, has a free
/// slot.
#[repr(C)]
#[allow(missing_docs)]
struct RdxtreeNode {
    parent: *mut Self,
    index: c_uint,
    height: c_uint,
    nr_entries: c_uint,
    alloc_bm: u64,
    entries: [*mut c_void; RDXTREE_RADIX_SIZE],
}

const _: () = {
    assert!(size_of::<RdxtreeNode>() == 544);
    assert!(offset_of!(RdxtreeNode, parent) == 0);
    assert!(offset_of!(RdxtreeNode, index) == 8);
    assert!(offset_of!(RdxtreeNode, height) == 12);
    assert!(offset_of!(RdxtreeNode, nr_entries) == 16);
    assert!(offset_of!(RdxtreeNode, alloc_bm) == 24);
    assert!(offset_of!(RdxtreeNode, entries) == 32);
};

/// `rdxtree_node_cache` of kern/rdxtree.c.
static RDXTREE_NODE_CACHE: SyncCell<KmemCache> =
    SyncCell(UnsafeCell::new(KmemCache::zeroed()));

/// The node cache; [`cache_init`] must have run.
fn node_cache() -> *mut KmemCache {
    RDXTREE_NODE_CACHE.0.get()
}

/// `rdxtree_cache_init()` of <kern/rdxtree.h>.
pub(crate) fn cache_init() {
    // SAFETY: startup calls this once, before any tree can allocate a node,
    // and the cache is not shared before that.
    unsafe {
        (*node_cache()).init(
            b"rdxtree_node",
            size_of::<RdxtreeNode>(),
            0,
            None,
            CacheInitFlags::EMPTY,
        );
    };
}

/// One slot of a node, tagged as `rdxtree_node_to_entry()` tagged it: the
/// low bit distinguishes a child node from a stored pointer.
#[derive(Clone, Copy)]
enum Entry {
    /// A pointer the caller stored, at the bottom of a tree.
    Ptr(NonNull<c_void>),
    /// An internal node.
    Node(NonNull<RdxtreeNode>),
}

impl Entry {
    /// The tag bit `rdxtree_node_to_entry()` sets; stored pointers are
    /// 4-byte aligned and leave it clear.
    const NODE_TAG: usize = 1;

    /// The entry a slot holds, or `None` when the slot is empty.
    fn from_raw(raw: *mut c_void) -> Option<Self> {
        // `rdxtree_entry_addr()` masks the tag before its null check, so a
        // slot that holds only tag bits counts as empty.
        if raw.addr() & RDXTREE_ENTRY_ADDR_MASK == 0 {
            return None;
        }

        // SAFETY: `raw` is non-null, and every non-null slot holds an entry
        // this module wrote through `into_raw()`.
        Some(unsafe { Self::from_non_null(raw) })
    }

    /// The entry a non-null slot holds.
    ///
    /// # Safety
    ///
    /// `raw` must be non-null, and a set low bit must mean the address is a
    /// live [`RdxtreeNode`] this tree owns.
    unsafe fn from_non_null(raw: *mut c_void) -> Self {
        if raw.addr() & Self::NODE_TAG != 0 {
            Self::Node(unsafe {
                NonNull::new_unchecked(
                    raw.map_addr(|addr| addr & RDXTREE_ENTRY_ADDR_MASK).cast(),
                )
            })
        } else {
            Self::Ptr(unsafe { NonNull::new_unchecked(raw) })
        }
    }

    /// The node a tagged, non-null slot holds, per `rdxtree_entry_is_node()`.
    ///
    /// # Safety
    ///
    /// `raw` must be non-null with the node tag set.
    unsafe fn node_from_raw(raw: *mut c_void) -> NonNull<RdxtreeNode> {
        unsafe {
            NonNull::new_unchecked(
                raw.map_addr(|addr| addr & RDXTREE_ENTRY_ADDR_MASK).cast(),
            )
        }
    }

    /// The slot content, tag included.
    fn into_raw(self) -> *mut c_void {
        match self {
            Self::Ptr(ptr) => ptr.as_ptr(),
            Self::Node(node) => node
                .as_ptr()
                .cast::<c_void>()
                .map_addr(|addr| addr | Self::NODE_TAG),
        }
    }

    /// The address without the tag, `rdxtree_entry_addr()` in C.
    const fn into_ptr(self) -> NonNull<c_void> {
        match self {
            Self::Ptr(ptr) => ptr,
            Self::Node(node) => node.cast(),
        }
    }

    /// The node this entry denotes, if it is one.
    const fn node(self) -> Option<NonNull<RdxtreeNode>> {
        match self {
            Self::Node(node) => Some(node),
            Self::Ptr(_) => None,
        }
    }
}

impl RdxtreeNode {
    /// `rdxtree_node_create()` in C.
    fn create(height: c_uint) -> Result<NonNull<Self>, Error> {
        // SAFETY: the cache is initialized before any tree exists.
        let Some(mem) = (unsafe { (*node_cache()).alloc() }) else {
            return Err(Error::ResourceShortage);
        };

        let node = mem.cast::<Self>();

        // SAFETY: the cache hands out `size_of::<Self>()` bytes, and the
        // fresh allocation has no other owner.  The fields are written in
        // place: a whole-node temporary would spend a page-stack's worth of
        // room in this call chain.
        unsafe {
            let dst = node.as_ptr();
            (*dst).parent = ptr::null_mut();
            (*dst).index = 0;
            (*dst).height = height;
            (*dst).nr_entries = 0;
            (*dst).alloc_bm = RDXTREE_BM_FULL;
            ptr::write_bytes(
                (*dst).entries.as_mut_ptr(),
                0,
                RDXTREE_RADIX_SIZE,
            );
        }

        Ok(node)
    }

    /// `rdxtree_node_schedule_destruction()` in C.
    fn destroy(node: NonNull<Self>) {
        // SAFETY: the caller gives back a node this module allocated.
        unsafe { (*node_cache()).free(node.cast::<u8>()) };
    }

    /// `rdxtree_node_link()` in C.
    const fn link(&mut self, parent: NonNull<Self>, index: usize) {
        self.parent = parent.as_ptr();
        self.index = field_index(index);
    }

    /// `rdxtree_node_unlink()` in C.
    const fn unlink(&mut self) {
        self.parent = ptr::null_mut();
    }

    /// `rdxtree_node_full()` in C.
    const fn is_full(&self) -> bool {
        self.nr_entries == field_index(RDXTREE_RADIX_SIZE)
    }

    /// `rdxtree_node_empty()` in C.
    const fn is_empty(&self) -> bool {
        self.nr_entries == 0
    }

    /// `rdxtree_node_insert()` in C.
    fn insert(&mut self, index: usize, entry: Entry) {
        self.nr_entries += 1;
        self.entries[index] = entry.into_raw();
    }

    /// `rdxtree_node_remove()` in C.
    const fn remove(&mut self, index: usize) {
        self.nr_entries -= 1;
        self.entries[index] = ptr::null_mut();
    }

    /// The entry of slot `index`, or `None` when the slot is empty.
    fn entry(&self, index: usize) -> Option<Entry> {
        Entry::from_raw(self.entries[index])
    }

    /// `rdxtree_node_find()` in C: the first entry from `index` on.
    fn find(&self, index: usize) -> Option<(usize, Entry)> {
        let mut index = index;

        while let Some(&raw) = self.entries.get(index) {
            if let Some(entry) = Entry::from_raw(raw) {
                return Some((index, entry));
            }

            index += 1;
        }

        None
    }

    /// `rdxtree_node_bm_set()` in C.
    const fn bm_set(&mut self, index: usize) {
        self.alloc_bm |= 1u64 << index;
    }

    /// `rdxtree_node_bm_clear()` in C.
    const fn bm_clear(&mut self, index: usize) {
        self.alloc_bm &= !(1u64 << index);
    }

    /// `rdxtree_node_bm_is_set()` in C.
    const fn bm_is_set(&self, index: usize) -> bool {
        self.alloc_bm & (1u64 << index) != 0
    }

    /// `rdxtree_node_bm_empty()` in C.
    const fn bm_is_empty(&self) -> bool {
        self.alloc_bm == 0
    }

    /// `rdxtree_node_bm_first()` in C: the lowest free slot, `None` when
    /// the node is full.
    const fn bm_first(&self) -> Option<usize> {
        if self.alloc_bm == 0 {
            None
        } else {
            // A trailing-zero count is below 64, so it fits every `usize`.
            Some(self.alloc_bm.trailing_zeros() as usize)
        }
    }

    /// `rdxtree_insert_bm_clear()` in C.
    fn insert_bm_clear(mut node: NonNull<Self>, mut index: usize) {
        loop {
            // SAFETY: every node on a parent chain is a live node.
            let current = unsafe { &mut *node.as_ptr() };

            current.bm_clear(index);

            if !current.is_full() || current.parent.is_null() {
                break;
            }

            index = slot_index(current.index);
            // SAFETY: a linked node's parent is live.
            node = unsafe { NonNull::new_unchecked(current.parent) };
        }
    }

    /// `rdxtree_remove_bm_set()` in C.
    fn remove_bm_set(mut node: NonNull<Self>, mut index: usize) {
        loop {
            // SAFETY: every node on a parent chain is a live node.
            let current = unsafe { &mut *node.as_ptr() };

            current.bm_set(index);

            if current.parent.is_null() {
                break;
            }

            index = slot_index(current.index);
            // SAFETY: a linked node's parent is live.
            node = unsafe { NonNull::new_unchecked(current.parent) };

            // SAFETY: the parent is live.
            if unsafe { (*node.as_ptr()).bm_is_set(index) } {
                break;
            }
        }
    }
}

/// Whether a lookup stops at the stored pointer or at its slot, the
/// `get_slot` argument of `rdxtree_lookup_common()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lookup {
    /// `rdxtree_lookup()`: the stored pointer.
    Value,
    /// `rdxtree_lookup_slot()`: the slot holding it.
    Slot,
}

/// What a [`Lookup`] found.
#[derive(Clone, Copy)]
pub(crate) enum Found {
    /// The stored pointer.
    Value(NonNull<c_void>),
    /// The address of the slot holding the pointer.
    Slot(*mut *mut c_void),
}

impl Found {
    /// The `void *` a C caller receives.
    pub(crate) const fn address(self) -> *mut c_void {
        match self {
            Self::Value(ptr) => ptr.as_ptr(),
            Self::Slot(slot) => slot.cast(),
        }
    }
}

impl RdxtreeIter {
    /// `rdxtree_iter_init()` of <`kern/rdxtree_i.h`>, whose static inline the
    /// header keeps for its C callers.
    pub(crate) const fn new() -> Self {
        Self {
            node: ptr::null_mut(),
            key: RdxtreeKey::LAST,
        }
    }
}

impl Rdxtree {
    /// `rdxtree_init()` of <kern/rdxtree.h>.
    pub(crate) const fn init(&mut self) {
        self.height = 0;
        self.root = ptr::null_mut();
    }

    /// A fresh node, or `Error::ResourceShortage` after shrinking the tree
    /// as `rdxtree_grow()` did.
    fn create_node(
        &mut self,
        height: c_uint,
    ) -> Result<NonNull<RdxtreeNode>, Error> {
        match RdxtreeNode::create(height) {
            Ok(node) => Ok(node),
            Err(error) => {
                self.shrink();
                Err(error)
            }
        }
    }

    /// `rdxtree_shrink()` in C.
    fn shrink(&mut self) {
        while self.height > 0 {
            // SAFETY: above height zero the root is a tagged node.
            let node = unsafe { Entry::node_from_raw(self.root) };

            // SAFETY: `node` is a live node of this tree.
            if unsafe { (*node.as_ptr()).nr_entries } != 1 {
                break;
            }

            // SAFETY: `node` is live.
            let Some(entry) = (unsafe { (*node.as_ptr()).entry(0) }) else {
                break;
            };

            if self.height > 1 {
                let Entry::Node(child) = entry else {
                    break;
                };

                // SAFETY: the child is a live node of this tree.
                unsafe { (*child.as_ptr()).unlink() };
            }

            self.height -= 1;
            self.root = entry.into_raw();
            RdxtreeNode::destroy(node);
        }
    }

    /// `rdxtree_grow()` in C.
    fn grow(&mut self, key: RdxtreeKey) -> Result<(), Error> {
        let mut new_height = self.height + 1;

        while key > RdxtreeKey::max_for_height(new_height) {
            new_height += 1;
        }

        if self.root.is_null() {
            self.height = new_height;
            return Ok(());
        }

        let mut root = if self.height == 0 {
            // SAFETY: the check above proves the root is not null.
            let entry = unsafe { Entry::from_non_null(self.root) };
            let node = self.create_node(0)?;

            // SAFETY: `node` is fresh and the entry is a live stored
            // pointer.
            unsafe {
                (*node.as_ptr()).bm_clear(0);
                (*node.as_ptr()).insert(0, entry);
            }

            self.height = 1;
            self.root = Entry::Node(node).into_raw();
            node
        } else {
            // SAFETY: above height zero the root is a tagged node.
            unsafe { Entry::node_from_raw(self.root) }
        };

        while new_height > self.height {
            let node = self.create_node(self.height)?;

            // SAFETY: `root` is a live node of this tree and `node` is a
            // fresh one.
            unsafe {
                (*root.as_ptr()).link(node, 0);

                if (*root.as_ptr()).bm_is_empty() {
                    (*node.as_ptr()).bm_clear(0);
                }

                (*node.as_ptr()).insert(0, Entry::Node(root));
            }

            self.height += 1;
            self.root = Entry::Node(node).into_raw();
            root = node;
        }

        Ok(())
    }

    /// `rdxtree_insert_common()` in C.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] when `key` is already used, and
    /// [`Error::ResourceShortage`] when a node cannot be allocated.
    pub(crate) fn insert(
        &mut self,
        key: RdxtreeKey,
        ptr: NonNull<c_void>,
    ) -> Result<*mut *mut c_void, Error> {
        if key > RdxtreeKey::max_for_height(self.height) {
            self.grow(key)?;
        }

        let mut height = self.height;

        if height == 0 {
            if !self.root.is_null() {
                return Err(Error::InvalidArgument);
            }

            self.root = ptr.as_ptr();
            return Ok(ptr::addr_of_mut!(self.root));
        }

        let mut node = Entry::from_raw(self.root).and_then(Entry::node);
        let mut prev: Option<NonNull<RdxtreeNode>> = None;
        let mut index = 0usize;
        let mut shift = (height - 1) * RDXTREE_RADIX;

        loop {
            let current = if let Some(current) = node {
                current
            } else {
                let created = match RdxtreeNode::create(height - 1) {
                    Ok(created) => created,
                    Err(error) => {
                        match prev {
                            Some(prev) => self.cleanup(prev),
                            None => self.height = 0,
                        }
                        return Err(error);
                    }
                };

                match prev {
                    Some(parent) => {
                        // SAFETY: `parent` is a live node of this tree,
                        // and `index` is the slot the previous
                        // iteration descended through.
                        unsafe {
                            (*created.as_ptr()).link(parent, index);
                            (*parent.as_ptr())
                                .insert(index, Entry::Node(created));
                        }
                    }
                    None => self.root = Entry::Node(created).into_raw(),
                }

                created
            };

            index = key.index_at(shift);
            // SAFETY: `current` is a live node of this tree.
            let entry = unsafe { (*current.as_ptr()).entry(index) };

            shift = shift.wrapping_sub(RDXTREE_RADIX);
            height -= 1;

            if height == 0 {
                if entry.is_some() {
                    return Err(Error::InvalidArgument);
                }

                // SAFETY: `current` is a live node, and the slot is empty.
                unsafe {
                    (*current.as_ptr()).insert(index, Entry::Ptr(ptr));
                }
                RdxtreeNode::insert_bm_clear(current, index);

                // SAFETY: `current` is live and `index` addresses its slot.
                return Ok(unsafe {
                    ptr::addr_of_mut!((*current.as_ptr()).entries[index])
                });
            }

            match entry {
                None => node = None,
                Some(Entry::Node(child)) => node = Some(child),
                // A stored pointer above the bottom of a tree is not a
                // state this module can build.
                Some(Entry::Ptr(_)) => return Err(Error::InvalidArgument),
            }
            prev = Some(current);
        }
    }

    /// `rdxtree_insert_alloc_common()` in C.
    ///
    /// # Errors
    ///
    /// As [`Rdxtree::insert`].
    pub(crate) fn insert_alloc(
        &mut self,
        ptr: NonNull<c_void>,
    ) -> Result<(RdxtreeKey, *mut *mut c_void), Error> {
        let mut height = self.height;

        if height == 0 {
            if self.root.is_null() {
                self.root = ptr.as_ptr();
                return Ok((RdxtreeKey::ZERO, ptr::addr_of_mut!(self.root)));
            }

            let key = RdxtreeKey::max_for_height(0).wrapping_add(1);
            return self.insert(key, ptr).map(|slot| (key, slot));
        }

        // SAFETY: above height zero the root is a tagged node.
        let mut node = Some(unsafe { Entry::node_from_raw(self.root) });
        let mut parent: Option<NonNull<RdxtreeNode>> = None;
        let mut index = 0usize;
        let mut key = RdxtreeKey::ZERO;
        let mut shift = (height - 1) * RDXTREE_RADIX;

        loop {
            let current = if let Some(current) = node {
                current
            } else {
                // The root is never null in this function, so a node
                // that the descent found missing has a parent to be
                // linked into.
                let Some(parent) = parent else {
                    return Err(Error::InvalidArgument);
                };

                let created = match RdxtreeNode::create(height - 1) {
                    Ok(created) => created,
                    Err(error) => {
                        self.cleanup(parent);
                        return Err(error);
                    }
                };

                // SAFETY: `parent` is a live node of this tree, and
                // `index` is the slot the previous iteration descended
                // through.
                unsafe {
                    (*created.as_ptr()).link(parent, index);
                    (*parent.as_ptr()).insert(index, Entry::Node(created));
                }

                created
            };

            // SAFETY: `current` is a live node of this tree.
            let Some(free) = (unsafe { (*current.as_ptr()).bm_first() })
            else {
                let key = RdxtreeKey::max_for_height(height).wrapping_add(1);
                return self.insert(key, ptr).map(|slot| (key, slot));
            };

            index = free;
            key = key.with_index(index, shift);

            // SAFETY: `current` is a live node of this tree.
            let entry = unsafe { (*current.as_ptr()).entry(index) };

            shift = shift.wrapping_sub(RDXTREE_RADIX);
            height -= 1;

            if height == 0 {
                if entry.is_some() {
                    return Err(Error::InvalidArgument);
                }

                // SAFETY: `current` is a live node, and the slot is empty.
                unsafe {
                    (*current.as_ptr()).insert(index, Entry::Ptr(ptr));
                }
                RdxtreeNode::insert_bm_clear(current, index);

                // SAFETY: `current` is live and `index` addresses its slot.
                return Ok((key, unsafe {
                    ptr::addr_of_mut!((*current.as_ptr()).entries[index])
                }));
            }

            match entry {
                None => node = None,
                Some(Entry::Node(child)) => node = Some(child),
                // A stored pointer above the bottom of a tree is not a
                // state this module can build.
                Some(Entry::Ptr(_)) => return Err(Error::InvalidArgument),
            }
            parent = Some(current);
        }
    }

    /// `rdxtree_remove()` in C.
    pub(crate) fn remove(
        &mut self,
        key: RdxtreeKey,
    ) -> Option<NonNull<c_void>> {
        let mut height = self.height;

        if key > RdxtreeKey::max_for_height(height) {
            return None;
        }

        if height == 0 {
            let entry = Entry::from_raw(self.root);
            self.root = ptr::null_mut();
            return entry.map(Entry::into_ptr);
        }

        // SAFETY: above height zero the root is a tagged node.
        let mut node = Some(unsafe { Entry::node_from_raw(self.root) });
        let mut shift = (height - 1) * RDXTREE_RADIX;

        loop {
            let current = node?;
            let index = key.index_at(shift);

            // SAFETY: `current` is a live node of this tree.
            let entry = unsafe { (*current.as_ptr()).entry(index) };

            shift = shift.wrapping_sub(RDXTREE_RADIX);
            height -= 1;

            if height == 0 {
                let ptr = entry?.into_ptr();

                // SAFETY: `current` is live.
                unsafe {
                    (*current.as_ptr()).remove(index);
                }
                RdxtreeNode::remove_bm_set(current, index);
                self.cleanup(current);
                return Some(ptr);
            }

            node = entry.and_then(Entry::node);
        }
    }

    /// `rdxtree_cleanup()` in C.
    fn cleanup(&mut self, node: NonNull<RdxtreeNode>) {
        let mut node = node;

        loop {
            // SAFETY: every node this walk visits is a live node of this
            // tree.
            let current = unsafe { &mut *node.as_ptr() };

            if !current.is_empty() {
                if current.parent.is_null() {
                    self.shrink();
                }
                break;
            }

            let parent = current.parent;

            if parent.is_null() {
                self.height = 0;
                self.root = ptr::null_mut();
                RdxtreeNode::destroy(node);
                break;
            }

            let index = slot_index(current.index);
            // SAFETY: a linked node's parent is live.
            let parent = unsafe { NonNull::new_unchecked(parent) };

            // SAFETY: `node` is live and `parent` is its parent.
            unsafe {
                (*node.as_ptr()).unlink();
                (*parent.as_ptr()).remove(index);
            }
            RdxtreeNode::destroy(node);
            node = parent;
        }
    }

    /// `rdxtree_lookup_common()` in C, with `get_slot` as [`Lookup`].
    pub(crate) fn lookup(
        &self,
        key: RdxtreeKey,
        want: Lookup,
    ) -> Option<Found> {
        let root = Entry::from_raw(self.root);

        let (mut node, mut height) = match root {
            Some(Entry::Node(node)) => {
                // SAFETY: `node` is a live node of this tree.
                (Some(node), unsafe { (*node.as_ptr()).height } + 1)
            }
            _ => (None, 0),
        };

        if key > RdxtreeKey::max_for_height(height) {
            return None;
        }

        if height == 0 {
            let root = root?;
            return Some(match want {
                Lookup::Value => Found::Value(root.into_ptr()),
                Lookup::Slot => {
                    Found::Slot(ptr::addr_of!(self.root).cast_mut())
                }
            });
        }

        let mut shift = (height - 1) * RDXTREE_RADIX;

        loop {
            let current = node?;
            let index = key.index_at(shift);

            // SAFETY: `current` is a live node of this tree.
            let entry = unsafe { (*current.as_ptr()).entry(index) };

            shift = shift.wrapping_sub(RDXTREE_RADIX);
            height -= 1;

            if height == 0 {
                let entry = entry?;
                return Some(match want {
                    Lookup::Value => Found::Value(entry.into_ptr()),
                    // SAFETY: `current` is live and `index` addresses its
                    // slot.
                    Lookup::Slot => Found::Slot(unsafe {
                        ptr::addr_of_mut!((*current.as_ptr()).entries[index])
                    }),
                });
            }

            node = entry.and_then(Entry::node);
        }
    }

    /// `rdxtree_walk_next()` in C; `rdxtree_walk()` calls it.
    fn walk_next(&self, iter: &mut RdxtreeIter) -> Option<NonNull<c_void>> {
        let root = match Entry::from_raw(self.root) {
            Some(Entry::Node(node)) => node,
            Some(Entry::Ptr(ptr)) => {
                if iter.key == RdxtreeKey::LAST {
                    iter.key = RdxtreeKey::ZERO;
                    return Some(ptr);
                }
                return None;
            }
            None => return None,
        };

        let mut key = iter.key.wrapping_add(1);

        if key == RdxtreeKey::ZERO && !iter.node.is_null() {
            return None;
        }

        'restart: loop {
            let mut node = root;
            // SAFETY: `root` is a live node of this tree.
            let mut height = unsafe { (*root.as_ptr()).height } + 1;

            if key > RdxtreeKey::max_for_height(height) {
                return None;
            }

            let mut shift = (height - 1) * RDXTREE_RADIX;

            loop {
                let prev = node;
                let mut index = key.index_at(shift);
                let orig_index = index;

                // SAFETY: `prev` is a live node of this tree.
                let Some((found_index, entry)) =
                    (unsafe { (*prev.as_ptr()).find(index) })
                else {
                    // The C shifts a 32-bit key by up to 36 here, which the
                    // target masks to 5 bits; the wrapping shift masks the
                    // same way.
                    shift = shift.wrapping_add(RDXTREE_RADIX);
                    key = key
                        .wrapping_shr(shift)
                        .wrapping_add(1)
                        .wrapping_shl(shift);

                    if key == RdxtreeKey::ZERO {
                        return None;
                    }

                    continue 'restart;
                };

                index = found_index;

                if orig_index != index {
                    key = key
                        .wrapping_shr(shift)
                        .wrapping_add(field_index(index - orig_index))
                        .wrapping_shl(shift);
                }

                shift = shift.wrapping_sub(RDXTREE_RADIX);
                height -= 1;

                if height == 0 {
                    iter.node = prev.as_ptr().cast();
                    iter.key = key;
                    return Some(entry.into_ptr());
                }

                // A stored pointer above the bottom of a tree is not a
                // state this module can build.
                node = entry.node()?;
            }
        }
    }

    /// `rdxtree_walk()` in C.
    pub(crate) fn walk(
        &self,
        iter: &mut RdxtreeIter,
    ) -> Option<NonNull<c_void>> {
        if iter.node.is_null() {
            return self.walk_next(iter);
        }

        let mut index = iter.key.wrapping_add(1).index_at(0);

        if index != 0 {
            let orig_index = index;

            // SAFETY: `walk_next` stored the node holding a pointer here.
            let node = unsafe { &*iter.node.cast::<RdxtreeNode>() };

            if let Some((found_index, entry)) = node.find(index) {
                index = found_index;
                iter.key = iter
                    .key
                    .wrapping_add(field_index(index - orig_index))
                    .wrapping_add(1);
                return Some(entry.into_ptr());
            }
        }

        self.walk_next(iter)
    }

    /// `rdxtree_remove_all()` in C.
    pub(crate) fn remove_all(&mut self) {
        if self.height == 0 {
            if !self.root.is_null() {
                self.root = ptr::null_mut();
            }
            return;
        }

        loop {
            let mut iter = RdxtreeIter::new();
            self.walk_next(&mut iter);

            if iter.node.is_null() {
                break;
            }

            // SAFETY: `walk_next` only reports live nodes, and only
            // non-null ones arrive here.
            let node = unsafe {
                NonNull::new_unchecked(iter.node.cast::<RdxtreeNode>())
            };

            // SAFETY: `node` is a live node of this tree.
            let parent = unsafe { (*node.as_ptr()).parent };

            if parent.is_null() {
                self.init();
            } else {
                // SAFETY: `node` is a live node of this tree.
                let index = unsafe { slot_index((*node.as_ptr()).index) };
                // SAFETY: a linked node's parent is live.
                let parent = unsafe { NonNull::new_unchecked(parent) };

                // SAFETY: `node` is live and `parent` is its parent.
                unsafe {
                    (*parent.as_ptr()).remove(index);
                }
                RdxtreeNode::remove_bm_set(parent, index);
                self.cleanup(parent);

                // SAFETY: `node` is live.
                unsafe { (*node.as_ptr()).parent = ptr::null_mut() };
            }

            RdxtreeNode::destroy(node);
        }
    }
}

/// `rdxtree_replace_slot()` in C: store `ptr` into `*slot`, returning the
/// previous value.
pub(crate) const fn replace_slot(
    slot: &mut *mut c_void,
    ptr: *mut c_void,
) -> *mut c_void {
    core::mem::replace(slot, ptr)
}
