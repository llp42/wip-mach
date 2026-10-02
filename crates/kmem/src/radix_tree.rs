// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! A radix tree of `T` over 32-bit keys.
//!
//! Keys are dense integers: one level of the tree selects 6 key bits, so
//! a tree over the full [`RadixKey`] domain is at most 6 levels deep and
//! a lookup is at most 6 node chases.  Nodes are allocated through the
//! owner's [`Alloc`] and are freed on removal and on drop.  The tree
//! never waits; a short heap is [`Error::ResourceShortage`].
//!
//! | operation | cost |
//! |---|---|
//! | [`get`](RadixTree::get), [`insert`](RadixTree::insert), [`remove`](RadixTree::remove) | O(height) |
//! | [`insert_alloc`](RadixTree::insert_alloc) | O(height), lowest free key |
//! | [`iter`](RadixTree::iter) | O(1) amortised per item |
//! | [`clear`](RadixTree::clear) | O(nodes) |
//!
//! A tree is not internally locked; the caller serialises it.

// Descent paths and the iterator stack index a fixed `MAX_HEIGHT` array
// under an invariant the walk itself maintains: `depth` is never more
// than the key's bit depth.  Slot indices come from a 6-bit mask.
#![expect(
    clippy::indexing_slicing,
    reason = "depth and slot indices are bounded by the descent invariant"
)]
#![expect(
    clippy::cast_possible_truncation,
    reason = "slot indices fit the 6-bit fanout mask"
)]

use crate::alloc::{Alloc, AllocError, allocate, release};
use core::alloc::Layout;
use core::fmt;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

/// The key bits one level of the tree selects.
const RADIX_BITS: u32 = 6;

/// The entries one node holds.
const RADIX_SIZE: usize = 1 << RADIX_BITS;

/// The key bits one level of the tree selects, as a mask.
const RADIX_MASK: u32 = (RADIX_SIZE - 1) as u32;

/// Levels a [`RadixKey`] can need: `ceil(32 / 6)`.
const MAX_HEIGHT: u32 = u32::BITS.div_ceil(RADIX_BITS);

/// The height limit covers the whole key space, so no descent can need
/// a shift of 32 bits or more.
const _: () = assert!(RADIX_BITS * MAX_HEIGHT >= u32::BITS);

/// The length of a descent path.
const MAX_HEIGHT_USIZE: usize = MAX_HEIGHT as usize;

/// Every slot of a fresh node has free capacity under it.
const FREE_BM_FULL: u64 = u64::MAX;

/// The layout of one node.
const fn node_layout<T>() -> Layout {
    Layout::new::<Node<T>>()
}

/// A tree key: a 32-bit integer address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RadixKey(u32);

impl RadixKey {
    /// The first key, which a tree of height zero holds.
    const ZERO: Self = Self(0);

    /// The key an integer stands for.
    #[must_use]
    pub const fn from_raw(bits: u32) -> Self {
        Self(bits)
    }

    /// The integer this key stands for.
    #[must_use]
    pub const fn into_raw(self) -> u32 {
        self.0
    }

    /// The largest key a tree of `height` levels holds.
    const fn max_for_height(height: u32) -> Self {
        let shift = RADIX_BITS * height;
        if shift < u32::BITS {
            Self((1 << shift) - 1)
        } else {
            Self(u32::MAX)
        }
    }

    /// The entry this key selects at `shift`, `(key >> shift) & mask`.
    const fn index_at(self, shift: u32) -> usize {
        ((self.0 >> shift) & RADIX_MASK) as usize
    }

    /// `key | (index << shift)`, the key an allocation walk assembles.
    const fn with_index(self, index: usize, shift: u32) -> Self {
        Self(self.0 | ((index as u32) << shift))
    }
}

/// What a node slot holds.
enum Entry<T> {
    /// A value at the bottom of the tree.
    Value(T),
    /// A child node.
    Node(NonNull<Node<T>>),
}

impl<T> Entry<T> {
    /// The stored value, or `None` for a child node.
    fn into_value(self) -> Option<T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Node(_) => None,
        }
    }

    /// The stored value, by reference.
    const fn as_value(&self) -> Option<&T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Node(_) => None,
        }
    }

    /// The stored value, uniquely, by reference.
    const fn as_value_mut(&mut self) -> Option<&mut T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Node(_) => None,
        }
    }
}

/// One level of the tree.
///
/// # Invariants
///
/// Bit `i` of `free_bm` is set when slot `i` is empty, or holds a node
/// whose subtree still has a free key.  `nr_entries` counts occupied
/// slots.
struct Node<T> {
    nr_entries: u32,
    free_bm: u64,
    slots: [Option<Entry<T>>; RADIX_SIZE],
}

impl<T> Node<T> {
    /// A node with every slot free.
    fn new() -> Self {
        Self {
            nr_entries: 0,
            free_bm: FREE_BM_FULL,
            slots: core::array::from_fn(|_| None),
        }
    }

    /// The first slot with free capacity under it.
    const fn first_free(&self) -> Option<usize> {
        if self.free_bm == 0 {
            None
        } else {
            Some(self.free_bm.trailing_zeros() as usize)
        }
    }

    /// Clears bit `index`: the slot or its subtree is now full.
    const fn clear_free(&mut self, index: usize) {
        self.free_bm &= !(1_u64 << index);
    }

    /// Sets bit `index`: the slot or its subtree has free capacity.
    const fn set_free(&mut self, index: usize) {
        self.free_bm |= 1_u64 << index;
    }

    /// Whether the node holds no entries.
    const fn is_empty(&self) -> bool {
        self.nr_entries == 0
    }

    /// Whether the node's subtree still has a free key.
    const fn has_free(&self) -> bool {
        self.free_bm != 0
    }

    /// The slot at `index`.
    ///
    /// # Safety
    ///
    /// `index` is below `RADIX_SIZE`.
    unsafe fn slot(&self, index: usize) -> Option<&Entry<T>> {
        // SAFETY: `index` is a slot index of this node.
        unsafe { self.slots.get_unchecked(index).as_ref() }
    }

    /// The slot at `index`, uniquely.
    ///
    /// # Safety
    ///
    /// `index` is below `RADIX_SIZE`.
    unsafe fn slot_mut(&mut self, index: usize) -> &mut Option<Entry<T>> {
        // SAFETY: `index` is a slot index of this node.
        unsafe { self.slots.get_unchecked_mut(index) }
    }

    /// Takes the entry in `index`, leaving the slot free.
    ///
    /// # Safety
    ///
    /// `index` is below `RADIX_SIZE`.
    unsafe fn take(&mut self, index: usize) -> Option<Entry<T>> {
        // SAFETY: `index` is a slot index of this node.
        let entry = unsafe { self.slot_mut(index) }.take();
        // The bookkeeping follows the entry: a slot is taken when it
        // holds one, and a free slot stays free.
        entry.inspect(|_| {
            self.nr_entries -= 1;
            self.set_free(index);
        })
    }

    /// Takes the value in `index` when the slot holds one, and nothing
    /// otherwise: an empty slot and a child node both leave the tree as
    /// it is.
    ///
    /// # Safety
    ///
    /// `index` is below `RADIX_SIZE`.
    unsafe fn take_value(&mut self, index: usize) -> Option<T> {
        // SAFETY: `index` is a slot index of this node.
        if let Some(Entry::Value(_)) = unsafe { self.slot(index) } {
            // SAFETY: `index` is a slot index and the slot holds a value.
            return unsafe { self.take(index) }.and_then(Entry::into_value);
        }
        None
    }

    /// Puts `entry` into `index`, which must be free.
    ///
    /// A value fills the slot; a child node keeps the free bit when its
    /// own subtree still has room.
    ///
    /// # Safety
    ///
    /// `index` is below `RADIX_SIZE` and the slot is empty.
    unsafe fn put(&mut self, index: usize, entry: Entry<T>) {
        let still_free = match &entry {
            Entry::Value(_) => false,
            // SAFETY: a stored node is live.
            Entry::Node(child) => unsafe { child.as_ref().has_free() },
        };
        // SAFETY: `index` is a slot index of this node.
        let slot = unsafe { self.slot_mut(index) };
        debug_assert!(slot.is_none());
        *slot = Some(entry);
        self.nr_entries += 1;
        if still_free {
            self.set_free(index);
        } else {
            self.clear_free(index);
        }
    }
}

/// The result of a tree operation that can fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The key already holds a value.
    Exists,
    /// Memory is short.
    ResourceShortage,
}

impl From<AllocError> for Error {
    fn from(_: AllocError) -> Self {
        Self::ResourceShortage
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exists => f.write_str("key already holds a value"),
            Self::ResourceShortage => f.write_str("memory allocation failed"),
        }
    }
}

/// One node a descent visited: the node and the slot it left through.
struct Frame<T> {
    node: NonNull<Node<T>>,
    index: usize,
}

/// A radix tree of `T` over [`RadixKey`].
pub struct RadixTree<T, A: Alloc> {
    /// Levels to traverse; 0 means `root` is a stored value.
    height: u32,
    root: Option<Entry<T>>,
    alloc: A,
}

// SAFETY: a tree owns its nodes and values, and moves its allocator with it.
#[expect(
    clippy::non_send_fields_in_send_ty,
    reason = "NonNull nodes are only reached through the owning tree"
)]
unsafe impl<T: Send, A: Alloc + Send> Send for RadixTree<T, A> {}
// SAFETY: shared access is shared access to the values only.
unsafe impl<T: Sync, A: Alloc + Sync> Sync for RadixTree<T, A> {}

impl<T, A: Alloc> RadixTree<T, A> {
    /// An empty tree that allocates through `alloc`.
    #[must_use]
    pub const fn new(alloc: A) -> Self {
        Self {
            height: 0,
            root: None,
            alloc,
        }
    }

    /// Whether the tree holds no values.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// The value at `key`, if any.
    #[must_use]
    pub fn get(&self, key: RadixKey) -> Option<&T> {
        self.find(key)?.as_value()
    }

    /// A unique reference to the value at `key`, if any.
    #[must_use]
    pub fn get_mut(&mut self, key: RadixKey) -> Option<&mut T> {
        self.find_mut(key)?.as_value_mut()
    }

    /// Stores `value` at `key`, which must be free.
    ///
    /// # Errors
    ///
    /// [`Error::Exists`] when `key` already holds a value, and
    /// [`Error::ResourceShortage`] when a node cannot be allocated.  A
    /// failure leaves the tree unchanged.
    pub fn insert(&mut self, key: RadixKey, value: T) -> Result<(), Error> {
        if key > RadixKey::max_for_height(self.height) {
            self.grow(key)?;
        }
        if self.height == 0 {
            return if self.root.is_some() {
                Err(Error::Exists)
            } else {
                self.root = Some(Entry::Value(value));
                Ok(())
            };
        }
        self.place(key, value, false).map(|_| ())
    }

    /// Stores `value` at the lowest free key and hands back that key and
    /// a reference to the stored value.
    ///
    /// # Errors
    ///
    /// [`Error::ResourceShortage`] when a node cannot be allocated.  A
    /// failure leaves the tree unchanged.
    pub fn insert_alloc(
        &mut self,
        value: T,
    ) -> Result<(RadixKey, &mut T), Error> {
        if self.root.is_none() {
            self.root = Some(Entry::Value(value));
            return self.stored_at(RadixKey::ZERO);
        }
        if self.height == 0 {
            let key = RadixKey::max_for_height(0).with_index(1, 0);
            self.grow(key)?;
        }
        let (key, _) = self.place(RadixKey::ZERO, value, true)?;
        self.stored_at(key)
    }

    /// Replaces the value at `key`, handing the old one back.
    ///
    /// A free key is filled; the tree grows when `key` is past its
    /// current height.
    ///
    /// # Errors
    ///
    /// [`Error::ResourceShortage`] when a node cannot be allocated.  On
    /// failure `value` is dropped and the tree is unchanged.
    pub fn replace(
        &mut self,
        key: RadixKey,
        value: T,
    ) -> Result<Option<T>, Error> {
        if let Some(Entry::Value(old)) = self.find_mut(key) {
            return Ok(Some(core::mem::replace(old, value)));
        }
        self.insert(key, value)?;
        Ok(None)
    }

    /// Removes the value at `key`, if any.
    pub fn remove(&mut self, key: RadixKey) -> Option<T> {
        self.remove_entry(key)?.into_value()
    }

    /// Drops every value and frees every node.
    pub fn clear(&mut self) {
        self.height = 0;
        if let Some(root) = self.root.take() {
            self.free_entry(root);
        }
    }

    /// Walks the tree in key order.
    pub fn iter(&self) -> Iter<'_, T> {
        Iter::new(self)
    }
}

impl<'a, T, A: Alloc> IntoIterator for &'a RadixTree<T, A> {
    type Item = (RadixKey, &'a T);
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T, A: Alloc> RadixTree<T, A> {
    /// The entry at `key`, if the descent finds one.
    fn find(&self, key: RadixKey) -> Option<&Entry<T>> {
        if key > RadixKey::max_for_height(self.height) {
            return None;
        }
        let mut entry = self.root.as_ref()?;
        let mut height = self.height;
        let mut shift = height.saturating_sub(1) * RADIX_BITS;
        while height > 0 {
            let Entry::Node(node) = entry else {
                #[cfg(debug_assertions)]
                #[expect(
                    clippy::panic,
                    reason = "a value sits only at the bottom level"
                )]
                {
                    panic!("radix tree: a value sits above the bottom level");
                }
                #[cfg(not(debug_assertions))]
                return None;
            };
            // SAFETY: a stored node is live for the life of `self`.
            let node = unsafe { node.as_ref() };
            // SAFETY: `index_at` masks to a slot index.
            entry = unsafe { node.slot(key.index_at(shift)) }?;
            shift = shift.saturating_sub(RADIX_BITS);
            height -= 1;
        }
        Some(entry)
    }

    /// The entry at `key`, uniquely, if the descent finds one.
    fn find_mut(&mut self, key: RadixKey) -> Option<&mut Entry<T>> {
        if key > RadixKey::max_for_height(self.height) {
            return None;
        }
        let mut entry = self.root.as_mut()?;
        let mut height = self.height;
        let mut shift = height.saturating_sub(1) * RADIX_BITS;
        while height > 0 {
            let Entry::Node(node) = entry else {
                #[cfg(debug_assertions)]
                #[expect(
                    clippy::panic,
                    reason = "a value sits only at the bottom level"
                )]
                {
                    panic!("radix tree: a value sits above the bottom level");
                }
                #[cfg(not(debug_assertions))]
                return None;
            };
            // SAFETY: a stored node is live for the life of `self`, and
            // `&mut self` keeps this access unique.
            let node = unsafe { node.as_mut() };
            // SAFETY: `index_at` masks to a slot index.
            entry = unsafe { node.slot_mut(key.index_at(shift)) }.as_mut()?;
            shift = shift.saturating_sub(RADIX_BITS);
            height -= 1;
        }
        Some(entry)
    }

    /// The value a call just stored at `key`, by reference.
    fn stored_at(
        &mut self,
        key: RadixKey,
    ) -> Result<(RadixKey, &mut T), Error> {
        self.find_mut(key)
            .and_then(Entry::as_value_mut)
            .map(|stored| (key, stored))
            .ok_or(Error::ResourceShortage)
    }

    /// Descends to a leaf and stores `value`.
    ///
    /// When `lowest_free` is set the walk takes the lowest free slot at
    /// each level and assembles that key; otherwise it follows `key`.
    /// On failure the nodes this call created are freed and the tree is
    /// left as it was.
    fn place(
        &mut self,
        key: RadixKey,
        value: T,
        lowest_free: bool,
    ) -> Result<(RadixKey, *mut Option<Entry<T>>), Error> {
        let mut path: [Frame<T>; MAX_HEIGHT_USIZE] =
            core::array::from_fn(|_| Frame {
                node: NonNull::dangling(),
                index: 0,
            });
        let mut depth = 0_usize;
        let mut created: [NonNull<Node<T>>; MAX_HEIGHT_USIZE] =
            core::array::from_fn(|_| NonNull::dangling());
        let mut created_n = 0_usize;
        let mut key = if lowest_free { RadixKey::ZERO } else { key };
        let mut height = self.height;
        let mut shift = (height - 1) * RADIX_BITS;

        let mut current = match self.root.as_mut() {
            Some(Entry::Node(node)) => *node,
            Some(Entry::Value(_)) => return Err(Error::Exists),
            None => match self.create_node() {
                Ok(node) => {
                    created[created_n] = node;
                    created_n += 1;
                    self.root = Some(Entry::Node(node));
                    node
                }
                Err(error) => {
                    drop(value);
                    return Err(error);
                }
            },
        };

        loop {
            // SAFETY: `current` is a live node of this tree.
            let node = unsafe { current.as_mut() };
            let index = if lowest_free {
                if let Some(index) = node.first_free() {
                    index
                } else {
                    self.rollback_created(&created, created_n);
                    debug_assert!(
                        self.height < MAX_HEIGHT,
                        "radix tree: the key space is exhausted"
                    );
                    let next =
                        RadixKey::max_for_height(self.height).with_index(1, 0);
                    self.grow(next)?;
                    return self.place(next, value, true);
                }
            } else {
                key.index_at(shift)
            };
            if lowest_free {
                key = key.with_index(index, shift);
            }

            if height == 1 {
                // SAFETY: `index` is a slot index of `node`.
                if unsafe { node.slot(index) }.is_some() {
                    self.rollback_created(&created, created_n);
                    drop(value);
                    return Err(Error::Exists);
                }
                // SAFETY: `index` is in range and the slot is empty.
                unsafe {
                    node.put(index, Entry::Value(value));
                }
                path[depth] = Frame {
                    node: current,
                    index,
                };
                depth += 1;
                Self::mark_full_along(&path[depth - 1], &path[..depth - 1]);
                // SAFETY: `index` addresses `node`'s slot.
                let slot = ptr::from_mut(unsafe { node.slot_mut(index) });
                return Ok((key, slot));
            }

            // SAFETY: `index` is a slot index of `node`.
            let child = match unsafe { node.slot(index) } {
                Some(Entry::Node(child)) => *child,
                Some(Entry::Value(_)) => {
                    self.rollback_created(&created, created_n);
                    drop(value);
                    return Err(Error::Exists);
                }
                None => match self.create_node() {
                    Ok(child) => {
                        created[created_n] = child;
                        created_n += 1;
                        // SAFETY: the slot is empty and `index` is in range.
                        unsafe {
                            node.put(index, Entry::Node(child));
                        }
                        child
                    }
                    Err(error) => {
                        self.rollback_created(&created, created_n);
                        drop(value);
                        return Err(error);
                    }
                },
            };
            path[depth] = Frame {
                node: current,
                index,
            };
            depth += 1;
            current = child;
            shift = shift.saturating_sub(RADIX_BITS);
            height -= 1;
        }
    }

    /// Frees the nodes a failed descent created.
    ///
    /// Those nodes hold only pointers to each other, so the blocks are
    /// returned without walking slots: a deeper node is already freed.
    fn rollback_created(
        &mut self,
        created: &[NonNull<Node<T>>; MAX_HEIGHT as usize],
        n: usize,
    ) {
        for i in (0..n).rev() {
            // SAFETY: the block came from `create_node` with this layout.
            unsafe {
                release(&self.alloc, created[i].cast(), node_layout::<T>());
            }
        }
        if n > 0
            && let Some(Entry::Node(node)) = self.root
            && created[..n].contains(&node)
        {
            self.root = None;
            self.height = 0;
        }
    }

    /// Clears free bits upward after the leaf node filled up.
    ///
    /// `leaf` is the node just filled and `ancestors` the frames it was
    /// reached through: a parent keeps its free bit while some other slot
    /// under it still has room.
    fn mark_full_along(leaf: &Frame<T>, ancestors: &[Frame<T>]) {
        // SAFETY: the frame names a live node of this tree.
        if unsafe { leaf.node.as_ref() }.has_free() {
            return;
        }
        for frame in ancestors.iter().rev() {
            let mut parent = frame.node;
            // SAFETY: the frame names a live node of this tree.
            let parent = unsafe { parent.as_mut() };
            parent.clear_free(frame.index);
            if parent.has_free() {
                return;
            }
        }
    }

    /// Sets free bits upward after a leaf slot was emptied.
    ///
    /// `ancestors` are the frames the leaf was reached through; the walk
    /// stops at a parent whose bit was already set.
    fn mark_free_along(ancestors: &[Frame<T>]) {
        for frame in ancestors.iter().rev() {
            let mut parent = frame.node;
            // SAFETY: the frame names a live node of this tree.
            let parent = unsafe { parent.as_mut() };
            let already = parent.free_bm & (1_u64 << frame.index) != 0;
            parent.set_free(frame.index);
            if already {
                return;
            }
        }
    }

    /// A fresh node from the owner's allocator.
    fn create_node(&self) -> Result<NonNull<Node<T>>, Error> {
        let block = allocate(&self.alloc, node_layout::<T>(), false)?;
        // SAFETY: the block is `Node<T>`-sized and -aligned.
        let node = block.cast::<Node<T>>();
        // SAFETY: the block is uninitialised room for one node.
        unsafe { node.as_ptr().write(Node::new()) };
        Ok(node)
    }

    /// Drops a node's entries and returns its block.
    ///
    /// # Safety
    ///
    /// `node` is a live node this tree owns and nothing else reaches.
    unsafe fn destroy_node(&mut self, node: NonNull<Node<T>>) {
        // SAFETY: `node` is live and uniquely reached here.
        let owned = unsafe { ptr::read(node.as_ptr()) };
        let mut slots = owned.slots;
        for slot in &mut slots {
            if let Some(entry) = slot.take() {
                self.free_entry(entry);
            }
        }
        // SAFETY: the block came from `create_node` with this layout.
        unsafe {
            release(&self.alloc, node.cast(), node_layout::<T>());
        }
    }

    /// Drops a value, or a whole subtree of nodes.
    fn free_entry(&mut self, entry: Entry<T>) {
        match entry {
            Entry::Value(value) => drop(value),
            Entry::Node(node) => {
                // SAFETY: the node is live and this tree owns it.
                unsafe { self.destroy_node(node) };
            }
        }
    }

    /// Grows the tree until `key` fits.
    fn grow(&mut self, key: RadixKey) -> Result<(), Error> {
        let mut new_height = self.height.saturating_add(1);
        while key > RadixKey::max_for_height(new_height) {
            new_height += 1;
        }

        if self.root.is_none() {
            self.height = new_height;
            return Ok(());
        }

        let mut root = if self.height == 0 {
            let mut node = self.create_node()?;
            match self.root.take() {
                Some(Entry::Value(value)) => {
                    // SAFETY: the node is fresh and the slot is free.
                    unsafe { node.as_mut().put(0, Entry::Value(value)) };
                }
                other => {
                    self.root = other;
                    // SAFETY: the new node is empty.
                    unsafe { self.destroy_node(node) };
                    #[cfg(debug_assertions)]
                    #[expect(
                        clippy::panic,
                        reason = "a height-zero root is a value or nothing"
                    )]
                    {
                        panic!("radix tree: a node root at height zero");
                    }
                    #[cfg(not(debug_assertions))]
                    return Err(Error::ResourceShortage);
                }
            }
            self.height = 1;
            self.root = Some(Entry::Node(node));
            node
        } else {
            match self.root {
                Some(Entry::Node(node)) => node,
                Some(Entry::Value(_)) | None => {
                    #[cfg(debug_assertions)]
                    #[expect(
                        clippy::panic,
                        reason = "a value root lives only at height zero"
                    )]
                    {
                        panic!(
                            "radix tree: a value root at a height above zero"
                        );
                    }
                    #[cfg(not(debug_assertions))]
                    return Err(Error::ResourceShortage);
                }
            }
        };

        while new_height > self.height {
            let mut node = self.create_node()?;
            // SAFETY: both nodes are live; `root` becomes the child.
            unsafe {
                let parent = node.as_mut();
                let child_free = root.as_ref().has_free();
                parent.put(0, Entry::Node(root));
                if !child_free {
                    parent.clear_free(0);
                }
            }
            self.height += 1;
            self.root = Some(Entry::Node(node));
            root = node;
        }
        Ok(())
    }

    /// Removes the entry at `key` and hands it back.
    fn remove_entry(&mut self, key: RadixKey) -> Option<Entry<T>> {
        if self.root.is_none() || key > RadixKey::max_for_height(self.height) {
            return None;
        }
        if self.height == 0 {
            return self.root.take();
        }

        let mut path: [Frame<T>; MAX_HEIGHT_USIZE] =
            core::array::from_fn(|_| Frame {
                node: NonNull::dangling(),
                index: 0,
            });
        let mut depth = 0_usize;
        let mut height = self.height;
        let mut shift = (height - 1) * RADIX_BITS;
        let mut current = match self.root {
            Some(Entry::Node(node)) => node,
            Some(Entry::Value(_)) | None => {
                #[cfg(debug_assertions)]
                #[expect(
                    clippy::panic,
                    reason = "a value root lives only at height zero"
                )]
                {
                    panic!("radix tree: a value root at a height above zero");
                }
                #[cfg(not(debug_assertions))]
                return None;
            }
        };

        loop {
            // SAFETY: `current` is a live node of this tree.
            let node = unsafe { current.as_mut() };
            let index = key.index_at(shift);
            path[depth] = Frame {
                node: current,
                index,
            };
            depth += 1;

            if height == 1 {
                // SAFETY: `index` is a slot index of `node`.
                let value = unsafe { node.take_value(index) }?;
                Self::mark_free_along(&path[..depth - 1]);
                self.cleanup_along(&path, depth);
                return Some(Entry::Value(value));
            }

            // SAFETY: `index` is a slot index of `node`.
            let child = match unsafe { node.slot(index) } {
                Some(Entry::Node(child)) => *child,
                Some(Entry::Value(_)) | None => return None,
            };
            current = child;
            shift = shift.saturating_sub(RADIX_BITS);
            height -= 1;
        }
    }

    /// Frees empty nodes along `path` and shrinks a one-entry root.
    fn cleanup_along(&mut self, path: &[Frame<T>], depth: usize) {
        for i in (0..depth).rev() {
            let mut current = path[i].node;
            // SAFETY: the frame names a live node of this tree.
            let node = unsafe { current.as_mut() };
            if !node.is_empty() {
                break;
            }
            if i == 0 {
                // SAFETY: the empty root is uniquely reached from `self`.
                unsafe { self.destroy_node(path[i].node) };
                self.root = None;
                self.height = 0;
                return;
            }
            let parent_index = path[i - 1].index;
            let mut parent_ptr = path[i - 1].node;
            // SAFETY: the parent is live and its slot holds this child.
            let parent = unsafe { parent_ptr.as_mut() };
            // SAFETY: `parent_index` is a slot index of `parent`.
            while let Some(entry) = unsafe { parent.take(parent_index) } {
                // SAFETY: the entry came from the parent's slot.
                self.free_entry(entry);
            }
        }
        self.shrink();
    }

    /// Collapses a root that holds only one entry.
    fn shrink(&mut self) {
        while self.height > 0 {
            let Some(Entry::Node(node)) = self.root else {
                #[cfg(debug_assertions)]
                #[expect(
                    clippy::panic,
                    reason = "the root is a node while the height is positive"
                )]
                {
                    panic!(
                        "radix tree: the root is not a node above height zero"
                    );
                }
                #[cfg(not(debug_assertions))]
                {
                    self.height = 0;
                    return;
                }
            };
            // SAFETY: the root is a live node.
            let root = unsafe { node.as_ref() };
            if root.nr_entries != 1 {
                return;
            }
            let Some(index) = (0..RADIX_SIZE).find(|&i| {
                // SAFETY: `i` is a slot index.
                unsafe { root.slot(i).is_some() }
            }) else {
                #[cfg(debug_assertions)]
                #[expect(
                    clippy::panic,
                    reason = "one entry names one occupied slot"
                )]
                {
                    panic!("radix tree: one entry but no occupied slot");
                }
                #[cfg(not(debug_assertions))]
                return;
            };
            let mut node = node;
            // SAFETY: `index` holds the single entry.
            let entry = unsafe { node.as_mut().take(index) };
            // SAFETY: the node is now empty and uniquely reached.
            unsafe { self.destroy_node(node) };
            self.root = entry;
            self.height -= 1;
        }
    }
}

impl<T, A: Alloc> Drop for RadixTree<T, A> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl<T: fmt::Debug, A: Alloc> fmt::Debug for RadixTree<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

/// A forward walk of a [`RadixTree`] in key order.
pub struct Iter<'a, T> {
    stack: [IterFrame<T>; MAX_HEIGHT as usize],
    depth: usize,
    pending: Option<(RadixKey, &'a T)>,
    _marker: PhantomData<&'a T>,
}

struct IterFrame<T> {
    node: NonNull<Node<T>>,
    next: usize,
    /// The key bits this node's level and everything above it have set.
    base: RadixKey,
    /// Levels this node still selects, including its own slots.
    height: u32,
}

impl<'a, T> Iter<'a, T> {
    fn new<A: Alloc>(tree: &'a RadixTree<T, A>) -> Self {
        let mut iter = Self {
            stack: core::array::from_fn(|_| IterFrame {
                node: NonNull::dangling(),
                next: 0,
                base: RadixKey::ZERO,
                height: 0,
            }) as [IterFrame<T>; MAX_HEIGHT_USIZE],
            depth: 0,
            pending: None,
            _marker: PhantomData,
        };
        match tree.root.as_ref() {
            Some(Entry::Value(value)) => {
                iter.pending = Some((RadixKey::ZERO, value));
            }
            Some(Entry::Node(node)) => {
                iter.push(*node, RadixKey::ZERO, tree.height);
            }
            None => {}
        }
        iter
    }

    /// Records `node` as the level to scan next.
    const fn push(
        &mut self,
        node: NonNull<Node<T>>,
        base: RadixKey,
        height: u32,
    ) {
        self.stack[self.depth] = IterFrame {
            node,
            next: 0,
            base,
            height,
        };
        self.depth += 1;
    }

    /// The next value at or below the top of the stack.
    fn advance(&mut self) -> Option<(RadixKey, &'a T)> {
        while self.depth > 0 {
            let at = self.depth - 1;
            let (node, base, height) = {
                let frame = &self.stack[at];
                (frame.node, frame.base, frame.height)
            };
            // SAFETY: the frame names a live node the tree still owns.
            let node_ref = unsafe { node.as_ref() };
            while self.stack[at].next < RADIX_SIZE {
                let index = self.stack[at].next;
                self.stack[at].next += 1;
                // SAFETY: `index` is a slot index.
                let Some(entry) = (unsafe { node_ref.slot(index) }) else {
                    continue;
                };
                let shift = (height - 1) * RADIX_BITS;
                let key = base.with_index(index, shift);
                return match entry {
                    Entry::Value(value) => Some((key, value)),
                    Entry::Node(child) => {
                        self.push(*child, key, height - 1);
                        self.advance()
                    }
                };
            }
            self.depth -= 1;
        }
        None
    }
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = (RadixKey, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        self.pending.take().or_else(|| self.advance())
    }
}

impl<T> fmt::Debug for Iter<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Iter")
            .field("depth", &self.depth)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{Heap, Tracked};
    use core::cell::Cell;
    use std::vec::Vec;

    fn key(bits: u32) -> RadixKey {
        RadixKey::from_raw(bits)
    }

    #[test]
    fn empty_tree_holds_nothing() {
        let heap = Heap::new();
        let mut tree: RadixTree<u32, &Heap> = RadixTree::new(&heap);
        assert!(tree.is_empty());
        assert!(tree.get(key(0)).is_none());
        assert!(tree.remove(key(0)).is_none());
        assert_eq!(tree.iter().count(), 0);
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn height_zero_holds_one_value() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(0), 42).unwrap();
        assert!(!tree.is_empty());
        assert_eq!(tree.get(key(0)), Some(&42));
        assert!(tree.get(key(1)).is_none());
        assert_eq!(tree.iter().collect::<Vec<_>>(), vec![(key(0), &42)]);
        assert_eq!(tree.remove(key(0)), Some(42));
        assert!(tree.is_empty());
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn insert_duplicate_leaves_the_old_value() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(0), 1).unwrap();
        assert_eq!(tree.insert(key(0), 2), Err(Error::Exists));
        assert_eq!(tree.get(key(0)), Some(&1));
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn insert_alloc_fills_from_zero() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        for i in 0..100_u32 {
            let (k, v) = tree.insert_alloc(i).unwrap();
            assert_eq!(k, key(i));
            assert_eq!(*v, i);
        }
        assert_eq!(tree.iter().count(), 100);
    }

    #[test]
    fn insert_alloc_reuses_a_freed_key() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        for i in 0..5_u32 {
            let _ = tree.insert_alloc(i).unwrap();
        }
        assert_eq!(tree.remove(key(1)), Some(1));
        assert_eq!(tree.remove(key(3)), Some(3));
        assert_eq!(tree.insert_alloc(50).unwrap().0, key(1));
        assert_eq!(tree.insert_alloc(51).unwrap().0, key(3));
        assert_eq!(tree.insert_alloc(52).unwrap().0, key(5));
    }

    #[test]
    fn get_mut_and_replace() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(7), 1).unwrap();
        *tree.get_mut(key(7)).unwrap() += 1;
        assert_eq!(tree.replace(key(7), 9), Ok(Some(2)));
        assert_eq!(tree.get(key(7)), Some(&9));
        assert_eq!(tree.replace(key(8), 3), Ok(None));
        assert_eq!(tree.get(key(8)), Some(&3));
    }

    #[test]
    fn replace_fills_a_free_key() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        assert_eq!(tree.replace(key(0), 1), Ok(None));
        assert_eq!(tree.replace(key(0), 2), Ok(Some(1)));
        assert_eq!(tree.get(key(0)), Some(&2));
    }

    #[test]
    fn iter_walks_in_key_order() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        for bits in [10_u32, 0, 3, 100_000, 64, 63, 65] {
            tree.insert(key(bits), bits).unwrap();
        }
        let keys: Vec<u32> = tree.iter().map(|(k, _)| k.into_raw()).collect();
        assert_eq!(keys, vec![0, 3, 10, 63, 64, 65, 100_000]);
    }

    #[test]
    fn remove_frees_empty_nodes() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        for i in 0..200_u32 {
            let _ = tree.insert_alloc(i).unwrap();
        }
        assert!(heap.live() > 0);
        while let Some((k, _)) = tree.iter().next() {
            let _ = tree.remove(k).unwrap();
        }
        assert!(tree.is_empty());
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn clear_and_drop_free_everything() {
        let heap = Heap::new();
        let drops = Cell::new(0);
        {
            let mut tree = RadixTree::<Tracked<'_>, &Heap>::new(&heap);
            for i in 0..50_u32 {
                tree.insert(key(i * 3), Tracked::new(&drops)).unwrap();
            }
            assert!(heap.live() > 0);
            tree.clear();
            assert!(tree.is_empty());
            assert_eq!(heap.live(), 0);
            assert_eq!(drops.get(), 50);
            for i in 0..10_u32 {
                tree.insert(key(i), Tracked::new(&drops)).unwrap();
            }
        }
        assert_eq!(heap.live(), 0);
        assert_eq!(drops.get(), 60);
    }

    #[test]
    fn grow_and_shrink_across_heights() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(0), 0).unwrap();
        tree.insert(key(63), 63).unwrap();
        tree.insert(key(64), 64).unwrap();
        tree.insert(key(1 << 12), 1).unwrap();
        assert_eq!(tree.iter().count(), 4);
        assert_eq!(tree.remove(key(1 << 12)), Some(1));
        assert_eq!(tree.remove(key(64)), Some(64));
        assert_eq!(tree.remove(key(63)), Some(63));
        assert_eq!(tree.get(key(0)), Some(&0));
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn insert_past_the_end_of_a_height() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(0), 0).unwrap();
        tree.insert(key(1 << 6), 1).unwrap();
        tree.insert(key(u32::MAX), 2).unwrap();
        assert_eq!(tree.get(key(1 << 6)), Some(&1));
        assert_eq!(tree.get(key(u32::MAX)), Some(&2));
    }

    #[test]
    fn a_failed_insert_leaves_the_tree_unchanged() {
        let heap = Heap::failing_from(1);
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(0), 0).unwrap();
        // Key 64 needs a second level; the heap fails the second node.
        assert_eq!(tree.insert(key(64), 1), Err(Error::ResourceShortage));
        assert_eq!(tree.get(key(0)), Some(&0));
        assert!(tree.get(key(64)).is_none());
        assert_eq!(tree.iter().count(), 1);
    }

    #[test]
    fn a_failed_insert_alloc_leaves_the_tree_unchanged() {
        let heap = Heap::failing_from(1);
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        // The first 64 keys share one node (heap call 0).
        for i in 0..64_u32 {
            let _ = tree.insert_alloc(i).unwrap();
        }
        assert_eq!(tree.insert_alloc(64).err(), Some(Error::ResourceShortage));
        assert_eq!(tree.iter().count(), 64);
    }

    #[test]
    fn a_failed_grow_drops_the_value() {
        let heap = Heap::failing_from(0);
        let drops = Cell::new(0);
        let mut tree = RadixTree::<Tracked<'_>, &Heap>::new(&heap);
        let err = tree.insert(key(1 << 6), Tracked::new(&drops));
        assert_eq!(err, Err(Error::ResourceShortage));
        assert_eq!(drops.get(), 1);
        assert!(tree.is_empty());
    }

    #[test]
    fn insert_alloc_spills_to_the_next_node() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        // 64 keys fill the first leaf; the 65th needs a second node.
        for i in 0..70_u32 {
            let (k, _) = tree.insert_alloc(i).unwrap();
            assert_eq!(k, key(i));
        }
        assert_eq!(tree.iter().count(), 70);
        assert_eq!(tree.get(key(64)), Some(&64));
    }

    #[test]
    fn debug_prints_the_map() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(2), 20).unwrap();
        let printed = format!("{tree:?}");
        assert!(printed.contains('2'));
        assert!(printed.contains("20"));
        assert!(format!("{:?}", tree.iter()).contains("Iter"));
    }

    #[test]
    fn display_names_the_error() {
        assert_eq!(Error::Exists.to_string(), "key already holds a value");
        assert_eq!(
            Error::ResourceShortage.to_string(),
            "memory allocation failed"
        );
    }

    #[test]
    fn into_iterator_walks() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(1), 10).unwrap();
        tree.insert(key(0), 20).unwrap();
        let keys: Vec<u32> =
            (&tree).into_iter().map(|(k, _)| k.into_raw()).collect();
        assert_eq!(keys, vec![0, 1]);
    }

    #[test]
    fn remove_misses_at_every_level() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(1 << 6), 1).unwrap();
        assert!(tree.remove(key((1 << 6) + 1)).is_none());
        assert!(tree.remove(key(2 << 6)).is_none());
        assert!(tree.remove(key(u32::MAX)).is_none());
        assert_eq!(tree.iter().count(), 1);
    }

    #[test]
    fn get_rejects_a_key_past_the_height() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(0), 0).unwrap();
        assert!(tree.get(key(64)).is_none());
        assert!(tree.get_mut(key(64)).is_none());
    }

    #[test]
    fn replace_into_a_deep_key() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        assert_eq!(tree.replace(key(1 << 12), 1), Ok(None));
        assert_eq!(tree.replace(key(1 << 12), 2), Ok(Some(1)));
        assert_eq!(tree.get(key(1 << 12)), Some(&2));
    }

    #[test]
    fn insert_over_a_height_zero_root_grows() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(0), 0).unwrap();
        tree.insert(key(1), 1).unwrap();
        tree.insert(key(64), 2).unwrap();
        assert_eq!(tree.iter().count(), 3);
        assert_eq!(tree.get(key(64)), Some(&2));
    }

    #[test]
    fn failed_create_on_an_empty_tree() {
        let heap = Heap::failing_from(0);
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(0), 0).unwrap();
        // Height 0 with a value; the grow's first node fails.
        assert_eq!(tree.insert(key(1), 1), Err(Error::ResourceShortage));
        assert_eq!(tree.iter().count(), 1);
    }

    #[test]
    fn failed_node_under_a_live_root() {
        let heap = Heap::failing_from(1);
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        for i in 0..64_u32 {
            tree.insert(key(i), i).unwrap();
        }
        // The next key needs a sibling leaf; heap call 1 fails.
        assert_eq!(tree.insert(key(64), 64), Err(Error::ResourceShortage));
        assert_eq!(tree.iter().count(), 64);
        assert!(tree.get(key(64)).is_none());
    }

    #[test]
    fn remove_from_a_height_zero_tree() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(0), 7).unwrap();
        assert!(tree.remove(key(1)).is_none());
        assert_eq!(tree.remove(key(0)), Some(7));
        assert!(tree.is_empty());
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn clear_an_empty_tree_is_a_noop() {
        let heap = Heap::new();
        let mut tree: RadixTree<u32, &Heap> = RadixTree::new(&heap);
        tree.clear();
        assert!(tree.is_empty());
    }

    #[test]
    fn shrink_collapses_a_chain() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(1 << 18), 1).unwrap();
        assert!(heap.live() > 0);
        assert_eq!(tree.remove(key(1 << 18)), Some(1));
        assert!(tree.is_empty());
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn iter_on_an_empty_tree() {
        let heap = Heap::new();
        let tree: RadixTree<u32, &Heap> = RadixTree::new(&heap);
        assert_eq!(tree.iter().next(), None);
    }

    #[test]
    fn insert_alloc_on_a_fresh_tree() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        assert_eq!(tree.insert_alloc(5).unwrap().0, key(0));
    }

    #[test]
    fn from_alloc_error_maps_to_resource_shortage() {
        let err: Error = AllocError.into();
        assert_eq!(err, Error::ResourceShortage);
    }

    /// A node in a leaf slot is not a value: lookups miss and the heap
    /// still balances after a clear.
    #[test]
    fn a_node_in_a_leaf_slot_is_not_a_value() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        let mut root = tree.create_node().unwrap();
        tree.root = Some(Entry::Node(root));
        tree.height = 1;
        tree.insert(key(1), 1).unwrap();
        tree.insert(key(2), 2).unwrap();
        // SAFETY: the root is live; slot 1 held a value we replace.
        let spare = tree.create_node().unwrap();
        unsafe {
            let slot = root.as_mut().slot_mut(1);
            *slot = Some(Entry::Node(spare));
        }
        assert!(tree.get(key(1)).is_none());
        assert!(tree.get_mut(key(1)).is_none());
        assert!(tree.remove(key(1)).is_none());
        tree.clear();
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn insert_into_a_slot_that_holds_a_node() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        let mut root = tree.create_node().unwrap();
        tree.root = Some(Entry::Node(root));
        tree.height = 1;
        tree.insert(key(1), 1).unwrap();
        tree.insert(key(2), 2).unwrap();
        // SAFETY: the root is live; slot 1 held a value we replace.
        let spare = tree.create_node().unwrap();
        unsafe {
            let slot = root.as_mut().slot_mut(1);
            *slot = Some(Entry::Node(spare));
        }
        assert_eq!(tree.insert(key(1), 9), Err(Error::Exists));
        tree.clear();
    }

    #[test]
    fn insert_alloc_into_a_tree_whose_root_is_a_value() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(0), 0).unwrap();
        let (k, v) = tree.insert_alloc(1).unwrap();
        assert_eq!(k, key(1));
        assert_eq!(*v, 1);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "radix tree: a node root at height zero"]
    fn insert_alloc_of_a_node_root_at_height_zero_panics() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        let spare = tree.create_node().unwrap();
        tree.root = Some(Entry::Node(spare));
        tree.height = 0;
        let _placed = tree.insert_alloc(1);
    }

    #[test]
    fn duplicate_insert_above_the_bottom() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(64), 1).unwrap();
        assert_eq!(tree.insert(key(64), 2), Err(Error::Exists));
        assert_eq!(tree.get(key(64)), Some(&1));
    }

    #[test]
    fn place_finds_a_value_where_a_node_belongs() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        let mut root = tree.create_node().unwrap();
        tree.root = Some(Entry::Node(root));
        tree.height = 1;
        tree.insert(key(0), 0).unwrap();
        tree.insert(key(1), 1).unwrap();
        // SAFETY: the root is live; slot 1 becomes a value in a non-leaf.
        unsafe {
            let slot = root.as_mut().slot_mut(1);
            *slot = Some(Entry::Value(9));
        }
        tree.height = 2;
        assert_eq!(tree.insert(key(64), 1), Err(Error::Exists));
    }

    #[test]
    fn place_rejects_a_value_root_at_a_nonzero_height() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(0), 0).unwrap();
        tree.height = 1;
        assert_eq!(tree.insert(key(1), 1), Err(Error::Exists));
    }

    #[test]
    fn failed_second_node_during_insert() {
        let heap = Heap::failing_from(1);
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        // One node comes from heap call 0; the sibling leaf fails at call 1.
        tree.insert(key(0), 0).unwrap();
        assert_eq!(tree.insert(key(64), 1), Err(Error::ResourceShortage));
        assert_eq!(tree.iter().count(), 1);
    }

    #[test]
    fn mark_free_stops_when_the_bit_was_already_set() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        for i in 0..3_u32 {
            let _ = tree.insert_alloc(i).unwrap();
        }
        assert_eq!(tree.remove(key(1)), Some(1));
        assert_eq!(tree.remove(key(2)), Some(2));
    }

    #[test]
    fn entry_value_arms_for_a_node() {
        let heap = Heap::new();
        let tree = RadixTree::<u32, &Heap>::new(&heap);
        let spare = tree.create_node().unwrap();
        assert!(Entry::<u32>::Node(spare).as_value().is_none());
        let mut entry = Entry::<u32>::Node(spare);
        assert!(entry.as_value_mut().is_none());
        assert!(entry.into_value().is_none());
        // `into_value` of a node drops the pointer; the block is not walked.
        heap.forget_live();
    }

    #[test]
    fn rollback_frees_a_partial_path() {
        let heap = Heap::failing_from(2);
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        assert_eq!(tree.insert(key(1 << 12), 1), Err(Error::ResourceShortage));
        assert!(tree.is_empty());
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn grow_past_the_height_limit() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.height = MAX_HEIGHT;
        assert_eq!(tree.insert(key(u32::MAX), 1), Ok(()));
        assert_eq!(tree.height, MAX_HEIGHT);
    }

    #[test]
    fn filling_a_leaf_leaves_a_sibling_slot_free() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        for i in 0..=127_u32 {
            tree.insert(key(i), i).unwrap();
        }
        for i in 0..=127_u32 {
            assert_eq!(tree.get(key(i)), Some(&i));
        }
        // The root kept its free bit for the slots it never descended
        // through, so the walk stopped at the full leaf's parent.
        assert_eq!(tree.insert(key(128), 128), Ok(()));
        assert_eq!(tree.get(key(128)), Some(&128));
        assert_eq!(heap.live(), 4);
    }

    #[test]
    fn a_full_parent_stops_the_free_bit_walk() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        for i in 0..=4095_u32 {
            tree.insert(key(i), i).unwrap();
        }
        // The height-two tree holds every key it can address; the walk
        // ran out of free bits on the parent and the next value grows
        // the tree.
        let (k, v) = tree.insert_alloc(4096).unwrap();
        assert_eq!(k, key(4096));
        assert_eq!(*v, 4096);
    }

    #[test]
    fn a_missing_key_on_a_tall_tree_is_a_miss() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(64), 1).unwrap();
        assert!(tree.get(key(65)).is_none());
        assert!(tree.get_mut(key(65)).is_none());
        assert!(tree.remove(key(65)).is_none());
        assert_eq!(tree.iter().count(), 1);
    }

    #[test]
    fn a_failed_grow_in_insert_alloc_leaves_the_tree_unchanged() {
        let heap = Heap::failing_from(0);
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        // A height-zero root stores the value with no allocation.
        let (k, v) = tree.insert_alloc(0).unwrap();
        assert_eq!(k, key(0));
        assert_eq!(*v, 0);
        // The next value needs a node to grow into; the heap is dry.
        assert_eq!(tree.insert_alloc(1).err(), Some(Error::ResourceShortage));
        assert_eq!(tree.get(key(0)), Some(&0));
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn a_failed_replace_leaves_the_tree_unchanged() {
        let heap = Heap::failing_from(0);
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        assert_eq!(
            tree.replace(key(1 << 6), 1).err(),
            Some(Error::ResourceShortage)
        );
        assert!(tree.is_empty());
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn tracked_values_take_the_lowest_free_key() {
        let drops = Cell::new(0);
        let heap = Heap::new();
        let mut tree = RadixTree::<Tracked<'_>, &Heap>::new(&heap);
        let (k, _v) = tree.insert_alloc(Tracked::new(&drops)).unwrap();
        assert_eq!(k, key(0));
        let (k, _v) = tree.insert_alloc(Tracked::new(&drops)).unwrap();
        assert_eq!(k, key(1));
        tree.clear();
        assert_eq!(drops.get(), 2);
    }

    #[test]
    fn a_failed_insert_with_a_tracked_value_rolls_back() {
        let drops = Cell::new(0);
        let heap = Heap::failing_from(2);
        let mut tree = RadixTree::<Tracked<'_>, &Heap>::new(&heap);
        assert_eq!(
            tree.insert(key(1 << 12), Tracked::new(&drops)).err(),
            Some(Error::ResourceShortage)
        );
        assert!(tree.is_empty());
        assert_eq!(heap.live(), 0);
        assert_eq!(drops.get(), 1);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "radix tree: a value sits above the bottom level"]
    fn get_of_a_value_root_above_the_bottom_panics() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.root = Some(Entry::Value(9));
        tree.height = 1;
        let _found = tree.get(key(0));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "radix tree: a value sits above the bottom level"]
    fn get_mut_of_a_value_root_above_the_bottom_panics() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.root = Some(Entry::Value(9));
        tree.height = 1;
        let _found = tree.get_mut(key(0));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "radix tree: a value root at a height above zero"]
    fn grow_into_a_value_root_above_the_bottom_panics() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.root = Some(Entry::Value(9));
        tree.height = 1;
        // Key 64 needs a second level; growing meets the value root.
        tree.insert(key(64), 1).unwrap();
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "radix tree: a value root at a height above zero"]
    fn remove_of_a_value_root_above_the_bottom_panics() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.root = Some(Entry::Value(9));
        tree.height = 1;
        let _gone = tree.remove(key(0));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "radix tree: the root is not a node above height zero"]
    fn shrink_of_a_value_root_above_the_bottom_panics() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.root = Some(Entry::Value(9));
        tree.height = 1;
        tree.shrink();
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "radix tree: one entry but no occupied slot"]
    fn shrink_of_an_empty_root_counting_one_entry_panics() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        let mut root = tree.create_node().unwrap();
        // SAFETY: the node is fresh and owned by the test.
        unsafe {
            root.as_mut().nr_entries = 1;
        }
        tree.root = Some(Entry::Node(root));
        tree.height = 1;
        tree.shrink();
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "slot.is_none()"]
    fn put_into_an_occupied_slot_panics() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        let mut handle = tree.create_node().unwrap();
        tree.root = Some(Entry::Node(handle));
        tree.height = 1;
        // SAFETY: the node is live and slot 0 is free, then taken.
        unsafe {
            handle.as_mut().put(0, Entry::Value(1));
            handle.as_mut().put(0, Entry::Value(2));
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "radix tree: the key space is exhausted"]
    fn insert_alloc_into_a_full_tree_at_the_height_limit_panics() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        let mut root = tree.create_node().unwrap();
        // SAFETY: the node is fresh and owned by the test.
        unsafe {
            root.as_mut().free_bm = 0;
        }
        tree.root = Some(Entry::Node(root));
        tree.height = MAX_HEIGHT;
        let _placed = tree.insert_alloc(1);
    }
}
