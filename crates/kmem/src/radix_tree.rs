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
//! The performance comparison against the `kern/rdxtree` this replaced
//! lives in the `rdxtree-bench` crate.  The old tree is a verbatim
//! BSD-2-Clause snapshot with host shims for `kern::slab`, `utils::cell`
//! and `vm::error`; that cannot sit beside this MIT code.  Unit tests of
//! this tree are in `tests` below.
//!
//! | operation | cost |
//! |---|---|
//! | [`get`](RadixTree::get), [`insert`](RadixTree::insert), [`remove`](RadixTree::remove) | O(height) |
//! | [`insert_alloc`](RadixTree::insert_alloc) | O(height), lowest free key |
//! | [`iter`](RadixTree::iter) | O(1) amortised per item |
//! | [`clear`](RadixTree::clear) | O(nodes) |
//!
//! A tree is not internally locked; the caller serialises it.

// The iterator stack indexes a fixed `MAX_HEIGHT` array under an
// invariant the walk itself maintains: `depth` is never more than the
// key's bit depth.  Slot indices come from a 6-bit mask.
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
use core::mem::ManuallyDrop;
use core::mem::MaybeUninit;
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

/// A value appeared where only a child node belongs.
fn value_above_bottom<T>() -> Option<T> {
    #[cfg(debug_assertions)]
    #[expect(clippy::panic, reason = "a value sits only at the bottom level")]
    {
        panic!("radix tree: a value sits above the bottom level");
    }
    #[cfg(not(debug_assertions))]
    None
}

/// What a node slot holds, by value.
enum Entry<T> {
    /// A value at the bottom of the tree.
    Value(T),
    /// A child node.
    Node(NonNull<Node<T>>),
}

/// Slot storage: a value or a child pointer, discriminated by the
/// node's bitmaps.  `ManuallyDrop` because the node drops values
/// itself when it destroys a slot.
union SlotBits<T> {
    value: ManuallyDrop<T>,
    node: NonNull<Node<T>>,
}

/// One level of the tree.
///
/// # Invariants
///
/// Bit `i` of `free_bm` is set when slot `i` is empty, or holds a node
/// whose subtree still has a free key.  Bit `i` of `used_bm` is set
/// when slot `i` holds something.  Bit `i` of `tag_bm` is set when that
/// something is a child node.
struct Node<T> {
    free_bm: u64,
    used_bm: u64,
    tag_bm: u64,
    slots: [MaybeUninit<SlotBits<T>>; RADIX_SIZE],
}

impl<T> Node<T> {
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
        self.used_bm == 0
    }

    /// Whether the node's subtree still has a free key.
    const fn has_free(&self) -> bool {
        self.free_bm != 0
    }

    /// Takes the entry in `index`, leaving the slot free.
    ///
    /// # Safety
    ///
    /// `index` is below `RADIX_SIZE` and its slot holds an entry.
    unsafe fn take(&mut self, index: usize) -> Entry<T> {
        debug_assert!(
            self.used_bm & (1_u64 << index) != 0,
            "radix tree: take of an empty slot"
        );
        self.used_bm &= !(1_u64 << index);
        self.set_free(index);
        // SAFETY: the slot holds an entry, so it is initialised.
        let bits =
            unsafe { self.slots.get_unchecked(index).assume_init_read() };
        if self.tag_bm & (1_u64 << index) != 0 {
            self.tag_bm &= !(1_u64 << index);
            // SAFETY: `tag_bm` said this slot held a child node.
            Entry::Node(unsafe { bits.node })
        } else {
            // SAFETY: `tag_bm` said this slot held a value.
            Entry::Value(unsafe { ManuallyDrop::into_inner(bits.value) })
        }
    }

    /// Takes the value in `index` when the slot holds one, and nothing
    /// otherwise: an empty slot and a child node both leave the tree as
    /// it is.
    ///
    /// # Safety
    ///
    /// `index` is below `RADIX_SIZE`.
    unsafe fn take_value(&mut self, index: usize) -> Option<T> {
        let bit = 1_u64 << index;
        if self.used_bm & bit == 0 || self.tag_bm & bit != 0 {
            return None;
        }
        // SAFETY: the slot is occupied and `tag_bm` says it holds a
        // value, so it is initialised.
        let bits =
            unsafe { self.slots.get_unchecked(index).assume_init_read() };
        self.used_bm &= !bit;
        self.set_free(index);
        // SAFETY: `tag_bm` said the slot held a value.
        Some(unsafe { ManuallyDrop::into_inner(bits.value) })
    }

    /// The child node in `index`.
    ///
    /// # Safety
    ///
    /// `index` is below `RADIX_SIZE` and its slot holds a child node.
    unsafe fn child_at(&self, index: usize) -> NonNull<Self> {
        debug_assert!(
            self.tag_bm & (1_u64 << index) != 0,
            "radix tree: slot does not hold a child node"
        );
        // SAFETY: `index` is a slot index and the slot is occupied.
        let bits =
            unsafe { self.slots.get_unchecked(index).assume_init_ref() };
        // SAFETY: `tag_bm` says this slot holds a child node.
        unsafe { bits.node }
    }

    /// Puts `value` into `index`, which must be free.  A value fills the
    /// slot.
    ///
    /// # Safety
    ///
    /// `index` is below `RADIX_SIZE` and the slot is empty.
    unsafe fn put_value(&mut self, index: usize, value: T) {
        debug_assert_eq!(
            self.used_bm & (1_u64 << index),
            0,
            "radix tree: slot already used"
        );
        debug_assert_eq!(
            self.tag_bm & (1_u64 << index),
            0,
            "radix tree: an empty slot carries no node tag"
        );
        // SAFETY: `index` is a slot index of this node.
        unsafe {
            let _ = self.slots.get_unchecked_mut(index).write(SlotBits {
                value: ManuallyDrop::new(value),
            });
        }
        self.used_bm |= 1_u64 << index;
        self.clear_free(index);
    }

    /// Puts `child` into `index`, which must be free.  The free bit
    /// stays set when the child's own subtree still has room.
    ///
    /// # Safety
    ///
    /// `index` is below `RADIX_SIZE` and the slot is empty.
    unsafe fn put_node(&mut self, index: usize, child: NonNull<Self>) {
        debug_assert_eq!(
            self.used_bm & (1_u64 << index),
            0,
            "radix tree: slot already used"
        );
        // SAFETY: a stored node is live.
        let still_free = unsafe { child.as_ref().has_free() };
        // SAFETY: `index` is a slot index of this node.
        unsafe {
            let _ = self
                .slots
                .get_unchecked_mut(index)
                .write(SlotBits { node: child });
        }
        self.used_bm |= 1_u64 << index;
        self.tag_bm |= 1_u64 << index;
        if still_free {
            self.set_free(index);
        } else {
            self.clear_free(index);
        }
    }

    /// The address of the value in `index`.
    ///
    /// # Safety
    ///
    /// `index` is below `RADIX_SIZE` and the slot holds a value.
    unsafe fn value_ptr(&mut self, index: usize) -> *mut T {
        // SAFETY: `index` is a slot index and the slot holds a value.
        let bits =
            unsafe { self.slots.get_unchecked_mut(index).assume_init_mut() };
        // SAFETY: `tag_bm` says the slot holds a value.
        ptr::addr_of_mut!(bits.value).cast::<T>()
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

/// The result of a [`RadixTree::remove_in`] frame, for its parent.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Up {
    /// The node holds no entries; the parent must unlink it.
    Empty,
    /// The node still holds entries and its subtree gained a free key;
    /// the parent sets its free bit and keeps walking only if that bit
    /// was clear.
    Gained,
    /// The free bookkeeping above this node is already correct.
    Settled,
}

/// The top of a tree.
///
/// The height travels with what hangs from it, so a value cannot sit
/// above the bottom level and a node cannot sit at height zero.
enum Root<T> {
    /// The root node and the levels below it.
    Node(NonNull<Node<T>>, u32),
    /// The single value of a height-zero tree.
    Value(T),
    /// No values; the height only says how many levels a first value
    /// would descend.
    Empty(u32),
}

impl<T> Root<T> {
    /// The levels to traverse; a value sits at the bottom.
    const fn height(&self) -> u32 {
        match self {
            Self::Value(_) => 0,
            Self::Empty(height) | Self::Node(_, height) => *height,
        }
    }
}

/// A radix tree of `T` over [`RadixKey`].
pub struct RadixTree<T, A: Alloc> {
    root: Root<T>,
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
            root: Root::Empty(0),
            alloc,
        }
    }

    /// Whether the tree holds no values.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        matches!(self.root, Root::Empty(_))
    }

    /// The value at `key`, if any.
    #[must_use]
    pub fn get(&self, key: RadixKey) -> Option<&T> {
        let (root, mut height) = match &self.root {
            Root::Node(node, height) => (*node, *height),
            Root::Value(value) => {
                return (key == RadixKey::ZERO).then_some(value);
            }
            Root::Empty(_) => return None,
        };
        if key > RadixKey::max_for_height(height) {
            return None;
        }
        // SAFETY: a stored node is live for the life of `self`.
        let mut node = unsafe { root.as_ref() };
        let mut shift = (height - 1) * RADIX_BITS;
        loop {
            let index = key.index_at(shift);
            let bit = 1_u64 << index;
            if node.used_bm & bit == 0 {
                return None;
            }
            height -= 1;
            let is_node = node.tag_bm & bit != 0;
            if height == 0 {
                if is_node {
                    return None;
                }
                // SAFETY: the slot holds a value and `index` is a slot
                // index; `ManuallyDrop` is transparent over `T`.
                return Some(unsafe {
                    &*ptr::from_ref(
                        &node
                            .slots
                            .get_unchecked(index)
                            .assume_init_ref()
                            .value,
                    )
                    .cast::<T>()
                });
            }
            if !is_node {
                return value_above_bottom();
            }
            // SAFETY: `tag_bm` says the slot holds a child node, which is
            // live for the life of `self`.
            let child = unsafe { node.child_at(index) };
            // SAFETY: a stored node is live for the life of `self`.
            node = unsafe { child.as_ref() };
            shift -= RADIX_BITS;
        }
    }

    /// A unique reference to the value at `key`, if any.
    #[must_use]
    pub fn get_mut(&mut self, key: RadixKey) -> Option<&mut T> {
        self.find_mut(key)
    }

    /// Stores `value` at `key`, which must be free.
    ///
    /// # Errors
    ///
    /// [`Error::Exists`] when `key` already holds a value, and
    /// [`Error::ResourceShortage`] when a node cannot be allocated.  A
    /// failure leaves the tree unchanged.
    pub fn insert(&mut self, key: RadixKey, value: T) -> Result<(), Error> {
        if key > RadixKey::max_for_height(self.root.height()) {
            self.grow(key)?;
        }
        match self.root {
            Root::Empty(0) => {
                self.root = Root::Value(value);
                Ok(())
            }
            // A lone value at the bottom takes the first key, and
            // `place` rejects the key that reaches it.
            _ => self.place::<false>(key, value).map(|_| ()),
        }
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
        if let Root::Empty(_) = self.root {
            // A tree with no node holds its first value at the first
            // key, with no allocation.
            self.root = Root::Value(value);
            // The write above is the only one, so the lookup hits.
            return self
                .find_mut(RadixKey::ZERO)
                .map(|stored| (RadixKey::ZERO, stored))
                .ok_or(Error::ResourceShortage);
        }
        if let Root::Value(_) = self.root {
            // Key one needs a single level, so the lone value moves into
            // a node.
            self.grow(RadixKey::from_raw(1))?;
        }
        self.place::<true>(RadixKey::ZERO, value)
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
        if let Some(old) = self.find_mut(key) {
            return Ok(Some(core::mem::replace(old, value)));
        }
        self.insert(key, value)?;
        Ok(None)
    }

    /// Removes the value at `key`, if any.
    pub fn remove(&mut self, key: RadixKey) -> Option<T> {
        if self.root.height() == 0 {
            // A height-zero tree holds one value, at the first key.
            if key != RadixKey::ZERO {
                return None;
            }
            return match core::mem::replace(&mut self.root, Root::Empty(0)) {
                Root::Value(value) => Some(value),
                // A tree with no root holds nothing; the empty root goes
                // straight back.
                other => {
                    self.root = other;
                    None
                }
            };
        }

        let (root, height) = match self.root {
            Root::Node(node, height) => (node, height),
            // A tall tree with no root holds nothing.
            Root::Empty(_) | Root::Value(_) => return None,
        };
        let shift = (height - 1) * RADIX_BITS;
        let (value, up) = self.remove_in(root, height, shift, key)?;
        if up == Up::Empty {
            // SAFETY: the root holds no entries and is uniquely reached.
            unsafe { self.destroy_node(root) };
            self.root = Root::Empty(0);
        } else {
            self.shrink();
        }
        Some(value)
    }

    /// Drops every value and frees every node.
    pub fn clear(&mut self) {
        match core::mem::replace(&mut self.root, Root::Empty(0)) {
            Root::Value(value) => drop(value),
            // SAFETY: the root is a live node this tree owns.
            Root::Node(node, _) => unsafe { self.destroy_node(node) },
            Root::Empty(_) => {}
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
    /// The value at `key`, uniquely, if the descent finds one.
    fn find_mut(&mut self, key: RadixKey) -> Option<&mut T> {
        let (root, mut height) = match &mut self.root {
            Root::Node(node, height) => (*node, *height),
            Root::Value(value) => {
                return (key == RadixKey::ZERO).then_some(value);
            }
            Root::Empty(_) => return None,
        };
        if key > RadixKey::max_for_height(height) {
            return None;
        }
        let mut current = root;
        let mut shift = (height - 1) * RADIX_BITS;
        loop {
            let index = key.index_at(shift);
            let bit = 1_u64 << index;
            // SAFETY: `current` is a live node of this tree.
            let node = unsafe { current.as_mut() };
            if node.used_bm & bit == 0 {
                return None;
            }
            height -= 1;
            let is_node = node.tag_bm & bit != 0;
            if height == 0 {
                if is_node {
                    return None;
                }
                // SAFETY: the slot holds a value and `&mut self` keeps
                // that access unique.
                return Some(unsafe { &mut *node.value_ptr(index) });
            }
            if !is_node {
                return value_above_bottom();
            }
            // SAFETY: `tag_bm` says the slot holds a child node.
            current = unsafe { node.child_at(index) };
            shift -= RADIX_BITS;
        }
    }

    /// Descends to a leaf and stores `value`.
    ///
    /// When `LOWEST_FREE` is set the walk takes the lowest free slot at
    /// each level and assembles that key; otherwise it follows `key`.
    /// On failure the nodes this call created are freed and the tree is
    /// left as it was.
    fn place<const LOWEST_FREE: bool>(
        &mut self,
        key: RadixKey,
        value: T,
    ) -> Result<(RadixKey, &mut T), Error> {
        let key = if LOWEST_FREE { RadixKey::ZERO } else { key };

        let (node, height) = match self.root {
            Root::Node(node, height) => {
                if LOWEST_FREE {
                    // SAFETY: the root is a live node of this tree.
                    if !unsafe { node.as_ref() }.has_free() {
                        // Every key under this height is taken; the next
                        // one lives a level higher.
                        debug_assert!(
                            height < MAX_HEIGHT,
                            "radix tree: the key space is exhausted"
                        );
                        let next =
                            RadixKey::max_for_height(height).with_index(1, 0);
                        self.grow(next)?;
                        return self.place::<true>(next, value);
                    }
                }
                (node, height)
            }
            Root::Empty(height) => match self.create_node() {
                Ok(node) => {
                    self.root = Root::Node(node, height);
                    (node, height)
                }
                Err(error) => {
                    drop(value);
                    return Err(error);
                }
            },
            // A value root holds the first key, and the caller grew the
            // tree for any key past it.
            Root::Value(_) => return Err(Error::Exists),
        };
        let shift = (height - 1) * RADIX_BITS;
        match self.place_in::<LOWEST_FREE>(node, height, shift, key, value) {
            Ok((key, stored, _)) => {
                // SAFETY: `stored` addresses the value just written, and
                // `&mut self` keeps that access unique.
                Ok((key, unsafe { &mut *stored }))
            }
            Err(error) => {
                if unsafe { node.as_ref() }.is_empty() {
                    // SAFETY: the root holds no entries and is uniquely
                    // reached; the descent left it empty.
                    unsafe { self.destroy_node(node) };
                    self.root = Root::Empty(height);
                }
                Err(error)
            }
        }
    }

    /// One level of a [`place`](Self::place) descent.
    ///
    /// Returns the assembled key, a pointer to the stored value, and
    /// whether the subtree rooted at `node` is now full so the caller can
    /// clear its free bit.  A node this call created is unlinked and
    /// freed before the error returns.
    fn place_in<const LOWEST_FREE: bool>(
        &mut self,
        mut node: NonNull<Node<T>>,
        height: u32,
        shift: u32,
        key: RadixKey,
        value: T,
    ) -> Result<(RadixKey, *mut T, bool), Error> {
        let (index, key, bit) = {
            // SAFETY: `node` is a live node of this tree.
            let slot = unsafe { node.as_ref() };
            let (index, key) = if LOWEST_FREE {
                let Some(index) = slot.first_free() else {
                    drop(value);
                    // The caller grows the tree before a full root is
                    // placed into, so a full node here is not a state a
                    // free key walk can reach.
                    #[cfg(debug_assertions)]
                    #[expect(
                        clippy::panic,
                        reason = "a free-key walk never reaches a full node"
                    )]
                    {
                        panic!(
                            "radix tree: a free-key walk reached a full node"
                        );
                    }
                    #[cfg(not(debug_assertions))]
                    return Err(Error::ResourceShortage);
                };
                (index, key.with_index(index, shift))
            } else {
                (key.index_at(shift), key)
            };
            (index, key, 1_u64 << index)
        };

        if height == 1 {
            // SAFETY: `node` is a live node of this tree.
            let slot = unsafe { node.as_mut() };
            if LOWEST_FREE {
                // A free bit at the bottom names an empty slot: a value
                // occupies its slot and clears the bit.
                debug_assert_eq!(
                    slot.used_bm & bit,
                    0,
                    "radix tree: a free-key walk reached a full slot"
                );
            } else if slot.used_bm & bit != 0 {
                drop(value);
                return Err(Error::Exists);
            }
            // SAFETY: `index` is in range and the slot is empty.
            unsafe {
                slot.put_value(index, value);
            }
            // SAFETY: `index` addresses the value just stored, and
            // `&mut self` keeps that access unique.
            let stored = unsafe { slot.value_ptr(index) };
            return Ok((key, stored, !slot.has_free()));
        }

        let (child, created) = {
            // SAFETY: `node` is a live node of this tree.
            let slot = unsafe { node.as_mut() };
            if slot.used_bm & bit == 0 {
                let child = match self.create_node() {
                    Ok(child) => child,
                    Err(error) => {
                        drop(value);
                        return Err(error);
                    }
                };
                // SAFETY: the slot is empty and `index` is in range.
                unsafe {
                    slot.put_node(index, child);
                }
                (child, true)
            } else if slot.tag_bm & bit != 0 {
                // SAFETY: `index` names an occupied node slot.
                (unsafe { slot.child_at(index) }, false)
            } else {
                drop(value);
                return Err(Error::Exists);
            }
        };

        let child_shift = shift.saturating_sub(RADIX_BITS);
        match self.place_in::<LOWEST_FREE>(
            child,
            height - 1,
            child_shift,
            key,
            value,
        ) {
            Ok((key, stored, full)) => {
                // SAFETY: `node` is a live node of this tree.
                let slot = unsafe { node.as_mut() };
                if full {
                    slot.clear_free(index);
                }
                Ok((key, stored, !slot.has_free()))
            }
            Err(error) => {
                if created {
                    // SAFETY: `node` is a live node of this tree.
                    let slot = unsafe { node.as_mut() };
                    // SAFETY: the slot holds the node this call created
                    // and a node entry is only a pointer, so the unlink
                    // can be dropped.  The child's own descent already
                    // freed what it created.
                    drop(unsafe { slot.take(index) });
                    // SAFETY: the child is empty and uniquely reached.
                    unsafe { self.destroy_node(child) };
                }
                Err(error)
            }
        }
    }

    /// One level of a [`remove`](Self::remove) descent.  Returns the
    /// value and how the parent must treat this node.
    fn remove_in(
        &mut self,
        mut node: NonNull<Node<T>>,
        height: u32,
        shift: u32,
        key: RadixKey,
    ) -> Option<(T, Up)> {
        let index = key.index_at(shift);
        let bit = 1_u64 << index;

        if height == 1 {
            // SAFETY: `node` is a live node of this tree.
            let slot = unsafe { node.as_mut() };
            // SAFETY: `index` is a slot index of `slot`.
            let value = unsafe { slot.take_value(index) }?;
            return Some((
                value,
                if slot.is_empty() {
                    Up::Empty
                } else {
                    Up::Gained
                },
            ));
        }

        let child = {
            // SAFETY: `node` is a live node of this tree.
            let slot = unsafe { node.as_ref() };
            if slot.used_bm & bit == 0 || slot.tag_bm & bit == 0 {
                return None;
            }
            // SAFETY: `index` names an occupied node slot.
            unsafe { slot.child_at(index) }
        };
        let (value, up) = self.remove_in(
            child,
            height - 1,
            shift.saturating_sub(RADIX_BITS),
            key,
        )?;
        // SAFETY: `node` is a live node of this tree.
        let slot = unsafe { node.as_mut() };
        match up {
            Up::Empty => {
                // SAFETY: the slot holds the empty child and a node entry
                // is only a pointer, so the unlink can be dropped.  The
                // child is freed below.
                drop(unsafe { slot.take(index) });
                // SAFETY: the empty child is uniquely reached.
                unsafe { self.destroy_node(child) };
                Some((
                    value,
                    if slot.is_empty() {
                        Up::Empty
                    } else {
                        Up::Gained
                    },
                ))
            }
            Up::Gained => {
                let already = slot.free_bm & bit != 0;
                slot.set_free(index);
                Some((value, if already { Up::Settled } else { Up::Gained }))
            }
            Up::Settled => Some((value, Up::Settled)),
        }
    }

    /// A fresh node from the owner's allocator.
    ///
    /// The fields are written in place: a whole-node temporary would
    /// spend a node's worth of room in this call chain.
    fn create_node(&self) -> Result<NonNull<Node<T>>, Error> {
        let block = allocate(&self.alloc, node_layout::<T>(), false)?;
        // SAFETY: the block is `Node<T>`-sized and -aligned.
        let node = block.cast::<Node<T>>();
        // SAFETY: the block is uninitialised room for one node; slot
        // storage starts uninitialised and only `used_bm` makes a slot
        // readable.
        unsafe {
            let dst = node.as_ptr();
            (*dst).free_bm = FREE_BM_FULL;
            (*dst).used_bm = 0;
            (*dst).tag_bm = 0;
        }
        Ok(node)
    }

    /// Drops a node's entries and returns its block.
    ///
    /// # Safety
    ///
    /// `node` is a live node this tree owns and nothing else reaches.
    unsafe fn destroy_node(&mut self, mut node: NonNull<Node<T>>) {
        {
            // SAFETY: `node` is live and uniquely reached here.
            let slots = unsafe { node.as_mut() };
            let mut children = slots.used_bm & slots.tag_bm;
            while children != 0 {
                let index = children.trailing_zeros() as usize;
                children &= children - 1;
                // SAFETY: `index` names a set `tag_bm` bit.
                let bits = unsafe {
                    slots.slots.get_unchecked(index).assume_init_read()
                };
                // SAFETY: `tag_bm` said the slot held a child node.
                unsafe { self.destroy_node(bits.node) };
            }
            // Values without a destructor need not be read.
            if core::mem::needs_drop::<T>() {
                let mut values = slots.used_bm & !slots.tag_bm;
                while values != 0 {
                    let index = values.trailing_zeros() as usize;
                    values &= values - 1;
                    // SAFETY: `index` names a set `used_bm` value bit.
                    let bits = unsafe {
                        slots.slots.get_unchecked(index).assume_init_read()
                    };
                    // SAFETY: `tag_bm` said the slot held a value.
                    drop(unsafe { ManuallyDrop::into_inner(bits.value) });
                }
            }
        }
        // SAFETY: the block came from `create_node` with this layout.
        unsafe {
            release(&self.alloc, node.cast(), node_layout::<T>());
        }
    }

    /// Grows the tree until `key` fits.
    fn grow(&mut self, key: RadixKey) -> Result<(), Error> {
        let mut new_height = self.root.height().saturating_add(1);
        while key > RadixKey::max_for_height(new_height) {
            new_height += 1;
        }

        // The root comes apart so the new levels can be built on top of
        // it; a failure puts it back.
        let mut root = match core::mem::replace(&mut self.root, Root::Empty(0))
        {
            Root::Empty(_) => {
                self.root = Root::Empty(new_height);
                return Ok(());
            }
            Root::Value(value) => {
                let mut node = match self.create_node() {
                    Ok(node) => node,
                    Err(error) => {
                        self.root = Root::Value(value);
                        return Err(error);
                    }
                };
                // SAFETY: the node is fresh and the slot is free.
                unsafe { node.as_mut().put_value(0, value) };
                self.root = Root::Node(node, 1);
                node
            }
            Root::Node(node, height) => {
                self.root = Root::Node(node, height);
                node
            }
        };

        while new_height > self.root.height() {
            let mut node = self.create_node()?;
            // SAFETY: both nodes are live; `root` becomes the child.
            unsafe {
                node.as_mut().put_node(0, root);
            }
            self.root = Root::Node(node, self.root.height() + 1);
            root = node;
        }
        Ok(())
    }

    /// Collapses a root that holds only one entry.
    fn shrink(&mut self) {
        loop {
            let Root::Node(node, height) = self.root else {
                return;
            };
            // SAFETY: the root is a live node.
            let root = unsafe { node.as_ref() };
            // Exactly one occupied slot names the entry to collapse.
            if root.used_bm == 0 || root.used_bm & (root.used_bm - 1) != 0 {
                return;
            }
            let index = root.used_bm.trailing_zeros() as usize;
            if index != 0 {
                // A level above a nonzero slot carries key bits: dropping
                // it would move the entry's key.
                return;
            }
            let mut node = node;
            // SAFETY: the single occupied slot holds the entry.
            let entry = unsafe { node.as_mut().take(index) };
            // SAFETY: the node is now empty and uniquely reached.
            unsafe { self.destroy_node(node) };
            // A child node takes the root's place one level down; a
            // value sits only in the bottom level and ends the collapse.
            // A node in the bottom level is a broken tree: it keeps its
            // level, so the descent stays in range.
            self.root = match entry {
                Entry::Value(value) => Root::Value(value),
                Entry::Node(child) => Root::Node(child, height.max(2) - 1),
            };
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
    /// The key of slot zero at this level.
    base: RadixKey,
    /// Key distance between adjacent slots at this level.
    step: u32,
    /// The occupied slots the walk has not reached yet.
    left: u64,
}

impl<'a, T> Iter<'a, T> {
    fn new<A: Alloc>(tree: &'a RadixTree<T, A>) -> Self {
        let mut iter = Self {
            stack: core::array::from_fn(|_| IterFrame {
                node: NonNull::dangling(),
                base: RadixKey::ZERO,
                step: 0,
                left: 0,
            }),
            depth: 0,
            pending: None,
            _marker: PhantomData,
        };
        match &tree.root {
            Root::Empty(_) => {}
            Root::Value(value) => {
                iter.pending = Some((RadixKey::ZERO, value));
            }
            Root::Node(node, height) => {
                let shift = (height - 1) * RADIX_BITS;
                // SAFETY: the root is a live node for the life of the
                // iterator.
                let left = unsafe { node.as_ref() }.used_bm;
                iter.push(*node, RadixKey::ZERO, 1_u32 << shift, left);
            }
        }
        iter
    }

    /// Records `node` as the level to scan next: `base` is slot 0's key
    /// and `left` the slots still to visit.
    const fn push(
        &mut self,
        node: NonNull<Node<T>>,
        base: RadixKey,
        step: u32,
        left: u64,
    ) {
        self.stack[self.depth] = IterFrame {
            node,
            base,
            step,
            left,
        };
        self.depth += 1;
    }
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = (RadixKey, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(item) = self.pending.take() {
            return Some(item);
        }
        loop {
            if self.depth == 0 {
                return None;
            }
            let at = self.depth - 1;
            let frame = &mut self.stack[at];
            let left = frame.left;
            if left == 0 {
                self.depth -= 1;
                continue;
            }
            frame.left &= left - 1;
            let index = left.trailing_zeros() as usize;
            let step = frame.step;
            let base = frame.base.into_raw();
            let node = frame.node;
            // Slot `index` sits `step` keys past slot zero; a leaf has
            // one key per slot.
            let key = RadixKey::from_raw(base.wrapping_add(if step == 1 {
                index as u32
            } else {
                step.wrapping_mul(index as u32)
            }));
            // SAFETY: the frame names a live node the tree still owns.
            let node_ref = unsafe { node.as_ref() };
            // SAFETY: `index` names a set `used_bm` bit.
            let bits = unsafe {
                node_ref.slots.get_unchecked(index).assume_init_ref()
            };
            if node_ref.tag_bm & (1_u64 << index) != 0 {
                // SAFETY: `tag_bm` says the slot holds a child node,
                // which is live while the tree is.
                let child = unsafe { bits.node };
                self.push(
                    child,
                    key,
                    step >> RADIX_BITS,
                    unsafe { child.as_ref() }.used_bm,
                );
                continue;
            }
            // SAFETY: the slot holds a value; the tree outlives the
            // iterator, and `ManuallyDrop` is transparent over `T`.
            let value = unsafe { &*ptr::from_ref(&bits.value).cast::<T>() };
            return Some((key, value));
        }
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
    fn get_on_a_tall_tree_without_a_root_is_a_miss() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.root = Root::Empty(2);
        assert!(tree.get(key(0)).is_none());
        assert!(tree.get_mut(key(0)).is_none());
        assert!(tree.remove(key(0)).is_none());
    }

    #[test]
    fn get_mut_and_replace() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(7), 1).unwrap();
        assert!(tree.get_mut(key(8)).is_none());
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
        for i in 0..300_u32 {
            tree.insert(key(i * 3), i).unwrap();
        }
        let keys: Vec<u32> = tree.iter().map(|(k, _)| k.into_raw()).collect();
        assert_eq!(keys, (0..300_u32).map(|i| i * 3).collect::<Vec<_>>());
    }

    #[test]
    fn iter_skips_a_trailing_gap_in_a_node() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        for i in 0..64_u32 {
            tree.insert(key(i), i).unwrap();
        }
        assert_eq!(tree.remove(key(63)), Some(63));
        let keys: Vec<u32> = tree.iter().map(|(k, _)| k.into_raw()).collect();
        assert_eq!(keys, (0..63).collect::<Vec<_>>());
    }

    #[test]
    fn iter_walks_a_sparse_key_order() {
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

    /// The last entry of a tall tree keeps its key: a level above a
    /// nonzero slot is part of the key, so it stays.
    #[test]
    fn removing_a_neighbour_keeps_the_other_key() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(0), 0).unwrap();
        tree.insert(key(1 << 12), 1).unwrap();
        assert_eq!(tree.remove(key(0)), Some(0));
        assert!(tree.get(key(0)).is_none());
        assert_eq!(tree.get(key(1 << 12)), Some(&1));
        assert_eq!(tree.iter().collect::<Vec<_>>(), vec![(key(1 << 12), &1)]);
        tree.clear();
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
        // A node root has a level to spare, and the key is still past it.
        tree.insert(key(1), 1).unwrap();
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
        tree.root = Root::Node(root, 1);
        tree.insert(key(1), 1).unwrap();
        tree.insert(key(2), 2).unwrap();
        // SAFETY: the root is live; slot 1 held a value we replace.
        let spare = tree.create_node().unwrap();
        unsafe {
            let _old = root.as_mut().take(1);
            root.as_mut().put_node(1, spare);
        }
        assert!(tree.get(key(1)).is_none());
        assert!(tree.get_mut(key(1)).is_none());
        assert!(tree.remove(key(1)).is_none());
        assert_eq!(tree.iter().count(), 1);
        tree.clear();
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn insert_into_a_slot_that_holds_a_node() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        let mut root = tree.create_node().unwrap();
        tree.root = Root::Node(root, 1);
        tree.insert(key(1), 1).unwrap();
        tree.insert(key(2), 2).unwrap();
        // SAFETY: the root is live; slot 1 held a value we replace.
        let spare = tree.create_node().unwrap();
        unsafe {
            let _old = root.as_mut().take(1);
            root.as_mut().put_node(1, spare);
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
        tree.root = Root::Node(root, 1);
        tree.insert(key(0), 0).unwrap();
        tree.insert(key(1), 1).unwrap();
        // SAFETY: the root is live; slot 1 becomes a value in a non-leaf.
        unsafe {
            let _old = root.as_mut().take(1);
            root.as_mut().put_value(1, 9);
        }
        tree.root = Root::Node(root, 2);
        assert_eq!(tree.insert(key(64), 1), Err(Error::Exists));
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

    /// A removal leaves a three-level tree's bottom leaf non-empty while
    /// the level above it already had its free bit set, so the walk
    /// settles there instead of telling the root.
    #[test]
    fn remove_settles_where_the_free_bit_was_already_set() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.insert(key(0), 0).unwrap();
        tree.insert(key(1), 1).unwrap();
        tree.insert(key(1 << 12), 2).unwrap();
        assert_eq!(tree.remove(key(0)), Some(0));
        assert_eq!(tree.get(key(1)), Some(&1));
        assert_eq!(tree.get(key(1 << 12)), Some(&2));
        assert_eq!(tree.iter().count(), 2);
    }

    /// A node root at height zero holds no value: the remove misses and
    /// the block is still the tree's to free.
    #[test]
    fn rollback_frees_a_partial_path() {
        let heap = Heap::failing_from(2);
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        assert_eq!(tree.insert(key(1 << 12), 1), Err(Error::ResourceShortage));
        assert!(tree.is_empty());
        assert_eq!(heap.live(), 0);
    }

    /// A failed descent frees the nodes it made and leaves a root it did
    /// not make alone.
    #[test]
    fn rollback_keeps_a_root_it_did_not_create() {
        let heap = Heap::failing_from(4);
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        // Three nodes carry the first key: a root, a child and a leaf.
        tree.insert(key(1 << 12), 1).unwrap();
        // The next key needs two fresh nodes, and the second one fails.
        assert_eq!(tree.insert(key(1 << 13), 2), Err(Error::ResourceShortage));
        assert_eq!(tree.get(key(1 << 12)), Some(&1));
        assert!(tree.get(key(1 << 13)).is_none());
        assert_eq!(tree.iter().count(), 1);
        assert_eq!(heap.live(), 3);
    }

    #[test]
    fn grow_past_the_height_limit() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        tree.root = Root::Empty(MAX_HEIGHT);
        assert_eq!(tree.insert(key(u32::MAX), 1), Ok(()));
        assert_eq!(tree.root.height(), MAX_HEIGHT);
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
    fn get_of_a_value_in_a_non_leaf_slot_panics() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        let mut root = tree.create_node().unwrap();
        tree.root = Root::Node(root, 1);
        tree.insert(key(0), 0).unwrap();
        // SAFETY: the root is live; slot 0 becomes a value at height 2.
        unsafe {
            let _old = root.as_mut().take(0);
            root.as_mut().put_value(0, 9);
        }
        tree.root = Root::Node(root, 2);
        let _found = tree.get(key(0));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "radix tree: a value sits above the bottom level"]
    fn get_mut_of_a_value_in_a_non_leaf_slot_panics() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        let mut root = tree.create_node().unwrap();
        tree.root = Root::Node(root, 1);
        tree.insert(key(0), 0).unwrap();
        // SAFETY: the root is live; slot 0 becomes a value at height 2.
        unsafe {
            let _old = root.as_mut().take(0);
            root.as_mut().put_value(0, 9);
        }
        tree.root = Root::Node(root, 2);
        let _found = tree.get_mut(key(0));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "slot already used"]
    fn put_into_an_occupied_slot_panics() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        let mut handle = tree.create_node().unwrap();
        tree.root = Root::Node(handle, 1);
        // SAFETY: the node is live and slot 0 is free, then taken.
        unsafe {
            handle.as_mut().put_value(0, 1);
            handle.as_mut().put_value(0, 2);
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
        tree.root = Root::Node(root, MAX_HEIGHT);
        let _placed = tree.insert_alloc(1);
    }

    /// A subtree the parent's free bit calls free but that is full is not
    /// a state a free-key walk can descend into: the walk panics instead
    /// of reading a slot that holds nothing.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic = "radix tree: a free-key walk reached a full node"]
    fn a_free_key_walk_into_a_full_node_panics() {
        let heap = Heap::new();
        let mut tree = RadixTree::<u32, &Heap>::new(&heap);
        let mut root = tree.create_node().unwrap();
        tree.root = Root::Node(root, 2);
        let mut leaf = tree.create_node().unwrap();
        // SAFETY: the root is live and slot 0 is free, and the leaf is
        // live; the leaf then claims a free key the root believes in.
        unsafe {
            root.as_mut().put_node(0, leaf);
            leaf.as_mut().free_bm = 0;
        }
        let _placed = tree.insert_alloc(1);
    }
}
