// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2011-2018 Richard Braun
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
//
// Derived from librbraun (commit cc2f34dc189074e8a93c03ebc5c0790661353b86)
// original files: src/rdxtree.c, src/rdxtree.h and src/rdxtree_i.h

//! A radix tree of non-owning pointers under 64-bit keys.
//!
//! One level of the tree selects six key bits, and the tree is only as tall
//! as its largest key needs: at most 11 levels.  Leaves are `NonNull<T>` the
//! tree never dereferences or frees.  They must be four-byte aligned,
//! because the low bit of an entry tells a child node from a leaf.  Nodes
//! come from the owner's [`Alloc`] and are freed on removal, shrinking,
//! [`clear`](RadixTree::clear) and drop.  An insertion that cannot get a
//! node is [`Error::NoMemory`]; nothing waits.
//!
//! With key allocation on, each node keeps a bitmap of the slots with room
//! below them, and [`insert_alloc`](RadixTree::insert_alloc) follows the
//! lowest set bit down.  A node clears its bit in the parent once every one
//! of its slots is occupied, even while a child below it still has room, so
//! allocation can pass over a free key until a removal under that node sets
//! the bit again.
//!
//! The performance comparison against the tree the kernel's name tables
//! started from lives in the `rdxtree-bench` crate.
//!
//! | operation | cost |
//! |---|---|
//! | [`get`](RadixTree::get), [`insert`](RadixTree::insert), [`remove`](RadixTree::remove) | O(height) |
//! | [`insert_alloc`](RadixTree::insert_alloc) | O(height) |
//! | [`iter`](RadixTree::iter) | O(1) amortised per item |
//! | [`clear`](RadixTree::clear) | O(nodes × height) |
//!
//! Mutation takes the tree exclusively; a [`Slot`] borrows it exclusively
//! and an [`Iter`] shares it.  A tree is not internally locked; the caller
//! serialises it.

#![expect(
    clippy::indexing_slicing,
    reason = "entry indices come from a six-bit mask, a bitmap bit, or a scan that stops at an occupied entry"
)]

use crate::alloc::{Alloc, AllocError};
use core::alloc::Layout;
use core::fmt;
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

const RADIX: u16 = 6;
const SIZE: usize = 64;

/// An insertion cannot overwrite an occupied key or recover from exhaustion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The key is already occupied.
    Busy,
    /// The allocator could not supply a node.
    NoMemory,
}

#[repr(C)]
struct Node {
    parent: *mut Self,
    index: u16,
    height: u16,
    count: u16,
    bitmap: u64,
    entries: [*mut (); SIZE],
}

fn address(entry: *mut ()) -> *mut () {
    entry.map_addr(|addr| addr & !3)
}

fn is_node(entry: *mut ()) -> bool {
    entry.addr() & 1 != 0
}

fn node_entry(node: *mut Node) -> *mut () {
    node.cast::<()>().map_addr(|addr| addr | 1)
}

const fn max_key(height: u16) -> u64 {
    let shift = height * RADIX;
    if shift < 64 {
        (1_u64 << shift) - 1
    } else {
        u64::MAX
    }
}

/// # Safety
/// `shift` is below 64; reachable tree heights select at most bit 60.
unsafe fn index_at(key: u64, shift: u16) -> u16 {
    u16::from(unsafe { key.unchecked_shr(u32::from(shift)) }.to_le_bytes()[0])
        & 63
}

fn check_pointer<T>(pointer: NonNull<T>) {
    assert_eq!(pointer.as_ptr().addr() & 3, 0, "unaligned leaf pointer");
}

impl Node {
    #[cold]
    #[inline]
    fn create<A: Alloc>(
        alloc: &A,
        height: u16,
    ) -> Result<NonNull<Self>, AllocError> {
        let block = alloc.alloc(Layout::new::<Self>())?;
        let node = block.cast::<Self>();
        // SAFETY: `Alloc` supplies unique, aligned storage for a complete node.
        // Each field is initialized before the node escapes. Zero bytes form
        // valid integers and null thin pointers in the header and entry array.
        unsafe {
            let raw = node.as_ptr();
            raw.cast::<u8>()
                .write_bytes(0, core::mem::offset_of!(Self, bitmap));
            (&raw mut (*raw).height).write(height);
            (&raw mut (*raw).bitmap).write(u64::MAX);
            (&raw mut (*raw).entries).write_bytes(0, 1);
        }
        Ok(node)
    }

    /// # Safety
    /// `node` is a live node from `alloc`, detached from the tree, with no
    /// outstanding references. Its children have been detached or freed.
    unsafe fn free<A: Alloc>(alloc: &A, node: *mut Self) {
        unsafe {
            alloc.free(
                NonNull::new_unchecked(node.cast()),
                Layout::new::<Self>(),
            );
        };
    }

    /// # Safety
    /// `node` is exclusively accessible and live; `index` is below 64 and empty.
    unsafe fn insert(node: *mut Self, index: u16, entry: *mut ()) {
        unsafe {
            debug_assert!((*node).entries[usize::from(index)].is_null());
            (*node).count += 1;
            (*node).entries[usize::from(index)] = entry;
        }
    }

    /// # Safety
    /// `node` is exclusively accessible and live; `index` is below 64 and occupied.
    unsafe fn remove(node: *mut Self, index: u16) {
        unsafe {
            debug_assert!(!(*node).entries[usize::from(index)].is_null());
            (*node).count -= 1;
            (*node).entries[usize::from(index)] = ptr::null_mut();
        }
    }

    /// # Safety
    /// `node` and its ancestors are live and exclusively accessible.
    /// `index` is below 64 and names a newly occupied leaf or full child.
    unsafe fn clear_bit(mut node: *mut Self, mut index: u16) {
        unsafe {
            loop {
                (*node).bitmap &= !(1_u64 << index);
                if usize::from((*node).count) != SIZE
                    || (*node).parent.is_null()
                {
                    break;
                }
                index = (*node).index;
                node = (*node).parent;
            }
        }
    }

    /// # Safety
    /// `node` and its ancestors are live and exclusively accessible.
    /// `index` is below 64 and names capacity made available by removal.
    unsafe fn set_bit(mut node: *mut Self, mut index: u16) {
        unsafe {
            loop {
                (*node).bitmap |= 1_u64 << index;
                if (*node).parent.is_null() {
                    break;
                }
                index = (*node).index;
                node = (*node).parent;
                if (*node).bitmap & (1_u64 << index) != 0 {
                    break;
                }
            }
        }
    }
}

/// Owns internal nodes, while leaves remain the caller's responsibility.
///
/// Node addresses stay stable until removal, shrinking, clearing or drop.
pub struct RadixTree<T, A: Alloc> {
    height: u16,
    key_alloc: bool,
    root: *mut (),
    alloc: A,
    marker: PhantomData<NonNull<T>>,
}

impl<T, A: Alloc> RadixTree<T, A> {
    /// `key_alloc` enables bitmap maintenance and automatic key allocation.
    #[must_use]
    pub const fn new(alloc: A, key_alloc: bool) -> Self {
        Self {
            height: 0,
            key_alloc,
            root: ptr::null_mut(),
            alloc,
            marker: PhantomData,
        }
    }

    /// Leaves remain owned by the caller, on success and on failure.
    ///
    /// # Panics
    /// The pointer is not four-byte aligned.
    ///
    /// # Errors
    /// [`Error::Busy`] for an occupied key, or [`Error::NoMemory`].
    pub fn insert(
        &mut self,
        key: u64,
        pointer: NonNull<T>,
    ) -> Result<(), Error> {
        self.insert_impl(key, pointer, None)
    }

    /// The returned slot prevents structural mutation until its borrow ends.
    ///
    /// # Panics
    /// The pointer is not four-byte aligned.
    ///
    /// # Errors
    /// [`Error::Busy`] for an occupied key, or [`Error::NoMemory`].
    #[inline]
    pub fn insert_slot(
        &mut self,
        key: u64,
        pointer: NonNull<T>,
    ) -> Result<Slot<'_, T>, Error> {
        let mut entry = ptr::null_mut();
        self.insert_impl(key, pointer, Some(&mut entry))?;
        // SAFETY: insertion returns an occupied entry in this exclusively
        // borrowed tree; the borrow keeps its node or root location live.
        Ok(Slot {
            entry: unsafe { &mut *entry },
            marker: PhantomData,
        })
    }

    #[inline(never)]
    fn insert_impl(
        &mut self,
        key: u64,
        pointer: NonNull<T>,
        slot: Option<&mut *mut *mut ()>,
    ) -> Result<(), Error> {
        check_pointer(pointer);
        // SAFETY: an exclusive tree borrow owns every reachable node; heights
        // and masked indices select initialized entries. Leaves are never read.
        unsafe {
            if key > max_key(self.height) {
                self.grow(key)?;
            }
            if self.height == 0 {
                if !self.root.is_null() {
                    return Err(Error::Busy);
                }
                self.root = pointer.as_ptr().cast();
                if let Some(slot) = slot {
                    *slot = &raw mut self.root;
                }
                return Ok(());
            }
            let mut node = address(self.root).cast::<Node>();
            if self.height == 1 && !node.is_null() {
                let index = usize::from(index_at(key, 0));
                if !(*node).entries[index].is_null() {
                    return Err(Error::Busy);
                }
                (*node).count += 1;
                (*node).entries[index] = pointer.as_ptr().cast();
                if self.key_alloc {
                    (*node).bitmap &= !(1_u64 << index);
                }
                if let Some(slot) = slot {
                    *slot = &raw mut (*node).entries[index];
                }
                return Ok(());
            }
            let mut prev = ptr::null_mut::<Node>();
            let mut index = 0;
            let mut height = self.height;
            let mut shift = (height - 1) * RADIX;
            loop {
                if node.is_null() {
                    node = if let Ok(node) =
                        Node::create(&self.alloc, height - 1)
                    {
                        node.as_ptr()
                    } else {
                        if prev.is_null() {
                            self.height = 0;
                        } else {
                            self.cleanup(prev);
                        }
                        return Err(Error::NoMemory);
                    };
                    if prev.is_null() {
                        self.root = node_entry(node);
                    } else {
                        (*node).parent = prev;
                        (*node).index = index;
                        Node::insert(prev, index, node_entry(node));
                    }
                }
                prev = node;
                index = index_at(key, shift);
                node = address((*prev).entries[usize::from(index)]).cast();
                shift = shift.wrapping_sub(RADIX);
                height -= 1;
                if height == 0 {
                    break;
                }
            }
            if !node.is_null() {
                return Err(Error::Busy);
            }
            Node::insert(prev, index, pointer.as_ptr().cast());
            if self.key_alloc {
                Node::clear_bit(prev, index);
            }
            if let Some(slot) = slot {
                *slot = &raw mut (*prev).entries[usize::from(index)];
            }
            Ok(())
        }
    }

    /// Bitmap traversal chooses a free key; propagation quirks can skip holes.
    ///
    /// # Panics
    /// Key allocation is disabled, or the pointer is not four-byte aligned.
    ///
    /// # Errors
    /// [`Error::NoMemory`], or [`Error::Busy`] when allocation wraps to an
    /// occupied key at the limit of the key space.
    pub fn insert_alloc(&mut self, pointer: NonNull<T>) -> Result<u64, Error> {
        self.insert_alloc_impl(pointer, None)
    }

    /// The slot remains valid for the duration of the exclusive tree borrow.
    ///
    /// # Panics
    /// Key allocation is disabled, or the pointer is not four-byte aligned.
    ///
    /// # Errors
    /// [`Error::NoMemory`] or [`Error::Busy`] at key-space exhaustion.
    pub fn insert_alloc_slot(
        &mut self,
        pointer: NonNull<T>,
    ) -> Result<(u64, Slot<'_, T>), Error> {
        let mut entry = ptr::null_mut();
        let key = self.insert_alloc_impl(pointer, Some(&mut entry))?;
        // SAFETY: successful slot insertion returns an occupied entry owned
        // by this exclusively borrowed tree; the borrow keeps it live.
        Ok((
            key,
            Slot {
                entry: unsafe { &mut *entry },
                marker: PhantomData,
            },
        ))
    }

    #[expect(
        clippy::inline_always,
        reason = "Inlining removes the key Result temporary and unused slot output; measured faster on the host."
    )]
    #[inline(always)]
    fn insert_alloc_impl(
        &mut self,
        pointer: NonNull<T>,
        slot: Option<&mut *mut *mut ()>,
    ) -> Result<u64, Error> {
        assert!(self.key_alloc, "key allocation disabled");
        check_pointer(pointer);
        // SAFETY: the exclusive borrow owns all nodes and the bitmap selects
        // an empty leaf or child. New children are attached before descent.
        unsafe {
            let mut height = self.height;
            if height == 0 {
                if self.root.is_null() {
                    self.root = pointer.as_ptr().cast();
                    if let Some(slot) = slot {
                        *slot = &raw mut self.root;
                    }
                    return Ok(0);
                }
                self.grow(1)?;
                return self.insert_slot(1, pointer).map(|entry| {
                    if let Some(slot) = slot {
                        *slot = ptr::from_mut(entry.entry);
                    }
                    1
                });
            }
            let mut node = address(self.root).cast::<Node>();
            if height == 1 && (*node).bitmap != 0 {
                let index = (*node).bitmap.trailing_zeros().to_le_bytes()[0];
                (*node).count += 1;
                (*node).entries[usize::from(index)] = pointer.as_ptr().cast();
                (*node).bitmap &= !(1_u64 << index);
                if let Some(slot) = slot {
                    *slot = &raw mut (*node).entries[usize::from(index)];
                }
                return Ok(u64::from(index));
            }
            let mut prev = ptr::null_mut::<Node>();
            let mut index = 0;
            let mut key = 0;
            let mut shift = (height - 1) * RADIX;
            loop {
                if node.is_null() {
                    node = if let Ok(node) =
                        Node::create(&self.alloc, height - 1)
                    {
                        node.as_ptr()
                    } else {
                        self.cleanup(prev);
                        return Err(Error::NoMemory);
                    };
                    (*node).parent = prev;
                    (*node).index = index;
                    Node::insert(prev, index, node_entry(node));
                }
                prev = node;
                if (*node).bitmap == 0 {
                    key = max_key(height).wrapping_add(1);
                    if key > max_key(self.height) {
                        self.grow(key)?;
                    }
                    return self.insert_slot(key, pointer).map(|entry| {
                        if let Some(slot) = slot {
                            *slot = ptr::from_mut(entry.entry);
                        }
                        key
                    });
                }
                index = u16::from(
                    (*node).bitmap.trailing_zeros().to_le_bytes()[0],
                );
                height -= 1;
                if height == 0 {
                    key |= u64::from(index);
                    break;
                }
                key |= u64::from(index) << shift;
                node = address((*node).entries[usize::from(index)]).cast();
                shift -= RADIX;
            }
            Node::insert(prev, index, pointer.as_ptr().cast());
            Node::clear_bit(prev, index);
            if let Some(slot) = slot {
                *slot = &raw mut (*prev).entries[usize::from(index)];
            }
            Ok(key)
        }
    }

    /// Returns a non-owning pointer, without accessing its pointee.
    #[must_use]
    pub fn get(&self, key: u64) -> Option<NonNull<T>> {
        NonNull::new(self.lookup(key, false)?.cast())
    }

    /// An exclusive borrow keeps the slot live until the returned value expires.
    #[must_use]
    pub fn get_slot(&mut self, key: u64) -> Option<Slot<'_, T>> {
        let entry = self.lookup(key, true)?.cast::<*mut ()>();
        if self.height == 0 {
            return Some(Slot {
                entry: &mut self.root,
                marker: PhantomData,
            });
        }
        // SAFETY: lookup selects an occupied leaf; the exclusive tree borrow
        // prevents every other access to it for the returned slot's lifetime.
        Some(Slot {
            entry: unsafe { &mut *entry },
            marker: PhantomData,
        })
    }

    fn lookup(&self, key: u64, slot: bool) -> Option<*mut ()> {
        // SAFETY: reachable nodes are live during the tree borrow; each node
        // has an immutable height and each index selects an initialized entry.
        unsafe {
            // The shared borrow prevents resizing throughout this lookup.
            let mut height = self.height;
            if height == 0 {
                return (key == 0 && !self.root.is_null()).then_some(
                    if slot {
                        ptr::from_ref(&self.root).cast_mut().cast()
                    } else {
                        self.root
                    },
                );
            }
            if key > max_key(height) {
                return None;
            }
            let mut node = address(self.root).cast::<Node>();
            let mut shift = (height - 1) * RADIX;
            loop {
                if node.is_null() {
                    return None;
                }
                let index = index_at(key, shift);
                let location =
                    ptr::addr_of_mut!((*node).entries[usize::from(index)]);
                let entry = *location;
                height -= 1;
                if height == 0 {
                    return (!entry.is_null()).then_some(if slot {
                        location.cast()
                    } else {
                        entry
                    });
                }
                node = address(entry).cast();
                shift -= RADIX;
            }
        }
    }

    /// Frees empty internal nodes and shrinks through a sole child at index zero.
    /// Leaves remain the caller's responsibility.
    #[expect(
        clippy::inline_always,
        reason = "Inlining retains tree state across repeated removal; measured faster on the host."
    )]
    #[inline(always)]
    pub fn remove(&mut self, key: u64) -> Option<NonNull<T>> {
        if key > max_key(self.height) {
            return None;
        }
        if self.height == 0 {
            return NonNull::new(
                core::mem::replace(&mut self.root, ptr::null_mut()).cast(),
            );
        }
        // SAFETY: the exclusive tree borrow owns all nodes on the descent and
        // cleanup paths. The leaf is copied before its node can be freed.
        unsafe {
            let mut node = address(self.root).cast::<Node>();
            let mut height = self.height;
            let mut shift = (height - 1) * RADIX;
            loop {
                if node.is_null() {
                    return None;
                }
                let index = index_at(key, shift);
                let entry = address((*node).entries[usize::from(index)]);
                height -= 1;
                if height == 0 {
                    let pointer = NonNull::new(entry.cast())?;
                    if self.key_alloc {
                        Node::set_bit(node, index);
                    }
                    Node::remove(node, index);
                    self.cleanup(node);
                    return Some(pointer);
                }
                node = entry.cast();
                shift -= RADIX;
            }
        }
    }

    #[cold]
    #[inline(never)]
    fn grow(&mut self, key: u64) -> Result<(), Error> {
        // SAFETY: exclusive access owns the live root and every newly allocated
        // node. Each new root adopts the previous root before becoming visible.
        unsafe {
            let mut new_height = self.height + 1;
            while key > max_key(new_height) {
                new_height += 1;
            }
            if self.root.is_null() {
                self.height = new_height;
            } else {
                while self.height < new_height {
                    let node = if let Ok(node) =
                        Node::create(&self.alloc, self.height)
                    {
                        node.as_ptr()
                    } else {
                        self.shrink();
                        return Err(Error::NoMemory);
                    };
                    if self.height == 0 {
                        if self.key_alloc {
                            (*node).bitmap &= !1;
                        }
                    } else {
                        let root = address(self.root).cast::<Node>();
                        (*root).parent = node;
                        (*root).index = 0;
                        if self.key_alloc && (*root).bitmap == 0 {
                            (*node).bitmap &= !1;
                        }
                    }
                    Node::insert(node, 0, self.root);
                    self.height += 1;
                    self.root = node_entry(node);
                }
            }
        }
        Ok(())
    }

    #[expect(
        clippy::inline_always,
        reason = "Inlining lets cleanup retain node and height state in registers."
    )]
    #[inline(always)]
    fn shrink(&mut self) {
        // SAFETY: an exclusive tree borrow owns the root. A sole child at
        // index zero can replace it; no slots or iterators are outstanding.
        unsafe {
            while self.height > 0 {
                let node = address(self.root).cast::<Node>();
                if (*node).count != 1 {
                    break;
                }
                let entry = (*node).entries[0];
                if entry.is_null() {
                    break;
                }
                self.height -= 1;
                if self.height > 0 {
                    (*address(entry).cast::<Node>()).parent = ptr::null_mut();
                }
                self.root = entry;
                Node::free(&self.alloc, node);
            }
        }
    }

    /// # Safety
    /// `node` belongs to this exclusively borrowed tree and is live. Its
    /// ancestors are live and linked; no external references to nodes exist.
    #[expect(
        clippy::inline_always,
        reason = "Inlining removes a call from each removal and exposes the unchanged key-allocation flag."
    )]
    #[inline(always)]
    unsafe fn cleanup(&mut self, mut node: *mut Node) {
        unsafe {
            loop {
                if (*node).count != 0 {
                    if (*node).parent.is_null() {
                        self.shrink();
                    }
                    break;
                }
                if (*node).parent.is_null() {
                    self.height = 0;
                    self.root = ptr::null_mut();
                    Node::free(&self.alloc, node);
                    break;
                }
                let prev = node;
                node = (*node).parent;
                (*prev).parent = ptr::null_mut();
                Node::remove(node, (*prev).index);
                Node::free(&self.alloc, prev);
            }
        }
    }

    /// Visits pointers in increasing key order without accessing pointees.
    #[must_use]
    pub const fn iter(&self) -> Iter<'_, T, A> {
        Iter {
            tree: self,
            node: ptr::null_mut(),
            key: u64::MAX,
        }
    }

    /// Frees nodes without touching or freeing any leaf, and keeps the
    /// key-allocation setting for reuse.
    pub fn clear(&mut self) {
        if self.height == 0 {
            self.root = ptr::null_mut();
            return;
        }
        while self.height != 0 {
            // SAFETY: every reachable node is live and nonempty. Descent
            // selects the first occupied child until reaching a bottom node.
            // Exclusive access permits detaching it; cleanup frees only ancestors.
            unsafe {
                let mut node = address(self.root).cast::<Node>();
                let mut height = self.height;
                while height > 1 {
                    let mut index = 0;
                    while (*node).entries[index].is_null() {
                        index += 1;
                    }
                    node = address((*node).entries[index]).cast();
                    height -= 1;
                }
                let parent = (*node).parent;
                if parent.is_null() {
                    self.height = 0;
                    self.root = ptr::null_mut();
                } else {
                    if self.key_alloc {
                        Node::set_bit(parent, (*node).index);
                    }
                    Node::remove(parent, (*node).index);
                    self.cleanup(parent);
                    (*node).parent = ptr::null_mut();
                }
                Node::free(&self.alloc, node);
            }
        }
    }
}

impl<T, A: Alloc> Drop for RadixTree<T, A> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl<T, A: Alloc> fmt::Debug for RadixTree<T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

/// A replacement location tied to an exclusive tree borrow.
pub struct Slot<'a, T> {
    entry: &'a mut *mut (),
    marker: PhantomData<NonNull<T>>,
}

impl<T> Slot<'_, T> {
    /// Returns the occupied pointer without accessing its pointee.
    #[must_use]
    pub const fn load(&self) -> NonNull<T> {
        // SAFETY: only occupied slots can be constructed and replacements
        // cannot store a null pointer.
        unsafe { NonNull::new_unchecked((*self.entry).cast()) }
    }

    /// Returns the old pointer; ownership of both pointees stays with the caller.
    ///
    /// # Panics
    /// The replacement pointer is not four-byte aligned.
    pub fn replace(&mut self, pointer: NonNull<T>) -> NonNull<T> {
        check_pointer(pointer);
        let old = self.load();
        *self.entry = pointer.as_ptr().cast();
        old
    }
}

impl<T> fmt::Debug for Slot<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Slot").field(&self.load()).finish()
    }
}

/// Holds a shared tree borrow, preventing mutation during traversal.
pub struct Iter<'a, T, A: Alloc> {
    tree: &'a RadixTree<T, A>,
    node: *mut Node,
    key: u64,
}

impl<T, A: Alloc> Iterator for Iter<'_, T, A> {
    type Item = (u64, NonNull<T>);

    #[expect(
        clippy::inline_always,
        reason = "Inlining eliminates iterator state loads in the per-entry loop; measured faster on the host."
    )]
    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: the shared tree borrow keeps all traversed nodes live and
        // immutable. The saved node is a bottom node. Leaves are never read.
        unsafe {
            if !self.node.is_null() {
                let mut index = index_at(self.key.wrapping_add(1), 0);
                if index != 0 {
                    let orig = index;
                    let mut pointer = ptr::null_mut();
                    while usize::from(index) < SIZE {
                        pointer =
                            address((*self.node).entries[usize::from(index)]);
                        if !pointer.is_null() {
                            break;
                        }
                        index += 1;
                    }
                    if let Some(pointer) = NonNull::new(pointer.cast()) {
                        self.key += u64::from(index - orig) + 1;
                        return Some((self.key, pointer));
                    }
                }
            }
            let entry = self.tree.root;
            if entry.is_null() {
                return None;
            }
            if !is_node(entry) {
                if self.key != u64::MAX {
                    return None;
                }
                self.key = 0;
                return NonNull::new(address(entry).cast())
                    .map(|pointer| (0, pointer));
            }
            let mut key = self.key.wrapping_add(1);
            if key == 0 && !self.node.is_null() {
                return None;
            }
            let root = address(entry).cast::<Node>();
            'restart: loop {
                let mut node = root;
                let mut height = (*root).height + 1;
                if key > max_key(height) {
                    return None;
                }
                let mut shift = (height - 1) * RADIX;
                loop {
                    let prev = node;
                    let mut index = index_at(key, shift);
                    let orig = index;
                    let mut pointer = ptr::null_mut();
                    while usize::from(index) < SIZE {
                        pointer = address((*node).entries[usize::from(index)]);
                        if !pointer.is_null() {
                            break;
                        }
                        index += 1;
                    }
                    if pointer.is_null() {
                        shift += RADIX;
                        // The subtree ends at the top of the key space,
                        // so no key remains to seek.
                        if shift >= 64 {
                            return None;
                        }
                        key = ((key >> shift) + 1) << shift;
                        if key == 0 {
                            return None;
                        }
                        continue 'restart;
                    }
                    if orig != index {
                        key = ((key >> shift) + u64::from(index - orig))
                            << shift;
                    }
                    height -= 1;
                    if height == 0 {
                        self.node = prev;
                        self.key = key;
                        return NonNull::new(pointer.cast())
                            .map(|pointer| (key, pointer));
                    }
                    node = pointer.cast();
                    shift -= RADIX;
                }
            }
        }
    }
}

impl<'a, T, A: Alloc> IntoIterator for &'a RadixTree<T, A> {
    type Item = (u64, NonNull<T>);
    type IntoIter = Iter<'a, T, A>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T, A: Alloc> fmt::Debug for Iter<'_, T, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Iter")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Heap;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    fn leaf(value: usize) -> NonNull<u32> {
        NonNull::without_provenance(
            core::num::NonZeroUsize::new(value * 4).unwrap(),
        )
    }

    #[test]
    fn empty_and_direct_root_slots() {
        let heap = Heap::new();
        let mut tree = RadixTree::new(&heap, true);
        assert!(tree.get(0).is_none());
        assert!(tree.get_slot(0).is_none());
        assert!(tree.remove(0).is_none());
        assert!(tree.iter().next().is_none());
        tree.clear();
        let mut slot = tree.insert_slot(0, leaf(1)).unwrap();
        assert_eq!(slot.load(), leaf(1));
        assert_eq!(slot.replace(leaf(2)), leaf(1));
        assert_eq!(tree.insert(0, leaf(3)), Err(Error::Busy));
        assert_eq!(tree.insert_slot(0, leaf(3)).err(), Some(Error::Busy));
        assert_eq!(tree.get(0), Some(leaf(2)));
        assert_eq!(tree.get_slot(0).unwrap().load(), leaf(2));
        assert!(tree.get(1).is_none());
        assert!(tree.remove(1).is_none());
        let mut iter = tree.iter();
        assert_eq!(iter.next(), Some((0, leaf(2))));
        assert_eq!(iter.next(), None);
        assert_eq!(tree.remove(0), Some(leaf(2)));
        assert_eq!(heap.calls(), 0);
        let (key, mut slot) = tree.insert_alloc_slot(leaf(3)).unwrap();
        assert_eq!(key, 0);
        assert_eq!(slot.replace(leaf(4)), leaf(3));
        tree.clear();
        assert_eq!(tree.insert_alloc(leaf(5)), Ok(0));
    }

    #[test]
    fn sparse_keys_slots_and_shrinking() {
        let heap = Heap::new();
        let mut tree = RadixTree::new(&heap, true);
        let keys = [0, 1, 63, 64, 65, 4095, 4096, 1 << 30, 1 << 60, u64::MAX];
        for (i, key) in keys.into_iter().enumerate() {
            tree.insert(key, leaf(i + 1)).unwrap();
            assert_eq!(tree.insert(key, leaf(100)), Err(Error::Busy));
        }
        assert_eq!(tree.height, 11);
        assert_eq!(
            (&tree).into_iter().map(|(key, _)| key).collect::<Vec<_>>(),
            keys
        );
        for (i, key) in keys.into_iter().enumerate() {
            assert_eq!(tree.get(key), Some(leaf(i + 1)));
            let mut slot = tree.get_slot(key).unwrap();
            assert_eq!(slot.load(), leaf(i + 1));
            assert_eq!(slot.replace(leaf(i + 100)), leaf(i + 1));
        }
        for key in [2, 66, 128, 1 << 24, 1 << 61] {
            assert!(tree.get(key).is_none());
            assert!(tree.get_slot(key).is_none());
            assert!(tree.remove(key).is_none());
        }
        for (i, key) in keys.into_iter().enumerate().rev() {
            assert_eq!(tree.remove(key), Some(leaf(i + 100)));
        }
        assert_eq!(tree.height, 0);
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn sequential_allocation_reuses_holes_and_grows() {
        let heap = Heap::new();
        let mut tree = RadixTree::new(&heap, true);
        for key in 0..=64 {
            assert_eq!(tree.insert_alloc(leaf(1)), Ok(key));
        }
        tree.clear();
        for key in 0..5000 {
            let allocated = if key <= 65 || key % 2 == 0 {
                let (allocated, mut slot) =
                    tree.insert_alloc_slot(leaf(1)).unwrap();
                assert_eq!(slot.load(), leaf(1));
                assert_eq!(slot.replace(leaf(2)), leaf(1));
                assert_eq!(slot.replace(leaf(1)), leaf(2));
                allocated
            } else {
                tree.insert_alloc(leaf(1)).unwrap()
            };
            assert_eq!(allocated, key);
        }
        for key in [0, 63, 64, 4095, 4096, 4999] {
            assert_eq!(tree.remove(key), Some(leaf(1)));
        }
        for key in [0, 63, 4096, 4999, 5000, 5001] {
            assert_eq!(tree.insert_alloc(leaf(2)), Ok(key));
        }
        assert!(tree.get(64).is_none());
        assert!(tree.get(4095).is_none());
        assert_eq!(tree.insert_alloc(leaf(3)), Ok(5002));
        tree.clear();
        assert_eq!(heap.live(), 0);
        assert_eq!(tree.insert_alloc(leaf(1)), Ok(0));
    }

    #[test]
    fn preserves_bitmap_propagation_that_skips_free_keys() {
        let heap = Heap::new();
        let mut tree = RadixTree::new(&heap, true);
        for key in (0..=4096).step_by(64) {
            tree.insert(key, leaf(1)).unwrap();
        }
        for key in 1..64 {
            tree.insert(key, leaf(1)).unwrap();
        }
        assert!(tree.get(65).is_none());
        assert_eq!(tree.insert_alloc(leaf(2)), Ok(4097));
        assert_eq!(tree.remove(1), Some(leaf(1)));
        assert_eq!(tree.insert_alloc(leaf(3)), Ok(1));
    }

    #[test]
    fn failure_at_every_node_creation_preserves_existing_entries() {
        for existing in [None, Some(0), Some(64), Some(4096)] {
            for fail in 1..=24 {
                let heap = Heap::new();
                let mut tree = RadixTree::new(&heap, true);
                if let Some(key) = existing {
                    tree.insert(key, leaf(1)).unwrap();
                }
                heap.fail_from_now(fail - 1);
                let result = tree.insert(u64::MAX, leaf(2));
                if result.is_err() {
                    assert_eq!(result, Err(Error::NoMemory));
                }
                if let Some(key) = existing {
                    assert_eq!(tree.get(key), Some(leaf(1)));
                }
                assert_eq!(tree.get(u64::MAX), result.ok().map(|()| leaf(2)));
                heap.stop_failing();
                assert_eq!(
                    tree.insert(u64::MAX, leaf(2)),
                    if result.is_ok() {
                        Err(Error::Busy)
                    } else {
                        Ok(())
                    }
                );
                tree.clear();
                assert_eq!(heap.live(), 0);
            }
        }
    }

    #[test]
    fn allocation_failure_cleans_partial_descent() {
        for fail in 1..=3 {
            let heap = Heap::new();
            let mut tree = RadixTree::new(&heap, true);
            tree.insert(1 << 24, leaf(1)).unwrap();
            heap.fail_from_now(fail - 1);
            let result = if fail == 1 {
                tree.insert_alloc_slot(leaf(2)).map(|(key, _)| key)
            } else {
                tree.insert_alloc(leaf(2))
            };
            assert_eq!(result, Err(Error::NoMemory));
            assert_eq!(tree.get(1 << 24), Some(leaf(1)));
            assert_eq!(tree.iter().count(), 1);
            heap.stop_failing();
            assert_eq!(tree.insert_alloc(leaf(2)), Ok(0));
            tree.clear();
            assert_eq!(heap.live(), 0);
        }
    }

    #[test]
    fn automatic_growth_failure_preserves_a_full_root() {
        for occupied in [1, 64] {
            for with_slot in [false, true] {
                let heap = Heap::new();
                let mut tree = RadixTree::new(&heap, true);
                for key in 0..occupied {
                    assert_eq!(tree.insert_alloc(leaf(1)), Ok(key));
                }
                let live = heap.live();
                heap.fail_from_now(0);
                let result = if with_slot {
                    tree.insert_alloc_slot(leaf(2)).map(|(key, _)| key)
                } else {
                    tree.insert_alloc(leaf(2))
                };
                assert_eq!(result, Err(Error::NoMemory));
                assert_eq!(heap.live(), live);
                assert_eq!(
                    tree.iter().count(),
                    usize::try_from(occupied).unwrap()
                );
                for key in 0..occupied {
                    assert_eq!(tree.get(key), Some(leaf(1)));
                }
                heap.stop_failing();
                assert_eq!(tree.insert_alloc(leaf(2)), Ok(occupied));
                tree.clear();
                assert_eq!(heap.live(), 0);
            }
        }
    }

    #[test]
    fn exhausted_key_allocation_wraps_to_an_occupied_key() {
        let heap = Heap::new();
        let mut tree = RadixTree::new(&heap, true);
        tree.insert(0, leaf(1)).unwrap();
        tree.insert(u64::MAX, leaf(2)).unwrap();
        // Represent exhaustion without allocating the entire 64-bit key space.
        // SAFETY: the exclusive tree borrow owns this live internal root.
        unsafe { (*address(tree.root).cast::<Node>()).bitmap = 0 };
        assert_eq!(tree.insert_alloc(leaf(3)), Err(Error::Busy));
        assert_eq!(tree.insert_alloc_slot(leaf(3)).err(), Some(Error::Busy));
        assert_eq!(tree.get(0), Some(leaf(1)));
        assert_eq!(tree.get(u64::MAX), Some(leaf(2)));
        tree.clear();
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn clear_and_drop_with_bitmap_maintenance_disabled() {
        let heap = Heap::new();
        {
            let mut tree = RadixTree::new(&heap, false);
            for key in [0, 64, 4096, u64::MAX] {
                tree.insert(key, leaf(1)).unwrap();
            }
            assert_eq!(tree.remove(64), Some(leaf(1)));
            assert_eq!(tree.remove(u64::MAX), Some(leaf(1)));
            tree.clear();
            assert_eq!(heap.live(), 0);
            tree.insert(1, leaf(2)).unwrap();
            tree.insert(2, leaf(2)).unwrap();
            tree.insert(65, leaf(2)).unwrap();
        }
        assert_eq!(heap.live(), 0);
    }

    #[test]
    fn top_level_iteration_exhaustion_has_no_out_of_width_shift() {
        let heap = Heap::new();
        let mut tree = RadixTree::new(&heap, true);
        tree.insert(1 << 60, leaf(1)).unwrap();
        assert_eq!(tree.iter().collect::<Vec<_>>(), [(1 << 60, leaf(1))]);
        tree.clear();
        tree.insert(u64::MAX, leaf(2)).unwrap();
        let mut iter = tree.iter();
        assert_eq!(iter.next(), Some((u64::MAX, leaf(2))));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
        tree.clear();
        tree.insert(u64::MAX - 1, leaf(3)).unwrap();
        assert_eq!(tree.iter().collect::<Vec<_>>(), [(u64::MAX - 1, leaf(3))]);
    }

    #[test]
    fn clears_a_bottom_root_with_several_entries() {
        let heap = Heap::new();
        let mut tree = RadixTree::new(&heap, true);
        tree.insert(1, leaf(1)).unwrap();
        tree.insert(2, leaf(2)).unwrap();
        tree.clear();
        assert_eq!(tree.height, 0);
        assert_eq!(heap.live(), 0);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "assertion failed")]
    fn node_insert_checks_an_empty_slot() {
        let mut node = Node {
            parent: ptr::null_mut(),
            index: 0,
            height: 0,
            count: 1,
            bitmap: u64::MAX,
            entries: [leaf(1).as_ptr().cast(); SIZE],
        };
        // SAFETY: the live local node has exclusive access and a valid index.
        // The deliberately occupied slot exercises the invariant assertion.
        unsafe {
            Node::insert(&raw mut node, 0, leaf(2).as_ptr().cast());
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "assertion failed")]
    fn node_remove_checks_an_occupied_slot() {
        let mut node = Node {
            parent: ptr::null_mut(),
            index: 0,
            height: 0,
            count: 0,
            bitmap: u64::MAX,
            entries: [ptr::null_mut(); SIZE],
        };
        // SAFETY: the live local node has exclusive access and a valid index.
        // The deliberately empty slot exercises the invariant assertion.
        unsafe {
            Node::remove(&raw mut node, 0);
        }
    }

    #[test]
    fn seeded_operations_match_an_ordered_map() {
        let heap = Heap::new();
        let mut tree = RadixTree::new(&heap, true);
        let mut map = BTreeMap::new();
        let mut random = 123_456_789_u64;
        for step in 1..=12000 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let key = (random >> 8) & 0xffff;
            match random & 3 {
                0 => {
                    let expected = match map.entry(key) {
                        std::collections::btree_map::Entry::Vacant(entry) => {
                            let _ = entry.insert(leaf(step));
                            Ok(())
                        }
                        std::collections::btree_map::Entry::Occupied(_) => {
                            Err(Error::Busy)
                        }
                    };
                    assert_eq!(tree.insert(key, leaf(step)), expected);
                }
                1 => {
                    assert_eq!(tree.remove(key), map.remove(&key));
                }
                2 => {
                    assert_eq!(tree.get(key), map.get(&key).copied());
                }
                _ => {
                    if let Some(mut slot) = tree.get_slot(key) {
                        let old = map.insert(key, leaf(step));
                        assert_eq!(Some(slot.replace(leaf(step))), old);
                    }
                }
            }
            if step % 257 == 0 {
                assert_eq!(
                    tree.iter().collect::<Vec<_>>(),
                    map.iter()
                        .map(|(&key, &ptr)| (key, ptr))
                        .collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    #[should_panic(expected = "unaligned leaf pointer")]
    fn rejects_unaligned_insert() {
        let mut tree = RadixTree::new(Heap::new(), true);
        tree.insert(0, NonNull::<u8>::dangling()).unwrap();
    }

    #[test]
    #[should_panic(expected = "unaligned leaf pointer")]
    fn rejects_unaligned_replacement() {
        let mut tree = RadixTree::<u8, _>::new(Heap::new(), true);
        tree.insert(0, leaf(1).cast()).unwrap();
        let _ = tree.get_slot(0).unwrap().replace(NonNull::dangling());
    }

    #[test]
    #[should_panic(expected = "key allocation disabled")]
    fn rejects_disabled_key_allocation() {
        let mut tree = RadixTree::new(Heap::new(), false);
        let _ = tree.insert_alloc(leaf(1)).unwrap();
    }

    #[test]
    fn debug_shows_keys_and_pointers_only() {
        let heap = Heap::new();
        let mut tree = RadixTree::new(&heap, true);
        tree.insert(5, leaf(1)).unwrap();
        assert_eq!(format!("{tree:?}"), format!("{{5: {:?}}}", leaf(1)));
        let iter = tree.iter();
        assert_eq!(
            format!("{iter:?}"),
            format!("Iter {{ key: {}, .. }}", u64::MAX)
        );
        let slot = tree.get_slot(5).unwrap();
        assert_eq!(format!("{slot:?}"), format!("Slot({:?})", leaf(1)));
    }
}
