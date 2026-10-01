// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Cursors and the double-ended iterator over an [`RbTree`].
//!
//! A cursor rests on a node or on the ghost, the position before the
//! front and after the back: moving forward from the last node, or back
//! from the first, reaches the ghost, and moving on from the ghost wraps
//! to the other end.  A step is O(log n) at worst and O(1) amortised over
//! a walk.

use super::{Adapter, LEFT, Link, RIGHT, RbTree, balance};
use core::fmt;
use core::marker::PhantomData;
use core::ptr::NonNull;

/// A cursor over a shared [`RbTree`], borrowed for `'head`.
pub struct Cursor<'head, 'nodes, A: Adapter> {
    tree: &'head RbTree<'nodes, A>,
    current: Option<NonNull<Link>>,
}

impl<'head, 'nodes, A: Adapter> Cursor<'head, 'nodes, A> {
    pub(super) const fn new(
        tree: &'head RbTree<'nodes, A>,
        current: Option<NonNull<Link>>,
    ) -> Self {
        Self { tree, current }
    }

    /// Returns the node at the cursor, or `None` at the ghost.
    #[must_use]
    #[inline]
    pub fn current(&self) -> Option<&'head A::Node> {
        // SAFETY: a node stays live while it is on the tree.
        self.current.map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Returns a pointer to the node at the cursor, or `None` at the ghost.
    ///
    /// The pointer is the one the node was inserted with, so it may be
    /// written through wherever that insert allowed it, unlike one made
    /// from [`current`](Self::current).  It names the node only while the
    /// node is on the tree, and its link must never be written through it.
    #[must_use]
    #[inline]
    pub fn current_ptr(&self) -> Option<NonNull<A::Node>> {
        // SAFETY: a node stays live while it is on the tree.
        self.current.map(|link| unsafe { A::node(link) })
    }

    /// Moves to the next node: from the last node to the ghost, and from
    /// the ghost to the front.
    #[inline]
    pub fn move_next(&mut self) {
        // SAFETY: the cursor rests on the tree's ghost or on one of its
        // nodes.
        self.current = unsafe { self.tree.next_after(self.current) };
    }

    /// Moves to the previous node: from the first node to the ghost, and
    /// from the ghost to the back.
    #[inline]
    pub fn move_prev(&mut self) {
        // SAFETY: the cursor rests on the tree's ghost or on one of its
        // nodes.
        self.current = unsafe { self.tree.prev_before(self.current) };
    }

    /// Returns the node after the cursor without moving, or `None` past
    /// the last node; from the ghost, the front.
    #[must_use]
    #[inline]
    pub fn peek_next(&self) -> Option<&'head A::Node> {
        // SAFETY: the cursor rests on the tree's ghost or on one of its
        // nodes, and a node stays live while it is on the tree.
        unsafe { self.tree.next_after(self.current) }
            .map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Returns the node before the cursor without moving, or `None`
    /// before the first node; from the ghost, the back.
    #[must_use]
    #[inline]
    pub fn peek_prev(&self) -> Option<&'head A::Node> {
        // SAFETY: the cursor rests on the tree's ghost or on one of its
        // nodes, and a node stays live while it is on the tree.
        unsafe { self.tree.prev_before(self.current) }
            .map(|link| unsafe { A::node(link).as_ref() })
    }
}

/// A cursor over an exclusively borrowed [`RbTree`] that can unlink
/// nodes.
pub struct CursorMut<'head, 'nodes, A: Adapter> {
    tree: &'head mut RbTree<'nodes, A>,
    current: Option<NonNull<Link>>,
}

impl<'head, 'nodes, A: Adapter> CursorMut<'head, 'nodes, A> {
    pub(super) const fn new(
        tree: &'head mut RbTree<'nodes, A>,
        current: Option<NonNull<Link>>,
    ) -> Self {
        Self { tree, current }
    }

    /// Returns the node at the cursor, or `None` at the ghost.
    #[must_use]
    #[inline]
    pub fn current(&self) -> Option<&A::Node> {
        // SAFETY: a node stays live while it is on the tree.
        self.current.map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Returns a pointer to the node at the cursor, or `None` at the ghost.
    ///
    /// The pointer is the one the node was inserted with, so it may be
    /// written through wherever that insert allowed it, unlike one made
    /// from [`current`](Self::current).  It names the node only while the
    /// node is on the tree, and its link must never be written through it.
    #[must_use]
    #[inline]
    pub fn current_ptr(&self) -> Option<NonNull<A::Node>> {
        // SAFETY: a node stays live while it is on the tree.
        self.current.map(|link| unsafe { A::node(link) })
    }

    /// Moves to the next node: from the last node to the ghost, and from
    /// the ghost to the front.
    #[inline]
    pub fn move_next(&mut self) {
        // SAFETY: the cursor rests on the tree's ghost or on one of its
        // nodes.
        self.current = unsafe { self.tree.next_after(self.current) };
    }

    /// Moves to the previous node: from the first node to the ghost, and
    /// from the ghost to the back.
    #[inline]
    pub fn move_prev(&mut self) {
        // SAFETY: the cursor rests on the tree's ghost or on one of its
        // nodes.
        self.current = unsafe { self.tree.prev_before(self.current) };
    }

    /// Returns the node after the cursor without moving, or `None` past
    /// the last node; from the ghost, the front.
    #[must_use]
    #[inline]
    pub fn peek_next(&self) -> Option<&A::Node> {
        // SAFETY: the cursor rests on the tree's ghost or on one of its
        // nodes, and a node stays live while it is on the tree.
        unsafe { self.tree.next_after(self.current) }
            .map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Returns the node before the cursor without moving, or `None`
    /// before the first node; from the ghost, the back.
    #[must_use]
    #[inline]
    pub fn peek_prev(&self) -> Option<&A::Node> {
        // SAFETY: the cursor rests on the tree's ghost or on one of its
        // nodes, and a node stays live while it is on the tree.
        unsafe { self.tree.prev_before(self.current) }
            .map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Links `node` right after the cursor's node, which stays current;
    /// at the ghost, at the front.  The tree is not searched: the node goes
    /// where the cursor says, so this is the insert for a caller that
    /// already holds the node's predecessor.
    ///
    /// The key of `node` must lie between the keys of its two new
    /// neighbours.  A node out of order stays linked and misorders the
    /// lookups that cross it, and nothing else.
    ///
    /// # Panics
    ///
    /// In debug builds, when the tree is corrupt, when the cursor's link is
    /// on another tree, or when the key is out of order.
    #[inline]
    pub fn insert_after(&mut self, node: &'nodes mut A::Node) {
        // SAFETY: the `'nodes` borrow keeps the node live, unmoved and
        // reached only through the tree, and a `&mut` is on no other
        // tree.
        unsafe { self.insert_after_ptr(NonNull::from(node)) };
    }

    /// Links the node at `node` right after the cursor's node; at the
    /// ghost, at the front.  See [`insert_after`](Self::insert_after).
    ///
    /// # Panics
    ///
    /// In debug builds, when the tree is corrupt, when the cursor's link is
    /// on another tree, or when the key is out of order.
    ///
    /// # Safety
    ///
    /// `node` must meet the contract of
    /// [`insert_ptr`](RbTree::insert_ptr).
    #[inline]
    pub unsafe fn insert_after_ptr(&mut self, node: NonNull<A::Node>) {
        unsafe { self.tree.insert_beside(self.current, RIGHT, node) };
    }

    /// Links `node` right before the cursor's node, which stays current;
    /// at the ghost, at the back.  See [`insert_after`](Self::insert_after)
    /// for the order the key must keep.
    ///
    /// # Panics
    ///
    /// In debug builds, when the tree is corrupt, when the cursor's link is
    /// on another tree, or when the key is out of order.
    #[inline]
    pub fn insert_before(&mut self, node: &'nodes mut A::Node) {
        // SAFETY: the `'nodes` borrow keeps the node live, unmoved and
        // reached only through the tree, and a `&mut` is on no other
        // tree.
        unsafe { self.insert_before_ptr(NonNull::from(node)) };
    }

    /// Links the node at `node` right before the cursor's node; at the
    /// ghost, at the back.  See [`insert_after`](Self::insert_after).
    ///
    /// # Panics
    ///
    /// In debug builds, when the tree is corrupt, when the cursor's link is
    /// on another tree, or when the key is out of order.
    ///
    /// # Safety
    ///
    /// `node` must meet the contract of
    /// [`insert_ptr`](RbTree::insert_ptr).
    #[inline]
    pub unsafe fn insert_before_ptr(&mut self, node: NonNull<A::Node>) {
        unsafe { self.tree.insert_beside(self.current, LEFT, node) };
    }

    /// Unlinks the node at the cursor and returns it, moving to the next
    /// node; `None` at the ghost.
    ///
    /// # Panics
    ///
    /// In debug builds, when the tree is corrupt, or when the cursor's link
    /// is on another tree.
    #[inline]
    pub fn remove_current(&mut self) -> Option<&'nodes mut A::Node> {
        let at = self.current?;
        // SAFETY: the cursor rests on a node of the tree it borrows
        // exclusively, and that node is live; a removal relinks other
        // nodes without moving any.
        unsafe {
            self.current = balance::step(at, RIGHT);
            self.tree.unlink(at);
            Some(A::node(at).as_mut())
        }
    }
}

/// An iterator over the nodes of an [`RbTree`] in key order, or in
/// descending order reversed.
pub struct Iter<'head, A: Adapter> {
    front: Option<NonNull<Link>>,
    back: Option<NonNull<Link>>,
    nodes: PhantomData<&'head A::Node>,
}

impl<A: Adapter> Iter<'_, A> {
    pub(super) const fn new(
        front: Option<NonNull<Link>>,
        back: Option<NonNull<Link>>,
    ) -> Self {
        Self {
            front,
            back,
            nodes: PhantomData,
        }
    }

    /// Ends the walk if the two ends have met on the last node left,
    /// and returns whether they had.
    fn finish(&mut self) -> bool {
        let met = self.front == self.back;
        if met {
            self.front = None;
            self.back = None;
        }
        met
    }
}

impl<'head, A: Adapter> Iterator for Iter<'head, A> {
    type Item = &'head A::Node;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let at = self.front?;
        if !self.finish() {
            // SAFETY: the ends have not met, so `at` has a successor,
            // and a node stays live while it is on the tree.
            self.front = unsafe { balance::step(at, RIGHT) };
        }
        // SAFETY: a node stays live while it is on the tree, and the
        // iterator borrows the tree.
        Some(unsafe { A::node(at).as_ref() })
    }
}

impl<A: Adapter> DoubleEndedIterator for Iter<'_, A> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        let at = self.back?;
        if !self.finish() {
            // SAFETY: the ends have not met, so `at` has a predecessor,
            // and a node stays live while it is on the tree.
            self.back = unsafe { balance::step(at, LEFT) };
        }
        // SAFETY: a node stays live while it is on the tree, and the
        // iterator borrows the tree.
        Some(unsafe { A::node(at).as_ref() })
    }
}

impl<A: Adapter> fmt::Debug for Cursor<'_, '_, A> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cursor")
            .field("current", &self.current)
            .finish_non_exhaustive()
    }
}

impl<A: Adapter> fmt::Debug for CursorMut<'_, '_, A> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CursorMut")
            .field("current", &self.current)
            .finish_non_exhaustive()
    }
}

impl<A: Adapter> fmt::Debug for Iter<'_, A> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Iter")
            .field("front", &self.front)
            .field("back", &self.back)
            .finish()
    }
}
