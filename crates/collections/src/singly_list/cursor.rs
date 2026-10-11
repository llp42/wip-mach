// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Forward cursors and the iterator over a [`SinglyList`].
//!
//! A cursor rests on a node or on the ghost, the position before the
//! front and after the last node.  A cursor keeps no predecessor, so it
//! acts only on the node after it; at the ghost, that node is the front.

use super::{Adapter, Link, SinglyList, Slot, link_after, unlink_after};
use core::fmt;
use core::marker::PhantomData;
use core::ptr::NonNull;

/// A cursor over a shared [`SinglyList`], borrowed for `'head`.
pub struct Cursor<'head, 'nodes, A: Adapter> {
    list: &'head SinglyList<'nodes, A>,
    current: Option<NonNull<Link>>,
}

impl<'head, 'nodes, A: Adapter> Cursor<'head, 'nodes, A> {
    pub(super) const fn new(
        list: &'head SinglyList<'nodes, A>,
        current: Option<NonNull<Link>>,
    ) -> Self {
        Self { list, current }
    }

    /// Returns the node at the cursor, or `None` at the ghost.
    #[must_use]
    #[inline]
    pub fn current(&self) -> Option<&'head A::Node> {
        // SAFETY: a node stays live while it is on the list.
        self.current.map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Returns a pointer to the node at the cursor, or `None` at the ghost.
    ///
    /// The pointer is the one the node was pushed with, so it may be
    /// written through wherever that push allowed it, unlike one made from
    /// [`current`](Self::current).  It names the node only while the node
    /// is on the list, and its link must never be written through it.
    #[must_use]
    #[inline]
    pub fn current_ptr(&self) -> Option<NonNull<A::Node>> {
        // SAFETY: a node stays live while it is on the list.
        self.current.map(|link| unsafe { A::node(link) })
    }

    /// Moves to the next node: from the last node to the ghost, and from
    /// the ghost to the front.
    #[inline]
    pub fn move_next(&mut self) {
        // SAFETY: the cursor rests on the list's ghost or on one of its
        // nodes.
        self.current =
            unsafe { next_slot(&self.list.first, self.current) }.get();
    }

    /// Returns the node after the cursor without moving, or `None` past
    /// the last node; from the ghost, the front.
    #[must_use]
    #[inline]
    pub fn peek_next(&self) -> Option<&'head A::Node> {
        // SAFETY: the cursor rests on the list's ghost or on one of its
        // nodes, and a node stays live while it is on the list.
        unsafe { next_slot(&self.list.first, self.current) }
            .get()
            .map(|link| unsafe { A::node(link).as_ref() })
    }
}

/// A cursor over an exclusively borrowed [`SinglyList`] that can link
/// and unlink nodes.
pub struct CursorMut<'head, 'nodes, A: Adapter> {
    list: &'head mut SinglyList<'nodes, A>,
    current: Option<NonNull<Link>>,
}

impl<'head, 'nodes, A: Adapter> CursorMut<'head, 'nodes, A> {
    pub(super) const fn new(
        list: &'head mut SinglyList<'nodes, A>,
        current: Option<NonNull<Link>>,
    ) -> Self {
        Self { list, current }
    }

    /// Returns the node at the cursor, or `None` at the ghost.
    #[must_use]
    #[inline]
    pub fn current(&self) -> Option<&A::Node> {
        // SAFETY: a node stays live while it is on the list.
        self.current.map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Returns a pointer to the node at the cursor, or `None` at the ghost.
    ///
    /// The pointer is the one the node was pushed with, so it may be
    /// written through wherever that push allowed it, unlike one made from
    /// [`current`](Self::current).  It names the node only while the node
    /// is on the list, and its link must never be written through it.
    #[must_use]
    #[inline]
    pub fn current_ptr(&self) -> Option<NonNull<A::Node>> {
        // SAFETY: a node stays live while it is on the list.
        self.current.map(|link| unsafe { A::node(link) })
    }

    /// Moves to the next node: from the last node to the ghost, and from
    /// the ghost to the front.
    #[inline]
    pub fn move_next(&mut self) {
        self.current = self.next_slot().get();
    }

    /// Returns the node after the cursor without moving, or `None` past
    /// the last node; from the ghost, the front.
    #[must_use]
    #[inline]
    pub fn peek_next(&self) -> Option<&A::Node> {
        // SAFETY: a node stays live while it is on the list.
        self.next_slot()
            .get()
            .map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Links `node` after the cursor; at the ghost, at the front.  The
    /// cursor does not move.
    #[inline]
    pub fn insert_after(&mut self, node: &'nodes mut A::Node) {
        // SAFETY: the `'nodes` borrow keeps the node live, unmoved and
        // reached only through the list, and a `&mut` is on no other
        // list.
        unsafe { self.insert_after_ptr(NonNull::from(node)) };
    }

    /// Links the node at `node` after the cursor; at the ghost, at the
    /// front.  The cursor does not move.
    ///
    /// # Safety
    ///
    /// `node` must meet the contract of
    /// [`push_front_ptr`](SinglyList::push_front_ptr).
    #[inline]
    pub unsafe fn insert_after_ptr(&mut self, node: NonNull<A::Node>) {
        let link = unsafe { A::link(node) };
        unsafe { link_after(self.next_slot(), link) };
    }

    /// Unlinks the node after the cursor and returns it, or `None` past
    /// the last node; at the ghost, unlinks the front.  The cursor does
    /// not move.
    #[inline]
    pub fn remove_next(&mut self) -> Option<&'nodes mut A::Node> {
        // SAFETY: the slot is the head or a link of this list.
        unsafe { unlink_after::<A>(self.next_slot()) }
    }

    fn next_slot(&self) -> &Slot {
        // SAFETY: the cursor rests on the list's ghost or on one of its
        // nodes.
        unsafe { next_slot(&self.list.first, self.current) }
    }
}

/// Returns the slot after `current`: the head's own at the ghost.
///
/// # Safety
///
/// `current` must be `None` or the link of a live node on the list
/// headed by `first`.
unsafe fn next_slot(first: &Slot, current: Option<NonNull<Link>>) -> &Slot {
    current.map_or(first, |link| unsafe { &link.as_ref().next })
}

/// An iterator over the nodes of a [`SinglyList`], front to back.
pub struct Iter<'head, A: Adapter> {
    next: Option<NonNull<Link>>,
    nodes: PhantomData<&'head A::Node>,
}

impl<A: Adapter> Iter<'_, A> {
    pub(super) const fn new(first: Option<NonNull<Link>>) -> Self {
        Self {
            next: first,
            nodes: PhantomData,
        }
    }
}

impl<'head, A: Adapter> Iterator for Iter<'head, A> {
    type Item = &'head A::Node;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let link = self.next?;
        // SAFETY: a node stays live while it is on the list, and the
        // iterator borrows the list.
        unsafe {
            self.next = link.as_ref().next.get();
            Some(A::node(link).as_ref())
        }
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
        f.debug_struct("Iter").field("next", &self.next).finish()
    }
}
