// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Forward cursors and the iterator over a [`SimpleQueue`].
//!
//! A cursor rests on a node or on the ghost, the position before the
//! front and after the last node.  A cursor keeps no predecessor, so it
//! acts only on the node after it; at the ghost, that node is the front.

use super::{Adapter, Link, SimpleQueue};
use core::fmt;
use core::marker::PhantomData;
use core::ptr::NonNull;

/// A cursor over a shared [`SimpleQueue`], borrowed for `'head`.
pub struct Cursor<'head, 'nodes, A: Adapter> {
    queue: &'head SimpleQueue<'nodes, A>,
    current: Option<NonNull<Link>>,
}

impl<'head, 'nodes, A: Adapter> Cursor<'head, 'nodes, A> {
    pub(super) const fn new(
        queue: &'head SimpleQueue<'nodes, A>,
        current: Option<NonNull<Link>>,
    ) -> Self {
        Self { queue, current }
    }

    /// Returns the node at the cursor, or `None` at the ghost.
    #[must_use]
    #[inline]
    pub fn current(&self) -> Option<&'head A::Node> {
        // SAFETY: a node stays live while it is on the queue.
        self.current.map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Returns a pointer to the node at the cursor, or `None` at the ghost.
    ///
    /// The pointer is the one the node was pushed with, so it may be
    /// written through wherever that push allowed it, unlike one made from
    /// [`current`](Self::current).  It names the node only while the node
    /// is on the queue, and its link must never be written through it.
    #[must_use]
    #[inline]
    pub fn current_ptr(&self) -> Option<NonNull<A::Node>> {
        // SAFETY: a node stays live while it is on the queue.
        self.current.map(|link| unsafe { A::node(link) })
    }

    /// Moves to the next node: from the last node to the ghost, and from
    /// the ghost to the front.
    #[inline]
    pub fn move_next(&mut self) {
        // SAFETY: the cursor rests on the queue's ghost or on one of its
        // nodes.
        self.current = unsafe { next_after(self.queue, self.current) };
    }

    /// Returns the node after the cursor without moving, or `None` past
    /// the last node; from the ghost, the front.
    #[must_use]
    #[inline]
    pub fn peek_next(&self) -> Option<&'head A::Node> {
        // SAFETY: the cursor rests on the queue's ghost or on one of its
        // nodes, and a node stays live while it is on the queue.
        unsafe { next_after(self.queue, self.current) }
            .map(|link| unsafe { A::node(link).as_ref() })
    }
}

/// A cursor over an exclusively borrowed [`SimpleQueue`] that can link
/// and unlink nodes.
pub struct CursorMut<'head, 'nodes, A: Adapter> {
    queue: &'head SimpleQueue<'nodes, A>,
    current: Option<NonNull<Link>>,
    exclusive: PhantomData<&'head mut SimpleQueue<'nodes, A>>,
}

impl<'head, 'nodes, A: Adapter> CursorMut<'head, 'nodes, A> {
    /// Returns a cursor at `current`.  The caller's `Pin<&mut>` borrow
    /// of the queue is what makes the cursor exclusive.
    pub(super) const fn new(
        queue: &'head SimpleQueue<'nodes, A>,
        current: Option<NonNull<Link>>,
    ) -> Self {
        Self {
            queue,
            current,
            exclusive: PhantomData,
        }
    }

    /// Returns the node at the cursor, or `None` at the ghost.
    #[must_use]
    #[inline]
    pub fn current(&self) -> Option<&A::Node> {
        // SAFETY: a node stays live while it is on the queue.
        self.current.map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Returns a pointer to the node at the cursor, or `None` at the ghost.
    ///
    /// The pointer is the one the node was pushed with, so it may be
    /// written through wherever that push allowed it, unlike one made from
    /// [`current`](Self::current).  It names the node only while the node
    /// is on the queue, and its link must never be written through it.
    #[must_use]
    #[inline]
    pub fn current_ptr(&self) -> Option<NonNull<A::Node>> {
        // SAFETY: a node stays live while it is on the queue.
        self.current.map(|link| unsafe { A::node(link) })
    }

    /// Moves to the next node: from the last node to the ghost, and from
    /// the ghost to the front.
    #[inline]
    pub fn move_next(&mut self) {
        // SAFETY: the cursor rests on the queue's ghost or on one of its
        // nodes.
        self.current = unsafe { next_after(self.queue, self.current) };
    }

    /// Returns the node after the cursor without moving, or `None` past
    /// the last node; from the ghost, the front.
    #[must_use]
    #[inline]
    pub fn peek_next(&self) -> Option<&A::Node> {
        // SAFETY: the cursor rests on the queue's ghost or on one of its
        // nodes, and a node stays live while it is on the queue.
        unsafe { next_after(self.queue, self.current) }
            .map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Links `node` after the cursor; at the ghost, at the front.  The
    /// cursor does not move.
    #[inline]
    pub fn insert_after(&mut self, node: &'nodes mut A::Node) {
        // SAFETY: the `'nodes` borrow keeps the node live, unmoved and
        // reached only through the queue, and a `&mut` is on no other
        // queue.
        unsafe { self.insert_after_ptr(NonNull::from(node)) };
    }

    /// Links the node at `node` after the cursor; at the ghost, at the
    /// front.  The cursor does not move.
    ///
    /// # Safety
    ///
    /// `node` must meet the contract of
    /// [`push_front_ptr`](SimpleQueue::push_front_ptr).
    #[inline]
    pub unsafe fn insert_after_ptr(&mut self, node: NonNull<A::Node>) {
        let link = unsafe { A::link(node) };
        unsafe { self.queue.link_after(self.slot(), link) };
    }

    /// Unlinks the node after the cursor and returns it, or `None` past
    /// the last node; at the ghost, unlinks the front.  The cursor does
    /// not move.
    #[inline]
    pub fn remove_next(&mut self) -> Option<&'nodes mut A::Node> {
        // SAFETY: the slot is the head or a link of this queue, which the
        // cursor holds exclusively.
        unsafe { self.queue.unlink_after(self.slot()) }
    }

    /// Returns the link whose `next` is the node after the cursor.
    fn slot(&self) -> NonNull<Link> {
        self.current
            .unwrap_or_else(|| NonNull::from(&self.queue.head))
    }
}

/// Returns the link after `current`; the first at the ghost.
///
/// # Safety
///
/// `current` must be `None` or the link of a live node on `queue`.
unsafe fn next_after<A>(
    queue: &SimpleQueue<'_, A>,
    current: Option<NonNull<Link>>,
) -> Option<NonNull<Link>>
where
    A: Adapter,
{
    current
        .map_or(&queue.head, |link| unsafe { link.as_ref() })
        .next
        .get()
}

/// An iterator over the nodes of a [`SimpleQueue`], front to back.
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
        // SAFETY: a node stays live while it is on the queue, and the
        // iterator borrows the queue.
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
