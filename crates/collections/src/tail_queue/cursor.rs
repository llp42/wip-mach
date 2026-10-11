// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Cursors and the double-ended iterator over a [`TailQueue`].
//!
//! A cursor rests on a node or on the ghost, the position before the
//! front and after the back: moving forward from the last node, or back
//! from the first, reaches the ghost, and moving on from the ghost wraps
//! to the other end.

use super::{Adapter, Link, TailQueue};
use core::fmt;
use core::marker::PhantomData;
use core::ptr::NonNull;

/// A cursor over a shared [`TailQueue`], borrowed for `'head`.
pub struct Cursor<'head, 'nodes, A: Adapter> {
    queue: &'head TailQueue<'nodes, A>,
    current: Option<NonNull<Link>>,
}

impl<'head, 'nodes, A: Adapter> Cursor<'head, 'nodes, A> {
    pub(super) const fn new(
        queue: &'head TailQueue<'nodes, A>,
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

    /// Moves to the previous node: from the first node to the ghost, and
    /// from the ghost to the back.
    #[inline]
    pub fn move_prev(&mut self) {
        // SAFETY: the cursor rests on the queue's ghost or on one of its
        // nodes.
        self.current = unsafe { self.queue.prev_before(self.current) };
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

    /// Returns the node before the cursor without moving, or `None`
    /// before the first node; from the ghost, the back.
    #[must_use]
    #[inline]
    pub fn peek_prev(&self) -> Option<&'head A::Node> {
        // SAFETY: the cursor rests on the queue's ghost or on one of its
        // nodes, and a node stays live while it is on the queue.
        unsafe { self.queue.prev_before(self.current) }
            .map(|link| unsafe { A::node(link).as_ref() })
    }
}

/// A cursor over an exclusively borrowed [`TailQueue`] that can link and
/// unlink nodes.
pub struct CursorMut<'head, 'nodes, A: Adapter> {
    queue: &'head TailQueue<'nodes, A>,
    current: Option<NonNull<Link>>,
    exclusive: PhantomData<&'head mut TailQueue<'nodes, A>>,
}

impl<'head, 'nodes, A: Adapter> CursorMut<'head, 'nodes, A> {
    /// Returns a cursor at `current`.  The caller's `Pin<&mut>` borrow
    /// of the queue is what makes the cursor exclusive.
    pub(super) const fn new(
        queue: &'head TailQueue<'nodes, A>,
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

    /// Moves to the previous node: from the first node to the ghost, and
    /// from the ghost to the back.
    #[inline]
    pub fn move_prev(&mut self) {
        // SAFETY: the cursor rests on the queue's ghost or on one of its
        // nodes.
        self.current = unsafe { self.queue.prev_before(self.current) };
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

    /// Returns the node before the cursor without moving, or `None`
    /// before the first node; from the ghost, the back.
    #[must_use]
    #[inline]
    pub fn peek_prev(&self) -> Option<&A::Node> {
        // SAFETY: the cursor rests on the queue's ghost or on one of its
        // nodes, and a node stays live while it is on the queue.
        unsafe { self.queue.prev_before(self.current) }
            .map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Links `node` after the cursor; at the ghost, at the front.  The
    /// cursor does not move.
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of the cursor's link does not
    /// point back at it: the queue is corrupt.
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
    /// # Panics
    ///
    /// In debug builds, when a neighbour of the cursor's link does not
    /// point back at it: the queue is corrupt.
    ///
    /// # Safety
    ///
    /// `node` must meet the contract of
    /// [`push_front_ptr`](TailQueue::push_front_ptr).
    #[inline]
    pub unsafe fn insert_after_ptr(&mut self, node: NonNull<A::Node>) {
        let link = unsafe { A::link(node) };
        let at = match self.current {
            None => self.queue.ends_link(),
            Some(at) => {
                unsafe { super::check(at) };
                at
            }
        };
        unsafe { self.queue.link_after(at, link) };
    }

    /// Links `node` before the cursor; at the ghost, at the back.  The
    /// cursor does not move.
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of the cursor's link does not
    /// point back at it: the queue is corrupt.
    #[inline]
    pub fn insert_before(&mut self, node: &'nodes mut A::Node) {
        // SAFETY: the `'nodes` borrow keeps the node live, unmoved and
        // reached only through the queue, and a `&mut` is on no other
        // queue.
        unsafe { self.insert_before_ptr(NonNull::from(node)) };
    }

    /// Links the node at `node` before the cursor; at the ghost, at the
    /// back.  The cursor does not move.
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of the cursor's link does not
    /// point back at it: the queue is corrupt.
    ///
    /// # Safety
    ///
    /// `node` must meet the contract of
    /// [`push_front_ptr`](TailQueue::push_front_ptr).
    #[inline]
    pub unsafe fn insert_before_ptr(&mut self, node: NonNull<A::Node>) {
        let link = unsafe { A::link(node) };
        let at = match self.current {
            None => self.queue.tail(),
            Some(at) => unsafe {
                super::check(at);
                NonNull::new_unchecked(at.as_ref().prev.get().cast_mut())
            },
        };
        unsafe { self.queue.link_after(at, link) };
    }

    /// Unlinks the node at the cursor and returns it, moving to the next
    /// node; `None` at the ghost.
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of the cursor's link does not
    /// point back at it: the queue is corrupt.
    #[inline]
    pub fn remove_current(&mut self) -> Option<&'nodes mut A::Node> {
        let at = self.current?;
        // SAFETY: the cursor rests on a node of the queue it borrows
        // exclusively, and that node is live.
        unsafe {
            self.current = at.as_ref().next.get();
            self.queue.unlink(at);
            Some(A::node(at).as_mut())
        }
    }

    /// Puts `node` where the node at the cursor is, rests on `node` and
    /// returns the node it replaced.
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of the cursor's link does not
    /// point back at it: the queue is corrupt.
    ///
    /// # Errors
    ///
    /// At the ghost, which holds no node to replace: links nothing and
    /// hands `node` back.
    #[inline]
    pub fn replace_current(
        &mut self,
        node: &'nodes mut A::Node,
    ) -> Result<&'nodes mut A::Node, &'nodes mut A::Node> {
        let Some(at) = self.current else {
            return Err(node);
        };
        // SAFETY: the `'nodes` borrow keeps the node live, unmoved and
        // reached only through the queue, a `&mut` is on no other queue,
        // and the cursor rests on a node of the queue it borrows
        // exclusively.
        unsafe {
            let link = A::link(NonNull::from(node));
            self.queue.replace(at, link);
            self.current = Some(link);
            Ok(A::node(at).as_mut())
        }
    }

    /// Puts the node at `node` where the node at the cursor is, rests on
    /// it and returns the node it replaced; at the ghost, links nothing
    /// and returns `None`.
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of the cursor's link does not
    /// point back at it: the queue is corrupt.
    ///
    /// # Safety
    ///
    /// `node` must meet the contract of
    /// [`push_front_ptr`](TailQueue::push_front_ptr).
    #[inline]
    pub unsafe fn replace_current_ptr(
        &mut self,
        node: NonNull<A::Node>,
    ) -> Option<&'nodes mut A::Node> {
        let at = self.current?;
        let link = unsafe { A::link(node) };
        unsafe { self.queue.replace(at, link) };
        self.current = Some(link);
        Some(unsafe { A::node(at).as_mut() })
    }
}

/// Returns the link after `current`; the first at the ghost.
///
/// # Safety
///
/// `current` must be `None` or the link of a live node on `queue`.
unsafe fn next_after<A>(
    queue: &TailQueue<'_, A>,
    current: Option<NonNull<Link>>,
) -> Option<NonNull<Link>>
where
    A: Adapter,
{
    current
        .map_or(&queue.ends, |link| unsafe { link.as_ref() })
        .next
        .get()
}

/// An iterator over the nodes of a [`TailQueue`], front to back, or
/// back to front reversed.
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
            // SAFETY: a node stays live while it is on the queue.
            self.front = unsafe { at.as_ref() }.next.get();
        }
        // SAFETY: a node stays live while it is on the queue, and the
        // iterator borrows the queue.
        Some(unsafe { A::node(at).as_ref() })
    }
}

impl<A: Adapter> DoubleEndedIterator for Iter<'_, A> {
    #[inline]
    fn next_back(&mut self) -> Option<Self::Item> {
        let at = self.back?;
        if !self.finish() {
            // SAFETY: `at` is not the first node left, so its `prev` is
            // the previous node's link, and that node is live.
            self.back = Some(unsafe {
                NonNull::new_unchecked(at.as_ref().prev.get().cast_mut())
            });
        }
        // SAFETY: a node stays live while it is on the queue, and the
        // iterator borrows the queue.
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
