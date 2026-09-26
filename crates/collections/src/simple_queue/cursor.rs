// SPDX-License-Identifier: MIT
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

#[cfg(test)]
mod tests {
    use crate::simple_queue::SimpleQueue;
    use crate::test_items::{Item, SimpleItem, items, ptr, ptrs, value};
    use core::pin::{Pin, pin};

    type Queue<'nodes> = SimpleQueue<'nodes, SimpleItem>;

    fn values(queue: &Queue<'_>) -> Vec<u32> {
        queue.iter().map(|item| item.value).collect()
    }

    fn fill<'nodes>(
        mut queue: Pin<&mut Queue<'nodes>>,
        nodes: &'nodes mut [Item],
    ) {
        for node in nodes {
            queue.as_mut().push_back(node);
        }
    }

    #[test]
    fn cursor_walks_through_the_ghost() {
        let mut nodes = items(&[1, 2]);
        let mut queue = pin!(Queue::new());
        fill(queue.as_mut(), &mut nodes);
        let mut cursor = queue.cursor_front();
        assert_eq!(cursor.current().unwrap().value, 1);
        assert_eq!(cursor.peek_next().unwrap().value, 2);
        cursor.move_next();
        assert!(cursor.peek_next().is_none());
        cursor.move_next();
        assert!(cursor.current().is_none());
        assert_eq!(cursor.peek_next().unwrap().value, 1);
        cursor.move_next();
        assert_eq!(cursor.current().unwrap().value, 1);
    }

    #[test]
    fn current_ptr_is_the_pushed_pointer_and_none_at_the_ghost() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let mut queue = pin!(Queue::new());
        for node in &raw {
            // SAFETY: the nodes outlive the queue, nothing else reaches
            // them, and they are on no queue.
            unsafe { queue.as_mut().push_back_ptr(*node) };
        }
        let mut shared = queue.cursor_front();
        assert_eq!(shared.current_ptr(), Some(raw[0]));
        shared.move_next();
        assert_eq!(shared.current_ptr(), Some(raw[1]));
        shared.move_next();
        assert_eq!(shared.current_ptr(), None);
        let mut exclusive = queue.as_mut().cursor_front_mut();
        assert_eq!(exclusive.current_ptr(), Some(raw[0]));
        exclusive.move_next();
        exclusive.move_next();
        assert_eq!(exclusive.current_ptr(), None);
    }

    #[test]
    fn cursor_mut_walks_through_the_ghost() {
        let mut nodes = items(&[1, 2]);
        let mut queue = pin!(Queue::new());
        fill(queue.as_mut(), &mut nodes);
        let mut cursor = queue.as_mut().cursor_front_mut();
        assert_eq!(cursor.current().unwrap().value, 1);
        assert_eq!(cursor.peek_next().unwrap().value, 2);
        cursor.move_next();
        cursor.move_next();
        assert!(cursor.current().is_none());
        assert_eq!(cursor.peek_next().unwrap().value, 1);
    }

    #[test]
    fn insert_after_at_the_ghost_middle_and_last() {
        let [mut n0, mut n1, mut n2, mut n3, mut n4] =
            [0, 1, 2, 3, 4].map(Item::new);
        let mut queue = pin!(Queue::new());
        {
            let mut cursor = queue.as_mut().cursor_front_mut();
            cursor.insert_after(&mut n1);
            cursor.move_next();
            cursor.insert_after(&mut n3);
            cursor.insert_after(&mut n2);
            cursor.move_next();
            cursor.move_next();
            cursor.insert_after(&mut n4);
            cursor.move_next();
            cursor.move_next();
            assert!(cursor.current().is_none());
            cursor.insert_after(&mut n0);
        }
        assert_eq!(values(&queue), [0, 1, 2, 3, 4]);
        assert_eq!(queue.back().unwrap().value, 4);
    }

    #[test]
    fn insert_after_ptr_links_a_raw_node() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let mut queue = pin!(Queue::new());
        let mut cursor = queue.as_mut().cursor_front_mut();
        // SAFETY: the nodes outlive the queue, nothing else reaches them,
        // and they are on no queue.
        unsafe {
            cursor.insert_after_ptr(raw[1]);
            cursor.insert_after_ptr(raw[0]);
        }
        assert_eq!(values(&queue), [1, 2]);
        assert_eq!(queue.back().unwrap().value, 2);
    }

    #[test]
    fn remove_next_moves_the_tail_back() {
        let mut nodes = items(&[1, 2, 3]);
        let mut queue = pin!(Queue::new());
        fill(queue.as_mut(), &mut nodes);
        {
            let mut cursor = queue.as_mut().cursor_front_mut();
            cursor.move_next();
            assert_eq!(value(cursor.remove_next()), Some(3));
            assert!(cursor.remove_next().is_none());
        }
        assert_eq!(queue.back().unwrap().value, 2);
        {
            let mut cursor = queue.as_mut().cursor_front_mut();
            cursor.move_next();
            cursor.move_next();
            assert_eq!(value(cursor.remove_next()), Some(1));
            assert_eq!(value(cursor.remove_next()), Some(2));
            assert!(cursor.remove_next().is_none());
        }
        assert!(queue.is_empty());
        assert!(queue.back().is_none());
    }

    #[test]
    fn cursor_from_a_node_acts_after_it() {
        let mut nodes = items(&[1, 2, 3]);
        let first = ptr(&nodes[0]);
        let mut queue = pin!(Queue::new());
        fill(queue.as_mut(), &mut nodes);
        // SAFETY: the item is on this queue.
        let mut cursor = unsafe { queue.as_mut().cursor_mut_from_ptr(first) };
        assert_eq!(cursor.current().unwrap().value, 1);
        assert_eq!(value(cursor.remove_next()), Some(2));
        assert_eq!(values(&queue), [1, 3]);
    }

    #[test]
    fn cursors_and_iterators_debug_print_their_position() {
        let mut nodes = items(&[1]);
        let raw = ptrs(&mut nodes);
        let mut head = pin!(Queue::new());
        // SAFETY: the node outlives the head, nothing else reaches it, and
        // it is on no structure.
        unsafe { head.as_mut().push_front_ptr(raw[0]) };
        assert!(format!("{:?}", head.cursor_front()).starts_with("Cursor {"));
        assert!(format!("{:?}", head.iter()).starts_with("Iter {"));
        assert!(
            format!("{:?}", head.as_mut().cursor_front_mut())
                .starts_with("CursorMut {")
        );
        assert!(format!("{:?}", *head).starts_with("SimpleQueue {"));
    }
}
