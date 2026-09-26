// SPDX-License-Identifier: MIT
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

#[cfg(test)]
mod tests {
    use crate::singly_list::SinglyList;
    use crate::test_items::{Item, SinglyItem, items, ptr, ptrs, value};

    type List<'nodes> = SinglyList<'nodes, SinglyItem>;

    fn values(list: &List<'_>) -> Vec<u32> {
        list.iter().map(|item| item.value).collect()
    }

    fn fill<'nodes>(list: &mut List<'nodes>, nodes: &'nodes mut [Item]) {
        for node in nodes.iter_mut().rev() {
            list.push_front(node);
        }
    }

    #[test]
    fn cursor_walks_through_the_ghost() {
        let mut nodes = items(&[1, 2]);
        let mut list = List::new();
        fill(&mut list, &mut nodes);
        let mut cursor = list.cursor_front();
        assert_eq!(cursor.current().unwrap().value, 1);
        assert_eq!(cursor.peek_next().unwrap().value, 2);
        cursor.move_next();
        assert_eq!(cursor.current().unwrap().value, 2);
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
        let mut list = List::new();
        for node in raw.iter().rev() {
            // SAFETY: the nodes outlive the list, nothing else reaches
            // them, and they are on no list.
            unsafe { list.push_front_ptr(*node) };
        }
        let mut shared = list.cursor_front();
        assert_eq!(shared.current_ptr(), Some(raw[0]));
        shared.move_next();
        assert_eq!(shared.current_ptr(), Some(raw[1]));
        shared.move_next();
        assert_eq!(shared.current_ptr(), None);
        let mut exclusive = list.cursor_front_mut();
        assert_eq!(exclusive.current_ptr(), Some(raw[0]));
        exclusive.move_next();
        exclusive.move_next();
        assert_eq!(exclusive.current_ptr(), None);
    }

    #[test]
    fn cursor_on_an_empty_list_stays_at_the_ghost() {
        let list = List::new();
        let mut cursor = list.cursor_front();
        assert!(cursor.current().is_none());
        assert!(cursor.peek_next().is_none());
        cursor.move_next();
        assert!(cursor.current().is_none());
    }

    #[test]
    fn cursor_mut_walks_through_the_ghost() {
        let mut nodes = items(&[1, 2]);
        let mut list = List::new();
        fill(&mut list, &mut nodes);
        let mut cursor = list.cursor_front_mut();
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
        let mut list = List::new();
        {
            let mut cursor = list.cursor_front_mut();
            cursor.insert_after(&mut n3);
            cursor.insert_after(&mut n1);
            assert!(cursor.current().is_none());
        }
        assert_eq!(values(&list), [1, 3]);
        {
            let mut cursor = list.cursor_front_mut();
            cursor.insert_after(&mut n2);
            cursor.move_next();
            cursor.move_next();
            cursor.insert_after(&mut n4);
            cursor.move_next();
            cursor.move_next();
            assert!(cursor.current().is_none());
            cursor.insert_after(&mut n0);
        }
        assert_eq!(values(&list), [0, 1, 2, 3, 4]);
    }

    #[test]
    fn insert_after_ptr_links_a_raw_node() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let mut list = List::new();
        let mut cursor = list.cursor_front_mut();
        // SAFETY: the nodes outlive the list, nothing else reaches them,
        // and they are on no list.
        unsafe {
            cursor.insert_after_ptr(raw[1]);
            cursor.insert_after_ptr(raw[0]);
        }
        assert_eq!(values(&list), [1, 2]);
    }

    #[test]
    fn remove_next_at_the_ghost_middle_and_last() {
        let mut nodes = items(&[1, 2, 3]);
        let mut list = List::new();
        fill(&mut list, &mut nodes);
        let mut cursor = list.cursor_front_mut();
        assert_eq!(value(cursor.remove_next()), Some(2));
        assert!(cursor.remove_next().is_some());
        assert!(cursor.remove_next().is_none());
        cursor.move_next();
        assert!(cursor.current().is_none());
        assert_eq!(value(cursor.remove_next()), Some(1));
        assert!(cursor.remove_next().is_none());
        assert!(list.is_empty());
    }

    #[test]
    fn cursor_from_a_node_acts_after_it() {
        let mut nodes = items(&[1, 2, 3]);
        let second = ptr(&nodes[1]);
        let mut list = List::new();
        fill(&mut list, &mut nodes);
        // SAFETY: the item is on this list.
        let mut cursor = unsafe { list.cursor_mut_from_ptr(second) };
        assert_eq!(cursor.current().unwrap().value, 2);
        assert_eq!(value(cursor.remove_next()), Some(3));
        assert_eq!(values(&list), [1, 2]);
    }

    #[test]
    fn cursors_and_iterators_debug_print_their_position() {
        let mut nodes = items(&[1]);
        let raw = ptrs(&mut nodes);
        let mut head = List::new();
        // SAFETY: the node outlives the head, nothing else reaches it, and
        // it is on no structure.
        unsafe { head.push_front_ptr(raw[0]) };
        assert!(format!("{:?}", head.cursor_front()).starts_with("Cursor {"));
        assert!(format!("{:?}", head.iter()).starts_with("Iter {"));
        assert!(
            format!("{:?}", head.cursor_front_mut())
                .starts_with("CursorMut {")
        );
        assert!(format!("{head:?}").starts_with("SinglyList {"));
    }
}
