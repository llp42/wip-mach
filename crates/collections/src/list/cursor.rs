// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! Forward cursors and the iterator over a [`List`].
//!
//! A cursor rests on a node or on the ghost, the position before the
//! front and after the last node.  Links point back at their slot, so a
//! cursor links before and unlinks the node it rests on in O(1).

use super::{Adapter, Link, List, link_before, link_into, replace, unlink};
use core::fmt;
use core::marker::PhantomData;
use core::ptr::NonNull;

/// A cursor over a shared [`List`], borrowed for `'head`.
pub struct Cursor<'head, 'nodes, A: Adapter> {
    list: &'head List<'nodes, A>,
    current: Option<NonNull<Link>>,
}

impl<'head, 'nodes, A: Adapter> Cursor<'head, 'nodes, A> {
    pub(super) const fn new(
        list: &'head List<'nodes, A>,
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
        self.current = unsafe { next_after(self.list, self.current) };
    }

    /// Returns the node after the cursor without moving, or `None` past
    /// the last node; from the ghost, the front.
    #[must_use]
    #[inline]
    pub fn peek_next(&self) -> Option<&'head A::Node> {
        // SAFETY: the cursor rests on the list's ghost or on one of its
        // nodes, and a node stays live while it is on the list.
        unsafe { next_after(self.list, self.current) }
            .map(|link| unsafe { A::node(link).as_ref() })
    }
}

/// A cursor over an exclusively borrowed [`List`] that can link and
/// unlink nodes.
pub struct CursorMut<'head, 'nodes, A: Adapter> {
    list: &'head List<'nodes, A>,
    current: Option<NonNull<Link>>,
    exclusive: PhantomData<&'head mut List<'nodes, A>>,
}

impl<'head, 'nodes, A: Adapter> CursorMut<'head, 'nodes, A> {
    /// Returns a cursor at `current`.  The caller's `Pin<&mut>` borrow
    /// of the list is what makes the cursor exclusive.
    pub(super) const fn new(
        list: &'head List<'nodes, A>,
        current: Option<NonNull<Link>>,
    ) -> Self {
        Self {
            list,
            current,
            exclusive: PhantomData,
        }
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
        // SAFETY: the cursor rests on the list's ghost or on one of its
        // nodes.
        self.current = unsafe { next_after(self.list, self.current) };
    }

    /// Returns the node after the cursor without moving, or `None` past
    /// the last node; from the ghost, the front.
    #[must_use]
    #[inline]
    pub fn peek_next(&self) -> Option<&A::Node> {
        // SAFETY: the cursor rests on the list's ghost or on one of its
        // nodes, and a node stays live while it is on the list.
        unsafe { next_after(self.list, self.current) }
            .map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Links `node` after the cursor; at the ghost, at the front.  The
    /// cursor does not move.
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of the cursor's link does not
    /// point back at it: the list is corrupt.
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
    /// # Panics
    ///
    /// In debug builds, when a neighbour of the cursor's link does not
    /// point back at it: the list is corrupt.
    ///
    /// # Safety
    ///
    /// `node` must meet the contract of
    /// [`push_front_ptr`](List::push_front_ptr).
    #[inline]
    pub unsafe fn insert_after_ptr(&mut self, node: NonNull<A::Node>) {
        let link = unsafe { A::link(node) };
        match self.current {
            None => unsafe { link_into(&self.list.first, link) },
            Some(at) => unsafe {
                super::check(at);
                link_into(&at.as_ref().next, link);
            },
        }
    }

    /// Links `node` before the node at the cursor.  The cursor does not
    /// move.
    ///
    /// # Panics
    ///
    /// When the cursor is at the ghost, which has no slot before it; and
    /// in debug builds, when a neighbour of the cursor's link does not
    /// point back at it.
    #[inline]
    pub fn insert_before(&mut self, node: &'nodes mut A::Node) {
        // SAFETY: the `'nodes` borrow keeps the node live, unmoved and
        // reached only through the list, and a `&mut` is on no other
        // list.
        unsafe { self.insert_before_ptr(NonNull::from(node)) };
    }

    /// Links the node at `node` before the node at the cursor.  The
    /// cursor does not move.
    ///
    /// # Panics
    ///
    /// When the cursor is at the ghost, which has no slot before it; and
    /// in debug builds, when a neighbour of the cursor's link does not
    /// point back at it.
    ///
    /// # Safety
    ///
    /// `node` must meet the contract of
    /// [`push_front_ptr`](List::push_front_ptr).
    #[expect(
        clippy::expect_used,
        reason = "linking before the ghost is a documented panic"
    )]
    #[inline]
    pub unsafe fn insert_before_ptr(&mut self, node: NonNull<A::Node>) {
        let at = self.current.expect("list: insert_before at the ghost");
        unsafe { link_before(at, A::link(node)) };
    }

    /// Unlinks the node at the cursor and returns it, moving to the next
    /// node; `None` at the ghost.
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of the cursor's link does not
    /// point back at it: the list is corrupt.
    #[inline]
    pub fn remove_current(&mut self) -> Option<&'nodes mut A::Node> {
        let at = self.current?;
        // SAFETY: the cursor rests on a node of the list it borrows
        // exclusively, and that node is live.
        unsafe {
            self.current = at.as_ref().next.get();
            unlink(at);
            Some(A::node(at).as_mut())
        }
    }

    /// Puts `node` where the node at the cursor is, rests on `node` and
    /// returns the node it replaced.
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of the cursor's link does not
    /// point back at it: the list is corrupt.
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
        // reached only through the list, a `&mut` is on no other list,
        // and the cursor rests on a node of the list it borrows
        // exclusively.
        unsafe {
            let link = A::link(NonNull::from(node));
            replace(at, link);
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
    /// point back at it: the list is corrupt.
    ///
    /// # Safety
    ///
    /// `node` must meet the contract of
    /// [`push_front_ptr`](List::push_front_ptr).
    #[inline]
    pub unsafe fn replace_current_ptr(
        &mut self,
        node: NonNull<A::Node>,
    ) -> Option<&'nodes mut A::Node> {
        let at = self.current?;
        let link = unsafe { A::link(node) };
        unsafe { replace(at, link) };
        self.current = Some(link);
        Some(unsafe { A::node(at).as_mut() })
    }
}

/// Returns the link after `current`; the first at the ghost.
///
/// # Safety
///
/// `current` must be `None` or the link of a live node on `list`.
unsafe fn next_after<A>(
    list: &List<'_, A>,
    current: Option<NonNull<Link>>,
) -> Option<NonNull<Link>>
where
    A: Adapter,
{
    current
        .map_or(&list.first, |link| unsafe { &link.as_ref().next })
        .get()
}

/// An iterator over the nodes of a [`List`], front to back.
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
    use crate::list::List;
    use crate::test_items::{Item, ListItem, items, ptr, ptrs, value};
    use core::pin::{Pin, pin};

    type Items<'nodes> = List<'nodes, ListItem>;

    fn values(list: &Items<'_>) -> Vec<u32> {
        list.iter().map(|item| item.value).collect()
    }

    fn fill<'nodes>(
        mut list: Pin<&mut Items<'nodes>>,
        nodes: &'nodes mut [Item],
    ) {
        for node in nodes.iter_mut().rev() {
            list.as_mut().push_front(node);
        }
    }

    #[test]
    fn cursor_walks_through_the_ghost() {
        let mut nodes = items(&[1, 2]);
        let mut list = pin!(Items::new());
        fill(list.as_mut(), &mut nodes);
        let mut cursor = list.cursor_front();
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
        let mut list = pin!(Items::new());
        for node in raw.iter().rev() {
            // SAFETY: the nodes outlive the list, nothing else reaches
            // them, and they are on no list.
            unsafe { list.as_mut().push_front_ptr(*node) };
        }
        let mut shared = list.cursor_front();
        assert_eq!(shared.current_ptr(), Some(raw[0]));
        shared.move_next();
        assert_eq!(shared.current_ptr(), Some(raw[1]));
        shared.move_next();
        assert_eq!(shared.current_ptr(), None);
        let mut exclusive = list.as_mut().cursor_front_mut();
        assert_eq!(exclusive.current_ptr(), Some(raw[0]));
        exclusive.move_next();
        exclusive.move_next();
        assert_eq!(exclusive.current_ptr(), None);
    }

    #[test]
    fn cursor_mut_walks_through_the_ghost() {
        let mut nodes = items(&[1, 2]);
        let mut list = pin!(Items::new());
        fill(list.as_mut(), &mut nodes);
        let mut cursor = list.as_mut().cursor_front_mut();
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
        let mut list = pin!(Items::new());
        list.as_mut().push_front(&mut n3);
        list.as_mut().push_front(&mut n1);
        let mut cursor = list.as_mut().cursor_front_mut();
        cursor.insert_after(&mut n2);
        cursor.move_next();
        cursor.move_next();
        cursor.insert_after(&mut n4);
        cursor.move_next();
        cursor.move_next();
        assert!(cursor.current().is_none());
        cursor.insert_after(&mut n0);
        assert_eq!(values(&list), [0, 1, 2, 3, 4]);
    }

    #[test]
    fn insert_before_the_front_and_the_last() {
        let [mut n0, mut n1, mut n2, mut n3] = [0, 1, 2, 3].map(Item::new);
        let mut list = pin!(Items::new());
        list.as_mut().push_front(&mut n3);
        list.as_mut().push_front(&mut n1);
        let mut cursor = list.as_mut().cursor_front_mut();
        cursor.insert_before(&mut n0);
        cursor.move_next();
        cursor.insert_before(&mut n2);
        assert_eq!(cursor.current().unwrap().value, 3);
        assert_eq!(values(&list), [0, 1, 2, 3]);
    }

    #[test]
    fn the_ptr_inserts_link_raw_nodes() {
        let mut nodes = items(&[1, 2, 3]);
        let raw = ptrs(&mut nodes);
        let mut list = pin!(Items::new());
        let mut cursor = list.as_mut().cursor_front_mut();
        // SAFETY: the nodes outlive the list, nothing else reaches them,
        // and they are on no list.
        unsafe {
            cursor.insert_after_ptr(raw[2]);
            cursor.move_next();
            cursor.insert_before_ptr(raw[0]);
            cursor.insert_before_ptr(raw[1]);
        }
        assert_eq!(values(&list), [1, 2, 3]);
    }

    #[test]
    #[should_panic(expected = "insert_before at the ghost")]
    fn insert_before_at_the_ghost_panics() {
        let mut node = Item::new(1);
        let mut list = pin!(Items::new());
        let mut cursor = list.as_mut().cursor_front_mut();
        cursor.insert_before(&mut node);
    }

    #[test]
    fn remove_current_moves_to_the_next_node() {
        let mut nodes = items(&[1, 2, 3]);
        let mut list = pin!(Items::new());
        fill(list.as_mut(), &mut nodes);
        let mut cursor = list.as_mut().cursor_front_mut();
        cursor.move_next();
        assert_eq!(value(cursor.remove_current()), Some(2));
        assert_eq!(cursor.current().unwrap().value, 3);
        assert_eq!(value(cursor.remove_current()), Some(3));
        assert!(cursor.current().is_none());
        assert!(cursor.remove_current().is_none());
        cursor.move_next();
        assert_eq!(value(cursor.remove_current()), Some(1));
        assert!(list.is_empty());
    }

    #[test]
    fn replace_current_at_the_front_middle_last_and_ghost() {
        let mut nodes = items(&[1, 2, 3]);
        let mut extra = items(&[10, 20, 30, 40]);
        let (spare, others) = extra.split_last_mut().unwrap();
        let mut list = pin!(Items::new());
        fill(list.as_mut(), &mut nodes);
        let mut cursor = list.as_mut().cursor_front_mut();
        for (old, new) in [1, 2, 3].into_iter().zip(others) {
            let wanted = new.value;
            let replaced = cursor.replace_current(new).ok().unwrap();
            assert_eq!(replaced.value, old);
            assert_eq!(cursor.current().unwrap().value, wanted);
            cursor.move_next();
        }
        let refused = cursor.replace_current(spare).err().unwrap();
        assert_eq!(refused.value, 40);
        assert_eq!(values(&list), [10, 20, 30]);
    }

    #[test]
    fn replace_current_ptr_swaps_in_a_raw_node() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let mut list = pin!(Items::new());
        let mut cursor = list.as_mut().cursor_front_mut();
        // SAFETY: the nodes outlive the list, nothing else reaches them,
        // and they are on no list.
        unsafe {
            assert!(cursor.replace_current_ptr(raw[1]).is_none());
            cursor.insert_after_ptr(raw[0]);
            cursor.move_next();
            assert_eq!(value(cursor.replace_current_ptr(raw[1])), Some(1));
        }
        assert_eq!(values(&list), [2]);
    }

    #[test]
    fn cursor_from_a_node_rests_on_it() {
        let mut nodes = items(&[1, 2, 3]);
        let third = ptr(&nodes[2]);
        let mut list = pin!(Items::new());
        fill(list.as_mut(), &mut nodes);
        // SAFETY: the item is on this list.
        let mut cursor = unsafe { list.as_mut().cursor_mut_from_ptr(third) };
        assert_eq!(value(cursor.remove_current()), Some(3));
        assert_eq!(values(&list), [1, 2]);
    }

    #[test]
    fn cursors_and_iterators_debug_print_their_position() {
        let mut nodes = items(&[1]);
        let raw = ptrs(&mut nodes);
        let mut head = pin!(Items::new());
        // SAFETY: the node outlives the head, nothing else reaches it, and
        // it is on no structure.
        unsafe { head.as_mut().push_front_ptr(raw[0]) };
        assert!(format!("{:?}", head.cursor_front()).starts_with("Cursor {"));
        assert!(format!("{:?}", head.iter()).starts_with("Iter {"));
        assert!(
            format!("{:?}", head.as_mut().cursor_front_mut())
                .starts_with("CursorMut {")
        );
        assert!(format!("{:?}", *head).starts_with("List {"));
    }
}
