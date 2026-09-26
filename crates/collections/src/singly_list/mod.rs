// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! A singly linked list: a one-word head and one-word links, walked
//! forward only.
//!
//! The head points at the first node's link and each link at the next,
//! so the head holds no pointer into itself and moves freely.  Pushing
//! and popping at the front, and removing the node after a cursor, are
//! O(1); removing an arbitrary node walks from the front.
//!
//! Nodes are caller-owned and embed a [`Link`]; the list never allocates
//! or frees.  A list `SinglyList<'nodes, A>` takes each node as
//! `&'nodes mut A::Node` and hands it back the same way when it leaves, so
//! the borrow checker keeps a linked node alive, in place, reached only
//! through the list, and on one list at a time.  The `_ptr` pushes take
//! a raw pointer instead, for nodes whose lifetime no `'nodes` describes;
//! they are `unsafe` and their callers keep those promises by hand.
//!
//! A node is on a list from the push that links it until it leaves: by
//! removal, by [`clear`](SinglyList::clear), or by the list being
//! dropped or forgotten.  Leaving never writes to the node, so a link
//! carries no "unlinked" mark and the list has no `Drop`.
//!
//! ```text
//! use collections::singly_list::{self, Link, SinglyList};
//!
//! struct Waiter {
//!     id: u32,
//!     link: Link,
//! }
//!
//! singly_list::adapter!(WaiterAdapter = Waiter { link });
//!
//! let mut waiter = Waiter { id: 1, link: Link::new() };
//! let mut waiters = SinglyList::<WaiterAdapter>::new();
//! waiters.push_front(&mut waiter);
//! ```

mod adapter;
mod cursor;

#[doc(inline)]
pub use crate::__singly_list_adapter as adapter;
pub use adapter::Adapter;
pub use cursor::{Cursor, CursorMut, Iter};

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::mem::size_of;
use core::ptr::NonNull;

/// A pointer-sized location that points at a node's link: the head's
/// `first` or a link's `next`.
type Slot = Cell<Option<NonNull<Link>>>;

/// The field a node embeds to join one [`SinglyList`].
///
/// One word: the next node's link, `None` on the last node.
#[derive(Debug)]
pub struct Link {
    next: Slot,
}

impl Link {
    /// Returns a link for a node that is on no list.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            next: Cell::new(None),
        }
    }
}

impl Default for Link {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: a link's word is private to this module and only reached
// through the list holding its node, which reads it under `&` and writes
// it under `&mut`; the list's borrow orders every access.
unsafe impl Send for Link {}
// SAFETY: shared access to a link reaches no word of it; its list reads
// under `&` and writes only under `&mut`.
unsafe impl Sync for Link {}

const _: () = assert!(
    size_of::<Link>() == size_of::<usize>(),
    "a link is one word",
);

/// The error of [`remove_ptr`](SinglyList::remove_ptr): the node was not on
/// the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NotFound;

/// The head of a singly linked list of `A::Node`s borrowed for `'nodes`.
pub struct SinglyList<'nodes, A: Adapter> {
    first: Slot,
    nodes: PhantomData<(A, &'nodes mut A::Node)>,
}

impl<'nodes, A: Adapter> SinglyList<'nodes, A> {
    /// Returns an empty list.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            first: Cell::new(None),
            nodes: PhantomData,
        }
    }

    /// Returns whether the list holds no nodes.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.first.get().is_none()
    }

    /// Empties the list in O(1).
    ///
    /// The nodes are not touched: their links keep stale words, which
    /// the next push of each node overwrites, and the ones pushed as
    /// `&'nodes mut` stay borrowed until `'nodes` ends.
    #[inline]
    pub fn clear(&mut self) {
        self.first.set(None);
    }

    /// Returns the first node, or `None` when empty.
    #[must_use]
    #[inline]
    pub fn front(&self) -> Option<&A::Node> {
        // SAFETY: a node stays live while it is on the list.
        self.first
            .get()
            .map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Returns an iterator over the nodes, front to back.
    #[must_use]
    #[inline]
    pub const fn iter(&self) -> Iter<'_, A> {
        Iter::new(self.first.get())
    }

    /// Returns a cursor at the first node, or at the ghost when empty.
    #[must_use]
    #[inline]
    pub const fn cursor_front(&self) -> Cursor<'_, 'nodes, A> {
        let current = self.first.get();
        Cursor::new(self, current)
    }

    /// Returns a mutable cursor at the first node, or at the ghost when
    /// empty.
    #[inline]
    pub const fn cursor_front_mut(&mut self) -> CursorMut<'_, 'nodes, A> {
        let current = self.first.get();
        CursorMut::new(self, current)
    }

    /// Returns a mutable cursor at `node`.
    ///
    /// # Safety
    ///
    /// `node` must be on this list.
    #[inline]
    pub unsafe fn cursor_mut_from_ptr(
        &mut self,
        node: NonNull<A::Node>,
    ) -> CursorMut<'_, 'nodes, A> {
        let current = Some(unsafe { A::link(node) });
        CursorMut::new(self, current)
    }

    /// Pushes `node` at the front.
    #[inline]
    pub fn push_front(&mut self, node: &'nodes mut A::Node) {
        // SAFETY: the `'nodes` borrow keeps the node live, unmoved and
        // reached only through the list, and a `&mut` is on no other
        // list.
        unsafe { self.push_front_ptr(NonNull::from(node)) };
    }

    /// Pushes the node at `node` at the front.
    ///
    /// # Safety
    ///
    /// `node` must point at a node that stays live and unmoved, and that
    /// nothing reaches except through the list, until it leaves the
    /// list; its link must not be on any list.  The node leaves as
    /// `&'nodes mut`, so it must stay live for as long as that is used.
    #[inline]
    pub unsafe fn push_front_ptr(&mut self, node: NonNull<A::Node>) {
        let link = unsafe { A::link(node) };
        unsafe { link_after(&self.first, link) };
    }

    /// Unlinks the first node and returns it, or `None` when empty.
    #[must_use]
    #[inline]
    pub fn pop_front(&mut self) -> Option<&'nodes mut A::Node> {
        // SAFETY: the slot is the list's own head.
        unsafe { unlink_after::<A>(&self.first) }
    }

    /// Unlinks the node at `node`, walking from the front.
    ///
    /// `node` is only compared, never read, and the node is not handed
    /// back: the caller already holds a pointer to it.  One pushed as
    /// `&'nodes mut` stays borrowed until `'nodes` ends; a caller that pushed it
    /// with [`push_front_ptr`](Self::push_front_ptr) can push it again.
    ///
    /// # Errors
    ///
    /// [`NotFound`] when the node is not on this list, which is left
    /// as it was.
    #[inline]
    pub fn remove_ptr(
        &mut self,
        node: *const A::Node,
    ) -> Result<(), NotFound> {
        let mut slot = &self.first;
        while let Some(link) = slot.get() {
            // SAFETY: a node stays live while it is on the list.
            let next = unsafe { &link.as_ref().next };
            // SAFETY: a node stays live while it is on the list.
            if unsafe { A::node(link) }.as_ptr().cast_const() == node {
                slot.set(next.get());
                return Ok(());
            }
            slot = next;
        }
        Err(NotFound)
    }
}

impl<A: Adapter> Default for SinglyList<'_, A> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'head, A: Adapter> IntoIterator for &'head SinglyList<'_, A> {
    type Item = &'head A::Node;
    type IntoIter = Iter<'head, A>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<A: Adapter> fmt::Debug for SinglyList<'_, A> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SinglyList")
            .field("first", &self.first.get())
            .finish()
    }
}

// SAFETY: the list holds only pointers to nodes it hands out as `&Node`
// or `&'nodes mut Node`; `Node: Send + Sync` lets that access move threads.
unsafe impl<A: Adapter> Send for SinglyList<'_, A> where A::Node: Send + Sync {}
// SAFETY: `&SinglyList` only reads links and yields `&Node`, which
// `Node: Sync` lets several threads hold at once.
unsafe impl<A: Adapter> Sync for SinglyList<'_, A> where A::Node: Send + Sync {}

/// Links `link` into the slot `slot`, ahead of the node it points at.
///
/// # Safety
///
/// `slot` must be a list head or the link of a node on that list, and
/// `link` must meet the push contract of
/// [`push_front_ptr`](SinglyList::push_front_ptr).
unsafe fn link_after(slot: &Slot, link: NonNull<Link>) {
    unsafe { link.as_ref() }.next.set(slot.get());
    slot.set(Some(link));
}

/// Unlinks the node the slot `slot` points at and returns it, or `None`
/// when the slot is the end.
///
/// # Safety
///
/// `slot` must be a list head or the link of a node on that list, and
/// the caller must be entitled to the node for `'nodes`.
unsafe fn unlink_after<'nodes, A>(slot: &Slot) -> Option<&'nodes mut A::Node>
where
    A: Adapter,
{
    let link = slot.get()?;
    slot.set(unsafe { link.as_ref() }.next.get());
    Some(unsafe { A::node(link).as_mut() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_items::{Item, SinglyItem, items, ptrs, value};

    type List<'nodes> = SinglyList<'nodes, SinglyItem>;

    const _: () = assert!(size_of::<List<'_>>() == size_of::<usize>());

    fn values(list: &List<'_>) -> Vec<u32> {
        list.iter().map(|item| item.value).collect()
    }

    /// Pushes `nodes` so that the list reads in their order.
    fn fill<'nodes>(list: &mut List<'nodes>, nodes: &'nodes mut [Item]) {
        for node in nodes.iter_mut().rev() {
            list.push_front(node);
        }
    }

    #[test]
    fn new_and_default_are_empty() {
        assert!(List::new().is_empty());
        assert!(List::default().is_empty());
        assert!(List::new().front().is_none());
        assert!(Link::default().next.get().is_none());
    }

    #[test]
    fn push_front_is_lifo() {
        let mut nodes = items(&[1, 2, 3]);
        let mut list = List::new();
        for node in &mut nodes {
            list.push_front(node);
        }
        assert!(!list.is_empty());
        assert_eq!(list.front().unwrap().value, 3);
        assert_eq!(values(&list), [3, 2, 1]);
    }

    #[test]
    fn pop_front_hands_the_nodes_back() {
        let mut nodes = items(&[1, 2]);
        let mut list = List::new();
        fill(&mut list, &mut nodes);
        let first = list.pop_front().unwrap();
        first.value = 10;
        assert_eq!(first.value, 10);
        assert_eq!(value(list.pop_front()), Some(2));
        assert_eq!(value(list.pop_front()), None);
        assert!(list.is_empty());
    }

    #[test]
    fn push_front_ptr_links_raw_nodes() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let mut list = List::new();
        for node in raw.iter().rev() {
            // SAFETY: the nodes outlive the list, nothing else reaches
            // them, and they are on no list.
            unsafe { list.push_front_ptr(*node) };
        }
        assert_eq!(values(&list), [1, 2]);
    }

    #[test]
    fn clear_empties_and_nodes_rejoin() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let mut list = List::new();
        for node in &raw {
            // SAFETY: the nodes outlive the list, nothing else reaches
            // them, and they are on no list.
            unsafe { list.push_front_ptr(*node) };
        }
        list.clear();
        assert!(list.is_empty());
        for node in &raw {
            // SAFETY: the nodes left the list when it was cleared.
            unsafe { list.push_front_ptr(*node) };
        }
        assert_eq!(values(&list), [2, 1]);
    }

    #[test]
    fn remove_ptr_front_middle_last_and_missing() {
        let mut nodes = items(&[1, 2, 3, 4]);
        let raw = ptrs(&mut nodes);
        let stranger = Item::new(9);
        let mut list = List::new();
        for node in raw.iter().rev() {
            // SAFETY: the nodes outlive the list, nothing else reaches
            // them, and they are on no list.
            unsafe { list.push_front_ptr(*node) };
        }
        assert_eq!(list.remove_ptr(raw[1].as_ptr()), Ok(()));
        assert_eq!(values(&list), [1, 3, 4]);
        assert_eq!(list.remove_ptr(raw[0].as_ptr()), Ok(()));
        assert_eq!(values(&list), [3, 4]);
        assert_eq!(list.remove_ptr(raw[3].as_ptr()), Ok(()));
        assert_eq!(values(&list), [3]);
        assert_eq!(list.remove_ptr(&raw const stranger), Err(NotFound));
        assert_eq!(list.remove_ptr(raw[2].as_ptr()), Ok(()));
        assert_eq!(list.remove_ptr(raw[2].as_ptr()), Err(NotFound));
        assert!(list.is_empty());
        // SAFETY: the node left the list and nothing else reaches it.
        unsafe { list.push_front_ptr(raw[2]) };
        assert_eq!(values(&list), [3]);
    }

    #[test]
    fn into_iter_walks_front_to_back() {
        let mut nodes = items(&[1, 2, 3]);
        let mut list = List::new();
        fill(&mut list, &mut nodes);
        let walked: Vec<u32> = (&list).into_iter().map(|n| n.value).collect();
        assert_eq!(walked, [1, 2, 3]);
    }

    #[test]
    fn a_linked_head_moves_freely() {
        let mut nodes = items(&[1, 2]);
        let mut list = List::new();
        fill(&mut list, &mut nodes);
        let moved = Box::new(list);
        assert_eq!(values(&moved), [1, 2]);
    }

    #[test]
    fn heads_and_links_cross_threads() {
        fn check<T>(_: &T)
        where
            T: Send + Sync,
        {
        }
        check(&List::new());
        check(&Link::new());
    }
}
