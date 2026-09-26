// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! A simple queue: a two-word head, one-word links, walked forward only.
//!
//! The head holds the first node's link and the tail: the link whose
//! `next` ends the queue, which is the last node's or, when empty, the
//! head's own.  Pushing at either end, popping at the front, removing
//! the node after a cursor and appending another queue are O(1);
//! removing an arbitrary node walks from the front.
//!
//! The tail can point into the head, so a head is pinned: it mutates
//! through `Pin<&mut Self>` and stays in place while it holds nodes.  A
//! head in a `static` is pinned by construction; one inside a lock guard
//! is pinned with [`Pin::new_unchecked`], justified by the static never
//! moving.
//!
//! Nodes are caller-owned and embed a [`Link`]; the queue never
//! allocates or frees.  A queue `SimpleQueue<'nodes, A>` takes each node as
//! `&'nodes mut A::Node` and hands it back the same way when it leaves, so
//! the borrow checker keeps a linked node alive, in place, reached only
//! through the queue, and on one queue at a time.  The `_ptr` pushes
//! take a raw pointer instead, for nodes whose lifetime no `'nodes`
//! describes; they are `unsafe` and their callers keep those promises
//! by hand.
//!
//! A node is on a queue from the push that links it
//! until it leaves: by removal, by [`clear`](SimpleQueue::clear), by
//! [`append`](SimpleQueue::append) moving it to another queue's end, or
//! by the queue being dropped or forgotten.  Leaving never writes to the
//! node, so a link carries no "unlinked" mark and the queue has no
//! `Drop`.
//!
//! ```text
//! use collections::simple_queue::{self, Link, SimpleQueue};
//! use core::pin::pin;
//!
//! struct Request {
//!     id: u32,
//!     link: Link,
//! }
//!
//! simple_queue::adapter!(RequestAdapter = Request { link });
//!
//! let mut request = Request { id: 1, link: Link::new() };
//! let mut requests = pin!(SimpleQueue::<RequestAdapter>::new());
//! requests.as_mut().push_back(&mut request);
//! ```

mod adapter;
mod cursor;

#[doc(inline)]
pub use crate::__simple_queue_adapter as adapter;
pub use adapter::Adapter;
pub use cursor::{Cursor, CursorMut, Iter};

use core::cell::Cell;
use core::fmt;
use core::marker::{PhantomData, PhantomPinned};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::NonNull;

/// The field a node embeds to join one [`SimpleQueue`].
///
/// One word: the next node's link, `None` on the last node.  The head
/// embeds one too, so that the tail always names a link.
#[derive(Debug)]
pub struct Link {
    next: Cell<Option<NonNull<Self>>>,
}

impl Link {
    /// Returns a link for a node that is on no queue.
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
// through the queue holding its node, which reads it under `&` and
// writes it under `Pin<&mut>`; the queue's borrow orders every access.
unsafe impl Send for Link {}
// SAFETY: shared access to a link reaches no word of it; its queue reads
// under `&` and writes only under `Pin<&mut>`.
unsafe impl Sync for Link {}

const _: () = assert!(
    size_of::<Link>() == size_of::<usize>(),
    "a link is one word",
);

/// The error of [`remove_ptr`](SimpleQueue::remove_ptr): the node was not on
/// the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NotFound;

/// The head of a simple queue of `A::Node`s borrowed for `'nodes`.
pub struct SimpleQueue<'nodes, A: Adapter> {
    /// `head.next`: the first node's link.
    head: Link,
    /// The link whose `next` ends the queue; `None` stands for `head`,
    /// so that [`new`](Self::new) needs no address.
    last: Cell<Option<NonNull<Link>>>,
    nodes: PhantomData<(A, &'nodes mut A::Node)>,
    _pinned: PhantomPinned,
}

impl<'nodes, A: Adapter> SimpleQueue<'nodes, A> {
    /// Returns an empty queue.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            head: Link::new(),
            last: Cell::new(None),
            nodes: PhantomData,
            _pinned: PhantomPinned,
        }
    }

    /// Returns whether the queue holds no nodes.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.head.next.get().is_none()
    }

    /// Empties the queue in O(1).
    ///
    /// The nodes are not touched: their links keep stale words, which
    /// the next push of each node overwrites, and the ones pushed as
    /// `&'nodes mut` stay borrowed until `'nodes` ends.
    #[inline]
    pub fn clear(self: Pin<&mut Self>) {
        let this = self.into_ref().get_ref();
        this.head.next.set(None);
        this.last.set(None);
    }

    /// Returns the first node, or `None` when empty.
    #[must_use]
    #[inline]
    pub fn front(&self) -> Option<&A::Node> {
        // SAFETY: a node stays live while it is on the queue.
        self.head
            .next
            .get()
            .map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Returns the last node, or `None` when empty.
    #[must_use]
    #[inline]
    pub fn back(&self) -> Option<&A::Node> {
        // SAFETY: a non-empty queue's tail is its last node's link, and
        // a node stays live while it is on the queue.
        self.head
            .next
            .get()
            .map(|_| unsafe { A::node(self.tail()).as_ref() })
    }

    /// Returns an iterator over the nodes, front to back.
    #[must_use]
    #[inline]
    pub const fn iter(&self) -> Iter<'_, A> {
        Iter::new(self.head.next.get())
    }

    /// Returns a cursor at the first node, or at the ghost when empty.
    #[must_use]
    #[inline]
    pub const fn cursor_front(&self) -> Cursor<'_, 'nodes, A> {
        Cursor::new(self, self.head.next.get())
    }

    /// Returns a mutable cursor at the first node, or at the ghost when
    /// empty.
    #[must_use]
    #[inline]
    pub const fn cursor_front_mut(
        self: Pin<&mut Self>,
    ) -> CursorMut<'_, 'nodes, A> {
        let this = self.into_ref().get_ref();
        CursorMut::new(this, this.head.next.get())
    }

    /// Returns a mutable cursor at `node`.
    ///
    /// # Safety
    ///
    /// `node` must be on this queue.
    #[must_use]
    #[inline]
    pub unsafe fn cursor_mut_from_ptr(
        self: Pin<&mut Self>,
        node: NonNull<A::Node>,
    ) -> CursorMut<'_, 'nodes, A> {
        let current = Some(unsafe { A::link(node) });
        CursorMut::new(self.into_ref().get_ref(), current)
    }

    /// Pushes `node` at the front.
    #[inline]
    pub fn push_front(self: Pin<&mut Self>, node: &'nodes mut A::Node) {
        // SAFETY: the `'nodes` borrow keeps the node live, unmoved and
        // reached only through the queue, and a `&mut` is on no other
        // queue.
        unsafe { self.push_front_ptr(NonNull::from(node)) };
    }

    /// Pushes `node` at the back.
    #[inline]
    pub fn push_back(self: Pin<&mut Self>, node: &'nodes mut A::Node) {
        // SAFETY: the `'nodes` borrow keeps the node live, unmoved and
        // reached only through the queue, and a `&mut` is on no other
        // queue.
        unsafe { self.push_back_ptr(NonNull::from(node)) };
    }

    /// Pushes the node at `node` at the front.
    ///
    /// # Safety
    ///
    /// `node` must point at a node that stays live and unmoved, and that
    /// nothing reaches except through the queue, until it leaves the
    /// queue; its link must not be on any queue.  The node leaves as
    /// `&'nodes mut`, so it must stay live for as long as that is used.
    #[inline]
    pub unsafe fn push_front_ptr(
        self: Pin<&mut Self>,
        node: NonNull<A::Node>,
    ) {
        let this = self.into_ref().get_ref();
        let link = unsafe { A::link(node) };
        unsafe { this.link_after(NonNull::from(&this.head), link) };
    }

    /// Pushes the node at `node` at the back.
    ///
    /// # Safety
    ///
    /// `node` must meet the contract of
    /// [`push_front_ptr`](Self::push_front_ptr).
    #[inline]
    pub unsafe fn push_back_ptr(self: Pin<&mut Self>, node: NonNull<A::Node>) {
        let this = self.into_ref().get_ref();
        let link = unsafe { A::link(node) };
        unsafe { this.link_after(this.tail(), link) };
    }

    /// Unlinks the first node and returns it, or `None` when empty.
    #[must_use]
    #[inline]
    pub fn pop_front(self: Pin<&mut Self>) -> Option<&'nodes mut A::Node> {
        let this = self.into_ref().get_ref();
        // SAFETY: the slot is the queue's own head.
        unsafe { this.unlink_after(NonNull::from(&this.head)) }
    }

    /// Unlinks the node at `node`, walking from the front.
    ///
    /// `node` is only compared, never read, and the node is not handed
    /// back: the caller already holds a pointer to it.  One pushed as
    /// `&'nodes mut` stays borrowed until `'nodes` ends; a caller that pushed it
    /// with a `_ptr` push can push it again.
    ///
    /// # Errors
    ///
    /// [`NotFound`] when the node is not on this queue, which is left
    /// as it was.
    #[inline]
    pub fn remove_ptr(
        self: Pin<&mut Self>,
        node: *const A::Node,
    ) -> Result<(), NotFound> {
        let this = self.into_ref().get_ref();
        let mut slot = NonNull::from(&this.head);
        // SAFETY: `slot` is the head or the link of a node on the queue,
        // and a node stays live while it is on the queue.
        while let Some(link) = unsafe { slot.as_ref() }.next.get() {
            // SAFETY: `link` is the link of a node on the queue, and a node
            // stays live while it is on the queue.
            if unsafe { A::node(link) }.as_ptr().cast_const() == node {
                // SAFETY: `slot` is the head or a link of this queue.
                let _unlinked = unsafe { this.unlink_link_after(slot) };
                return Ok(());
            }
            slot = link;
        }
        Err(NotFound)
    }

    /// Moves every node of `other` to the back of this queue in O(1),
    /// leaving `other` empty.
    #[inline]
    pub fn append(self: Pin<&mut Self>, other: Pin<&mut Self>) {
        let this = self.into_ref().get_ref();
        let donor = other.into_ref().get_ref();
        let Some(first) = donor.head.next.get() else {
            return;
        };
        // SAFETY: the tail is the head or a live node's link.
        unsafe { this.tail().as_ref() }.next.set(Some(first));
        this.last.set(donor.last.get());
        donor.head.next.set(None);
        donor.last.set(None);
    }

    /// Returns the link whose `next` ends the queue.
    fn tail(&self) -> NonNull<Link> {
        self.last.get().unwrap_or_else(|| NonNull::from(&self.head))
    }

    /// Links `link` after the link `slot`, moving the tail when it lands
    /// last.
    ///
    /// # Safety
    ///
    /// `slot` must be this queue's head or the link of a node on it, and
    /// `link` must meet the push contract of
    /// [`push_front_ptr`](Self::push_front_ptr).
    unsafe fn link_after(&self, slot: NonNull<Link>, link: NonNull<Link>) {
        let next = unsafe { slot.as_ref() }.next.get();
        unsafe { link.as_ref() }.next.set(next);
        unsafe { slot.as_ref() }.next.set(Some(link));
        if next.is_none() {
            self.last.set(Some(link));
        }
    }

    /// Unlinks the node after the link `slot` and returns it, or `None`
    /// when `slot` is the tail.
    ///
    /// # Safety
    ///
    /// `slot` must be this queue's head or the link of a node on it, and
    /// the caller must hold the queue exclusively.
    unsafe fn unlink_after(
        &self,
        slot: NonNull<Link>,
    ) -> Option<&'nodes mut A::Node> {
        let link = unsafe { self.unlink_link_after(slot) }?;
        Some(unsafe { A::node(link).as_mut() })
    }

    /// Unlinks the link after the link `slot` and returns it, or `None`
    /// when `slot` is the tail.
    ///
    /// # Safety
    ///
    /// `slot` must be this queue's head or the link of a node on it, and
    /// the caller must hold the queue exclusively.
    unsafe fn unlink_link_after(
        &self,
        slot: NonNull<Link>,
    ) -> Option<NonNull<Link>> {
        let link = unsafe { slot.as_ref() }.next.get()?;
        let next = unsafe { link.as_ref() }.next.get();
        unsafe { slot.as_ref() }.next.set(next);
        if next.is_none() {
            self.last.set(Some(slot));
        }
        Some(link)
    }
}

impl<A: Adapter> Default for SimpleQueue<'_, A> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'head, A: Adapter> IntoIterator for &'head SimpleQueue<'_, A> {
    type Item = &'head A::Node;
    type IntoIter = Iter<'head, A>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<A: Adapter> fmt::Debug for SimpleQueue<'_, A> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimpleQueue")
            .field("first", &self.head.next.get())
            .field("last", &self.last.get())
            .finish()
    }
}

// SAFETY: the queue holds only pointers to nodes it hands out as `&Node`
// or `&'nodes mut Node`; `Node: Send + Sync` lets that access move threads.
unsafe impl<A: Adapter> Send for SimpleQueue<'_, A> where A::Node: Send + Sync {}
// SAFETY: `&SimpleQueue` only reads links and yields `&Node`, which
// `Node: Sync` lets several threads hold at once.
unsafe impl<A: Adapter> Sync for SimpleQueue<'_, A> where A::Node: Send + Sync {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_items::{Item, SimpleItem, items, ptrs};
    use core::pin::pin;

    type Queue<'nodes> = SimpleQueue<'nodes, SimpleItem>;

    const _: () = assert!(size_of::<Queue<'_>>() == 2 * size_of::<usize>());

    fn values(queue: &Queue<'_>) -> Vec<u32> {
        queue.iter().map(|item| item.value).collect()
    }

    /// Pushes `nodes` at the back, in order.
    fn fill<'nodes>(
        mut queue: Pin<&mut Queue<'nodes>>,
        nodes: &'nodes mut [Item],
    ) {
        for node in nodes {
            queue.as_mut().push_back(node);
        }
    }

    #[test]
    fn new_and_default_are_empty() {
        let queue = Queue::default();
        assert!(queue.is_empty());
        assert!(Queue::new().front().is_none());
        assert!(Queue::new().back().is_none());
        assert!(Link::default().next.get().is_none());
    }

    #[test]
    fn push_back_is_fifo_and_push_front_lifo() {
        let [mut n1, mut n2, mut n3] = [1, 2, 3].map(Item::new);
        let mut queue = pin!(Queue::new());
        queue.as_mut().push_back(&mut n2);
        queue.as_mut().push_front(&mut n1);
        queue.as_mut().push_back(&mut n3);
        assert_eq!(values(&queue), [1, 2, 3]);
        assert_eq!(queue.front().unwrap().value, 1);
        assert_eq!(queue.back().unwrap().value, 3);
    }

    #[test]
    fn push_front_on_empty_sets_the_tail() {
        let [mut n1, mut n2] = [1, 2].map(Item::new);
        let mut queue = pin!(Queue::new());
        queue.as_mut().push_front(&mut n1);
        queue.as_mut().push_back(&mut n2);
        assert_eq!(values(&queue), [1, 2]);
        assert_eq!(queue.back().unwrap().value, 2);
    }

    #[test]
    fn the_ptr_pushes_link_raw_nodes() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let mut queue = pin!(Queue::new());
        // SAFETY: the nodes outlive the queue, nothing else reaches them,
        // and they are on no queue.
        unsafe {
            queue.as_mut().push_back_ptr(raw[1]);
            queue.as_mut().push_front_ptr(raw[0]);
        }
        assert_eq!(values(&queue), [1, 2]);
    }

    #[test]
    fn pop_front_hands_the_nodes_back_and_resets_the_tail() {
        let mut nodes = items(&[1, 2]);
        let mut queue = pin!(Queue::new());
        fill(queue.as_mut(), &mut nodes);
        let first = queue.as_mut().pop_front().unwrap();
        first.value = 10;
        assert_eq!(first.value, 10);
        let second = queue.as_mut().pop_front().unwrap();
        assert!(queue.as_mut().pop_front().is_none());
        assert!(queue.back().is_none());
        queue.as_mut().push_back(second);
        assert_eq!(queue.back().unwrap().value, 2);
    }

    #[test]
    fn clear_empties_and_nodes_rejoin() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let mut queue = pin!(Queue::new());
        for node in &raw {
            // SAFETY: the nodes outlive the queue, nothing else reaches
            // them, and they are on no queue.
            unsafe { queue.as_mut().push_back_ptr(*node) };
        }
        queue.as_mut().clear();
        assert!(queue.is_empty());
        assert!(queue.back().is_none());
        for node in &raw {
            // SAFETY: the nodes left the queue when it was cleared.
            unsafe { queue.as_mut().push_back_ptr(*node) };
        }
        assert_eq!(values(&queue), [1, 2]);
    }

    #[test]
    fn remove_ptr_front_middle_last_and_missing() {
        let mut nodes = items(&[1, 2, 3, 4]);
        let raw = ptrs(&mut nodes);
        let stranger = Item::new(9);
        let mut queue = pin!(Queue::new());
        for node in &raw {
            // SAFETY: the nodes outlive the queue, nothing else reaches
            // them, and they are on no queue.
            unsafe { queue.as_mut().push_back_ptr(*node) };
        }
        assert_eq!(queue.as_mut().remove_ptr(raw[1].as_ptr()), Ok(()));
        assert_eq!(queue.as_mut().remove_ptr(raw[0].as_ptr()), Ok(()));
        assert_eq!(queue.as_mut().remove_ptr(raw[3].as_ptr()), Ok(()));
        assert_eq!(values(&queue), [3]);
        assert_eq!(queue.back().unwrap().value, 3);
        assert_eq!(
            queue.as_mut().remove_ptr(&raw const stranger),
            Err(NotFound)
        );
        assert_eq!(queue.as_mut().remove_ptr(raw[2].as_ptr()), Ok(()));
        assert_eq!(queue.as_mut().remove_ptr(raw[2].as_ptr()), Err(NotFound));
        assert!(queue.is_empty());
        // SAFETY: the node left the queue and nothing else reaches it.
        unsafe { queue.as_mut().push_back_ptr(raw[2]) };
        assert_eq!(queue.back().unwrap().value, 3);
    }

    #[test]
    fn append_moves_every_node_to_the_back() {
        let mut nodes = items(&[1, 2, 3, 4]);
        let (front, back) = nodes.split_at_mut(2);
        let mut queue = pin!(Queue::new());
        let mut other = pin!(Queue::new());
        fill(queue.as_mut(), front);
        fill(other.as_mut(), back);
        queue.as_mut().append(other.as_mut());
        assert_eq!(values(&queue), [1, 2, 3, 4]);
        assert_eq!(queue.back().unwrap().value, 4);
        assert!(other.is_empty());
        assert!(other.back().is_none());
        queue.as_mut().append(other.as_mut());
        assert_eq!(values(&queue), [1, 2, 3, 4]);
    }

    #[test]
    fn append_onto_an_empty_queue() {
        let mut nodes = items(&[1, 2]);
        let mut queue = pin!(Queue::new());
        let mut other = pin!(Queue::new());
        fill(other.as_mut(), &mut nodes);
        queue.as_mut().append(other.as_mut());
        assert_eq!(values(&queue), [1, 2]);
        assert_eq!(queue.back().unwrap().value, 2);
    }

    #[test]
    fn into_iter_walks_front_to_back() {
        let mut nodes = items(&[1, 2, 3]);
        let mut queue = pin!(Queue::new());
        fill(queue.as_mut(), &mut nodes);
        let walked: Vec<u32> =
            (&*queue).into_iter().map(|n| n.value).collect();
        assert_eq!(walked, [1, 2, 3]);
    }

    #[test]
    fn heads_and_links_cross_threads() {
        fn check<T>(_: &T)
        where
            T: Send + Sync,
        {
        }
        check(&Queue::new());
        check(&Link::new());
    }
}
