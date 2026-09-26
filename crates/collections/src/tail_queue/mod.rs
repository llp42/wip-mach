// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! A tail queue: a two-word head and two-word links, walked both ways.
//!
//! The head embeds a link of its own, `ends`: its `next` is the first
//! node's link and its `prev` the last node's.  Each node's link holds
//! the next node's link and the link whose `next` points back at it:
//! the previous node's, or `ends` for the first node.  So every back
//! pointer names a link, a backward step is one load and one compare
//! with `ends`, and any node leaves in O(1) given the head.  Pushing at
//! either end, linking before or after a cursor, and appending another
//! queue are O(1) too.
//!
//! The first node's link points into the head, so a head is pinned: it
//! mutates through `Pin<&mut Self>` and stays in place while it holds
//! nodes.  A head in a `static` is pinned by construction; one inside a
//! lock guard is pinned with [`Pin::new_unchecked`], justified by the
//! static never moving.
//!
//! Nodes are caller-owned and embed a [`Link`]; the queue never
//! allocates or frees.  A queue `TailQueue<'nodes, A>` takes each node as
//! `&'nodes mut A::Node` and hands it back the same way when it leaves, so
//! the borrow checker keeps a linked node alive, in place, reached only
//! through the queue, and on one queue at a time.  The `_ptr` pushes
//! take a raw pointer instead, for nodes whose lifetime no `'nodes`
//! describes; they are `unsafe` and their callers keep those promises
//! by hand.  Removing a node by its address is `unsafe` too: nothing in
//! a link says which queue holds it.
//!
//! A node is on a queue from the push that links it
//! until it leaves: by removal, by [`clear`](TailQueue::clear), by
//! [`append`](TailQueue::append) moving it to another queue's end, or by
//! the queue being dropped or forgotten.  Leaving writes nothing to the
//! node in release builds, so a link carries no "unlinked" mark and the
//! queue has no `Drop`.  Debug builds check that a link's neighbours
//! point back at it before every operation on it, and fill a leaving
//! link with dangling words.
//!
//! ```text
//! use collections::tail_queue::{self, Link, TailQueue};
//! use core::pin::pin;
//!
//! struct Thread {
//!     id: u32,
//!     link: Link,
//! }
//!
//! tail_queue::adapter!(ThreadAdapter = Thread { link });
//!
//! let mut thread = Thread { id: 1, link: Link::new() };
//! let mut run_queue = pin!(TailQueue::<ThreadAdapter>::new());
//! run_queue.as_mut().push_back(&mut thread);
//! ```

mod adapter;
mod cursor;

#[doc(inline)]
pub use crate::__tail_queue_adapter as adapter;
pub use adapter::Adapter;
pub use cursor::{Cursor, CursorMut, Iter};

use core::cell::Cell;
use core::fmt;
use core::marker::{PhantomData, PhantomPinned};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::{self, NonNull};

/// The field a node embeds to join one [`TailQueue`].
///
/// Two words: the next node's link, and the link whose `next` points at
/// this one.
#[derive(Debug)]
pub struct Link {
    next: Cell<Option<NonNull<Self>>>,
    /// The previous node's link, or the head's `ends` for the first node.
    prev: Cell<*const Self>,
}

impl Link {
    /// Returns a link for a node that is on no queue.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            next: Cell::new(None),
            prev: Cell::new(ptr::null()),
        }
    }
}

impl Default for Link {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: a link's words are private to this module and only reached
// through the queue holding its node, which reads them under `&` and
// writes them under `Pin<&mut>`; the queue's borrow orders every access.
unsafe impl Send for Link {}
// SAFETY: shared access to a link reaches no word of it; its queue reads
// under `&` and writes only under `Pin<&mut>`.
unsafe impl Sync for Link {}

const _: () = assert!(
    size_of::<Link>() == 2 * size_of::<usize>(),
    "a link is two words",
);

/// The head of a tail queue of `A::Node`s borrowed for `'nodes`.
pub struct TailQueue<'nodes, A: Adapter> {
    /// `ends.next`: the first node's link.  `ends.prev`: the link whose
    /// `next` ends the queue, the last node's or, when empty, `ends`
    /// itself; null stands for `ends`, so that [`new`](Self::new) needs
    /// no address.
    ends: Link,
    nodes: PhantomData<(A, &'nodes mut A::Node)>,
    _pinned: PhantomPinned,
}

impl<'nodes, A: Adapter> TailQueue<'nodes, A> {
    /// Returns an empty queue.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            ends: Link::new(),
            nodes: PhantomData,
            _pinned: PhantomPinned,
        }
    }

    /// Returns whether the queue holds no nodes.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.ends.next.get().is_none()
    }

    /// Empties the queue in O(1).
    ///
    /// The nodes are not touched: their links keep stale words, which
    /// the next push of each node overwrites, and the ones pushed as
    /// `&'nodes mut` stay borrowed until `'nodes` ends.
    #[inline]
    pub fn clear(self: Pin<&mut Self>) {
        self.ends.next.set(None);
        self.ends.prev.set(ptr::null());
    }

    /// Returns the first node, or `None` when empty.
    #[must_use]
    #[inline]
    pub fn front(&self) -> Option<&A::Node> {
        // SAFETY: a node stays live while it is on the queue.
        self.ends
            .next
            .get()
            .map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Returns the last node, or `None` when empty.
    #[must_use]
    #[inline]
    pub fn back(&self) -> Option<&A::Node> {
        // SAFETY: a node stays live while it is on the queue.
        self.last().map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Returns an iterator over the nodes, front to back; reversed, back
    /// to front.
    #[must_use]
    #[inline]
    pub fn iter(&self) -> Iter<'_, A> {
        Iter::new(self.ends.next.get(), self.last())
    }

    /// Returns a cursor at the first node, or at the ghost when empty.
    #[must_use]
    #[inline]
    pub const fn cursor_front(&self) -> Cursor<'_, 'nodes, A> {
        Cursor::new(self, self.ends.next.get())
    }

    /// Returns a cursor at the last node, or at the ghost when empty.
    #[must_use]
    #[inline]
    pub fn cursor_back(&self) -> Cursor<'_, 'nodes, A> {
        Cursor::new(self, self.last())
    }

    /// Returns a mutable cursor at the first node, or at the ghost when
    /// empty.
    #[must_use]
    #[inline]
    pub const fn cursor_front_mut(
        self: Pin<&mut Self>,
    ) -> CursorMut<'_, 'nodes, A> {
        let this = self.into_ref().get_ref();
        CursorMut::new(this, this.ends.next.get())
    }

    /// Returns a mutable cursor at the last node, or at the ghost when
    /// empty.
    #[must_use]
    #[inline]
    pub fn cursor_back_mut(self: Pin<&mut Self>) -> CursorMut<'_, 'nodes, A> {
        let this = self.into_ref().get_ref();
        CursorMut::new(this, this.last())
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
        let current = Some(unsafe { linked(A::link(node)) });
        CursorMut::new(self.into_ref().get_ref(), current)
    }

    /// Pushes `node` at the front.
    ///
    /// # Panics
    ///
    /// In debug builds, when the first node's link does not point back
    /// at the head: the queue is corrupt.
    #[inline]
    pub fn push_front(self: Pin<&mut Self>, node: &'nodes mut A::Node) {
        // SAFETY: the `'nodes` borrow keeps the node live, unmoved and
        // reached only through the queue, and a `&mut` is on no other
        // queue.
        unsafe { self.push_front_ptr(NonNull::from(node)) };
    }

    /// Pushes `node` at the back.
    ///
    /// # Panics
    ///
    /// In debug builds, when the tail link has a successor: the queue is
    /// corrupt.
    #[inline]
    pub fn push_back(self: Pin<&mut Self>, node: &'nodes mut A::Node) {
        // SAFETY: the `'nodes` borrow keeps the node live, unmoved and
        // reached only through the queue, and a `&mut` is on no other
        // queue.
        unsafe { self.push_back_ptr(NonNull::from(node)) };
    }

    /// Pushes the node at `node` at the front.
    ///
    /// # Panics
    ///
    /// In debug builds, when the first node's link does not point back
    /// at the head: the queue is corrupt.
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
        unsafe { this.link_after(this.ends_link(), A::link(node)) };
    }

    /// Pushes the node at `node` at the back.
    ///
    /// # Panics
    ///
    /// In debug builds, when the tail link has a successor: the queue is
    /// corrupt.
    ///
    /// # Safety
    ///
    /// `node` must meet the contract of
    /// [`push_front_ptr`](Self::push_front_ptr).
    #[inline]
    pub unsafe fn push_back_ptr(self: Pin<&mut Self>, node: NonNull<A::Node>) {
        let this = self.into_ref().get_ref();
        let tail = this.tail();
        debug_assert!(
            unsafe { tail.as_ref() }.next.get().is_none(),
            "tail queue: the tail link has a successor",
        );
        unsafe { this.link_after(tail, A::link(node)) };
    }

    /// Unlinks the node at `node` in O(1).  The node is not handed back:
    /// the caller already holds a pointer to it, and may push it again
    /// with a `_ptr` push.
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of the node's link does not
    /// point back at it: the queue is corrupt.
    ///
    /// # Safety
    ///
    /// `node` must be on this queue.
    #[inline]
    pub unsafe fn remove_ptr(self: Pin<&mut Self>, node: NonNull<A::Node>) {
        let this = self.into_ref().get_ref();
        unsafe { this.unlink(A::link(node)) };
    }

    /// Moves every node of `other` to the back of this queue in O(1),
    /// leaving `other` empty.
    #[inline]
    pub fn append(self: Pin<&mut Self>, other: Pin<&mut Self>) {
        let this = self.into_ref().get_ref();
        let donor = other.into_ref().get_ref();
        let Some(first) = donor.ends.next.get() else {
            return;
        };
        let tail = this.tail();
        // SAFETY: the tail is `ends` or a live node's link, and `first`
        // is the link of a live node on `other`.
        unsafe {
            tail.as_ref().next.set(Some(first));
            first.as_ref().prev.set(tail.as_ptr());
        }
        this.ends.prev.set(donor.tail().as_ptr());
        donor.ends.next.set(None);
        donor.ends.prev.set(ptr::null());
    }

    /// Returns the head's own link.
    fn ends_link(&self) -> NonNull<Link> {
        NonNull::from(&self.ends)
    }

    /// Returns the link whose `next` ends the queue: the last node's or
    /// `ends`.
    fn tail(&self) -> NonNull<Link> {
        NonNull::new(self.ends.prev.get().cast_mut())
            .unwrap_or_else(|| self.ends_link())
    }

    /// Returns the last node's link, or `None` when empty.
    fn last(&self) -> Option<NonNull<Link>> {
        self.ends.next.get().map(|_| self.tail())
    }

    /// Returns the link before `current`: the last at the ghost, and
    /// `None` before the first node.
    ///
    /// # Safety
    ///
    /// `current` must be `None` or the link of a live node on this
    /// queue.
    unsafe fn prev_before(
        &self,
        current: Option<NonNull<Link>>,
    ) -> Option<NonNull<Link>> {
        let prev = current.map_or_else(
            || self.tail(),
            |link| unsafe {
                NonNull::new_unchecked(link.as_ref().prev.get().cast_mut())
            },
        );
        (prev != self.ends_link()).then_some(prev)
    }

    /// Links `link` after the link `at`, which may be `ends`.
    ///
    /// # Panics
    ///
    /// In debug builds, when the link after `at` does not point back at
    /// it.
    ///
    /// # Safety
    ///
    /// `at` must be `ends` or the link of a node on this queue, and
    /// `link` must meet the push contract of
    /// [`push_front_ptr`](Self::push_front_ptr).
    unsafe fn link_after(&self, at: NonNull<Link>, link: NonNull<Link>) {
        let (anchor, new) = unsafe { (at.as_ref(), link.as_ref()) };
        let next = anchor.next.get();
        new.next.set(next);
        new.prev.set(at.as_ptr());
        match next {
            Some(after_ptr) => {
                let after = unsafe { after_ptr.as_ref() };
                debug_assert!(
                    ptr::eq(after.prev.get(), at.as_ptr()),
                    "tail queue: the next link does not point back",
                );
                after.prev.set(link.as_ptr());
            }
            None => self.ends.prev.set(link.as_ptr()),
        }
        anchor.next.set(Some(link));
    }

    /// Unlinks the node whose link is `at`.
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of `at` does not point back at
    /// it, or when `at` ends the queue without being its tail.
    ///
    /// # Safety
    ///
    /// `at` must be the link of a node on this queue.
    unsafe fn unlink(&self, at: NonNull<Link>) {
        unsafe { check(at) };
        let link = unsafe { at.as_ref() };
        let next = link.next.get();
        let prev = link.prev.get();
        unsafe { (*prev).next.set(next) };
        if let Some(after) = next {
            unsafe { after.as_ref() }.prev.set(prev);
        } else {
            debug_assert!(
                self.tail() == at,
                "tail queue: the last link is not the tail",
            );
            self.ends.prev.set(prev);
        }
        #[cfg(debug_assertions)]
        poison(link);
    }

    /// Puts `link` where the link `at` is and unlinks `at`.
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of `at` does not point back at
    /// it.
    ///
    /// # Safety
    ///
    /// `at` must be the link of a node on this queue, and `link` must
    /// meet the push contract of [`push_front_ptr`](Self::push_front_ptr).
    unsafe fn replace(&self, at: NonNull<Link>, link: NonNull<Link>) {
        unsafe { check(at) };
        let (old, new) = unsafe { (at.as_ref(), link.as_ref()) };
        let next = old.next.get();
        let prev = old.prev.get();
        new.next.set(next);
        new.prev.set(prev);
        match next {
            Some(after) => unsafe { after.as_ref() }.prev.set(link.as_ptr()),
            None => self.ends.prev.set(link.as_ptr()),
        }
        unsafe { (*prev).next.set(Some(link)) };
        #[cfg(debug_assertions)]
        poison(old);
    }
}

impl<A: Adapter> Default for TailQueue<'_, A> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'head, A: Adapter> IntoIterator for &'head TailQueue<'_, A> {
    type Item = &'head A::Node;
    type IntoIter = Iter<'head, A>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<A: Adapter> fmt::Debug for TailQueue<'_, A> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TailQueue")
            .field("first", &self.ends.next.get())
            .field("last", &self.ends.prev.get())
            .finish()
    }
}

// SAFETY: the queue holds only pointers to nodes it hands out as `&Node`
// or `&'nodes mut Node`; `Node: Send + Sync` lets that access move threads.
unsafe impl<A: Adapter> Send for TailQueue<'_, A> where A::Node: Send + Sync {}
// SAFETY: `&TailQueue` only reads links and yields `&Node`, which
// `Node: Sync` lets several threads hold at once.
unsafe impl<A: Adapter> Sync for TailQueue<'_, A> where A::Node: Send + Sync {}

/// Returns the queue's own pointer to the link `at`: the one the link
/// before it holds, which carries the access the node was pushed with.
///
/// # Safety
///
/// `at` must be the link of a node on a queue.
unsafe fn linked(at: NonNull<Link>) -> NonNull<Link> {
    unsafe { (*at.as_ref().prev.get()).next.get() }.unwrap_or(at)
}

/// Checks, in debug builds, that the neighbours of the link `at` point
/// back at it.
///
/// # Panics
///
/// In debug builds, when the next link's `prev` is not `at`, or when the
/// link before `at` does not point at it.
///
/// # Safety
///
/// `at` must be the link of a node on a queue.
unsafe fn check(at: NonNull<Link>) {
    let link = unsafe { at.as_ref() };
    if let Some(next) = link.next.get() {
        debug_assert!(
            ptr::eq(unsafe { next.as_ref() }.prev.get(), at.as_ptr()),
            "tail queue: the next link does not point back",
        );
    }
    debug_assert!(
        unsafe { (*link.prev.get()).next.get() } == Some(at),
        "tail queue: the link before a link does not point at it",
    );
}

/// Fills a leaving link with dangling words, so a stale use faults on a
/// recognisable address.
#[cfg(debug_assertions)]
fn poison(link: &Link) {
    link.next.set(Some(NonNull::dangling()));
    link.prev.set(ptr::dangling());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_items::{Item, TailItem, items, ptrs};
    use core::pin::pin;

    type Queue<'nodes> = TailQueue<'nodes, TailItem>;

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

    /// Pushes the raw `nodes` at the back, in order.
    fn fill_raw(mut queue: Pin<&mut Queue<'_>>, nodes: &[NonNull<Item>]) {
        for node in nodes {
            // SAFETY: the nodes outlive the queue, nothing else reaches
            // them, and they are on no queue.
            unsafe { queue.as_mut().push_back_ptr(*node) };
        }
    }

    fn remove(queue: Pin<&mut Queue<'_>>, node: NonNull<Item>) {
        // SAFETY: the node is on this queue.
        unsafe { queue.remove_ptr(node) };
    }

    #[test]
    fn new_and_default_are_empty() {
        let queue = Queue::default();
        assert!(queue.is_empty());
        assert!(queue.front().is_none());
        assert!(queue.back().is_none());
        assert!(Link::default().prev.get().is_null());
    }

    #[test]
    fn pushes_at_both_ends() {
        let [mut n1, mut n2, mut n3] = [1, 2, 3].map(Item::new);
        let mut queue = pin!(Queue::new());
        queue.as_mut().push_front(&mut n2);
        queue.as_mut().push_back(&mut n3);
        queue.as_mut().push_front(&mut n1);
        assert_eq!(values(&queue), [1, 2, 3]);
        assert_eq!(queue.front().unwrap().value, 1);
        assert_eq!(queue.back().unwrap().value, 3);
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
    fn remove_ptr_front_middle_last_and_only() {
        let mut nodes = items(&[1, 2, 3, 4]);
        let raw = ptrs(&mut nodes);
        let mut queue = pin!(Queue::new());
        fill_raw(queue.as_mut(), &raw);
        remove(queue.as_mut(), raw[1]);
        remove(queue.as_mut(), raw[0]);
        // SAFETY: the node left the queue and nothing else reaches it.
        unsafe { raw[0].as_ptr().as_mut() }.unwrap().value = 10;
        remove(queue.as_mut(), raw[3]);
        assert_eq!(values(&queue), [3]);
        assert_eq!(queue.back().unwrap().value, 3);
        remove(queue.as_mut(), raw[2]);
        assert!(queue.is_empty());
        assert!(queue.back().is_none());
        fill_raw(queue.as_mut(), &raw[..2]);
        assert_eq!(values(&queue), [10, 2]);
        assert_eq!(queue.back().unwrap().value, 2);
    }

    #[test]
    #[cfg(debug_assertions)]
    fn removal_poisons_the_link_in_debug_builds() {
        let mut nodes = items(&[1]);
        let raw = ptrs(&mut nodes);
        let mut queue = pin!(Queue::new());
        fill_raw(queue.as_mut(), &raw);
        remove(queue.as_mut(), raw[0]);
        // SAFETY: the node left the queue and nothing else reaches it.
        let node = unsafe { raw[0].as_ref() };
        assert_eq!(node.tail.next.get(), Some(NonNull::dangling()));
        assert!(ptr::eq(node.tail.prev.get(), ptr::dangling()));
    }

    #[test]
    fn clear_empties_and_nodes_rejoin() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let mut queue = pin!(Queue::new());
        fill_raw(queue.as_mut(), &raw);
        queue.as_mut().clear();
        assert!(queue.is_empty());
        assert!(queue.back().is_none());
        fill_raw(queue.as_mut(), &raw);
        assert_eq!(values(&queue), [1, 2]);
    }

    #[test]
    fn append_moves_every_node_to_the_back() {
        let mut nodes = items(&[1, 2, 3, 4]);
        let raw = ptrs(&mut nodes);
        let mut queue = pin!(Queue::new());
        let mut other = pin!(Queue::new());
        fill_raw(queue.as_mut(), &raw[..2]);
        fill_raw(other.as_mut(), &raw[2..]);
        queue.as_mut().append(other.as_mut());
        assert_eq!(values(&queue), [1, 2, 3, 4]);
        assert_eq!(queue.iter().next_back().unwrap().value, 4);
        assert!(other.is_empty());
        queue.as_mut().append(other.as_mut());
        assert_eq!(values(&queue), [1, 2, 3, 4]);
        remove(queue.as_mut(), raw[2]);
        assert_eq!(values(&queue), [1, 2, 4]);
    }

    #[test]
    fn append_onto_an_empty_queue() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let mut queue = pin!(Queue::new());
        let mut other = pin!(Queue::new());
        fill_raw(other.as_mut(), &raw);
        queue.as_mut().append(other.as_mut());
        assert_eq!(values(&queue), [1, 2]);
        assert_eq!(queue.back().unwrap().value, 2);
        remove(queue.as_mut(), raw[0]);
        assert_eq!(values(&queue), [2]);
    }

    #[test]
    fn iter_walks_both_ways_and_meets_in_the_middle() {
        let mut nodes = items(&[1, 2, 3, 4, 5]);
        let mut queue = pin!(Queue::new());
        assert!(queue.iter().next().is_none());
        assert!(queue.iter().next_back().is_none());
        fill(queue.as_mut(), &mut nodes);
        let reversed: Vec<u32> = queue.iter().rev().map(|n| n.value).collect();
        assert_eq!(reversed, [5, 4, 3, 2, 1]);
        let mut walk = (&*queue).into_iter();
        assert_eq!(walk.next().unwrap().value, 1);
        assert_eq!(walk.next_back().unwrap().value, 5);
        assert_eq!(walk.next().unwrap().value, 2);
        assert_eq!(walk.next_back().unwrap().value, 4);
        assert_eq!(walk.next_back().unwrap().value, 3);
        assert!(walk.next().is_none());
        assert!(walk.next_back().is_none());
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

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the next link does not point back")]
    fn push_front_catches_a_first_link_pointing_elsewhere() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let stray = Link::new();
        let mut queue = pin!(Queue::new());
        fill_raw(queue.as_mut(), &raw[1..]);
        // SAFETY: the node is live; the test corrupts its link.
        unsafe { raw[1].as_ref() }.tail.prev.set(&raw const stray);
        // SAFETY: the node outlives the queue and is on no queue.
        unsafe { queue.as_mut().push_front_ptr(raw[0]) };
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the tail link has a successor")]
    fn push_back_catches_a_tail_with_a_successor() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let mut queue = pin!(Queue::new());
        fill_raw(queue.as_mut(), &raw[..1]);
        // SAFETY: both nodes are live; the test corrupts the first link.
        unsafe {
            let second = NonNull::from(&raw[1].as_ref().tail);
            raw[0].as_ref().tail.next.set(Some(second));
        }
        fill_raw(queue.as_mut(), &raw[1..]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the next link does not point back")]
    fn remove_catches_a_next_link_pointing_elsewhere() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let stray = Link::new();
        let mut queue = pin!(Queue::new());
        fill_raw(queue.as_mut(), &raw);
        // SAFETY: the node is live; the test corrupts its link.
        unsafe { raw[1].as_ref() }.tail.prev.set(&raw const stray);
        remove(queue.as_mut(), raw[0]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the link before a link does not point at it")]
    fn remove_catches_a_prev_link_pointing_elsewhere() {
        let mut nodes = items(&[1]);
        let raw = ptrs(&mut nodes);
        let stray = Link::new();
        let mut queue = pin!(Queue::new());
        fill_raw(queue.as_mut(), &raw);
        // SAFETY: the node is live; the test corrupts its link.
        unsafe { raw[0].as_ref() }.tail.prev.set(&raw const stray);
        remove(queue.as_mut(), raw[0]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the last link is not the tail")]
    fn remove_catches_a_tail_pointing_elsewhere() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let mut queue = pin!(Queue::new());
        fill_raw(queue.as_mut(), &raw);
        // SAFETY: the node is live; the test corrupts the tail.
        let first = unsafe { &raw const raw[0].as_ref().tail };
        queue.ends.prev.set(first);
        remove(queue.as_mut(), raw[1]);
    }
}
