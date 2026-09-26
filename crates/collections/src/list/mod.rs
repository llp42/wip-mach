// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! A list: a one-word head and two-word links, walked forward only.
//!
//! Each link holds the next node's link and the slot that points back
//! at it: the head's `first` or the previous link's `next`.  So a node
//! leaves in O(1) from its own address, without the head, and a node
//! can be linked before or after any other.
//!
//! The first node's link points into the head, so a head is pinned: it
//! mutates through `Pin<&mut Self>` and stays in place while it holds
//! nodes.  A head in a `static` is pinned by construction; one inside a
//! lock guard is pinned with [`Pin::new_unchecked`], justified by the
//! static never moving.
//!
//! Nodes are caller-owned and embed a [`Link`]; the list never allocates
//! or frees.  A list `List<'nodes, A>` takes each node as `&'nodes mut A::Node`
//! and hands it back the same way when it leaves, so the borrow checker
//! keeps a linked node alive, in place, reached only through the list,
//! and on one list at a time.  The `_ptr` pushes take a raw pointer
//! instead, for nodes whose lifetime no `'nodes` describes; they are
//! `unsafe` and their callers keep those promises by hand.  Removing a
//! node by its address, without the head, is `unsafe` too: nothing in a
//! link says which list holds it.
//!
//! A node is on a list from the push that links it until it
//! leaves: by removal, by [`clear`](List::clear), or by the list being
//! dropped or forgotten; [`move_into`](List::move_into) hands every node
//! to another head.  Leaving writes nothing to the node in release
//! builds, so a link carries no "unlinked" mark and the list has no
//! `Drop`.  Debug builds check that a link's neighbours point back at it
//! before every operation on it, and fill a leaving link with dangling
//! words.
//!
//! ```text
//! use collections::list::{self, Link, List};
//! use core::pin::pin;
//!
//! struct Timer {
//!     deadline: u64,
//!     link: Link,
//! }
//!
//! list::adapter!(TimerAdapter = Timer { link });
//!
//! let mut timer = Timer { deadline: 10, link: Link::new() };
//! let mut timers = pin!(List::<TimerAdapter>::new());
//! timers.as_mut().push_front(&mut timer);
//! ```

mod adapter;
mod cursor;

#[doc(inline)]
pub use crate::__list_adapter as adapter;
pub use adapter::Adapter;
pub use cursor::{Cursor, CursorMut, Iter};

use core::cell::Cell;
use core::fmt;
use core::marker::{PhantomData, PhantomPinned};
use core::mem::size_of;
use core::pin::Pin;
use core::ptr::{self, NonNull};

/// A pointer-sized location that points at a node's link: the head's
/// `first` or a link's `next`.
type Slot = Cell<Option<NonNull<Link>>>;

/// The field a node embeds to join one [`List`].
///
/// Two words: the next node's link, and the slot that points at this
/// link.
#[derive(Debug)]
pub struct Link {
    next: Slot,
    /// The head's `first` or the previous link's `next`.
    slot: Cell<*const Slot>,
}

impl Link {
    /// Returns a link for a node that is on no list.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            next: Cell::new(None),
            slot: Cell::new(ptr::null()),
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
// through the list holding its node, which reads them under `&` and
// writes them under `Pin<&mut>` or under the exclusive access
// `List::remove_ptr` demands; that access orders every use.
unsafe impl Send for Link {}
// SAFETY: shared access to a link reaches no word of it; its list reads
// under `&` and writes only under exclusive access.
unsafe impl Sync for Link {}

const _: () = assert!(
    size_of::<Link>() == 2 * size_of::<usize>(),
    "a link is two words",
);

/// The head of a list of `A::Node`s borrowed for `'nodes`.
pub struct List<'nodes, A: Adapter> {
    first: Slot,
    nodes: PhantomData<(A, &'nodes mut A::Node)>,
    _pinned: PhantomPinned,
}

impl<'nodes, A: Adapter> List<'nodes, A> {
    /// Returns an empty list.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            first: Cell::new(None),
            nodes: PhantomData,
            _pinned: PhantomPinned,
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
    pub fn clear(self: Pin<&mut Self>) {
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
        Cursor::new(self, self.first.get())
    }

    /// Returns a mutable cursor at the first node, or at the ghost when
    /// empty.
    #[must_use]
    #[inline]
    pub const fn cursor_front_mut(
        self: Pin<&mut Self>,
    ) -> CursorMut<'_, 'nodes, A> {
        let this = self.into_ref().get_ref();
        CursorMut::new(this, this.first.get())
    }

    /// Returns a mutable cursor at `node`.
    ///
    /// # Safety
    ///
    /// `node` must be on this list.
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
    /// at the head: the list is corrupt.
    #[inline]
    pub fn push_front(self: Pin<&mut Self>, node: &'nodes mut A::Node) {
        // SAFETY: the `'nodes` borrow keeps the node live, unmoved and
        // reached only through the list, and a `&mut` is on no other
        // list.
        unsafe { self.push_front_ptr(NonNull::from(node)) };
    }

    /// Pushes the node at `node` at the front.
    ///
    /// # Panics
    ///
    /// In debug builds, when the first node's link does not point back
    /// at the head: the list is corrupt.
    ///
    /// # Safety
    ///
    /// `node` must point at a node that stays live and unmoved, and that
    /// nothing reaches except through the list, until it leaves the
    /// list; its link must not be on any list.  The node leaves as
    /// `&'nodes mut`, so it must stay live for as long as that is used.
    #[inline]
    pub unsafe fn push_front_ptr(
        self: Pin<&mut Self>,
        node: NonNull<A::Node>,
    ) {
        let link = unsafe { A::link(node) };
        unsafe { link_into(&self.first, link) };
    }

    /// Unlinks the node at `node` from the list that holds it, in O(1)
    /// and without its head.  The node is not handed back: the caller
    /// already holds a pointer to it, and may push it again with
    /// [`push_front_ptr`](Self::push_front_ptr).
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of the node's link does not
    /// point back at it: the list is corrupt.
    ///
    /// # Safety
    ///
    /// `node` must be on a `List<'nodes, A>` and nothing else may reach that
    /// list during the call.  Afterwards, no cursor of the list may rest
    /// on `node` and no iterator may be about to yield it.
    #[inline]
    pub unsafe fn remove_ptr(node: NonNull<A::Node>) {
        unsafe { unlink(A::link(node)) };
    }

    /// Hands every node to `into`, leaving this list empty; the nodes
    /// `into` held before leave it.
    #[inline]
    pub fn move_into(self: Pin<&mut Self>, into: Pin<&mut Self>) {
        let target = into.into_ref().get_ref();
        let first = self.first.get();
        target.first.set(first);
        if let Some(link) = first {
            // SAFETY: a node stays live while it is on the list.
            unsafe { link.as_ref() }.slot.set(&raw const target.first);
        }
        self.first.set(None);
    }
}

impl<A: Adapter> Default for List<'_, A> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'head, A: Adapter> IntoIterator for &'head List<'_, A> {
    type Item = &'head A::Node;
    type IntoIter = Iter<'head, A>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<A: Adapter> fmt::Debug for List<'_, A> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("List")
            .field("first", &self.first.get())
            .finish()
    }
}

// SAFETY: the list holds only pointers to nodes it hands out as `&Node`
// or `&'nodes mut Node`; `Node: Send + Sync` lets that access move threads.
unsafe impl<A: Adapter> Send for List<'_, A> where A::Node: Send + Sync {}
// SAFETY: `&List` only reads links and yields `&Node`, which
// `Node: Sync` lets several threads hold at once.
unsafe impl<A: Adapter> Sync for List<'_, A> where A::Node: Send + Sync {}

/// Links `link` into `slot`, ahead of the node the slot points at.
///
/// # Panics
///
/// In debug builds, when that node's link does not point back at `slot`.
///
/// # Safety
///
/// `slot` must be a list head or the `next` of a node on that list, and
/// `link` must meet the push contract of [`List::push_front_ptr`].
unsafe fn link_into(slot: &Slot, link: NonNull<Link>) {
    let new = unsafe { link.as_ref() };
    let next = slot.get();
    if let Some(after_ptr) = next {
        let after = unsafe { after_ptr.as_ref() };
        debug_assert!(
            ptr::eq(after.slot.get(), slot),
            "list: a link does not point back at its slot",
        );
        after.slot.set(&raw const new.next);
    }
    new.next.set(next);
    new.slot.set(slot);
    slot.set(Some(link));
}

/// Links `link` ahead of the node whose link is `at`.
///
/// # Panics
///
/// In debug builds, when a neighbour of `at` does not point back at it.
///
/// # Safety
///
/// `at` must be the link of a node on a list, and `link` must meet the
/// push contract of [`List::push_front_ptr`].
unsafe fn link_before(at: NonNull<Link>, link: NonNull<Link>) {
    unsafe { check(at) };
    let (target, new) = unsafe { (at.as_ref(), link.as_ref()) };
    let slot = target.slot.get();
    new.next.set(Some(at));
    new.slot.set(slot);
    unsafe { (*slot).set(Some(link)) };
    target.slot.set(&raw const new.next);
}

/// Unlinks the node whose link is `at`.
///
/// # Panics
///
/// In debug builds, when a neighbour of `at` does not point back at it.
///
/// # Safety
///
/// `at` must be the link of a node on a list that nothing else reaches
/// during the call.
unsafe fn unlink(at: NonNull<Link>) {
    unsafe { check(at) };
    let link = unsafe { at.as_ref() };
    let next = link.next.get();
    let slot = link.slot.get();
    unsafe { (*slot).set(next) };
    if let Some(after) = next {
        unsafe { after.as_ref() }.slot.set(slot);
    }
    #[cfg(debug_assertions)]
    poison(link);
}

/// Puts `link` where the link `at` is and unlinks `at`.
///
/// # Panics
///
/// In debug builds, when a neighbour of `at` does not point back at it.
///
/// # Safety
///
/// `at` must be the link of a node on a list, and `link` must meet the
/// push contract of [`List::push_front_ptr`].
unsafe fn replace(at: NonNull<Link>, link: NonNull<Link>) {
    unsafe { check(at) };
    let (old, new) = unsafe { (at.as_ref(), link.as_ref()) };
    let next = old.next.get();
    let slot = old.slot.get();
    new.next.set(next);
    new.slot.set(slot);
    if let Some(after) = next {
        unsafe { after.as_ref() }.slot.set(&raw const new.next);
    }
    unsafe { (*slot).set(Some(link)) };
    #[cfg(debug_assertions)]
    poison(old);
}

/// Returns the list's own pointer to the link `at`: the one its slot
/// holds, which carries the access the node was pushed with.
///
/// # Safety
///
/// `at` must be the link of a node on a list.
unsafe fn linked(at: NonNull<Link>) -> NonNull<Link> {
    unsafe { (*at.as_ref().slot.get()).get() }.unwrap_or(at)
}

/// Checks, in debug builds, that the neighbours of the link `at` point
/// back at it.
///
/// # Panics
///
/// In debug builds, when the next link's slot is not `at`'s `next`, or
/// when `at`'s slot does not point at `at`.
///
/// # Safety
///
/// `at` must be the link of a node on a list.
unsafe fn check(at: NonNull<Link>) {
    let link = unsafe { at.as_ref() };
    if let Some(next) = link.next.get() {
        debug_assert!(
            ptr::eq(unsafe { next.as_ref() }.slot.get(), &raw const link.next),
            "list: the next link does not point back",
        );
    }
    debug_assert!(
        unsafe { (*link.slot.get()).get() } == Some(at),
        "list: the slot before a link does not point at it",
    );
}

/// Fills a leaving link with dangling words in debug builds, so a stale
/// use faults on a recognisable address.
#[cfg(debug_assertions)]
fn poison(link: &Link) {
    link.next.set(Some(NonNull::dangling()));
    link.slot.set(ptr::dangling());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_items::{Item, ListItem, items, ptrs};
    use core::pin::pin;

    type Items<'nodes> = List<'nodes, ListItem>;

    const _: () = assert!(size_of::<Items<'_>>() == size_of::<usize>());

    fn values(list: &Items<'_>) -> Vec<u32> {
        list.iter().map(|item| item.value).collect()
    }

    /// Pushes the raw `nodes` so that the list reads in their order.
    fn fill_raw(mut list: Pin<&mut Items<'_>>, nodes: &[NonNull<Item>]) {
        for node in nodes.iter().rev() {
            // SAFETY: the nodes outlive the list, nothing else reaches
            // them, and they are on no list.
            unsafe { list.as_mut().push_front_ptr(*node) };
        }
    }

    fn remove(node: NonNull<Item>) {
        // SAFETY: the node is on a list that nothing else reaches.
        unsafe { Items::remove_ptr(node) };
    }

    #[test]
    fn new_and_default_are_empty() {
        assert!(Items::new().is_empty());
        assert!(Items::default().is_empty());
        assert!(Items::new().front().is_none());
        assert!(Link::default().slot.get().is_null());
    }

    #[test]
    fn push_front_is_lifo() {
        let mut nodes = items(&[1, 2, 3]);
        let mut list = pin!(Items::new());
        for node in &mut nodes {
            list.as_mut().push_front(node);
        }
        assert!(!list.is_empty());
        assert_eq!(list.front().unwrap().value, 3);
        assert_eq!(values(&list), [3, 2, 1]);
    }

    #[test]
    fn remove_ptr_needs_no_head() {
        let mut nodes = items(&[1, 2, 3, 4]);
        let raw = ptrs(&mut nodes);
        let mut list = pin!(Items::new());
        fill_raw(list.as_mut(), &raw);
        remove(raw[1]);
        assert_eq!(values(&list), [1, 3, 4]);
        remove(raw[0]);
        // SAFETY: the node left the list and nothing else reaches it.
        unsafe { raw[0].as_ptr().as_mut() }.unwrap().value = 10;
        assert_eq!(values(&list), [3, 4]);
        remove(raw[3]);
        assert_eq!(values(&list), [3]);
        remove(raw[2]);
        assert!(list.is_empty());
        fill_raw(list.as_mut(), &raw);
        assert_eq!(values(&list), [10, 2, 3, 4]);
    }

    #[test]
    #[cfg(debug_assertions)]
    fn removal_poisons_the_link_in_debug_builds() {
        let mut nodes = items(&[1]);
        let raw = ptrs(&mut nodes);
        let mut list = pin!(Items::new());
        fill_raw(list.as_mut(), &raw);
        remove(raw[0]);
        // SAFETY: the node left the list and nothing else reaches it.
        let node = unsafe { raw[0].as_ref() };
        assert_eq!(node.list.next.get(), Some(NonNull::dangling()));
        assert!(ptr::eq(node.list.slot.get(), ptr::dangling()));
    }

    #[test]
    fn clear_empties_and_nodes_rejoin() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let mut list = pin!(Items::new());
        fill_raw(list.as_mut(), &raw);
        list.as_mut().clear();
        assert!(list.is_empty());
        fill_raw(list.as_mut(), &raw);
        assert_eq!(values(&list), [1, 2]);
    }

    #[test]
    fn move_into_hands_the_nodes_over() {
        let mut nodes = items(&[1, 2, 3]);
        let raw = ptrs(&mut nodes);
        let mut from = pin!(Items::new());
        let mut into = pin!(Items::new());
        fill_raw(from.as_mut(), &raw[..2]);
        fill_raw(into.as_mut(), &raw[2..]);
        from.as_mut().move_into(into.as_mut());
        assert!(from.is_empty());
        assert_eq!(values(&into), [1, 2]);
        remove(raw[0]);
        assert_eq!(values(&into), [2]);
        from.as_mut().move_into(into.as_mut());
        assert!(into.is_empty());
    }

    #[test]
    fn into_iter_walks_front_to_back() {
        let mut nodes = items(&[1, 2, 3]);
        let mut list = pin!(Items::new());
        for node in nodes.iter_mut().rev() {
            list.as_mut().push_front(node);
        }
        let walked: Vec<u32> = (&*list).into_iter().map(|n| n.value).collect();
        assert_eq!(walked, [1, 2, 3]);
    }

    #[test]
    fn heads_and_links_cross_threads() {
        fn check<T>(_: &T)
        where
            T: Send + Sync,
        {
        }
        check(&Items::new());
        check(&Link::new());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "does not point back at its slot")]
    fn push_front_catches_a_first_link_pointing_elsewhere() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let stray: Slot = Cell::new(None);
        let mut list = pin!(Items::new());
        fill_raw(list.as_mut(), &raw[1..]);
        // SAFETY: the node is live; the test corrupts its link.
        unsafe { raw[1].as_ref() }.list.slot.set(&raw const stray);
        fill_raw(list.as_mut(), &raw[..1]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the next link does not point back")]
    fn remove_catches_a_next_link_pointing_elsewhere() {
        let mut nodes = items(&[1, 2]);
        let raw = ptrs(&mut nodes);
        let stray: Slot = Cell::new(None);
        let mut list = pin!(Items::new());
        fill_raw(list.as_mut(), &raw);
        // SAFETY: the node is live; the test corrupts its link.
        unsafe { raw[1].as_ref() }.list.slot.set(&raw const stray);
        remove(raw[0]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the slot before a link does not point at it")]
    fn remove_catches_a_slot_pointing_elsewhere() {
        let mut nodes = items(&[1]);
        let raw = ptrs(&mut nodes);
        let stray: Slot = Cell::new(None);
        let mut list = pin!(Items::new());
        fill_raw(list.as_mut(), &raw);
        // SAFETY: the node is live; the test corrupts its link.
        unsafe { raw[0].as_ref() }.list.slot.set(&raw const stray);
        remove(raw[0]);
    }
}
