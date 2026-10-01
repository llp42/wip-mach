// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! A red-black tree: a three-word head and three-word links, ordered by a
//! key the adapter extracts from each node.
//!
//! A link holds the node's parent, tagged with its colour, and its two
//! children, so no word is spent on a colour or a sentinel, and the head
//! holds the root and the first and last nodes.  Nothing points back into
//! the head, so a head is not pinned: it moves freely, like a
//! [`SinglyList`](crate::singly_list::SinglyList).
//!
//! The descent compares keys through [`Adapter::key`], monomorphised for
//! the tree.  The rebalancing is a separate, private core that sees links
//! alone and never a key, so every tree shares one copy of it.  Neighbours
//! are found through parent pointers, so a cursor or an iterator keeps no
//! stack and a walk costs O(1) amortised per step.
//!
//! Equal keys are allowed and stay in insertion order: an insert goes
//! after the nodes that compare equal.  A key at or past the last node, or
//! below the first, joins under that end without a search, so keys that
//! arrive in order cost no descent.  [`lower_bound`] and
//! [`upper_bound`] name the first and the last node at or around a key, so
//! a floor or a ceiling lookup is one call.
//!
//! Nodes are caller-owned and embed a [`Link`]; the tree never allocates
//! or frees.  A tree `RbTree<'nodes, A>` takes each node as
//! `&'nodes mut A::Node` and hands it back the same way when it leaves, so
//! the borrow checker keeps a linked node alive, in place, reached only
//! through the tree, and on one tree at a time.  The `_ptr` forms take a
//! raw pointer instead, for nodes whose lifetime no `'nodes` describes;
//! they are `unsafe` and their callers keep those promises by hand.
//! Removing a node by its address is `unsafe` too: nothing in a link says
//! which tree holds it.
//!
//! A node is on a tree from the insert that links it until it leaves: by
//! removal, by [`clear`](RbTree::clear), or by the tree being dropped or
//! forgotten.  Leaving writes nothing to the node in release builds, so a
//! link carries no "unlinked" mark and the tree has no `Drop`.  Debug
//! builds check that a link's neighbours point back at it before every
//! operation on it, and fill a leaving link with dangling words.
//!
//! ```text
//! use collections::rb_tree::{self, Link, RbTree};
//!
//! struct Region {
//!     start: usize,
//!     link: Link,
//! }
//!
//! rb_tree::adapter!(RegionAdapter = Region { link } key(usize) = |region| region.start);
//!
//! let mut a = Region { start: 0x1000, link: Link::new() };
//! let mut b = Region { start: 0x3000, link: Link::new() };
//!
//! let mut regions = RbTree::<RegionAdapter>::new();
//! regions.insert(&mut a);
//! regions.insert(&mut b);
//!
//! // The region that starts at or before an address.
//! let below = regions.upper_bound(Bound::Included(&0x2000));
//! assert_eq!(below.current().unwrap().start, 0x1000);
//! ```
//!
//! [`lower_bound`]: RbTree::lower_bound
//! [`upper_bound`]: RbTree::upper_bound

mod adapter;
mod balance;
mod cursor;

#[doc(inline)]
pub use crate::__rb_tree_adapter as adapter;
pub use adapter::Adapter;
pub use cursor::{Cursor, CursorMut, Iter};

use core::cell::Cell;
use core::cmp::Ordering;
use core::fmt;
use core::hint::select_unpredictable;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ops::Bound;
use core::ptr::{self, NonNull};
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering::Relaxed;

/// The root of a tree: its first link, or `None` when empty.
type Root = Option<NonNull<Link>>;

/// The left side of a link.
const LEFT: bool = false;
/// The right side of a link.
const RIGHT: bool = true;

/// Bit 0 of a link's parent word: set when the link is black.
const BLACK: usize = 1;

/// The field a node embeds to join one [`RbTree`].
///
/// Three words: the parent link, tagged with the colour, and the two
/// children.
#[derive(Debug)]
pub struct Link {
    /// The parent's link, or null for the root; bit 0 is [`BLACK`].
    ///
    /// An atomic with relaxed ordering, which compiles to plain loads and
    /// stores, and not a `Cell`: the compiler narrows a colour change on a
    /// `Cell` to a byte read-modify-write, and the next full-word load of
    /// the parent then waits for the store to retire instead of reading it
    /// from the store buffer.
    parent_color: AtomicPtr<Self>,
    left: Cell<Option<NonNull<Self>>>,
    right: Cell<Option<NonNull<Self>>>,
}

impl Link {
    /// Returns a link for a node that is on no tree.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            parent_color: AtomicPtr::new(ptr::null_mut()),
            left: Cell::new(None),
            right: Cell::new(None),
        }
    }

    /// Returns the parent's link, or `None` for the root.
    fn parent(&self) -> Option<NonNull<Self>> {
        NonNull::new(self.parent_word().map_addr(|addr| addr & !BLACK))
    }

    /// Sets the parent's link and keeps the colour.
    fn set_parent(&self, parent: Option<NonNull<Self>>) {
        let colour = self.parent_word().addr() & BLACK;
        let raw = parent.map_or(ptr::null_mut(), NonNull::as_ptr);
        self.parent_color
            .store(raw.map_addr(|addr| addr | colour), Relaxed);
    }

    fn is_black(&self) -> bool {
        self.parent_word().addr() & BLACK != 0
    }

    fn set_black(&self) {
        self.set_color(true);
    }

    fn set_red(&self) {
        self.set_color(false);
    }

    fn set_color(&self, black: bool) {
        let parent = self.parent_word();
        let addr = parent.addr() & !BLACK | usize::from(black);
        self.parent_color.store(parent.with_addr(addr), Relaxed);
    }

    /// Returns the left and the right child, loaded together.
    ///
    /// Volatile reads, so that the compiler cannot fold the pair and a
    /// later compare into one load whose address waits for the compare: a
    /// descent picks between two children already in registers, and each
    /// level waits for one load and one select, not for two loads in a
    /// row.
    #[inline]
    fn children(&self) -> (Option<NonNull<Self>>, Option<NonNull<Self>>) {
        // SAFETY: the cells are valid for reads, and no write to them is
        // in progress: a descent holds the tree.  An `Option<NonNull>` has
        // the layout of a raw pointer, null for `None`.
        let (left, right) = unsafe {
            (
                ptr::read_volatile(self.left.as_ptr().cast::<*mut Self>()),
                ptr::read_volatile(self.right.as_ptr().cast::<*mut Self>()),
            )
        };
        (NonNull::new(left), NonNull::new(right))
    }

    #[inline]
    fn parent_word(&self) -> *mut Self {
        self.parent_color.load(Relaxed)
    }

    /// Returns the slot of the child on a side.
    const fn slot(&self, right: bool) -> &Cell<Option<NonNull<Self>>> {
        if right { &self.right } else { &self.left }
    }

    /// Makes the link a red leaf below `parent`.
    #[inline]
    fn reset(&self, parent: Option<NonNull<Self>>) {
        self.parent_color
            .store(parent.map_or(ptr::null_mut(), NonNull::as_ptr), Relaxed);
        self.left.set(None);
        self.right.set(None);
    }
}

impl Default for Link {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: a link's words are private to this module and only reached
// through the tree holding its node, which reads them under `&` and
// writes them under `&mut`; the tree's borrow orders every access.
unsafe impl Send for Link {}
// SAFETY: shared access to a link reaches no word of it; its tree reads
// under `&` and writes only under `&mut`.
unsafe impl Sync for Link {}

const _: () = assert!(
    size_of::<Link>() == 3 * size_of::<usize>(),
    "a link is three words",
);
const _: () = assert!(
    align_of::<Link>() > BLACK,
    "a link's address leaves bit 0 free for the colour",
);

/// The head of a red-black tree of `A::Node`s borrowed for `'nodes`.
pub struct RbTree<'nodes, A: Adapter> {
    root: Root,
    /// The first link, the one with the least key.
    min: Root,
    /// The last link, the one with the greatest key.
    max: Root,
    nodes: PhantomData<(A, &'nodes mut A::Node)>,
}

impl<'nodes, A: Adapter> RbTree<'nodes, A> {
    /// Returns an empty tree.
    #[must_use]
    #[inline]
    pub const fn new() -> Self {
        Self {
            root: None,
            min: None,
            max: None,
            nodes: PhantomData,
        }
    }

    /// Returns whether the tree holds no nodes.
    #[must_use]
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Empties the tree in O(1).
    ///
    /// The nodes are not touched: their links keep stale words, which
    /// the next insert of each node overwrites, and the ones inserted as
    /// `&'nodes mut` stay borrowed until `'nodes` ends.
    #[inline]
    pub const fn clear(&mut self) {
        self.root = None;
        self.min = None;
        self.max = None;
    }

    /// Returns the first node, the one with the least key, or `None` when
    /// empty.
    #[must_use]
    #[inline]
    pub fn front(&self) -> Option<&A::Node> {
        // SAFETY: a node stays live while it is on the tree.
        self.first().map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Returns the last node, the one with the greatest key, or `None`
    /// when empty.
    #[must_use]
    #[inline]
    pub fn back(&self) -> Option<&A::Node> {
        // SAFETY: a node stays live while it is on the tree.
        self.last().map(|link| unsafe { A::node(link).as_ref() })
    }

    /// Returns an iterator over the nodes in key order; reversed, in
    /// descending order.
    #[must_use]
    #[inline]
    pub const fn iter(&self) -> Iter<'_, A> {
        Iter::new(self.first(), self.last())
    }

    /// Returns a cursor at the first node, or at the ghost when empty.
    #[must_use]
    #[inline]
    pub const fn cursor_front(&self) -> Cursor<'_, 'nodes, A> {
        Cursor::new(self, self.first())
    }

    /// Returns a cursor at the last node, or at the ghost when empty.
    #[must_use]
    #[inline]
    pub const fn cursor_back(&self) -> Cursor<'_, 'nodes, A> {
        Cursor::new(self, self.last())
    }

    /// Returns a mutable cursor at the first node, or at the ghost when
    /// empty.
    #[must_use]
    #[inline]
    pub const fn cursor_front_mut(&mut self) -> CursorMut<'_, 'nodes, A> {
        let current = self.first();
        CursorMut::new(self, current)
    }

    /// Returns a mutable cursor at the last node, or at the ghost when
    /// empty.
    #[must_use]
    #[inline]
    pub const fn cursor_back_mut(&mut self) -> CursorMut<'_, 'nodes, A> {
        let current = self.last();
        CursorMut::new(self, current)
    }

    /// Returns a mutable cursor at `node`.
    ///
    /// # Panics
    ///
    /// In debug builds, when the tree is corrupt (a neighbour of the node's
    /// link does not point back at it, or a cached end is wrong), when the
    /// node is on another tree, or when the adapter does not map its link
    /// back to the node.
    ///
    /// # Safety
    ///
    /// `node` must be on this tree.
    #[must_use]
    #[inline]
    pub unsafe fn cursor_mut_from_ptr(
        &mut self,
        node: NonNull<A::Node>,
    ) -> CursorMut<'_, 'nodes, A> {
        let current = Some(unsafe { linked(self.root, Self::link_for(node)) });
        CursorMut::new(self, current)
    }

    /// Returns a cursor at the first node whose key is on `bound`'s
    /// greater side, or at the ghost when there is none.
    ///
    /// `Included(key)` finds the first node with a key `>= key`,
    /// `Excluded(key)` the first with a key `> key`, and `Unbounded` the
    /// front.  Among equal keys, the first inserted comes first.
    #[must_use]
    #[inline]
    pub fn lower_bound(&self, bound: Bound<&A::Key>) -> Cursor<'_, 'nodes, A> {
        Cursor::new(self, self.lower_link(bound))
    }

    /// Returns a cursor at the last node whose key is on `bound`'s lesser
    /// side, or at the ghost when there is none.
    ///
    /// `Included(key)` finds the last node with a key `<= key`,
    /// `Excluded(key)` the last with a key `< key`, and `Unbounded` the
    /// back.  Among equal keys, the last inserted comes last.
    #[must_use]
    #[inline]
    pub fn upper_bound(&self, bound: Bound<&A::Key>) -> Cursor<'_, 'nodes, A> {
        Cursor::new(self, self.upper_link(bound))
    }

    /// Like [`lower_bound`](Self::lower_bound), with a cursor that can
    /// unlink nodes.
    #[must_use]
    #[inline]
    pub fn lower_bound_mut(
        &mut self,
        bound: Bound<&A::Key>,
    ) -> CursorMut<'_, 'nodes, A> {
        let current = self.lower_link(bound);
        CursorMut::new(self, current)
    }

    /// Like [`upper_bound`](Self::upper_bound), with a cursor that can
    /// unlink nodes.
    #[must_use]
    #[inline]
    pub fn upper_bound_mut(
        &mut self,
        bound: Bound<&A::Key>,
    ) -> CursorMut<'_, 'nodes, A> {
        let current = self.upper_link(bound);
        CursorMut::new(self, current)
    }

    /// Links `node` after every node whose key compares equal to its own.
    ///
    /// # Panics
    ///
    /// In debug builds, when the tree is corrupt (a neighbour of the link
    /// the node joins below does not point back at it, or a cached end is
    /// wrong), or when the adapter does not map the node's link back to the
    /// node.
    #[inline]
    pub fn insert(&mut self, node: &'nodes mut A::Node) {
        // SAFETY: the `'nodes` borrow keeps the node live, unmoved and
        // reached only through the tree, and a `&mut` is on no other
        // tree.
        unsafe { self.insert_ptr(NonNull::from(node)) };
    }

    /// Links the node at `node` after every node whose key compares equal
    /// to its own.
    ///
    /// # Panics
    ///
    /// In debug builds, when the tree is corrupt (a neighbour of the link
    /// the node joins below does not point back at it, or a cached end is
    /// wrong), or when the adapter does not map the node's link back to the
    /// node.
    ///
    /// # Safety
    ///
    /// `node` must point at a node that stays live and unmoved, and that
    /// nothing reaches except through the tree, until it leaves the tree;
    /// its link must not be on any tree.  The node leaves as `&'nodes
    /// mut`, so it must stay live for as long as that is used.
    #[inline]
    pub unsafe fn insert_ptr(&mut self, node: NonNull<A::Node>) {
        let link = unsafe { Self::link_for(node) };
        #[cfg(debug_assertions)]
        self.check_ends();
        let key = A::key(unsafe { node.as_ref() });
        let (Some(min), Some(max)) = (self.min, self.max) else {
            unsafe { self.link_below(None, LEFT, link) };
            self.min = Some(link);
            self.max = Some(link);
            return;
        };
        // A key at or past the last node, or below the first, needs no
        // search: the node joins under the end it passes.  A run of keys
        // in order takes this road every time, and the compares are
        // predictable; any other key fails them at the cost of two loads.
        if A::key(unsafe { A::node(max).as_ref() }) <= key {
            unsafe { self.link_below(Some(max), RIGHT, link) };
            self.max = Some(link);
            return;
        }
        if key < A::key(unsafe { A::node(min).as_ref() }) {
            unsafe { self.link_below(Some(min), LEFT, link) };
            self.min = Some(link);
            return;
        }
        let mut parent = None;
        let mut right = LEFT;
        let mut at = self.root;
        while let Some(current) = at {
            parent = at;
            let (below, above) = unsafe { current.as_ref() }.children();
            right = A::key(unsafe { A::node(current).as_ref() }) <= key;
            at = select_unpredictable(right, above, below);
        }
        unsafe { self.link_below(parent, right, link) };
    }

    /// Links `link` as a new red leaf on the side `right` of `parent`, or
    /// as the root when `parent` is `None`, and rebalances.
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of `parent` does not point back
    /// at it, when `parent` is not on this tree, when the slot is taken, or
    /// when there is no `parent` and the tree is not empty.
    ///
    /// # Safety
    ///
    /// `parent` must be `None` for an empty tree, or the link of a node
    /// of this tree with no child on that side; `link` must meet the
    /// contract of [`insert_ptr`](Self::insert_ptr).
    unsafe fn link_below(
        &mut self,
        parent: Option<NonNull<Link>>,
        right: bool,
        link: NonNull<Link>,
    ) {
        match parent {
            None => {
                debug_assert!(
                    self.root.is_none(),
                    "rb tree: a link joins as the root of a tree that is not empty",
                );
                self.root = Some(link);
            }
            Some(above) => {
                unsafe { check(self.root, above) };
                let slot = unsafe { above.as_ref() }.slot(right);
                debug_assert!(
                    slot.get().is_none(),
                    "rb tree: the slot to link into is not empty",
                );
                slot.set(Some(link));
            }
        }
        unsafe { link.as_ref() }.reset(parent);
        unsafe { balance::insert_color(&mut self.root, link) };
    }

    /// Links the node at `node` right after the link `at` when `toward`
    /// is `RIGHT`, right before it when `LEFT`.  At the ghost, `None`, that
    /// is at the front for `RIGHT` and at the back for `LEFT`.
    ///
    /// The place comes from the tree's shape, not from a compare: the
    /// new link is the child of `at` on that side when there is none, and
    /// otherwise the child, on the other side, of the last link of the
    /// subtree there.
    ///
    /// # Panics
    ///
    /// In debug builds, when the tree is corrupt, when `at` is on another
    /// tree, when the adapter does not map the node's link back to the
    /// node, or when the key of the node does not lie between those of its
    /// two new neighbours.
    ///
    /// # Safety
    ///
    /// `at` must be `None` or the link of a node on this tree, and `node`
    /// must meet the contract of [`insert_ptr`](Self::insert_ptr).
    unsafe fn insert_beside(
        &mut self,
        at: Option<NonNull<Link>>,
        toward: bool,
        node: NonNull<A::Node>,
    ) {
        let link = unsafe { Self::link_for(node) };
        #[cfg(debug_assertions)]
        self.check_ends();
        if let Some(here) = at {
            unsafe { check(self.root, here) };
        }
        #[cfg(debug_assertions)]
        unsafe {
            self.check_beside(at, toward, &A::key(node.as_ref()));
        }
        let empty = self.root.is_none();
        let new_max =
            empty || if toward { at == self.max } else { at.is_none() };
        let new_min =
            empty || if toward { at.is_none() } else { at == self.min };
        let subtree = at.map_or(self.root, |here| {
            unsafe { here.as_ref() }.slot(toward).get()
        });
        // An empty `subtree` means the tree is empty (no parent), or `at`
        // has no child on that side.
        let (parent, right) = unsafe { balance::extreme(subtree, !toward) }
            .map_or((at, toward), |edge| (Some(edge), !toward));
        unsafe { self.link_below(parent, right, link) };
        if new_max {
            self.max = Some(link);
        }
        if new_min {
            self.min = Some(link);
        }
    }

    /// Checks that `key` lies between the keys of the two links it would
    /// go between, were it linked beside `at` as [`insert_beside`] does.
    ///
    /// # Panics
    ///
    /// When it is below its new predecessor's key, or above its new
    /// successor's.
    ///
    /// # Safety
    ///
    /// `at` must be `None` or the link of a node on this tree.
    ///
    /// [`insert_beside`]: Self::insert_beside
    #[cfg(debug_assertions)]
    unsafe fn check_beside(
        &self,
        at: Option<NonNull<Link>>,
        toward: bool,
        key: &A::Key,
    ) {
        let (prev, next) = if toward {
            (at, unsafe { self.next_after(at) })
        } else {
            (unsafe { self.prev_before(at) }, at)
        };
        if let Some(before) = prev {
            debug_assert!(
                A::key(unsafe { A::node(before).as_ref() }) <= *key,
                "rb tree: inserted below its predecessor",
            );
        }
        if let Some(after) = next {
            debug_assert!(
                *key <= A::key(unsafe { A::node(after).as_ref() }),
                "rb tree: inserted above its successor",
            );
        }
    }

    /// Links the node at `node` right after the node at `after`, with no
    /// search and no cursor: the insert for a caller that holds the
    /// predecessor's address, as a map does that keeps its entries in a
    /// list as well.
    ///
    /// The key of `node` must lie between the keys of its two new
    /// neighbours; a node out of order stays linked and misorders the
    /// lookups that cross it, and nothing else.
    ///
    /// # Panics
    ///
    /// In debug builds, when the tree is corrupt, when `after` is on
    /// another tree, or when the key is out of order.
    ///
    /// # Safety
    ///
    /// `after` must be on this tree, and `node` must meet the contract of
    /// [`insert_ptr`](Self::insert_ptr).
    #[inline]
    pub unsafe fn insert_after_ptr(
        &mut self,
        after: NonNull<A::Node>,
        node: NonNull<A::Node>,
    ) {
        unsafe {
            self.insert_beside(Some(Self::link_for(after)), RIGHT, node);
        };
    }

    /// Links the node at `node` right before the node at `before`, with no
    /// search and no cursor.  See [`insert_after_ptr`](Self::insert_after_ptr)
    /// for the order the key must keep.
    ///
    /// # Panics
    ///
    /// In debug builds, when the tree is corrupt, when `before` is on
    /// another tree, or when the key is out of order.
    ///
    /// # Safety
    ///
    /// `before` must be on this tree, and `node` must meet the contract of
    /// [`insert_ptr`](Self::insert_ptr).
    #[inline]
    pub unsafe fn insert_before_ptr(
        &mut self,
        before: NonNull<A::Node>,
        node: NonNull<A::Node>,
    ) {
        unsafe {
            self.insert_beside(Some(Self::link_for(before)), LEFT, node);
        };
    }

    /// Unlinks the node at `node`.  The node is not handed back: the
    /// caller already holds a pointer to it, and may insert it again
    /// with [`insert_ptr`](Self::insert_ptr).
    ///
    /// # Panics
    ///
    /// In debug builds, when the tree is corrupt (a neighbour of the node's
    /// link does not point back at it, or a cached end is wrong), when the
    /// node is on another tree, or when the adapter does not map its link
    /// back to the node.
    ///
    /// # Safety
    ///
    /// `node` must be on this tree.
    #[inline]
    pub unsafe fn remove_ptr(&mut self, node: NonNull<A::Node>) {
        unsafe { self.unlink(Self::link_for(node)) };
    }

    /// Returns the first link, or `None` when empty.
    const fn first(&self) -> Option<NonNull<Link>> {
        self.min
    }

    /// Returns the last link, or `None` when empty.
    const fn last(&self) -> Option<NonNull<Link>> {
        self.max
    }

    /// Returns the link after `current`; the first at the ghost.
    ///
    /// # Safety
    ///
    /// `current` must be `None` or the link of a live node on this tree.
    unsafe fn next_after(
        &self,
        current: Option<NonNull<Link>>,
    ) -> Option<NonNull<Link>> {
        current.map_or_else(
            || self.first(),
            |at| unsafe { balance::step(at, RIGHT) },
        )
    }

    /// Returns the link before `current`; the last at the ghost.
    ///
    /// # Safety
    ///
    /// `current` must be `None` or the link of a live node on this tree.
    unsafe fn prev_before(
        &self,
        current: Option<NonNull<Link>>,
    ) -> Option<NonNull<Link>> {
        current.map_or_else(
            || self.last(),
            |at| unsafe { balance::step(at, LEFT) },
        )
    }

    fn lower_link(&self, bound: Bound<&A::Key>) -> Option<NonNull<Link>> {
        match bound {
            Bound::Unbounded => self.first(),
            Bound::Included(key) => self.first_at_least(key, Ordering::Equal),
            Bound::Excluded(key) => {
                self.first_at_least(key, Ordering::Greater)
            }
        }
    }

    fn upper_link(&self, bound: Bound<&A::Key>) -> Option<NonNull<Link>> {
        match bound {
            Bound::Unbounded => self.last(),
            Bound::Included(key) => self.last_at_most(key, Ordering::Equal),
            Bound::Excluded(key) => self.last_at_most(key, Ordering::Less),
        }
    }

    /// Returns the first link whose key compares to `key` as `at_least` or
    /// greater.
    fn first_at_least(
        &self,
        key: &A::Key,
        at_least: Ordering,
    ) -> Option<NonNull<Link>> {
        let mut found = None;
        let mut at = self.root;
        while let Some(current) = at {
            // SAFETY: a node stays live while it is on the tree.
            let (below, above) = unsafe { current.as_ref() }.children();
            let current_key = A::key(unsafe { A::node(current).as_ref() });
            let hit = current_key.cmp(key) >= at_least;
            found = select_unpredictable(hit, at, found);
            at = select_unpredictable(hit, below, above);
        }
        found
    }

    /// Returns the last link whose key compares to `key` as `at_most` or
    /// less.
    fn last_at_most(
        &self,
        key: &A::Key,
        at_most: Ordering,
    ) -> Option<NonNull<Link>> {
        let mut found = None;
        let mut at = self.root;
        while let Some(current) = at {
            // SAFETY: a node stays live while it is on the tree.
            let (below, above) = unsafe { current.as_ref() }.children();
            let current_key = A::key(unsafe { A::node(current).as_ref() });
            let hit = current_key.cmp(key) <= at_most;
            found = select_unpredictable(hit, at, found);
            at = select_unpredictable(hit, above, below);
        }
        found
    }

    /// Checks that the cached first and last links are the leftmost and
    /// the rightmost of the tree.
    ///
    /// # Panics
    ///
    /// In debug builds, when either end is not where the tree's shape puts
    /// it.
    #[cfg(debug_assertions)]
    fn check_ends(&self) {
        // SAFETY: the root is `None` or a link of this tree.
        unsafe {
            debug_assert!(
                self.min == balance::extreme(self.root, LEFT),
                "rb tree: the first node is not the leftmost",
            );
            debug_assert!(
                self.max == balance::extreme(self.root, RIGHT),
                "rb tree: the last node is not the rightmost",
            );
        }
    }

    /// Returns the link of `node`, after checking in debug builds that the
    /// adapter maps it back.
    ///
    /// # Panics
    ///
    /// In debug builds, when [`Adapter::node`] does not return `node` for
    /// the link [`Adapter::link`] returned.
    ///
    /// # Safety
    ///
    /// `node` must point at a live node.
    unsafe fn link_for(node: NonNull<A::Node>) -> NonNull<Link> {
        let link = unsafe { A::link(node) };
        debug_assert!(
            unsafe { A::node(link) } == node,
            "rb tree: the adapter does not map a link back to its node",
        );
        link
    }

    /// Unlinks the node whose link is `at`.
    ///
    /// # Panics
    ///
    /// In debug builds, when a neighbour of `at` does not point back at
    /// it, when `at` is on another tree, or when a cached end is wrong.
    ///
    /// # Safety
    ///
    /// `at` must be the link of a node on this tree.
    unsafe fn unlink(&mut self, at: NonNull<Link>) {
        unsafe { check(self.root, at) };
        #[cfg(debug_assertions)]
        self.check_ends();
        if self.max == Some(at) {
            self.max = unsafe { balance::step(at, LEFT) };
        }
        if self.min == Some(at) {
            self.min = unsafe { balance::step(at, RIGHT) };
        }
        unsafe { balance::erase(&mut self.root, at) };
        #[cfg(debug_assertions)]
        poison(unsafe { at.as_ref() });
    }
}

impl<A: Adapter> Default for RbTree<'_, A> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'head, A: Adapter> IntoIterator for &'head RbTree<'_, A> {
    type Item = &'head A::Node;
    type IntoIter = Iter<'head, A>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<A: Adapter> fmt::Debug for RbTree<'_, A> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RbTree")
            .field("root", &self.root)
            .field("first", &self.min)
            .field("last", &self.max)
            .finish()
    }
}

// SAFETY: the tree holds only pointers to nodes it hands out as `&Node`
// or `&'nodes mut Node`; `Node: Send + Sync` lets that access move threads.
unsafe impl<A: Adapter> Send for RbTree<'_, A> where A::Node: Send + Sync {}
// SAFETY: `&RbTree` only reads links and yields `&Node`, which
// `Node: Sync` lets several threads hold at once.
unsafe impl<A: Adapter> Sync for RbTree<'_, A> where A::Node: Send + Sync {}

/// Returns the tree's own pointer to the link `at`: the one the link
/// above it, or the root, holds, which carries the access the node was
/// inserted with.
///
/// # Panics
///
/// In debug builds, when a neighbour of `at` does not point back at it.
///
/// # Safety
///
/// `at` must be the link of a node on the tree rooted at `root`.
unsafe fn linked(root: Root, at: NonNull<Link>) -> NonNull<Link> {
    unsafe { check(root, at) };
    unsafe { at.as_ref() }.parent().map_or_else(
        || root.unwrap_or(at),
        |above| {
            let above_link = unsafe { above.as_ref() };
            above_link
                .slot(above_link.right.get() == Some(at))
                .get()
                .unwrap_or(at)
        },
    )
}

/// Checks, in debug builds, that the neighbours of the link `at` point
/// back at it.
///
/// # Panics
///
/// In debug builds, when a child's parent is not `at`, when `at` has no
/// parent and is not the root, when its parent has no child `at`, or when
/// climbing from `at` does not end at `root`: the link is on another tree.
///
/// # Safety
///
/// `at` must be the link of a node on the tree rooted at `root`.
unsafe fn check(root: Root, at: NonNull<Link>) {
    let link = unsafe { at.as_ref() };
    if let Some(left) = link.left.get() {
        debug_assert!(
            unsafe { left.as_ref() }.parent() == Some(at),
            "rb tree: the left child does not point back",
        );
    }
    if let Some(right) = link.right.get() {
        debug_assert!(
            unsafe { right.as_ref() }.parent() == Some(at),
            "rb tree: the right child does not point back",
        );
    }
    match link.parent() {
        None => debug_assert!(
            root == Some(at),
            "rb tree: a link with no parent is not the root",
        ),
        Some(above) => {
            let above_link = unsafe { above.as_ref() };
            debug_assert!(
                above_link.left.get() == Some(at)
                    || above_link.right.get() == Some(at),
                "rb tree: the parent does not point at its child",
            );
        }
    }
    // A loop, so gated: a condition inside `debug_assert!` is dead code in
    // a release build, but a walk before it is not.
    #[cfg(debug_assertions)]
    {
        let mut top = at;
        while let Some(above) = unsafe { top.as_ref() }.parent() {
            top = above;
        }
        assert!(root == Some(top), "rb tree: the link is not on this tree");
    }
}

/// Fills a leaving link with dangling words, so a stale use faults on a
/// recognisable address.
#[cfg(debug_assertions)]
fn poison(link: &Link) {
    link.parent_color.store(ptr::dangling_mut(), Relaxed);
    link.left.set(Some(NonNull::dangling()));
    link.right.set(Some(NonNull::dangling()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_items::{Item, RbItem, items, ptr, ptrs};
    use core::iter;

    type Tree<'nodes> = RbTree<'nodes, RbItem>;

    const _: () = assert!(size_of::<Tree<'_>>() == 3 * size_of::<usize>());

    /// Checks the invariants below `at` and returns its black height.
    fn check_below(
        at: Option<NonNull<Link>>,
        parent: Option<NonNull<Link>>,
        values: &mut Vec<u32>,
    ) -> usize {
        let Some(here) = at else {
            return 1;
        };
        // SAFETY: the tree's nodes are live for the test.
        let link = unsafe { here.as_ref() };
        assert_eq!(link.parent(), parent, "parent word");
        if !link.is_black() {
            for child in [link.left.get(), link.right.get()] {
                // SAFETY: as above.
                assert!(
                    child.is_none_or(|red| unsafe { red.as_ref() }.is_black()),
                    "a red link has a red child",
                );
            }
        }
        let below = check_below(link.left.get(), Some(here), values);
        // SAFETY: as above.
        values.push(RbItem::key(unsafe { RbItem::node(here).as_ref() }));
        let other = check_below(link.right.get(), Some(here), values);
        assert_eq!(below, other, "unequal black heights");
        below.saturating_add(usize::from(link.is_black()))
    }

    /// Checks every invariant of the tree and returns its values in
    /// order.
    fn validate(tree: &Tree<'_>) -> Vec<u32> {
        if let Some(root) = tree.root {
            // SAFETY: the tree's nodes are live for the test.
            assert!(unsafe { root.as_ref() }.is_black(), "red root");
        }
        // SAFETY: the tree's nodes are live for the test.
        unsafe {
            assert_eq!(tree.min, balance::extreme(tree.root, LEFT), "first");
            assert_eq!(tree.max, balance::extreme(tree.root, RIGHT), "last");
        }
        let mut values = Vec::new();
        let _height = check_below(tree.root, None, &mut values);
        assert!(values.is_sorted(), "not in order: {values:?}");
        let forward: Vec<u32> = tree.iter().map(|item| item.value).collect();
        assert_eq!(forward, values);
        let mut backward: Vec<u32> =
            tree.iter().rev().map(|item| item.value).collect();
        backward.reverse();
        assert_eq!(backward, values);
        values
    }

    fn insert_raw(tree: &mut Tree<'_>, node: NonNull<Item>) {
        // SAFETY: the nodes outlive the tree, nothing else reaches them,
        // and they are on no tree.
        unsafe { tree.insert_ptr(node) };
    }

    fn remove(tree: &mut Tree<'_>, node: NonNull<Item>) {
        // SAFETY: the node is on this tree.
        unsafe { tree.remove_ptr(node) };
    }

    /// Returns `count` node values `0..count`, as `u32`s.
    fn values_below(count: u32) -> Vec<u32> {
        (0..count).collect()
    }

    /// Continues every ordering of `rest` after `order`, and calls
    /// `each` with the complete ones.
    fn extend(
        order: &mut Vec<u32>,
        rest: &mut Vec<u32>,
        each: &mut impl FnMut(&[u32]),
    ) {
        if rest.is_empty() {
            each(order);
            return;
        }
        for at in 0..rest.len() {
            let next = rest.remove(at);
            order.push(next);
            extend(order, rest, each);
            let _popped: Option<u32> = order.pop();
            rest.insert(at, next);
        }
    }

    /// Calls `each` with every ordering of `0..count`.
    fn permutations(count: u32, each: &mut impl FnMut(&[u32])) {
        extend(&mut Vec::new(), &mut values_below(count), each);
    }

    /// Returns the node of value `value` among `raw`, which holds the
    /// nodes of `0..`.
    fn node_of(raw: &[NonNull<Item>], value: u32) -> NonNull<Item> {
        raw[usize::try_from(value).unwrap()]
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0.wrapping_shl(13);
            self.0 ^= self.0.wrapping_shr(7);
            self.0 ^= self.0.wrapping_shl(17);
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            let wide = u128::from(self.next())
                .wrapping_mul(u128::try_from(bound).unwrap());
            usize::try_from(wide.wrapping_shr(64)).unwrap()
        }

        fn value_below(&mut self, bound: u32) -> u32 {
            u32::try_from(self.below(usize::try_from(bound).unwrap())).unwrap()
        }
    }

    #[test]
    fn new_and_default_are_empty() {
        let tree = Tree::default();
        assert!(tree.is_empty());
        assert!(tree.front().is_none());
        assert!(tree.back().is_none());
        assert!(tree.iter().next().is_none());
        assert!(Link::default().parent().is_none());
        assert!(Link::new().left.get().is_none());
        assert_eq!(validate(&tree), Vec::<u32>::new());
    }

    #[test]
    fn insert_orders_ascending_descending_and_shuffled_runs() {
        for values in [
            values_below(100),
            values_below(100).into_iter().rev().collect(),
            (0..100)
                .map(|step: u32| {
                    step.wrapping_mul(37).checked_rem(101).unwrap()
                })
                .collect(),
        ] {
            let mut nodes = items(&values);
            let mut tree = Tree::new();
            for node in &mut nodes {
                tree.insert(node);
                drop(validate(&tree));
            }
            let mut sorted = values.clone();
            sorted.sort_unstable();
            assert_eq!(validate(&tree), sorted);
            assert_eq!(tree.front().unwrap().value, sorted[0]);
            assert_eq!(tree.back().unwrap().value, sorted[99]);
        }
    }

    #[test]
    fn every_insert_order_and_remove_order_of_up_to_six_nodes() {
        for count in 1..=6 {
            permutations(count, &mut |inserts| {
                permutations(count, &mut |removals| {
                    let mut nodes = items(&values_below(count));
                    let raw = ptrs(&mut nodes);
                    let mut tree = Tree::new();
                    for &value in inserts {
                        insert_raw(&mut tree, node_of(&raw, value));
                        drop(validate(&tree));
                    }
                    let mut left = values_below(count);
                    for &value in removals {
                        remove(&mut tree, node_of(&raw, value));
                        left.retain(|&kept| kept != value);
                        assert_eq!(validate(&tree), left);
                    }
                    assert!(tree.is_empty());
                });
            });
        }
    }

    #[test]
    fn every_insert_order_and_every_single_removal_of_eight_nodes() {
        const COUNT: u32 = 8;
        permutations(COUNT, &mut |inserts| {
            for gone in 0..COUNT {
                let mut nodes = items(&values_below(COUNT));
                let raw = ptrs(&mut nodes);
                let mut tree = Tree::new();
                for &value in inserts {
                    insert_raw(&mut tree, node_of(&raw, value));
                }
                remove(&mut tree, node_of(&raw, gone));
                let want: Vec<u32> =
                    (0..COUNT).filter(|&value| value != gone).collect();
                assert_eq!(validate(&tree), want);
            }
        });
    }

    #[test]
    fn a_random_model_with_duplicate_keys() {
        const KEYS: u32 = 24;
        const STEPS: usize = 20_000;
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let values: Vec<u32> = iter::repeat_with(|| rng.value_below(KEYS))
            .take(64)
            .collect();
        let mut nodes = items(&values);
        let mut free = ptrs(&mut nodes);
        // The expected in-order nodes, equal keys in insertion order.
        let mut model: Vec<NonNull<Item>> = Vec::new();
        let key_of = |node: NonNull<Item>| unsafe { node.as_ref() }.value;
        let mut tree = Tree::new();

        for _ in 0..STEPS {
            let choice = rng.below(13);
            if (choice < 5 || model.is_empty()) && !free.is_empty() {
                let node = free.swap_remove(rng.below(free.len()));
                insert_raw(&mut tree, node);
                let at = model
                    .partition_point(|&held| key_of(held) <= key_of(node));
                model.insert(at, node);
            } else if choice < 8 {
                let node = model.remove(rng.below(model.len()));
                remove(&mut tree, node);
                free.push(node);
            } else if choice < 10 && !free.is_empty() {
                // A node with the key of a random neighbour goes right
                // after or right before it, by cursor.
                let node = free.swap_remove(rng.below(free.len()));
                let at = rng.below(model.len());
                let key = key_of(model[at]);
                // SAFETY: the node is on no tree, and nothing else reaches it.
                unsafe { (*node.as_ptr()).value = key };
                // SAFETY: the neighbour is on this tree.
                let mut cursor =
                    unsafe { tree.cursor_mut_from_ptr(model[at]) };
                if rng.below(2) == 0 {
                    // SAFETY: the node outlives the tree and is on no tree.
                    unsafe { cursor.insert_after_ptr(node) };
                    model.insert(at.saturating_add(1), node);
                } else {
                    // SAFETY: as above.
                    unsafe { cursor.insert_before_ptr(node) };
                    model.insert(at, node);
                }
            } else {
                let probe = rng.value_below(KEYS);
                let at = model.partition_point(|&held| key_of(held) < probe);
                let mut cursor = tree.lower_bound_mut(Bound::Included(&probe));
                assert_eq!(cursor.current_ptr(), model.get(at).copied());
                if let Some(node) = cursor.remove_current() {
                    free.push(NonNull::from(node));
                    let _gone: NonNull<Item> = model.remove(at);
                    assert_eq!(cursor.current_ptr(), model.get(at).copied());
                }
            }
            let held: Vec<u32> =
                model.iter().map(|&node| key_of(node)).collect();
            assert_eq!(validate(&tree), held);
            let in_order: Vec<NonNull<Item>> = tree.iter().map(ptr).collect();
            assert_eq!(in_order, model);

            let probe = rng.value_below(KEYS + 2);
            let first = |keep: &dyn Fn(u32) -> bool| {
                model.iter().position(|&node| keep(key_of(node)))
            };
            let last = |keep: &dyn Fn(u32) -> bool| {
                model.iter().rposition(|&node| keep(key_of(node)))
            };
            let pick = |found: Option<usize>| found.map(|at| model[at]);
            let lower = |bound| tree.lower_bound(bound).current_ptr();
            let upper = |bound| tree.upper_bound(bound).current_ptr();
            assert_eq!(
                lower(Bound::Included(&probe)),
                pick(first(&|key| key >= probe))
            );
            assert_eq!(
                lower(Bound::Excluded(&probe)),
                pick(first(&|key| key > probe))
            );
            assert_eq!(
                upper(Bound::Included(&probe)),
                pick(last(&|key| key <= probe))
            );
            assert_eq!(
                upper(Bound::Excluded(&probe)),
                pick(last(&|key| key < probe))
            );
        }
    }

    #[test]
    fn bounds_name_the_first_and_last_of_equal_keys() {
        let mut nodes = items(&[10, 20, 20, 30]);
        let raw = ptrs(&mut nodes);
        let mut tree = Tree::new();
        for &node in &raw {
            insert_raw(&mut tree, node);
        }
        let lower = |bound| tree.lower_bound(bound).current_ptr();
        let upper = |bound| tree.upper_bound(bound).current_ptr();
        assert_eq!(lower(Bound::Included(&20)), Some(raw[1]));
        assert_eq!(lower(Bound::Excluded(&20)), Some(raw[3]));
        assert_eq!(lower(Bound::Included(&15)), Some(raw[1]));
        assert_eq!(lower(Bound::Included(&31)), None);
        assert_eq!(lower(Bound::Unbounded), Some(raw[0]));
        assert_eq!(upper(Bound::Included(&20)), Some(raw[2]));
        assert_eq!(upper(Bound::Excluded(&20)), Some(raw[0]));
        assert_eq!(upper(Bound::Included(&9)), None);
        assert_eq!(upper(Bound::Unbounded), Some(raw[3]));
        let mut cursor = tree.upper_bound_mut(Bound::Included(&25));
        assert_eq!(cursor.current_ptr(), Some(raw[2]));
        assert_eq!(cursor.remove_current().map(|node| node.value), Some(20));
        assert_eq!(cursor.current().unwrap().value, 30);
        assert_eq!(validate(&tree), [10, 20, 30]);
    }

    #[test]
    fn front_back_and_cursors_on_both_ends() {
        let mut nodes = items(&[2, 1, 3]);
        let mut tree = Tree::new();
        for node in &mut nodes {
            tree.insert(node);
        }
        assert_eq!(tree.cursor_front().current().unwrap().value, 1);
        assert_eq!(tree.cursor_back().current().unwrap().value, 3);
        assert_eq!(tree.cursor_front_mut().current().unwrap().value, 1);
        assert_eq!(tree.cursor_back_mut().current().unwrap().value, 3);
        let mut visited = Vec::new();
        for item in &tree {
            visited.push(item.value);
        }
        assert_eq!(visited, [1, 2, 3]);
    }

    #[test]
    fn cursor_walks_both_ways_through_the_ghost() {
        let mut nodes = items(&[1, 2, 3]);
        let mut tree = Tree::new();
        for node in &mut nodes {
            tree.insert(node);
        }
        let mut shared = tree.cursor_front();
        assert!(shared.peek_prev().is_none());
        assert_eq!(shared.peek_next().unwrap().value, 2);
        shared.move_prev();
        assert!(shared.current().is_none());
        assert!(shared.current_ptr().is_none());
        assert_eq!(shared.peek_prev().unwrap().value, 3);
        assert_eq!(shared.peek_next().unwrap().value, 1);
        shared.move_prev();
        assert_eq!(shared.current().unwrap().value, 3);
        shared.move_prev();
        assert_eq!(shared.current().unwrap().value, 2);
        shared.move_next();
        shared.move_next();
        assert!(shared.current().is_none());
        shared.move_next();
        assert_eq!(shared.current().unwrap().value, 1);

        let mut exclusive = tree.cursor_back_mut();
        assert!(exclusive.peek_next().is_none());
        assert_eq!(exclusive.peek_prev().unwrap().value, 2);
        exclusive.move_next();
        assert!(exclusive.current().is_none());
        assert_eq!(exclusive.peek_next().unwrap().value, 1);
        assert_eq!(exclusive.peek_prev().unwrap().value, 3);
        exclusive.move_next();
        assert_eq!(exclusive.current().unwrap().value, 1);
        exclusive.move_prev();
        exclusive.move_prev();
        assert_eq!(exclusive.current().unwrap().value, 3);
        assert!(exclusive.current_ptr().is_some());
    }

    #[test]
    fn cursors_on_an_empty_tree_rest_at_the_ghost() {
        let mut tree = Tree::new();
        let mut shared = tree.cursor_back();
        assert!(shared.current().is_none());
        assert!(shared.peek_prev().is_none());
        assert!(shared.peek_next().is_none());
        shared.move_prev();
        shared.move_next();
        assert!(shared.current().is_none());
        let mut exclusive = tree.cursor_front_mut();
        assert!(exclusive.remove_current().is_none());
        assert!(exclusive.current().is_none());
        assert!(tree.lower_bound(Bound::Included(&1)).current().is_none());
    }

    #[test]
    fn current_ptr_is_the_inserted_pointer_through_every_shape_of_tree() {
        let mut nodes = items(&values_below(32));
        let raw = ptrs(&mut nodes);
        let mut tree = Tree::new();
        for &node in &raw {
            insert_raw(&mut tree, node);
        }
        let mut cursor = tree.cursor_front();
        for &node in &raw {
            assert_eq!(cursor.current_ptr(), Some(node));
            cursor.move_next();
        }
        for &node in &raw {
            // SAFETY: the node is on the tree.
            let found = unsafe { tree.cursor_mut_from_ptr(node) };
            assert_eq!(found.current_ptr(), Some(node));
        }
    }

    #[test]
    fn remove_current_moves_to_the_next_node_and_hands_the_node_back() {
        let mut nodes = items(&[1, 2, 3, 4, 5]);
        let mut tree = Tree::new();
        for node in &mut nodes {
            tree.insert(node);
        }
        let mut cursor = tree.cursor_front_mut();
        let mut gone = Vec::new();
        while let Some(node) = cursor.remove_current() {
            gone.push(node.value);
        }
        assert_eq!(gone, [1, 2, 3, 4, 5]);
        assert!(tree.is_empty());
    }

    #[test]
    fn cleared_and_removed_nodes_insert_again() {
        let mut nodes = items(&[3, 1, 2]);
        let raw = ptrs(&mut nodes);
        let mut tree = Tree::new();
        for &node in &raw {
            insert_raw(&mut tree, node);
        }
        tree.clear();
        assert!(tree.is_empty());
        for &node in &raw {
            insert_raw(&mut tree, node);
        }
        remove(&mut tree, raw[0]);
        insert_raw(&mut tree, raw[0]);
        assert_eq!(validate(&tree), [1, 2, 3]);
    }

    #[test]
    fn iter_walks_both_ways_and_meets_in_the_middle() {
        let mut nodes = items(&[1, 2, 3, 4, 5]);
        let mut tree = Tree::new();
        for node in &mut nodes {
            tree.insert(node);
        }
        let mut walk = tree.iter();
        assert_eq!(walk.next().unwrap().value, 1);
        assert_eq!(walk.next_back().unwrap().value, 5);
        assert_eq!(walk.next().unwrap().value, 2);
        assert_eq!(walk.next_back().unwrap().value, 4);
        assert_eq!(walk.next().unwrap().value, 3);
        assert!(walk.next_back().is_none());
        assert!(walk.next().is_none());
        assert!(format!("{walk:?}").contains("Iter"));
    }

    #[test]
    fn debug_prints_link_pointers_only() {
        struct NoDebug {
            key: u32,
            link: Link,
        }
        crate::rb_tree::adapter!(
            NoDebugItem = NoDebug { link } key(u32) = |item| item.key
        );
        let mut node = NoDebug {
            key: 1,
            link: Link::new(),
        };
        let mut tree = RbTree::<NoDebugItem>::new();
        tree.insert(&mut node);
        assert!(format!("{tree:?}").contains("RbTree"));
        assert!(format!("{:?}", tree.cursor_front()).contains("Cursor"));
        assert!(
            format!("{:?}", tree.cursor_front_mut()).contains("CursorMut")
        );
        assert!(format!("{:?}", Link::new()).contains("Link"));
    }

    #[test]
    fn heads_and_links_cross_threads() {
        fn check<Shared>()
        where
            Shared: Send + Sync,
        {
        }
        check::<Tree<'static>>();
        check::<Link>();
    }

    #[test]
    #[cfg(debug_assertions)]
    fn removal_poisons_the_link_in_debug_builds() {
        let mut nodes = items(&[1]);
        let raw = ptrs(&mut nodes);
        let mut tree = Tree::new();
        insert_raw(&mut tree, raw[0]);
        remove(&mut tree, raw[0]);
        // SAFETY: the node left the tree and nothing else reaches it.
        let node = unsafe { raw[0].as_ref() };
        assert_eq!(node.rb.left.get(), Some(NonNull::dangling()));
        assert_eq!(node.rb.right.get(), Some(NonNull::dangling()));
        assert!(ptr::eq(node.rb.parent_word(), ptr::dangling_mut()));
    }

    /// Returns a three-node tree, 1 2 3, and the pointers to its nodes.
    #[cfg(debug_assertions)]
    fn three(nodes: &mut [Item]) -> (Tree<'static>, Vec<NonNull<Item>>) {
        let raw = ptrs(nodes);
        let mut tree = Tree::new();
        for &node in &raw {
            insert_raw(&mut tree, node);
        }
        (tree, raw)
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the left child does not point back")]
    fn remove_catches_a_left_child_with_another_parent() {
        let mut nodes = items(&[1, 2, 3]);
        let (mut tree, raw) = three(&mut nodes);
        // SAFETY: the node is live; the test corrupts its link.
        unsafe { raw[0].as_ref() }.rb.set_parent(None);
        remove(&mut tree, raw[1]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the right child does not point back")]
    fn remove_catches_a_right_child_with_another_parent() {
        let mut nodes = items(&[1, 2, 3]);
        let (mut tree, raw) = three(&mut nodes);
        // SAFETY: the node is live; the test corrupts its link.
        unsafe { raw[2].as_ref() }.rb.set_parent(None);
        remove(&mut tree, raw[1]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "a link with no parent is not the root")]
    fn remove_catches_a_link_with_no_parent_that_is_not_the_root() {
        let mut nodes = items(&[1, 2, 3]);
        let (mut tree, raw) = three(&mut nodes);
        // SAFETY: the node is live; the test corrupts its link.
        unsafe { raw[2].as_ref() }.rb.set_parent(None);
        remove(&mut tree, raw[2]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the parent does not point at its child")]
    fn remove_catches_a_parent_that_does_not_point_back() {
        let mut nodes = items(&[1, 2, 3]);
        let (mut tree, raw) = three(&mut nodes);
        // SAFETY: both nodes are live; the test corrupts a link.
        unsafe {
            let first = NonNull::from(&raw[0].as_ref().rb);
            raw[2].as_ref().rb.set_parent(Some(first));
        }
        remove(&mut tree, raw[2]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the parent does not point at its child")]
    fn insert_catches_a_corrupt_parent() {
        let mut nodes = items(&[1, 2, 3]);
        let raw = ptrs(&mut nodes);
        let mut tree = Tree::new();
        insert_raw(&mut tree, raw[0]);
        insert_raw(&mut tree, raw[1]);
        // SAFETY: both nodes are live; the test corrupts a link.
        unsafe {
            let stray = NonNull::from(&raw[2].as_ref().rb);
            raw[1].as_ref().rb.set_parent(Some(stray));
        }
        insert_raw(&mut tree, raw[2]);
    }

    /// Returns `count` items whose keys are `2, 4, ..` and the pointers
    /// to them, then room for new ones: the keys in between are free.
    fn spaced(count: u32, extra: usize) -> Vec<Item> {
        let mut values: Vec<u32> =
            (1..=count).map(|step| step.wrapping_mul(2)).collect();
        values.extend(iter::repeat_n(0, extra));
        items(&values)
    }

    #[test]
    fn hinted_inserts_build_ascending_and_descending_trees() {
        let mut ascending = items(&values_below(100));
        let mut up = Tree::new();
        for node in &mut ascending {
            up.cursor_back_mut().insert_after(node);
            drop(validate(&up));
        }
        assert_eq!(validate(&up), values_below(100));

        let mut descending: Vec<Item> =
            items(&values_below(100)).into_iter().rev().collect();
        let mut down = Tree::new();
        for node in &mut descending {
            down.cursor_front_mut().insert_before(node);
            drop(validate(&down));
        }
        assert_eq!(validate(&down), values_below(100));
    }

    #[test]
    fn hinted_inserts_at_the_ghost_go_to_the_ends() {
        let [mut middle, mut low, mut mid_high, mut high] =
            [20, 10, 30, 40].map(Item::new);
        let mut tree = Tree::new();
        tree.insert(&mut middle);
        // The ghost of a non-empty tree: after it is the front, before it
        // the back.
        let mut ghost = tree.cursor_front_mut();
        ghost.move_prev();
        ghost.insert_after(&mut low);
        ghost.insert_before(&mut mid_high);
        ghost.insert_before(&mut high);
        assert!(ghost.current().is_none());
        assert_eq!(validate(&tree), [10, 20, 30, 40]);
    }

    #[test]
    fn a_hinted_insert_goes_after_and_before_every_node_of_every_shape() {
        for count in 1..=6 {
            permutations(count, &mut |inserts| {
                for at in 0..count {
                    for after in [false, true] {
                        let mut nodes = spaced(count, 1);
                        let raw = ptrs(&mut nodes);
                        let mut tree = Tree::new();
                        for &value in inserts {
                            insert_raw(&mut tree, node_of(&raw, value));
                        }
                        let base = node_of(&raw, at);
                        let extra = node_of(&raw, count);
                        let key = if after { 2 * at + 3 } else { 2 * at + 1 };
                        // SAFETY: the extra node is on no tree.
                        unsafe { (*extra.as_ptr()).value = key };
                        // SAFETY: the base node is on this tree.
                        let mut cursor =
                            unsafe { tree.cursor_mut_from_ptr(base) };
                        if after {
                            // SAFETY: the extra node outlives the tree.
                            unsafe { cursor.insert_after_ptr(extra) };
                        } else {
                            // SAFETY: as above.
                            unsafe { cursor.insert_before_ptr(extra) };
                        }
                        assert_eq!(cursor.current_ptr(), Some(base));
                        let mut want: Vec<u32> = (1..=count)
                            .map(|step| step.wrapping_mul(2))
                            .collect();
                        want.push(key);
                        want.sort_unstable();
                        assert_eq!(validate(&tree), want);
                    }
                }
            });
        }
    }

    /// Returns a two-node tree, 10 and 20, and the pointers to its nodes.
    #[cfg(debug_assertions)]
    fn pair(nodes: &mut [Item]) -> (Tree<'static>, Vec<NonNull<Item>>) {
        let raw = ptrs(nodes);
        let mut tree = Tree::new();
        for &node in &raw[..2] {
            insert_raw(&mut tree, node);
        }
        (tree, raw)
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "inserted below its predecessor")]
    fn insert_after_catches_a_key_below_the_cursor() {
        let mut nodes = items(&[10, 20, 5]);
        let (mut tree, raw) = pair(&mut nodes);
        // SAFETY: the node is on this tree, and the new one on none.
        unsafe {
            tree.cursor_mut_from_ptr(raw[1]).insert_after_ptr(raw[2]);
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "inserted above its successor")]
    fn insert_after_catches_a_key_above_the_next_node() {
        let mut nodes = items(&[10, 20, 30]);
        let (mut tree, raw) = pair(&mut nodes);
        // SAFETY: as above.
        unsafe {
            tree.cursor_mut_from_ptr(raw[0]).insert_after_ptr(raw[2]);
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "inserted below its predecessor")]
    fn insert_before_catches_a_key_below_the_previous_node() {
        let mut nodes = items(&[10, 20, 5]);
        let (mut tree, raw) = pair(&mut nodes);
        // SAFETY: as above.
        unsafe {
            tree.cursor_mut_from_ptr(raw[1]).insert_before_ptr(raw[2]);
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "inserted above its successor")]
    fn insert_before_catches_a_key_above_the_cursor() {
        let mut nodes = items(&[10, 20, 15]);
        let (mut tree, raw) = pair(&mut nodes);
        // SAFETY: as above.
        unsafe {
            tree.cursor_mut_from_ptr(raw[0]).insert_before_ptr(raw[2]);
        }
    }

    #[test]
    fn the_head_inserts_go_after_and_before_every_node_of_every_shape() {
        for count in 1..=5 {
            permutations(count, &mut |inserts| {
                for at in 0..count {
                    for after in [false, true] {
                        let mut nodes = spaced(count, 1);
                        let raw = ptrs(&mut nodes);
                        let mut tree = Tree::new();
                        for &value in inserts {
                            insert_raw(&mut tree, node_of(&raw, value));
                        }
                        let base = node_of(&raw, at);
                        let extra = node_of(&raw, count);
                        let key = if after { 2 * at + 3 } else { 2 * at + 1 };
                        // SAFETY: the extra node is on no tree.
                        unsafe { (*extra.as_ptr()).value = key };
                        // SAFETY: the base node is on this tree, the extra
                        // node outlives it, and the key is in order.
                        unsafe {
                            if after {
                                tree.insert_after_ptr(base, extra);
                            } else {
                                tree.insert_before_ptr(base, extra);
                            }
                        }
                        let mut want: Vec<u32> = (1..=count)
                            .map(|step| step.wrapping_mul(2))
                            .collect();
                        want.push(key);
                        want.sort_unstable();
                        assert_eq!(validate(&tree), want);
                    }
                }
            });
        }
    }

    #[test]
    fn keys_in_order_join_under_the_ends_and_keep_them_current() {
        // Past the last, below the first, equal to the last: no search.
        let mut nodes = items(&[5, 9, 1, 9, 0, 12]);
        let raw = ptrs(&mut nodes);
        let mut tree = Tree::new();
        for (step, &node) in raw.iter().enumerate() {
            insert_raw(&mut tree, node);
            drop(validate(&tree));
            assert_eq!(tree.front().unwrap().value, [5, 5, 1, 1, 0, 0][step]);
            assert_eq!(tree.back().unwrap().value, [5, 9, 9, 9, 9, 12][step]);
        }
        // The equal 9 went after the first 9.
        let nines: Vec<NonNull<Item>> = tree
            .iter()
            .filter(|item| item.value == 9)
            .map(ptr)
            .collect();
        assert_eq!(nines, [raw[1], raw[3]]);
        // Removing the ends moves them to the neighbours.
        remove(&mut tree, raw[5]);
        assert_eq!(tree.back().unwrap().value, 9);
        remove(&mut tree, raw[4]);
        assert_eq!(tree.front().unwrap().value, 1);
        for &node in &raw[..4] {
            remove(&mut tree, node);
            drop(validate(&tree));
        }
        assert!(tree.front().is_none() && tree.back().is_none());
    }

    /// Returns a tree of the first `count` nodes of `nodes`, in order, and
    /// the pointers to all of them.
    #[cfg(debug_assertions)]
    fn first_of(
        nodes: &mut [Item],
        count: usize,
    ) -> (Tree<'static>, Vec<NonNull<Item>>) {
        let raw = ptrs(nodes);
        let mut tree = Tree::new();
        for &node in &raw[..count] {
            insert_raw(&mut tree, node);
        }
        (tree, raw)
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the link is not on this tree")]
    fn remove_catches_a_node_of_another_tree() {
        let mut ours = items(&[1, 2, 3]);
        let mut theirs = items(&[4, 5, 6]);
        let (mut tree, _raw) = first_of(&mut ours, 3);
        let (_other, other_raw) = first_of(&mut theirs, 3);
        // The node is a valid member of its own tree, so only the climb to
        // the root can tell.
        remove(&mut tree, other_raw[0]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the link is not on this tree")]
    fn insert_after_ptr_catches_a_predecessor_of_another_tree() {
        let mut ours = items(&[1, 2, 3, 9]);
        let mut theirs = items(&[4, 5, 6]);
        let (mut tree, raw) = first_of(&mut ours, 3);
        let (_other, other_raw) = first_of(&mut theirs, 3);
        // SAFETY: the new node is on no tree; the predecessor is not on
        // this one, which the check reports.
        unsafe { tree.insert_after_ptr(other_raw[0], raw[3]) };
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the slot to link into is not empty")]
    fn link_below_catches_a_taken_slot() {
        let mut nodes = items(&[1, 2, 3, 4]);
        let (mut tree, raw) = first_of(&mut nodes, 3);
        // SAFETY: the nodes are live; the slot below the root's right is
        // taken, which the check reports.
        unsafe {
            let root = tree.root.unwrap();
            let link = NonNull::from(&raw[3].as_ref().rb);
            tree.link_below(Some(root), RIGHT, link);
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "joins as the root of a tree that is not empty")]
    fn link_below_catches_a_second_root() {
        let mut nodes = items(&[1, 2, 3, 4]);
        let (mut tree, raw) = first_of(&mut nodes, 3);
        // SAFETY: the node is live; there is no parent, but the tree holds
        // nodes, which the check reports.
        unsafe {
            let link = NonNull::from(&raw[3].as_ref().rb);
            tree.link_below(None, LEFT, link);
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the first node is not the leftmost")]
    fn remove_catches_a_wrong_first_node() {
        let mut nodes = items(&[1, 2, 3]);
        let (mut tree, raw) = first_of(&mut nodes, 3);
        // SAFETY: the node is live; the test corrupts the head.
        tree.min = Some(NonNull::from(unsafe { &raw[1].as_ref().rb }));
        remove(&mut tree, raw[2]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the last node is not the rightmost")]
    fn insert_catches_a_wrong_last_node() {
        let mut nodes = items(&[1, 2, 3, 4]);
        let (mut tree, raw) = first_of(&mut nodes, 3);
        // SAFETY: the node is live; the test corrupts the head.
        tree.max = Some(NonNull::from(unsafe { &raw[1].as_ref().rb }));
        insert_raw(&mut tree, raw[3]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the root is not black after an insert")]
    fn insert_catches_a_red_root() {
        let mut nodes = items(&[1, 2, 3, 4]);
        let (mut tree, raw) = first_of(&mut nodes, 3);
        // The leaves go black, so the fix-up stops at the new node's black
        // parent and leaves the red root alone.
        // SAFETY: the nodes are live; the test corrupts their colours.
        unsafe {
            raw[1].as_ref().rb.set_red();
            raw[0].as_ref().rb.set_black();
            raw[2].as_ref().rb.set_black();
        }
        insert_raw(&mut tree, raw[3]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the root is not black after a removal")]
    fn remove_catches_a_red_root() {
        let mut nodes = items(&[1, 2, 3]);
        let (mut tree, raw) = first_of(&mut nodes, 3);
        // A red leaf leaves without a fix-up, so nothing repairs the root.
        // SAFETY: the node is live; the test corrupts its colour.
        unsafe { raw[1].as_ref().rb.set_red() };
        remove(&mut tree, raw[0]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "the adapter does not map a link back")]
    fn insert_catches_an_adapter_that_forgets_the_offset() {
        #[repr(C)]
        struct Bad {
            value: u32,
            link: Link,
        }
        #[derive(Debug)]
        enum BadAdapter {}
        // SAFETY: `link` is the field's address, but `node` does not step
        // back by its offset: the test relies on the check reporting it.
        unsafe impl Adapter for BadAdapter {
            type Node = Bad;
            type Key = u32;

            unsafe fn link(node: NonNull<Bad>) -> NonNull<Link> {
                unsafe { NonNull::from(&mut (*node.as_ptr()).link) }
            }

            unsafe fn node(link: NonNull<Link>) -> NonNull<Bad> {
                link.cast()
            }

            fn key(node: &Bad) -> u32 {
                node.value
            }
        }
        let mut bad = Bad {
            value: 1,
            link: Link::new(),
        };
        assert_eq!(BadAdapter::key(&bad), 1);
        let mut tree = RbTree::<BadAdapter>::new();
        tree.insert(&mut bad);
    }
}
