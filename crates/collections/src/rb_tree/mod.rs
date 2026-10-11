// SPDX-License-Identifier: GPL-2.0-or-later
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
