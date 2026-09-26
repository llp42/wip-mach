// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The lock-order graph: the lock classes seen so far, and for each the
//! classes acquired while one of its locks was held.
//!
//! Readers need no lock: a class, once added, and an edge, once set, are
//! never taken back, so a reader that finds one may trust it.  Only
//! adding a class or an edge takes the graph lock, which the caller holds
//! across the re-check and the change.

// `core`'s atomics, not `crate::sync`'s: the checker is compiled only
// with debug assertions, and loom runs in release, so loom never models
// it.
use super::Class;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

/// How many lock classes the graph can tell apart.
pub(super) const CLASSES: usize = 512;

const WORDS: usize = CLASSES / u64::BITS as usize;

/// Slots in the class index: twice [`CLASSES`], so a probe always meets
/// an empty slot.
const SLOTS: usize = 2 * CLASSES;

/// A set of classes, by node.
type Set = [u64; WORDS];

const EMPTY: Set = [0; WORDS];

/// The order graph.
///
/// A node is a class's slot in `classes`; an edge `a -> b`, bit `b` of
/// `after[a]`, records a lock of class `b` acquired while one of class
/// `a` was held.  The graph stays acyclic: an edge that would close a
/// cycle is refused.
///
/// `index` is an open-addressed hash of the classes on their line and
/// column: each slot holds a node plus one, or zero while empty.  A slot
/// is published, with release, only once its node's class is stored.
pub(super) struct Graph {
    classes: [AtomicPtr<Location>; CLASSES],
    /// How many nodes are in use; changed only under the graph lock.
    len: AtomicUsize,
    index: [AtomicUsize; SLOTS],
    after: [[AtomicU64; WORDS]; CLASSES],
}

type Location = core::panic::Location<'static>;

/// Returns whether two lock-class sites are the same.
///
/// Compared by value, since a site's `Location` may be emitted more than
/// once, as by each codegen unit that builds a lock there; the line comes
/// first, as the cheapest to tell apart.
fn same(a: Class, b: Class) -> bool {
    let site = |class: Class| (class.line(), class.column(), class.file());
    site(a) == site(b)
}

/// Returns the index slot where the probe for `class` starts.
fn home(class: Class) -> usize {
    let key = (u64::from(class.line()) << 32) | u64::from(class.column());
    let hash = key.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    // The top bits, which mix every bit of the key.
    usize::try_from(hash >> (u64::BITS - SLOTS.trailing_zeros()))
        .unwrap_or_default()
}

const fn contains(set: &Set, node: usize) -> bool {
    set[node / 64] & (1 << (node % 64)) != 0
}

/// Returns the nodes in `set`.
fn nodes(set: Set) -> impl Iterator<Item = usize> {
    set.into_iter().enumerate().flat_map(|(word, mut bits)| {
        core::iter::from_fn(move || {
            let bit = bits.trailing_zeros() as usize;
            bits &= bits.wrapping_sub(1);
            (bit < 64).then_some(word * 64 + bit)
        })
    })
}

impl Graph {
    /// The graph with no classes.
    #[allow(
        clippy::declare_interior_mutable_const,
        clippy::large_stack_arrays,
        reason = "only the one static is built from it, at compile time"
    )]
    pub(super) const EMPTY: Self = Self {
        classes: [const { AtomicPtr::new(ptr::null_mut()) }; CLASSES],
        len: AtomicUsize::new(0),
        index: [const { AtomicUsize::new(0) }; SLOTS],
        after: [const { [const { AtomicU64::new(0) }; WORDS] }; CLASSES],
    };

    /// Looks `class` up: returns its node, or else the empty index slot
    /// where it would go.
    fn probe(&self, class: Class) -> Result<usize, usize> {
        let mut slot = home(class);
        loop {
            // Acquire pairs with the release in `add`, so the node's
            // class is visible.
            let Some(node) =
                self.index[slot].load(Ordering::Acquire).checked_sub(1)
            else {
                return Err(slot);
            };
            let seen = self.classes[node].load(Ordering::Relaxed);
            // SAFETY: a published node's class came from a `Class`, a
            // `&'static Location`.
            if same(unsafe { &*seen }, class) {
                return Ok(node);
            }
            slot = (slot + 1) % SLOTS;
        }
    }

    /// Returns `class`'s node, if it has one.
    pub(super) fn find(&self, class: Class) -> Option<usize> {
        self.probe(class).ok()
    }

    /// Returns `class`'s node, adding it if it is new, or `None` if the
    /// graph has no room for it.
    ///
    /// The caller holds the graph lock.
    pub(super) fn add(&self, class: Class) -> Option<usize> {
        self.probe(class).map_or_else(
            |slot| {
                let node = self.len.load(Ordering::Relaxed);
                self.classes
                    .get(node)?
                    .store(ptr::from_ref(class).cast_mut(), Ordering::Relaxed);
                self.len.store(node + 1, Ordering::Relaxed);
                self.index[slot].store(node + 1, Ordering::Release);
                Some(node)
            },
            Some,
        )
    }

    /// Returns whether a lock of node `taken` has been acquired while one
    /// of node `held` was held.
    pub(super) fn has(&self, held: usize, taken: usize) -> bool {
        self.after[held][taken / 64].load(Ordering::Relaxed)
            & (1 << (taken % 64))
            != 0
    }

    /// Records a lock of node `taken` acquired while one of node `held`
    /// was held; the two differ, and the edge is new.
    ///
    /// Returns `false`, and records nothing, if `taken` already reaches
    /// `held`, so that the new edge would close a cycle.  The caller holds
    /// the graph lock.
    pub(super) fn order(&self, held: usize, taken: usize) -> bool {
        if self.reaches(taken, held) {
            return false;
        }
        let _ = self.after[held][taken / 64]
            .fetch_or(1 << (taken % 64), Ordering::Relaxed);
        true
    }

    /// Returns the edges out of `node`.
    fn row(&self, node: usize) -> Set {
        core::array::from_fn(|word| {
            self.after[node][word].load(Ordering::Relaxed)
        })
    }

    /// Returns whether a path of one edge or more leads from `from` to
    /// `to`.  Exact only under the graph lock, which every edge is set
    /// under.
    fn reaches(&self, from: usize, to: usize) -> bool {
        let mut seen = self.row(from);
        let mut frontier = seen;
        while frontier != EMPTY {
            if contains(&frontier, to) {
                return true;
            }
            let mut next = EMPTY;
            for node in nodes(frontier) {
                for (word, after) in next.iter_mut().zip(self.row(node)) {
                    *word |= after;
                }
            }
            for (word, seen) in next.iter_mut().zip(&mut seen) {
                *word &= !*seen;
                *seen |= *word;
            }
            frontier = next;
        }
        false
    }
}
