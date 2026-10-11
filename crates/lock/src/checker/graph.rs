// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The lock-kind order graph: the kinds seen so far, and for each the
//! kinds acquired while one of its locks was held.
//!
//! Readers need no lock: a kind, once added, and an edge, once set, are
//! never taken back, so a reader that finds one may trust it.  Only
//! adding a kind or an edge takes the graph lock, which the caller holds
//! across the re-check and the change.

use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

/// How many lock names the graph can tell apart.
pub(super) const KINDS: usize = 128;

const WORDS: usize = KINDS / u64::BITS as usize;

/// Slots in the kind index: twice [`KINDS`], so a probe always meets an
/// empty slot.
const SLOTS: usize = 2 * KINDS;

/// A set of kinds, by node.
type Set = [u64; WORDS];

const EMPTY: Set = [0; WORDS];

/// One kind's name, held as the two words of a `&'static str`.
///
/// The bytes live in the binary, so they outlive the graph; the pointer is
/// the last word written and the first read, so a reader that sees one
/// sees the length it goes with.
struct Name {
    bytes: AtomicPtr<u8>,
    len: AtomicUsize,
}

impl Name {
    const fn new() -> Self {
        Self {
            bytes: AtomicPtr::new(ptr::null_mut()),
            len: AtomicUsize::new(0),
        }
    }

    /// Publishes `name`.
    fn set(&self, name: &'static str) {
        self.len.store(name.len(), Ordering::Relaxed);
        self.bytes
            .store(name.as_ptr().cast_mut(), Ordering::Release);
    }

    /// Returns the name, or `None` while the slot is empty.
    fn get(&self) -> Option<&'static str> {
        // Acquire pairs with the release in `set`, so the length is
        // visible with the pointer.
        let bytes = self.bytes.load(Ordering::Acquire);
        if bytes.is_null() {
            return None;
        }
        let len = self.len.load(Ordering::Relaxed);
        // SAFETY: `set` stored a pointer and length taken from a
        // `&'static str`, so they name that string's bytes, which live in
        // the binary and are valid UTF-8.
        Some(unsafe {
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(
                bytes, len,
            ))
        })
    }
}

/// The FNV-1a hash of a name's bytes.
fn hash(name: &str) -> usize {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
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

/// The order graph.
///
/// A node is a kind's slot in `names`; an edge `a -> b`, bit `b` of
/// `after[a]`, records a lock of kind `b` acquired while one of kind `a`
/// was held.  The graph stays acyclic: an edge that would close a cycle is
/// refused.
///
/// Two locks of one kind are one node, so the graph says nothing about
/// them; holding two at once is a fault only when it is the same lock
/// twice, which the record keyed on the address catches.
///
/// `index` is an open-addressed hash of the kind names: each slot holds a
/// node plus one, or zero while empty.  A slot is published, with release,
/// only once its node's name is stored.
pub(super) struct Graph {
    names: [Name; KINDS],
    /// How many nodes are in use; changed only under the graph lock.
    len: AtomicUsize,
    index: [AtomicUsize; SLOTS],
    after: [[AtomicU64; WORDS]; KINDS],
}

impl Graph {
    /// The graph with no kinds.
    #[allow(
        clippy::declare_interior_mutable_const,
        clippy::large_stack_arrays,
        reason = "only the one static is built from it, at compile time"
    )]
    pub(super) const EMPTY: Self = Self {
        names: [const { Name::new() }; KINDS],
        len: AtomicUsize::new(0),
        index: [const { AtomicUsize::new(0) }; SLOTS],
        after: [const { [const { AtomicU64::new(0) }; WORDS] }; KINDS],
    };

    /// Looks `name` up: returns its node, or else the empty index slot
    /// where it would go.
    fn probe(&self, name: &str) -> Result<usize, usize> {
        let mut slot = hash(name);
        loop {
            // Acquire pairs with the release in `add`, so the node's name
            // is visible.
            let Some(node) =
                self.index[slot].load(Ordering::Acquire).checked_sub(1)
            else {
                return Err(slot);
            };
            debug_assert!(
                self.names[node].get().is_some(),
                "a published kind slot holds no name",
            );
            if self.names[node].get() == Some(name) {
                return Ok(node);
            }
            slot = (slot + 1) % SLOTS;
        }
    }

    /// Returns the node of `name`, if it has one.
    pub(super) fn find(&self, name: &str) -> Option<usize> {
        self.probe(name).ok()
    }

    /// Returns the node of `name`, adding it if it is new, or `None` if
    /// the graph has no room for it.
    ///
    /// The caller holds the graph lock.
    pub(super) fn add(&self, name: &'static str) -> Option<usize> {
        self.probe(name).map_or_else(
            |slot| {
                let node = self.len.load(Ordering::Relaxed);
                self.names.get(node)?.set(name);
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
