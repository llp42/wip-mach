// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The per-thread record of held locks and irq-quiet sections.

use super::{Class, Kind};
use core::cell::Cell;

/// How many locks one thread may hold at once.
const CAPACITY: usize = 32;

/// One held lock.
#[derive(Clone, Copy, Debug)]
pub(super) struct Held {
    /// The lock's address, the identity a release names.
    pub(super) lock: usize,
    pub(super) class: Class,
    /// `class`'s slot in the order graph.
    pub(super) node: usize,
    pub(super) kind: Kind,
}

/// The locks and irq-quiet sections one thread holds, for the order
/// checker.
///
/// The platform keeps one per thread and hands it out through
/// [`Platform::held_locks`](crate::Platform::held_locks).  It belongs to
/// that thread alone, so it is built of plain `Cell`s: `Send`, not
/// `Sync`.  An interrupt handler on the thread's CPU may share it, since
/// each update is ordered so that a handler which leaves its locks and
/// sections balanced leaves the record as it found it.
///
/// Holds at most 32 locks; a thread that takes more panics.
#[derive(Debug)]
pub struct HeldLocks {
    /// A stack of the held locks, `len` deep, the latest on top.
    stack: [Cell<Option<Held>>; CAPACITY],
    len: Cell<usize>,
    irq_quiet: Cell<usize>,
}

impl HeldLocks {
    /// Returns an empty record.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stack: [const { Cell::new(None) }; CAPACITY],
            len: Cell::new(0),
            irq_quiet: Cell::new(0),
        }
    }

    /// Returns the held locks, oldest first.
    pub(super) fn iter(&self) -> impl Iterator<Item = Held> + '_ {
        self.stack[..self.len.get()].iter().filter_map(Cell::get)
    }

    /// Returns the stack slot of the latest hold of `lock`.
    fn position(&self, lock: usize) -> Option<usize> {
        self.stack[..self.len.get()]
            .iter()
            .rposition(|slot| slot.get().is_some_and(|held| held.lock == lock))
    }

    /// Returns the latest hold of `lock`.
    pub(super) fn find(&self, lock: usize) -> Option<Held> {
        self.stack[self.position(lock)?].get()
    }

    /// Pushes a hold.
    ///
    /// # Panics
    ///
    /// Panics if the thread already holds 32 locks.
    pub(super) fn push(&self, held: Held) {
        let len = self.len.get();
        assert!(
            len < CAPACITY,
            "held-lock stack overflow: a thread may hold at most {CAPACITY} \
             locks",
        );
        // Claims the slot before filling it, so a nested handler pushes
        // above it.
        self.len.set(len + 1);
        self.stack[len].set(Some(held));
    }

    /// Removes the latest hold of `lock`, wherever it is in the stack,
    /// and returns whether there was one, held as `kind`.
    pub(super) fn remove(&self, lock: usize, kind: Kind) -> bool {
        let Some(at) = self.position(lock) else {
            return false;
        };
        if !matches!(self.stack[at].get(), Some(held) if held.kind == kind) {
            return false;
        }
        let len = self.len.get();
        for slot in at..len - 1 {
            self.stack[slot].set(self.stack[slot + 1].get());
        }
        // Empties the old top before shrinking, so a nested handler never
        // pushes into a slot still being moved, nor sees a stale hold in
        // the slot a push has claimed but not yet filled.
        self.stack[len - 1].set(None);
        self.len.set(len - 1);
        true
    }

    /// Turns the latest hold of `lock` from a write hold into a read
    /// hold, and returns whether it was a write hold.
    pub(super) fn downgrade(&self, lock: usize) -> bool {
        let Some(at) = self.position(lock) else {
            return false;
        };
        let slot = &self.stack[at];
        match slot.get() {
            Some(held) if held.kind == Kind::Write => {
                slot.set(Some(Held {
                    kind: Kind::Read,
                    ..held
                }));
                true
            }
            _ => false,
        }
    }

    /// Returns how many irq-quiet sections the thread is in.
    pub(super) const fn irq_quiet(&self) -> &Cell<usize> {
        &self.irq_quiet
    }
}

impl Default for HeldLocks {
    fn default() -> Self {
        Self::new()
    }
}
