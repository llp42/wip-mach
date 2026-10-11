// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The per-thread record of held locks and irq-quiet sections.

use super::Kind;
use core::cell::Cell;
use core::sync::atomic::{AtomicUsize, Ordering, compiler_fence};

/// How many locks one thread may hold at once.
const CAPACITY: usize = 32;

/// One held lock.
#[derive(Clone, Copy, Debug)]
pub(super) struct Held {
    /// The lock's address, the identity a release names.
    pub(super) lock: usize,
    pub(super) kind: Kind,
    /// The lock's kind: the type path that is its node in the order graph.
    pub(super) name: &'static str,
}

/// One slot of the stack: a hold, or nothing.
///
/// An interrupt handler may read the slot between any two of the
/// interrupted thread's stores to it.  So the lock address, zero in an
/// empty slot, is the last store that fills the slot and the first that
/// empties it: the handler sees the slot empty or whole, never one hold's
/// kind beside another's lock.
#[derive(Debug)]
struct Slot {
    lock: AtomicUsize,
    kind: Cell<Kind>,
    name: Cell<&'static str>,
}

impl Slot {
    /// Returns an empty slot.
    const fn new() -> Self {
        Self {
            lock: AtomicUsize::new(0),
            kind: Cell::new(Kind::IrqSpin),
            name: Cell::new(""),
        }
    }

    /// Returns the hold, or `None` if the slot is empty.
    fn get(&self) -> Option<Held> {
        let lock = self.lock.load(Ordering::Acquire);
        if lock == 0 {
            return None;
        }
        Some(Held {
            lock,
            kind: self.kind.get(),
            name: self.name.get(),
        })
    }

    /// Returns whether the slot holds `lock`.
    fn holds(&self, lock: usize) -> bool {
        self.lock.load(Ordering::Acquire) == lock
    }

    /// Fills the slot with `held`, emptying it first.
    fn set(&self, held: Held) {
        self.clear();
        self.kind.set(held.kind);
        self.name.set(held.name);
        self.lock.store(held.lock, Ordering::Release);
    }

    /// Empties the slot.  The stores after this one stay after it.
    fn clear(&self) {
        self.lock.store(0, Ordering::Relaxed);
        compiler_fence(Ordering::SeqCst);
    }
}

/// The locks and irq-quiet sections one thread holds, for the checker.
///
/// The platform keeps one per thread and hands it out through
/// [`Platform::held_locks`](crate::Platform::held_locks).  It belongs to
/// that thread alone, so it is built of `Cell`s: `Send`, not `Sync`.  An
/// interrupt handler on the thread's CPU may share it, since each update
/// is ordered so that a handler which leaves its locks and sections
/// balanced leaves the record as it found it, and sees no slot half
/// written.
///
/// Holds at most 32 locks; a thread that takes more panics.
#[derive(Debug)]
pub struct HeldLocks {
    /// A stack of the held locks, `len` deep, the latest on top; the slots
    /// above it are empty.
    stack: [Slot; CAPACITY],
    len: Cell<usize>,
    irq_quiet: Cell<usize>,
}

impl HeldLocks {
    /// Returns an empty record.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stack: [const { Slot::new() }; CAPACITY],
            len: Cell::new(0),
            irq_quiet: Cell::new(0),
        }
    }

    /// Returns the held locks, oldest first.
    pub(super) fn iter(&self) -> impl Iterator<Item = Held> + '_ {
        self.stack[..self.len.get()].iter().filter_map(Slot::get)
    }

    /// Returns the stack slot of the latest hold of `lock`.
    fn position(&self, lock: usize) -> Option<usize> {
        self.stack[..self.len.get()]
            .iter()
            .rposition(|slot| slot.holds(lock))
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
        self.stack[len].set(held);
    }

    /// Removes the latest hold of `lock`, wherever it is in the stack,
    /// and returns whether there was one, held as `kind`.
    pub(super) fn remove(&self, lock: usize, kind: Kind) -> bool {
        let Some(at) = self.position(lock) else {
            return false;
        };
        if !self.stack[at].get().is_some_and(|held| held.kind == kind) {
            return false;
        }
        let len = self.len.get();
        for slot in at..len - 1 {
            match self.stack[slot + 1].get() {
                Some(held) => self.stack[slot].set(held),
                None => self.stack[slot].clear(),
            }
        }
        // Empties the old top before shrinking, so a nested handler never
        // pushes into a slot still being moved.
        self.stack[len - 1].clear();
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
                slot.kind.set(Kind::Read);
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
