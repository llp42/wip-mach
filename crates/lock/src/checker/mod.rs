// SPDX-License-Identifier: GPL-2.0-or-later
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The lock-order checker, in debug builds only.
//!
//! Every lock reports its acquisitions and releases, and every irq-quiet
//! section its entries and exits, to the hooks here.  Each thread keeps a
//! [`HeldLocks`] record; one global graph keeps the order in which lock
//! kinds have ever nested, and the checker panics at the first
//! acquisition that closes a cycle in it, before the lock is waited for.
//! It also panics on sleeping in an irq-quiet section or under a spinning
//! hold, on taking a lock the thread already holds, and on a release,
//! downgrade or section exit that matches nothing held.
//!
//! A lock's kind is the name it was built with, not its construction
//! site: every lock of a kind is one node
//! in the graph, as in FreeBSD's WITNESS, so a wrong nesting between two
//! locks of different kinds is caught even though they were built at two
//! sites.  Two locks of one kind are one node, and holding both at once is
//! no fault — only the same lock twice is, and the record tells those
//! apart by address.

mod graph;
mod held;

use crate::platform::Platform;
use core::sync::atomic::{AtomicBool, Ordering};
use graph::Graph;
use held::Held;
pub use held::HeldLocks;

/// How a lock is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// An irq spin lock: spinning, and holding an irq-quiet section.
    IrqSpin,
    /// A [`Mutex`](crate::Mutex); its waiter may sleep.
    Mutex,
    /// A [`RwLock`](crate::RwLock) held shared.
    Read,
    /// A [`RwLock`](crate::RwLock) held exclusive.
    Write,
}

impl Kind {
    /// Returns whether a waiter for a lock held this way may sleep.
    const fn sleeps(self) -> bool {
        matches!(self, Self::Mutex | Self::Read | Self::Write)
    }
}

/// Returns the last segment of a kind's type path, for a message.
fn short(name: &'static str) -> &'static str {
    name.rsplit("::").next().unwrap_or(name)
}

/// The order graph, read with no lock.
static GRAPH: Graph = Graph::EMPTY;

/// Serializes the changes to [`GRAPH`].
static GRAPH_LOCK: AtomicBool = AtomicBool::new(false);

/// Runs `f` with the graph lock held, for the thread whose record is
/// `held`.
///
/// `f` must not panic, or the lock stays held.
fn locked<P: Platform, R>(held: &HeldLocks, f: impl FnOnce() -> R) -> R {
    // Irq-quiet, so no handler on this CPU spins on the lock under its
    // own holder; a thread already irq-quiet enters no further section.
    let enter = held.irq_quiet().get() == 0;
    if enter {
        P::irq_quiet_enter();
    }
    while GRAPH_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let result = f();
    GRAPH_LOCK.store(false, Ordering::Release);
    if enter {
        // SAFETY: this thread entered the section above.
        unsafe { P::irq_quiet_exit() };
    }
    result
}

/// Panics unless the running thread may sleep: in no irq-quiet section
/// and holding no lock that spins.
fn check_may_sleep(held: &HeldLocks) {
    if let Some(spinning) = held.iter().find(|held| !held.kind.sleeps()) {
        panic!("may sleep while holding a {:?} lock", spinning.kind);
    }
    assert!(
        held.irq_quiet().get() == 0,
        "may sleep inside an irq-quiet section",
    );
}

/// Returns the node of `name`, adding it if it is new, or `None` if the
/// graph has no room for it.
///
/// Takes the graph lock only to add it.
fn node<P: Platform>(held: &HeldLocks, name: &'static str) -> Option<usize> {
    GRAPH
        .find(name)
        .or_else(|| locked::<P, _>(held, || GRAPH.add(name)))
}

/// Orders node `taken` after every kind `held` holds, and returns the hold
/// that would close a cycle, if any.
///
/// A hold of the acquiring lock's own kind is skipped: two locks of one
/// kind are one node, so the edge would lead from a node to itself.
///
/// Takes the graph lock only if an edge is missing, and checks again under
/// it, since another thread may have added the edge meanwhile.
fn order<P: Platform>(
    held: &HeldLocks,
    taken: usize,
    name: &'static str,
) -> Option<Held> {
    let missing = |before: &Held| {
        before.name != name
            && GRAPH
                .find(before.name)
                .is_some_and(|node| !GRAPH.has(node, taken))
    };
    if !held.iter().any(|before| missing(&before)) {
        return None;
    }
    locked::<P, _>(held, || {
        held.iter().filter(missing).find(|before| {
            let node = GRAPH.find(before.name).unwrap_or_default();
            !GRAPH.order(node, taken)
        })
    })
}

/// Checks and records an acquisition.
///
/// # Panics
///
/// Panics if `kind` sleeps while the thread is in an irq-quiet section or
/// holds a spinning lock, if the thread already holds `lock`, if `name`'s
/// kind would close a cycle in the lock order, if the graph is full, or if
/// the thread holds too many locks.
pub fn record<P: Platform>(
    held: &HeldLocks,
    lock: *const (),
    kind: Kind,
    name: &'static str,
) {
    if let Some(earlier) = held.find(lock.addr()) {
        panic!(
            "recursive acquisition: this {kind:?} lock is already held as \
             {:?}",
            earlier.kind,
        );
    }
    let Some(taken) = node::<P>(held, name) else {
        panic!(
            "the lock-kind graph is full: it tells at most {} kinds apart",
            graph::KINDS,
        );
    };
    if let Some(before) = order::<P>(held, taken, name) {
        panic!(
            "lock order: a {kind:?} lock of kind {} is taken while {} is \
             held, which would deadlock",
            short(name),
            short(before.name),
        );
    }
    held.push(Held {
        lock: lock.addr(),
        kind,
        name,
    });
}

/// Checks and records a blocking acquisition, before it waits.
///
/// # Panics
///
/// As [`record`].
pub fn acquire<P: Platform>(lock: *const (), kind: Kind, name: &'static str) {
    let held = P::held_locks();
    if kind.sleeps() {
        check_may_sleep(held);
    }
    record::<P>(held, lock, kind, name);
}

/// Records a successful try-acquisition.
///
/// # Panics
///
/// As [`record`].
pub fn try_acquired<P: Platform>(
    lock: *const (),
    kind: Kind,
    name: &'static str,
) {
    record::<P>(P::held_locks(), lock, kind, name);
}

/// Records a release, which may be out of acquisition order.
///
/// # Panics
///
/// Panics if the running thread does not hold `lock` as `kind`: a read
/// release of a write hold would otherwise corrupt the lock's word.
pub fn release<P: Platform>(lock: *const (), kind: Kind) {
    assert!(
        P::held_locks().remove(lock.addr(), kind),
        "release of a lock this thread does not hold as {kind:?}",
    );
}

/// Records a write hold becoming a read hold.
///
/// # Panics
///
/// Panics if the running thread does not hold `lock` for writing.
pub fn downgrade<P: Platform>(lock: *const ()) {
    assert!(
        P::held_locks().downgrade(lock.addr()),
        "downgrade of a lock this thread does not hold as Write",
    );
}

/// Checks that the running thread may sleep.
///
/// # Panics
///
/// Panics if the thread is in an irq-quiet section or holds a spinning
/// lock.
pub fn may_sleep<P: Platform>() {
    check_may_sleep(P::held_locks());
}

/// Records an irq-quiet section entry.
pub fn section_enter<P: Platform>() {
    let depth = P::held_locks().irq_quiet();
    depth.set(depth.get() + 1);
}

/// Records an irq-quiet section exit.
///
/// # Panics
///
/// Panics if the running thread is in no irq-quiet section.
pub fn section_exit<P: Platform>() {
    let depth = P::held_locks().irq_quiet();
    let entered = depth.get();
    assert!(entered > 0, "unbalanced irq-quiet section exit");
    depth.set(entered - 1);
}
