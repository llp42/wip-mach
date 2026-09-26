// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The lock-order checker, in debug builds only.
//!
//! Every lock reports its acquisitions and releases, and every irq-quiet
//! section its entries and exits, to the hooks here.  Each thread keeps a
//! [`HeldLocks`] record; one global graph keeps the order in which lock
//! classes have ever nested, and the checker panics at the first
//! acquisition that closes a cycle in it, before the lock is waited for.
//! It also panics on sleeping in an irq-quiet section or under a spinning
//! hold, on recursion, and on a release, downgrade or section exit that
//! matches nothing held.
//!
//! Classes are construction sites, so two locks built at one site are
//! one class, and a thread holds at most one lock of a class at a time: a
//! second is a panic, so that every class is a single node in the order
//! and needs no address-ordering convention between its locks.

mod graph;
mod held;

use crate::platform::Platform;
use crate::spin::ticket::Ticket;
use core::panic::Location;
use graph::Graph;
use held::Held;
pub use held::HeldLocks;

/// A lock class: the construction site shared by its locks.
pub(crate) type Class = &'static Location<'static>;

/// How a lock is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Spin,
    IrqSpin,
    Mutex,
    Read,
    Write,
}

impl Kind {
    /// Returns whether a waiter for a lock held this way may sleep.
    const fn sleeps(self) -> bool {
        matches!(self, Self::Mutex | Self::Read | Self::Write)
    }
}

/// The order graph, read with no lock.
static GRAPH: Graph = Graph::EMPTY;

/// Serializes the changes to [`GRAPH`].
///
/// Taken only in an irq-quiet section, entered straight through the
/// platform so the checker does not see it, and never held across a
/// panic.
static GRAPH_LOCK: Ticket = Ticket::new();

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
    GRAPH_LOCK.lock();
    let result = f();
    // SAFETY: this thread took the graph lock above.
    unsafe { GRAPH_LOCK.unlock() };
    if enter {
        // SAFETY: this thread entered the section above.
        unsafe { P::irq_quiet_exit() };
    }
    result
}

/// What an acquisition broke.
enum Violation {
    /// The class table is full.
    Full,
    /// The thread already holds this lock, of the acquisition's class.
    SameClass(Held),
    /// The acquisition, made while this lock was held, closes a cycle.
    Cycle(Held),
}

/// Returns `class`'s node, adding it if it is new.
///
/// Takes the graph lock only to add it.
fn node<P: Platform>(
    held: &HeldLocks,
    class: Class,
) -> Result<usize, Violation> {
    GRAPH
        .find(class)
        .or_else(|| locked::<P, _>(held, || GRAPH.add(class)))
        .ok_or(Violation::Full)
}

/// Orders node `taken`, a class `held` holds no lock of, after every class
/// `held` holds.
///
/// Takes the graph lock only if an edge is missing, and checks again
/// under it, since another thread may have added the edge meanwhile.
fn order<P: Platform>(
    held: &HeldLocks,
    taken: usize,
) -> Result<(), Violation> {
    let missing = |before: &Held| !GRAPH.has(before.node, taken);
    if !held.iter().any(|before| missing(&before)) {
        return Ok(());
    }
    locked::<P, _>(held, || {
        held.iter()
            .filter(missing)
            .find(|before| !GRAPH.order(before.node, taken))
            .map_or(Ok(()), |before| Err(Violation::Cycle(before)))
    })
}

/// Adds `class` to the graph and, if `ordered`, orders it after every
/// class `held` holds; then pushes the hold.
///
/// # Panics
///
/// Panics if the class table is full, if the thread already holds a lock
/// of `class`, if an edge closes a cycle, or if the thread holds too many
/// locks.
fn record<P: Platform>(
    held: &HeldLocks,
    lock: *const (),
    class: Class,
    kind: Kind,
    ordered: bool,
) {
    let node = node::<P>(held, class).and_then(|node| {
        if let Some(earlier) = held.iter().find(|before| before.node == node) {
            return Err(Violation::SameClass(earlier));
        }
        if ordered {
            order::<P>(held, node)?;
        }
        Ok(node)
    });
    match node {
        Ok(node) => held.push(Held {
            lock: lock.addr(),
            class,
            node,
            kind,
        }),
        Err(Violation::Full) => panic!(
            "lock class table full: at most {} classes, the {kind:?} lock \
             of class {class} is one more",
            graph::CLASSES,
        ),
        Err(Violation::SameClass(earlier)) => panic!(
            "second lock of class {class} held: {kind:?} lock taken while \
             {:?} lock of the class is held",
            earlier.kind,
        ),
        Err(Violation::Cycle(before)) => panic!(
            "lock order cycle: {kind:?} lock of class {class} taken while \
             holding {:?} lock of class {}, which was taken after it before",
            before.kind, before.class,
        ),
    }
}

/// Panics unless the running thread may sleep: in no irq-quiet section
/// and holding no lock that spins.
fn check_may_sleep(held: &HeldLocks) {
    if let Some(spinning) = held.iter().find(|held| !held.kind.sleeps()) {
        panic!(
            "may sleep while holding {:?} lock of class {}",
            spinning.kind, spinning.class,
        );
    }
    assert!(
        held.irq_quiet().get() == 0,
        "may sleep inside an irq-quiet section",
    );
}

/// Checks and records a blocking acquisition, before it waits.
///
/// # Panics
///
/// Panics if the acquisition could deadlock: if it closes a cycle in the
/// lock order, if the thread already holds `lock`, if it already holds a
/// lock of `class`, or if `kind` sleeps while the thread is in an
/// irq-quiet section or holds a spinning lock.  Also panics if the class
/// table or the thread's record is full.
pub(crate) fn acquire<P: Platform>(lock: *const (), class: Class, kind: Kind) {
    let held = P::held_locks();
    if kind.sleeps() {
        check_may_sleep(held);
    }
    if let Some(earlier) = held.find(lock.addr()) {
        panic!(
            "recursive acquisition: {kind:?} lock of class {class} is \
             already held as {:?}",
            earlier.kind,
        );
    }
    record::<P>(held, lock, class, kind, true);
}

/// Records a successful try-acquisition.
///
/// A try cannot deadlock, so it orders no held class before `class`; the
/// locks taken after it are still ordered after it.
///
/// # Panics
///
/// Panics if the thread already holds a lock of `class`, or if the class
/// table or the thread's record is full.
pub(crate) fn try_acquired<P: Platform>(
    lock: *const (),
    class: Class,
    kind: Kind,
) {
    record::<P>(P::held_locks(), lock, class, kind, false);
}

/// Checks that the running thread holds `lock` as `kind`.
///
/// # Panics
///
/// Panics if the thread holds no `kind` lock at `lock`.
pub(crate) fn assert_held<P: Platform>(lock: *const (), kind: Kind) {
    assert!(
        P::held_locks()
            .find(lock.addr())
            .is_some_and(|held| held.kind == kind),
        "{kind:?} lock is not held by the running thread",
    );
}

/// Records a release, which may be out of acquisition order.
///
/// # Panics
///
/// Panics if the running thread does not hold `lock`.
pub(crate) fn release<P: Platform>(lock: *const ()) {
    assert!(
        P::held_locks().remove(lock.addr()),
        "release of a lock this thread does not hold",
    );
}

/// Records a write hold becoming a read hold.
///
/// # Panics
///
/// Panics if the running thread does not hold `lock` for writing.
pub(crate) fn downgrade<P: Platform>(lock: *const ()) {
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
pub(crate) fn may_sleep<P: Platform>() {
    check_may_sleep(P::held_locks());
}

/// Records an irq-quiet section entry.
pub(crate) fn section_enter<P: Platform>() {
    let depth = P::held_locks().irq_quiet();
    depth.set(depth.get() + 1);
}

/// Records an irq-quiet section exit.
///
/// # Panics
///
/// Panics if the running thread is in no irq-quiet section.
pub(crate) fn section_exit<P: Platform>() {
    let depth = P::held_locks().irq_quiet();
    let entered = depth.get();
    assert!(entered > 0, "unbalanced irq-quiet section exit");
    depth.set(entered - 1);
}

#[cfg(all(test, not(loom)))]
mod tests;
