// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>

//! The kernel services a lock needs, supplied as a zero-sized type.

#[cfg(debug_assertions)]
use crate::checker::HeldLocks;
use crate::wait::WaitTable;
use core::ptr::NonNull;

/// A thread as the locks see it: the address of something the platform
/// keeps per thread.
///
/// The address is aligned to at least [`ThreadRef::ALIGN`], so a lock
/// word can carry flags in its low bits beside an owner.  The locks never
/// dereference it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ThreadRef(NonNull<u8>);

// SAFETY: a `ThreadRef` is an identity; the crate never dereferences it.
unsafe impl Send for ThreadRef {}
// SAFETY: as for `Send`, the address is only compared and stored.
unsafe impl Sync for ThreadRef {}

impl ThreadRef {
    /// The least alignment of a thread address.
    pub const ALIGN: usize = 8;

    /// Wraps the address of a thread's per-thread record.
    ///
    /// # Panics
    ///
    /// Panics if `addr` is not aligned to [`Self::ALIGN`].
    #[must_use]
    pub fn new(addr: NonNull<u8>) -> Self {
        assert!(
            addr.addr().get().is_multiple_of(Self::ALIGN),
            "thread address is not aligned to ThreadRef::ALIGN",
        );
        // A lock word keeps the owner as an integer; exposing the
        // provenance lets `from_addr` hand the platform back a pointer it
        // may dereference.
        let _ = addr.expose_provenance();
        Self(addr)
    }

    /// Returns the address given to [`Self::new`].
    #[must_use]
    pub const fn as_ptr(self) -> NonNull<u8> {
        self.0
    }

    /// Returns the thread's address.
    #[must_use]
    pub fn addr(self) -> usize {
        self.0.addr().get()
    }

    /// Rebuilds a reference from an address taken by [`Self::addr`].
    ///
    /// # Panics
    ///
    /// In debug builds, if `addr` is not aligned to [`Self::ALIGN`]: a
    /// lock word read as an owner held something else.
    pub(crate) fn from_addr(addr: usize) -> Option<Self> {
        debug_assert!(
            addr.is_multiple_of(Self::ALIGN),
            "lock word names a thread at a misaligned address",
        );
        NonNull::new(core::ptr::with_exposed_provenance_mut(addr)).map(Self)
    }
}

/// The kernel services a lock needs.
///
/// Implemented on a zero-sized marker type; every lock names it as a type
/// parameter and calls it through associated functions, so a lock holds
/// no platform value.
///
/// An irq-quiet section is a CPU-local region in which no local interrupt
/// handler runs.  Sections are per thread and nest as a count: a thread
/// is in one while it has entered more than it has left.
///
/// # Safety
///
/// Every lock's mutual exclusion rests on the implementation keeping each
/// function's contract below.
pub unsafe trait Platform: 'static {
    /// Returns the running thread: the same value for the thread's whole
    /// life, and distinct from every other live thread's.
    fn current() -> ThreadRef;

    /// Returns whether `thread` is on a CPU now.
    ///
    /// A hint for spinning waiters; it may be stale by the time it is
    /// read.  `thread` was read from a lock word, with acquire, so the
    /// record as its thread made it is visible; but the thread may have
    /// exited since, so the platform keeps its thread records addressable
    /// after exit (type-stable memory) or answers `false` for a dead
    /// thread.
    fn is_running(thread: ThreadRef) -> bool;

    /// Enters an irq-quiet section.
    fn irq_quiet_enter();

    /// Leaves an irq-quiet section.
    ///
    /// # Safety
    ///
    /// The running thread entered an irq-quiet section with
    /// [`Self::irq_quiet_enter`] that it has not left.
    unsafe fn irq_quiet_exit();

    /// Blocks the running thread until [`Self::unpark`] names it.
    ///
    /// An unpark that comes first makes the next park return at once.
    /// Park may also return for no reason, so callers re-check their
    /// condition in a loop.  Never called inside an irq-quiet section.
    fn park();

    /// Makes `thread`'s pending or next [`Self::park`] return.
    ///
    /// May be called from any context, including an irq-quiet section.
    /// `thread` may already have stopped waiting, and even have exited:
    /// the unpark must then be harmless, as for [`Self::is_running`].
    fn unpark(thread: ThreadRef);

    /// Returns the wait table every sleeping lock of this platform queues
    /// in.
    fn wait_table() -> &'static WaitTable;

    /// Returns the running thread's held-lock record, for the order
    /// checker.
    #[cfg(debug_assertions)]
    fn held_locks() -> &'static HeldLocks;
}

#[cfg(all(test, not(loom), debug_assertions))]
mod tests {
    use super::ThreadRef;

    #[test]
    #[should_panic = "lock word names a thread at a misaligned address"]
    fn rebuilding_a_misaligned_address_panics() {
        let _ = ThreadRef::from_addr(ThreadRef::ALIGN + 1);
    }
}
