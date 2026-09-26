# A contended lock is handed to its first waiter

A contended Mutex is released by writing its first waiter in as the new
owner before waking it, as Zircon's `Mutex` does; the RwLock hands off
the same way (ADR 0034). Waiters are served in arrival order.
Uncontended locking and unlocking stay single compare-and-swaps. Handoff
keeps the owner in the lock word true at every instant, so no running
thread can take the lock between the release and the wakeup, and no
waiter starves.

## Considered Options

- **Pure barging** (FreeBSD and NetBSD, and the lock crate's first
  choice): best throughput, but a waiter can starve, and every wakeup
  can lose the race and sleep again.
- **A handoff flag** (Linux's `MUTEX_FLAG_HANDOFF`): a head waiter that
  loses one race is handed the lock at the next unlock: one bit and one
  slow-path branch, but a running thread can still take the lock
  between a release and a wakeup until the head waiter has lost once.
