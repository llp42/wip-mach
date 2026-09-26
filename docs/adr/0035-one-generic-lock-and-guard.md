# One generic lock and guard over raw-lock traits

The safe layer is a single `Lock<R, T>` over a raw lock `R`, with one
`Guard` for exclusive holds and one `SharedGuard` for shared holds, as
Zircon's `Guard<LockType, Option>` serves every lock type. The raw locks
implement two public `unsafe` traits, `RawLock` and `RawSharedLock`, and
`SpinLock`, `IrqSpinLock`, `Mutex` and `RwLock` are aliases of `Lock`
over them. The guard is where the shared behaviour lives: data access,
loom tracking, `unlocked` (release, run, retake — what `Condvar` needs)
and adopting a lock taken through the raw layer. `assert_held` is on the
raw traits, which adoption checks in debug builds. Order-checker hooks and
handoff stay in the raw locks, so direct raw-layer use is still checked.

Zircon's `Option` parameter is left out: the lock type already fixes the
interrupt policy (ADR 0029), so a raw irq spin lock is the `IrqSave`
policy. The code is still the lock crate's own, not lock_api
(ADR 0031).

## Considered Options

- **A guard type per lock** (the first version): five guard types that
  repeated the same deref, drop, loom and unlock-relock code, plus a
  macro to teach `Condvar` each of them.
