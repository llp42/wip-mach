# Own lock wrappers, not lock_api

The safe guard layer is written in the lock crate rather than built on
lock_api's generic `Mutex<R, T>` and `RwLock<R, T>`. That keeps the data
cells visible to loom (lock_api uses `core::cell::UnsafeCell`), lets
guards carry platform state, lets the construction site set the lock
class, and adds no external dependency (ADR 0023).
