# `lock` — the kernel's locks, and when to use each

Four locks, one wait primitive and one guard, for a non-preemptible
microkernel with no spl:

| | Holder may sleep | Interrupts while held | Waiters | Size (release) |
|---|---|---|---|---|
| [`SpinLock`](#spinlock) | no | untouched | spin, FIFO (ticket) | 4 bytes |
| [`IrqSpinLock`](#irqspinlock) | no | quiet on this CPU | spin, FIFO (ticket) | 4 bytes |
| [`Mutex`](#mutex) | yes | untouched | spin while the owner runs, then sleep; handoff in arrival order | 1 word |
| [`RwLock`](#rwlock) | yes | untouched | sleep; served in arrival order; handoff | 1 word |
| [`Condvar`](#condvar) | — | — | sleep until notified | 1 byte |

Debug builds add a lock-class pointer to every lock, for the order
checker. Kernel code is never preempted
([ADR 0001](../../docs/adr/0001-preemptible-kernel-is-a-non-goal.md)), so no lock deals
with preemption; each lock type fixes its interrupt policy
([ADR 0029](../../docs/adr/0029-the-lock-type-decides-the-interrupt-policy.md)). The
set follows Zircon rather than the monolithic kernels
([ADR 0034](../../docs/adr/0034-the-lock-set-follows-zircon.md)). Terms are defined
in [the project glossary](../../GLOSSARY.md), under Locks.

## Choosing a lock

Ask, in order:

1. **Is it one word?** Use an atomic, not a lock.
2. **Does an interrupt handler touch it**, or is it taken where
   interrupts must stay quiet? → [`IrqSpinLock`](#irqspinlock).
3. **Can the holder sleep** — allocate, fault, wait, or take a `Mutex` or
   `RwLock` — or is the section more than a few dozen instructions? →
   [`Mutex`](#mutex).
4. **Many concurrent readers, long lookups, rare writers?** →
   [`RwLock`](#rwlock). Today that is Mach's IPC name tables only.
5. **Tiny, never sleeps, no interrupt handler touches it, and taken where
   sleeping is not allowed** — inside an `IrqSpinLock` region or the
   scheduler's own paths? → [`SpinLock`](#spinlock).
6. **Otherwise:** [`Mutex`](#mutex). It is the default.

Most of Mach's simple locks become `Mutex`es. Mach made nearly every lock
a spin lock (82–92% of its lock call sites) because it relied on spl and
never slept holding one; Zircon, the microkernel closest to Mach in
shape, makes 62% of its locks mutexes and keeps spinning for the
scheduler and for data shared with interrupt handlers.

## `SpinLock`

A ticket lock: waiters spin in arrival order; the holder must not sleep.
It leaves interrupts alone, so **no interrupt handler may ever take it** —
a handler that interrupted the holder on the same CPU would spin forever.

**Use it for** leaf data guarded for a handful of instructions, where the
code cannot sleep but is never reached from an interrupt handler:

- data nested under an `IrqSpinLock` region that handlers do not touch;
- small counters or lists read and written in the scheduler's and the
  wait table's own paths, when an atomic will not do.

**Not for** anything a handler touches (use `IrqSpinLock`) or anything
whose holder may sleep or run long (use `Mutex`).

## `IrqSpinLock`

A `SpinLock` whose holder is in an irq-quiet section: no local interrupt
handler runs while it is held, whether the platform masks or defers them.
It is **the only lock an interrupt handler may take**.

**Use it for** state shared between threads and interrupt handlers, and
the scheduler's state, which the clock interrupt and IPIs reach:

- the thread lock, run queues, processor and processor-set locks;
- the wait-event queues behind `assert_wait` and `thread_wakeup`;
- timer and callout queues driven by the clock interrupt;
- driver state shared with its interrupt handler: the kernel message
  buffer, tty queues, the I/O-done list, the interrupt dispatch table.

Keep the section short: every CPU that waits for it also has its
interrupts quiet.

## `Mutex`

The default lock. The owner is recorded in the lock word; a contender
spins while the owner is on a CPU, then sleeps in the wait table. A
contended release **hands the lock to the first waiter**, so no running
thread can barge in and no waiter starves
([ADR 0032](../../docs/adr/0032-a-contended-lock-is-handed-to-its-first-waiter.md)).
There is no priority inheritance
([ADR 0033](../../docs/adr/0033-no-priority-inheritance-no-priority-ordering.md)). The holder may
sleep.

**Use it for** kernel objects and anything whose holder may block:

- ports and port sets, their message queues, and the other IPC objects;
- tasks and threads (outside the scheduler's fields), their IPC port
  tables;
- VM objects, the page queues, address-space maps and the pmap
  ([ADR 0034](../../docs/adr/0034-the-lock-set-follows-zircon.md));
- devices and their request state not touched by interrupt handlers;
- the futex-like `gsync` buckets.

**Not for** interrupt handlers, or code inside an `IrqSpinLock` or
`SpinLock` region: the order checker panics if a thread may sleep there.

## `RwLock`

A sleeping reader-writer lock whose waiters are served **in arrival
order**, readers and writers alike: once anyone waits, newcomers queue
behind them, so neither side starves. A release hands the lock to the
first waiter, or to the run of readers ahead of the first waiting writer.
A writer can **downgrade** to a reader; nobody upgrades. **Keep read
sections short**: a waiting writer holds back every reader that arrives
after it.

**Use it for** tables read far more than written, where readers look up
for long enough that serializing them costs:

- Mach's IPC name tables (`ipc_space`), read on every right lookup.

**Not for** address-space maps: they take a `Mutex`, as Zircon's
`VmAspace` does, and page faults on one address space serialize
([ADR 0034](../../docs/adr/0034-the-lock-set-follows-zircon.md)). **To "upgrade"**,
release the read lock, take the write lock, and re-check what you read —
the path Mach's `vm_map_lookup` already takes when its upgrade fails.

## `Condvar`

Sleeps until notified, releasing any exclusive guard while it sleeps —
`Mutex`, `SpinLock`, `IrqSpinLock` or an `RwLock` write guard — and taking
it back before it returns. Always wait in a loop (`wait_while`): another
thread may take the lock first. A notify never sleeps and may come from an
interrupt handler.

**Use it for** waits tied to one lock's state — the `thread_sleep(event,
lock)` pattern: a port's message queue becoming non-empty, an object's
paging finishing, a busy page being released. Mach's free-form
`assert_wait`/`thread_wakeup` on arbitrary addresses stays in the
scheduler.

## The guard and the raw layer

The four locks are aliases of one `Lock<R, T>` over a raw lock `R`; its
data is reached only through a `Guard` (exclusive) or a `SharedGuard`
(shared), which unlock when dropped
([ADR 0035](../../docs/adr/0035-one-generic-lock-and-guard.md)). A guard also:

- **`unlocked(|| …)`**: releases the lock, runs the closure, and takes
  the lock back, even if the closure panics; the pattern behind Mach's
  "unlock, call out, relock".
- **`Guard::adopt(&lock)`** (unsafe): takes over a lock that was locked
  through the raw layer, so a path can lock in one function and let a
  guard unlock in another.

Each lock has a raw twin — `RawSpinLock`, `RawIrqSpinLock`, `RawMutex`,
`RawRwLock` — implementing the `RawLock` (and, for `RawRwLock`,
`RawSharedLock`) traits, with `unsafe` unlock and no data;
`lock.raw()` reaches a `Lock`'s. Use the raw layer where the lock lives in
a `#[repr(C)]` object next to the data it guards. `assert_held` on the raw
traits checks, in debug builds, that the running thread holds the lock.
Otherwise use the guarded type, which ties the data to its lock.

## Rules the order checker enforces

Debug builds check every acquisition:

- no lock-order cycles between lock classes (a class is a construction
  site);
- no sleeping — `Mutex`, `RwLock`, `Condvar::wait` — while in an
  irq-quiet section or holding a spin lock;
- no second lock of a class while the thread holds one, `try_*` included
  ([ADR 0036](../../docs/adr/0036-a-thread-holds-at-most-one-lock-of-a-class.md)), so no
  taking a lock the thread already holds, reads included;
- no releasing a lock the thread does not hold, or holds in another mode:
  a read unlock of a write hold, or the reverse.

## What else debug builds check

Beside the order checker, each unsafe path checks the lock's own word,
so a corrupt word or a broken handoff stops at its source:

- **Unlock:** a `Mutex` word must name the running thread, with at most
  the contested flag; a `RwLock` word must count a reader and no writer
  for a shared unlock, and name the running thread as writer for an
  exclusive unlock or a downgrade; a ticket lock must not be free.
- **Handoff:** a thread that a release woke must find the word naming
  it: as owner of a `Mutex`, as writer or counted reader of a `RwLock`.
  A queued waiter must not already be woken.
- **Guards:** a guard checks that the running thread holds its lock when
  it is made, when it hands out `&mut`, and when it unlocks; `&` access
  is unchecked, since a `Sync` guard may be read from another thread.
- **Wait table:** a bucket's queue is reached only with the bucket lock
  held, and an unwinding waiter must be on the queue it leaves.
- **Bounds:** a ticket lock refuses the 65535th thread to hold or wait
  for it, which the word could not tell from a free lock; a lock word
  read as an owner must be aligned like a thread.

## What is not here, and why

| Missing | Why |
|---|---|
| RCU, sequence locks | Zircon needs neither; the monolithic kernels spend them on networking and filesystems, which Mach leaves to servers (ADR 0034) |
| Spinning reader-writer lock | the pmap takes a `Mutex`, as in Zircon (ADR 0034) |
| Tokens | a DragonFly-only design tied to its LWKT threads |
| Priority inheritance and ordering | no preemption, and Mach's simple locks are never held across a block, so holders are rarely inverted (ADR 0033) |
| Critical mutex, preemption sections | preemption is a non-goal (ADR 0001) |
| `RwLock` upgrade | release, re-take and re-check instead; rare everywhere (0.1–0.7% of lock sites) |
| A big kernel lock | Mach never had one |
