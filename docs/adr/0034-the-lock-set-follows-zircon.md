# The lock set follows Zircon, a microkernel, not the monolithic kernels

The lock crate offers spin locks, irq spin locks, Mutex with handoff, a
fair RwLock, and Condvar, and the kernel synchronizes with nothing else.
Neither has RCU, a sequence lock, a spinning reader-writer lock or
tokens: Zircon, the microkernel closest to Mach in shape, needs none of
them, while the monolithic kernels that do use them spend them mostly
on networking and filesystems, which Mach leaves to user-space servers.
Following Zircon, Mach's address-space maps and page tables take
exclusive Mutexes, and only its IPC name tables take the RwLock, which
serves waiters in arrival order rather than preferring writers;
Zircon's `BrwLock` orders them by priority first (ADR 0033).

## Considered Options

- **A quiescent-state RCU in the kernel**: with no preemption (ADR 0001)
  a read section costs nothing, since a context switch, the idle loop
  and a tick taken in user mode are quiescent states. It was built, with
  a grace-period thread, hooks in the scheduler, idle loop and clock
  tick, and an `Rcu<T>`; withdrawn because its users were the default
  memory manager's port, written about once per boot, and thread records
  held a grace period past death for a late unpark, which a spin lock
  and the wait table now cover. A grace period lasts as long as the
  longest stretch any CPU runs without blocking, frees wait behind it
  while an allocation fails (ADR 0017), and its read sections were often
  only a comment saying nothing blocks in between, which no check sees.
  It can come back for a lookup the benches show RwLock contention on,
  such as IPC names or map entries.

## Consequences

- Page faults on one address space no longer run in parallel. Zircon
  accepts that for `VmAspace`; a reader-writer map lock can come back if
  the benches show fault contention.
- A lock never unparks a thread whose wait has returned, so a thread's
  record can be freed the moment it exits: a woken waiter takes its
  bucket lock once more before its wait returns.
