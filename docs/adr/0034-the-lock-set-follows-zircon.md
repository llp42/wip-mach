# The lock set follows Zircon, a microkernel, not the monolithic kernels

The lock crate offers spin locks, irq spin locks, Mutex with handoff, a
fair RwLock, and Condvar. It has no RCU, no sequence lock, no spinning
reader-writer lock and no tokens: Zircon, the microkernel closest to
Mach in shape, needs none of them, while the monolithic kernels that do
use them spend them mostly on networking and filesystems, which Mach
leaves to user-space servers. Following Zircon, Mach's address-space
maps and page tables take exclusive Mutexes, and only its IPC name
tables take the RwLock, which serves waiters in arrival order rather
than preferring writers; Zircon's `BrwLock` orders them by priority
first (ADR 0033).

## Consequences

Page faults on one address space no longer run in parallel. Zircon
accepts that for `VmAspace`; a reader-writer map lock can come back if
the benches show fault contention.
