# Debt register

Known gaps between the code and the target design. Remove an entry when
its completion condition is met; add one when a change introduces a gap.
Paths below are relative to `crates/` unless stated otherwise.

## Runtime behavior

- **User copies at address zero.** `mach/src/arch/x86_64/trap.rs`
  sends a fault at address zero to the kernel map before checking
  recovery, so a user copy can panic.
  **Done when:** it fails like a copy at any other unmapped user address.

- **Debugger requests panic.** `mach-host/src/machine.rs` sends
  `Halt::Debugger` through `mach/src/arch/x86_64/host_platform.rs`
  to `mach/src/kern/debug.rs`, which panics.
  **Done when:** the debugger reboot option parks every CPU, prints
  `debugger requested`, and waits for GDB.

- **Wakeups cancel another thread's timeout.** `clear_wait` in
  `mach-thread/src/sched_prim.rs` calls `Thread::stop_timer` on the
  sleeper.
  **Done when:** the sleeper stops its own timer when resuming from
  `thread_block`, and no wakeup path touches another thread's timer.

## Performance and scalability

- **No IPC fast path for short messages and direct handoff.** `mach-ipc/src/mach_msg.rs`
  only implements the generic path, allocating a kernel message buffer (`Kmsg`)
  and queueing even for small scalar messages or when a receiver is already
  blocked waiting on the destination port.
  **Done when:** short messages without out-of-line data or rights bypass buffer
  allocation, and a sender direct-switches or hands off to a blocked receiver.

- **Global runqueue lock contention.** `mach-sched/src/run_queue.rs` uses a single
  `SimpleLock` per `RunQueue` across processors, and `tools/boot-hurd.sh` defaults
  to `-smp 1`. As CPU count scales, cores contend on the runqueue lock.
  **Done when:** runqueues are per-CPU with work-stealing or load balancing, the
  global lock is eliminated, and `boot-hurd.sh` boots stably under QEMU with
  multiple CPUs (`-smp 2` and `-smp 4`).

- **Whole-map lock on concurrent page faults.** `mach-vm/src/vm_map.rs`
  protects `VmMap` with a whole-map `RawMutex<P::Lock>`, serializing concurrent
  faults across threads in the same address space.
  **Done when:** concurrent page faults in non-overlapping address ranges do not
  block each other, using range locks or fine-grained interval synchronization.

- **Missing PCID (Process-Context Identifiers) support.** `mach-pmap/src/pmap.rs`
  flushes all non-global TLB entries on address space switches via standard `CR3`
  writes.
  **Done when:** `CR4.PCIDE` is enabled and PCID tags are used to preserve TLB
  entries across `mach_msg` context switches.

- **Missing 2 MB superpage mapping.** `mach-pmap/src/pte.rs` and `mach-page`
  only map 4 KB base pages, increasing page-table walk latency and TLB pressure
  for large allocations.
  **Done when:** `mach-pmap` supports 2 MB large page entries for contiguous
  physical memory regions.

- **Missing hardware execution protection (NX / SMEP / SMAP).** `mach-pmap/src/pte.rs`
  does not enforce W^X with the XD/NX bit on data pages, and CR4 does not
  enable supervisor execution/access prevention.
  **Done when:** page tables set the NX bit on non-executable mappings, and
  SMEP/SMAP are enabled in CR4 where hardware supports them.

- **No userspace NVMe storage support.** The Hurd boot environment relies on
  legacy IDE/AHCI controllers, lacking support for modern NVMe storage devices.
  **Done when:** device dispatch in `mach-device` cleanly exposes PCI BAR MMIO and
  MSI interrupts so a userspace NVMe translator can drive root storage.

- **Unconditional copy-on-write mapping for small out-of-line data.**
  `mach-ipc/src/ipc_kmsg.rs` always invokes `map.copyin` or `map.copyin_page_list`
  for non-port out-of-line payloads, creating shadow VM objects, modifying page
  tables, and issuing SMP TLB shootdowns even for buffers under 64 KB where a
  physical copy is faster.
  **Done when:** out-of-line payloads below an adaptive threshold (e.g. 32 KB or
  64 KB) are copied via optimized kernel memory copies instead of COW page-table
  remapping, avoiding VM object allocation and TLB invalidation overhead.

- **No memory pressure notification interface for userland caches.**
  `mach-vm/src/vm_pageout.rs` lacks a mechanism to signal userland translators
  and servers when physical memory is scarce. Translators hoard large file and
  directory caches, forcing the kernel into pageout thrashing or paused
  allocation rather than reclaiming freeable userspace memory.
  **Done when:** a memory pressure notification port or event is exposed so
  translators (such as `ext2fs` and `libdiskfs`) can flush caches before pages
  are forced to swap.

- **Global timer wheel lock contention.** `mach/src/arch/x86_64/clock_platform.rs`
  defines a single global `WHEEL: HashedWheel`, causing all CPUs to contend on
  the same lock during timer registration, cancellation, and clock ticks.
  **Done when:** `HashedWheel` instances are partitioned per-CPU in `PerCpu`, with
  advances and local thread timeouts serviced without acquiring a global lock.

- **Synchronous RPC overhead in high-throughput block and network I/O.**
  `mach-device/src/ds_routines.rs` processes all I/O via individual `device_read`
  and `device_write` Mach messages and `io_req` tracking, incurring capability
  lookup, message buffer allocation, and context switch penalties for every block.
  **Done when:** `mach-device` provides a zero-copy shared-memory ring buffer
  interface (submission/completion queues) for userspace device drivers to submit
  asynchronous batch I/O without per-transfer Mach messages.

- **Full register state save and restore on fast system call entry.**
  `mach/src/arch/x86_64/locore.rs` unconditionally spills and reloads all 16
  general-purpose registers (including callee-saved `rbx`, `rbp`, `r12`-`r15`)
  in `syscall64` and `syscall64_restore_state`, even for non-blocking traps that
  do not context-switch.
  **Done when:** `syscall64` only saves caller-saved registers on the fast path,
  deferring callee-saved register spills until a thread blocks or yields.

## Locks and ownership

- **Legacy locks and `spl`.** The kernel still uses
  `mach/src/arch/x86_64/spl.rs`, `mach-pmap/src/lock.rs`, and the
  `SimpleLock` of `mach-page/src/simple_lock.rs`, which releases with
  `mem::forget` and `force_unlock`.
  **Done when:** all three files are gone, no `spl` identifier remains,
  and every former `SimpleLock` holds an `IrqSpinLock`, `SpinMutex` or
  `TicketLock` guard.

- **The order checker cannot see the spin locks.** The checker in
  `lock/src/checker/mod.rs` reports only `IrqSpinLock`, `Mutex` and
  `RwLock` acquisitions, so `SpinMutex`, `TicketLock`, `SimpleLock` and
  `LockData` nest with nothing watching.
  **Done when:** a spin acquisition reports to the checker, or the
  checker panics when a thread takes a spin lock while holding one.

- **Locks released in a different function than they are taken.** The
  call sites in `mach-vm`, `mach-ipc` and `mach-thread` pair
  `(*x).lock.lock()` with an `unlock()` in another function, the C's
  shape, in about 790 `unsafe` blocks, where a guard would make the
  hold visible in the signature.
  **Done when:** a shared object is reached through a guard or a method
  that takes its own lock, and no `unlock()` runs far from its `lock()`.

- **gsync and map locking untested against the recursive-read deadlock.**
  GNU Mach's `gsync_wait` re-took a map read lock behind a queued writer
  and died; `mach-gsync/src/gsync.rs` keeps maps read-locked across
  bucket work and releases them by hand, so the shape is near.
  **Done when:** the debug checker or a test shows no map lock is taken
  while a map hold is live, and no map hold waits on a page's busy bit.

- **No priority propagation across IPC.** A receiver serves a message at
  its own priority, so a high-priority client can wait behind work its
  own message queued at a lower one; `depress_priority` in
  `mach-sched/src/sched_info.rs` is the only priority coupling.
  **Done when:** a receiver inherits the sender's priority while it
  serves the message, and drops it when the service ends.

- **Manual reference counting.** Ports, tasks, threads, maps, and VM
  objects use explicit reference and release calls in `mach/src/kern/`,
  `mach-vm`, and `mach-ipc`.
  **Done when:** reference types own every counted object outside the
  MIG seam.

- **Mutable globals.** `static mut` still holds kernel state.
  **Done when:** no `static mut` declaration remains. A
  `&'static mut` type is not a declaration.

- **Unguarded shared state.** Several crates use `SyncCell` to make
  any `T` implement `Sync` and expose raw pointers.
  **Done when:** no `SyncCell` remains, and shared state uses guards,
  methods that take their own locks, or atomics.

## Interfaces and allocation

- **VM exposes kernel internals.** `mach-vm/src/platform.rs` exposes
  thread fields, port records, slab caches, and `kalloc`.
  **Done when:** `Platform` provides operations without thread-field or
  port-record accessors, and VM allocates through `kmem::Alloc`.

- **IPC depends on kernel allocation.** `mach-ipc/src/platform.rs`
  exposes slab caches; tables and messages use `kalloc` through VM.
  **Done when:** IPC allocates through `kmem::Alloc`.

- **The pmap depends on kernel slab caches.**
  `mach-pmap/src/platform.rs` exposes caches for maps, tables, and
  physical-to-virtual entries.
  **Done when:** the pmap allocates through `kmem::Alloc`.

- **The slab is derived from GNU Mach.** `mach-slab` implements the
  slab and general allocator behind `kalloc`.
  **Done when:** it is replaced by a non-derived implementation.

- **Allocation may sleep.** `Kalloc` in `mach/src/kern/kheap.rs`
  uses `kalloc`, which may sleep for a free page and violates
  `kmem::Alloc`'s no-wait contract.
  **Done when:** allocation cannot sleep, the kernel uses `kmem`
  types, and `Kalloc` and `kheap.rs` are gone.

## Code organization

- **Upstream file prefixes.** `mach-ipc/src/ipc_*.rs`,
  `mach-vm/src/vm_*.rs`, and `mach-device/src/dev_*.rs` repeat their
  module's name.
  **Done when:** module filenames no longer repeat their directory's
  prefix.

- **Several structures per file.** Kernel modules mix structures with
  behavior and data-only types.
  **Done when:** each structure with behavior has its own file, and
  data-only types live in the module's `types.rs`.

- **The old architecture name remains.**
  `mach/src/arch/x86_64/debug_i386.rs` uses `i386` in its filename.
  **Done when:** only the `mach_i386` ABI files retain that name.

- **Code markers.** `TODO`, `FIXME`, and `XXX` comments remain in
  `mach/src/arch/x86_64/locore.rs` and `mach-vm/src/`.
  **Done when:** each real gap has an entry here, redundant markers
  are removed, and no such code comment remains.

## Lints

- **Broad allowances and missing error documentation.** Kernel crates
  allow cast lints and other exceptions across whole crates or modules.
  Several expect `missing_errors_doc`; `collections/Cargo.toml` allows
  `single_call_fn` and `inline_modules` without reasons.
  **Done when:** no `#[allow(...)]` or `#![allow(...)]` remains; every
  crate denies `allow_attributes` and
  `allow_attributes_without_reason`; error cases are documented and
  `missing_errors_doc` expectations are gone; `collections` no longer
  allows `single_call_fn`; every manifest allowance has a reason.

- **Panic lints are missing.** Kernel subsystem manifests inherit only
  the workspace lints.
  **Done when:** `mach` and the `mach-*` kernel subsystem crates deny
  `unwrap_used`, `expect_used`, `indexing_slicing`, and `panic`.

- **MIG has no lint table.** `mach-mig-sys/Cargo.toml` has no lint
  rules.
  **Done when:** every crate has the baseline lint table.

## Missing ABI regression tests

These fixes need coverage in the frozen ABI suite:

| Case                                                          | Completion condition                                                                                         |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Non-canonical FS and GS bases (`mach/src/arch/x86_64/pcb.rs`) | `thread_setstatus` returns `KERN_INVALID_ARGUMENT`.                                                          |
| Concurrent display writes (`mach/src/arch/x86_64/kd/`)        | Two CPUs write the console without interleaving output.                                                      |
| Per-CPU exception stacks (`mach/src/arch/x86_64/ktss.rs`)     | Two CPUs fault at once and both keep running.                                                                |
| Invalid `mach_print` pointers (`mach/src/kern/console.rs`)    | Unmapped and kernel addresses print nothing and leave the kernel running.                                    |
| Wrong interrupt device type (`mach/src/device/intr.rs`)       | An I/O permission port makes both `device_intr_register` and `device_intr_ack` return `D_INVALID_OPERATION`. |

## Automation

- **Dependency checks.** There is no `deny.toml` or automated
  `cargo deny` check.
  **Done when:** `deny.toml` exists and CI runs `cargo deny check`.

- **CI.** There is no CI configuration.
  **Done when:** every PR runs the gate tasks, with boot gates at least
  nightly.
