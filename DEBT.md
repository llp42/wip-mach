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

## Locks and ownership

- **Legacy locks and `spl`.** The kernel still uses
  `mach/src/arch/x86_64/spl.rs` and `mach-pmap/src/lock.rs`.
  **Done when:** both files are gone and no `spl` identifier remains.

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
