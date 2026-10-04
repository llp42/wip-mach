# Debt register

The one document that describes the code as it is: each entry is a gap
between the code and an ADR (ADR 0012). A change that closes a gap
deletes its entry; a change that opens one adds it.

## The kernel keeps its own locks and spl

- **ADR**: ADRs 0029 and 0035; ADR 0027.
- **Where**: `kern/lock.rs`, `kern/kmutex.rs` and `arch/x86_64/spl.rs`
  in `crates/kernel/src`, with spl calls in 37 kernel files; `kernel`
  does not depend on `lock`.
- **Done when**: `kernel` depends on `lock`, those three files are
  gone, and no `spl` identifier remains in `crates/`.

## `clock` keeps its own irq-quiet lock

- **ADR**: ADRs 0029 and 0041.
- **Where**: `clock`'s `Critical` platform trait and `CriticalLock`
  (`src/critical.rs`, used across `src/` and `benches/timers.rs`, and
  described in its README), built on `spin::Mutex`.
- **Done when**: `clock`'s wheels and clock state take `lock`'s
  `IrqSpinLock`, and no `Critical` identifier remains in
  `crates/clock`.

## A waker cancels the sleeper's timeout

- **ADR**: ADR 0028.
- **Where**: `clear_wait` in `kern/sched_prim.rs` still calls
  `Thread::stop_timer` on the thread it wakes; the sleeper should stop
  its own callout on the way out of `thread_block` (continuations make
  that resume path non-local).
- **Done when**: no wakeup path touches another thread's timer.

## The machine-independent core is still in `kernel`

- **ADR**: ADR 0014.
- **Where**: `ipc/`, `vm/` above the pmap, and the task, thread,
  scheduler and device-dispatch modules of `kern/` and `device/`; the
  mechanisms `kern/rcu.rs` and `kern/boot_script.rs`.
- **Done when**: `crates/wip-mach` exists and holds the
  machine-independent core, and each mechanism has moved to its own
  crate or has been found to fail the split test.
- **Recorded outcomes**: `elf_load` passes the split test and lives in
  `crates/elf-load` as original MIT code with one `x86_64` reader;
  `ELFCLASS32` is rejected (ADR 0003).  The radix tree is rewritten as
  `kmem::RadixTree` (MIT, `A: Alloc`, typed leaves) and the IPC name
  tables use it; `kern/rdxtree.rs` is gone.

## Host tests compile kernel sources through a shim

- **ADR**: ADR 0014; ADR 0024.
- **Where**: `crates/host-tests` includes kernel source files verbatim.
- **Done when**: `crates/host-tests` is gone.

## The kernel links `alloc` and a global allocator

- **ADR**: ADR 0017.
- **Where**: `kern/kheap.rs` (the `#[global_allocator]` and `try_box`),
  and the 9 kernel files that use `alloc`.
- **Done when**: no `extern crate alloc` and no `#[global_allocator]`
  remain in `crates/`.

## The slab is derived from GNU Mach

- **ADR**: ADR 0017; ADR 0010.
- **Where**: `kern/slab.rs`, the slab and general allocator behind
  `kalloc`, is GPL code derived from GNU Mach.
- **Done when**: it is a non-derived rewrite, and `kern/slab.rs` is gone.

## The kernel's allocator may sleep

- **ADR**: ADR 0017.
- **Where**: `kalloc` may sleep for a free page, so `Kalloc`
  (`kern/kheap.rs`), the kernel's `kmem::Alloc`, breaks that trait's
  never-waits contract.
- **Done when**: no path from `kalloc` reaches a sleep, and `Kalloc`
  and `kern/kheap.rs` are gone once the kernel allocates only through
  `kmem` types.

## Counted objects are counted by hand

- **ADR**: ADR 0016.
- **Where**: ports, tasks, threads, maps and VM objects take and
  release references through explicit calls across `kern/`, `ipc/`
  and `vm/`.
- **Done when**: every counted object is held through a reference
  type outside the MIG seam.

## `kern_return_t` is used inside the kernel

- **ADR**: ADR 0015.
- **Where**: about 477 kernel functions return `c_int` or a
  `kern_return_t`.
- **Done when**: only the trap entry and the MIG seam produce a C
  integer result.

## C-visible symbols are spread through the kernel

- **ADR**: ADR 0027.
- **Where**: 218 `#[no_mangle]` in 25 files, including the 14
  `*_ffi.rs` modules under `arch/`, `device/`, `ipc/`, `kern/` and
  `vm/`, plus `ffi/` and `glue/`.
- **Done when**: every `#[no_mangle]` and `extern "C"` block sits in
  the one MIG seam module or names a symbol inline assembly uses.

## `static mut` holds global state

- **ADR**: ADR 0027.
- **Where**: 180 `static mut` in 54 kernel files.
- **Done when**: `grep -rn 'static mut ' crates` prints nothing.

## Module files keep upstream prefixes

- **ADR**: ADR 0027.
- **Where**: `ipc/ipc_*.rs`, `vm/vm_*.rs` and their peers in
  `crates/kernel/src`.
- **Done when**: no module file repeats its directory's prefix.

## Lint allowances

- **ADR**: ADR 0026; ADR 0027.
- **Where**: `kernel/src/main.rs` allows the `cast_*` lints and
  `inline_always` crate-wide to mirror the C; 210 `#[allow]`
  attributes across `crates/`; `kernel` does not deny
  `allow_attributes`; `collections/Cargo.toml` allows `single_call_fn`
  despite the no-single-caller-helper rule in `AGENTS.md`.
- **Done when**: no `#[allow(` or `#![allow(` remains in `crates/`, and
  every crate denies `allow_attributes` and
  `allow_attributes_without_reason`; `collections` no longer allows
  `single_call_fn`.

## The panic lints are not denied

- **ADR**: ADR 0018.
- **Where**: `crates/kernel/Cargo.toml`.
- **Done when**: `kernel` and `wip-mach` deny `unwrap_used`,
  `expect_used`, `indexing_slicing` and `panic`.

## Three crates lack manifest lint rules

- **ADR**: ADR 0026.
- **Where**: `host-tests`, `mach-mig-sys` and `rdxtree-bench` have no
  lint tables.
- **Done when**: every crate has the baseline lint table.

## Release Clippy rejects a radix-tree helper

- **ADR**: ADR 0024; ADR 0026.
- **Where**: `kmem/src/radix_tree.rs`'s `value_above_bottom` triggers
  `clippy::missing_const_for_fn` with debug assertions off.
- **Done when**: `mise run clippy::host` and `mise run clippy::kernel`
  pass in both profiles.

## Documentation does not pass with warnings denied

- **ADR**: ADR 0024.
- **Where**: `host-tests` has an unresolved link to `tests`; kernel
  documentation emits rustdoc warnings.
- **Done when**: `mise run doc::host` and `mise run doc::kernel` pass.

## `cov::kmem` counts misses no view of `radix_tree.rs` shows

- **ADR**: ADR 0024.
- **Where**: `cargo llvm-cov`'s summary counts 15 lines and 29 regions
  missed in `crates/kmem/src/radix_tree.rs`, while its own
  `llvm-cov export -format=lcov` has no zero-count record for the file,
  the HTML report marks no row uncovered, and `llvm-cov show` prints no
  zero-count line in any instantiation.  The committed tree measured
  100%; the in-progress rewrite is what started it, and per-instantiation
  gaps, unexecuted instantiations, inlining and `value_above_bottom` were
  each ruled out by experiment.
- **Done when**: `cov::kmem` passes again, or the counts are shown to be
  an artifact of the summary and the gate is trusted for this file.

## `RB_DEBUGGER` panics

- **ADR**: ADR 0018; ADR 0021.
- **Where**: the reboot path in `kern/machine.rs` calls the debugger
  entry, which panics because there is no debugger.
- **Done when**: `host_reboot` with `RB_DEBUGGER` parks every CPU,
  prints `debugger requested` and waits for GDB.

## Third-party runtime crates

- **ADR**: ADR 0023.
- **Where**: `spin` (the kernel, in 9 files, and `clock`'s
  `CriticalLock`).
- **Done when**: no `Cargo.toml` in the workspace names `spin`.

## `cargo deny` does not run

- **ADR**: ADR 0023.
- **Where**: there is no `deny.toml`, and no CI to run it.
- **Done when**: `deny.toml` exists and CI runs `cargo deny check`.

## Gates are not `mise` tasks

- **ADR**: ADR 0024.
- **Where**: `mise.toml` has no task for the ABI pack in `abi-test/`;
  `test::abi` runs only the dev Hurd smoke test. Its
  `test-boot-script` task runs a `boot-script-tests/` directory that
  does not exist.
- **Done when**: every gate of ADR 0024 is a `mise` task and every
  task runs.

## No CI

- **ADR**: ADR 0024.
- **Where**: the repository has no CI configuration.
- **Done when**: CI runs every gate's `mise` task on every PR, with the
  boot gates at least nightly.

## No Hurd smoke test

- **ADR**: ADR 0002; ADR 0024.
- **Where**: the Hurd reference image is booted by hand, through
  untracked scripts in `debug/`.
- **Done when**: a script fetches the pinned image and checks its
  sha256, and a `mise` task runs the smoke test of ADR 0002 end to end.

## Old-style licence headers

- **ADR**: ADR 0010.
- **Where**: 147 files carry `Copyright (c)` lines, with a provenance
  block that lacks `original files:`.
- **Done when**: `grep -rlE '^//\s+Copyright \(c\)' crates` prints
  nothing.

## Original files under BSD-2-Clause

- **ADR**: ADR 0010.
- **Where**: 19 original files: `kernel/src/` `main.rs`, `panic.rs`,
  `version.rs`, `arch.rs`, `arch/types.rs`, `arch/x86_64/mod.rs`,
  `arch/x86_64/pio.rs`, `device/mod.rs`, `ffi/mod.rs`, `glue/mod.rs`,
  `glue/mig.rs`, `ipc/mod.rs`, `kern/mod.rs`, `kern/console.rs`,
  `utils/mod.rs`, `utils/cell.rs`, `utils/string.rs`, `vm/mod.rs`; and
  `mach-mig-sys/src/lib.rs`.
- **Done when**: every `BSD-2-Clause` file in `crates/` has a
  provenance block.

## Upstream names in docs and comments

- **ADR**: ADR 0010; ADR 0025.
- **Where**: about 177 files cite upstream source paths or upstream
  internal names outside their provenance block.
- **Done when**: outside `// Derived from` and `// original files:`
  lines, no comment in `crates/` names a `.c`, `.h` or `.S` file, and
  none cites an upstream internal name.

## A file named after `i386`

- **ADR**: ADR 0008.
- **Where**: `arch/x86_64/debug_i386.rs`.
- **Done when**: no file in `crates/` has `i386` in its name except
  the `mach_i386` ABI files.

## Code markers

- **ADR**: ADR 0012.
- **Where**: `TODO`, `FIXME` and `XXX` comments in `arch/x86_64/locore.rs`,
  `arch/x86_64/apic.rs`, `vm/vm_user.rs` (four), `vm/vm_object.rs`
  and `vm/vm_map.rs` (two).
- **Done when**: `grep -rnE '//.*\b(TODO|FIXME|XXX)\b' crates` prints
  nothing. A marker that names a gap becomes its own entry; one that
  only repeats a limit GNU Mach has too is deleted.
