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

## The kernel runs the legacy clock

- **ADR**: ADRs 0038, 0039 and 0042; ADR 0028.
- **Where**: `kern/mach_clock.rs` keeps its own timeout wheel, pool and
  soft clock, and `arch/x86_64/hardclock.rs`, `com.rs`, `kd/esc.rs` and
  `kern/syscall_subr.rs` arm timeouts through it; nothing calls
  `Clock::tick`.
- **Done when**: every timeout is a `clock` `Callout` on a
  `HashedWheel`, one CPU calls `Clock::tick`, and the legacy wheel is
  gone.

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
- **Where**: the IPC handoff path in `kern/ipc_sched.rs` resets the
  woken thread's timer.
- **Done when**: no wakeup path touches another thread's timer.

## The IPC timeout conversion overflows

- **ADR**: ADR 0002.
- **Where**: the millisecond-to-tick conversion in `kern/ipc_sched.rs`
  multiplies in 32 bits and wraps above about 11.9 hours.
- **Done when**: every `u32` millisecond timeout converts to the tick
  count GNU Mach's arithmetic intends, without wrapping.

## The machine-independent core is still in `kernel`

- **ADR**: ADR 0014.
- **Where**: `ipc/`, `vm/` above the pmap, and the task, thread,
  scheduler and device-dispatch modules of `kern/` and `device/`; the
  mechanisms `kern/rcu.rs`, `kern/rdxtree.rs`, `kern/boot_script.rs`
  and `kern/elf_load.rs`.
- **Done when**: `crates/wip-mach` exists and holds the
  machine-independent core, and each mechanism has moved to its own
  crate or has been found to fail the split test.

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
  `inline_always` crate-wide to mirror the C; 239 `#[allow]`
  attributes across `crates/`; `kernel` does not deny
  `allow_attributes`.
- **Done when**: no `#[allow(` or `#![allow(` remains in `crates/`, and
  every crate denies `allow_attributes` and
  `allow_attributes_without_reason`.

## The panic lints are not denied

- **ADR**: ADR 0018.
- **Where**: `crates/kernel/Cargo.toml`.
- **Done when**: `kernel` and `wip-mach` deny `unwrap_used`,
  `expect_used`, `indexing_slicing` and `panic`.

## `RB_DEBUGGER` panics

- **ADR**: ADR 0018; ADR 0021.
- **Where**: the reboot path in `kern/machine.rs` calls the debugger
  entry, which panics because there is no debugger.
- **Done when**: `host_reboot` with `RB_DEBUGGER` parks every CPU,
  prints `debugger requested` and waits for GDB.

## Console code keeps kdb hooks

- **ADR**: ADR 0021.
- **Where**: `arch/x86_64/kd/mod.rs` and `kd/keyboard.rs`.
- **Done when**: no `kdb` or `ddb` reference remains in `crates/`.

## Third-party runtime crates

- **ADR**: ADR 0023.
- **Where**: `spin` (the kernel, in 9 files, and `clock`'s
  `CriticalLock`) and `intrusive-collections` (`vm/vm_map.rs` and the
  tree half of `kern/slab.rs`, which use its `RBTree`; `kern/mach_clock.rs`
  and `arch/x86_64/ioapic.rs`, for the legacy timeout wheel's
  `Timeout.chain`). While `intrusive-collections` remains, an object with
  one of its links is born whole: one struct literal, `Link::new()`
  included, `ptr::write`n into fresh storage, never fields stamped over
  recycled or zeroed memory. Its links carry an unlinked marker, and a
  stale one panics as "already linked" on the next insert.
- **Done when**: no `Cargo.toml` in the workspace names `spin` or
  `intrusive-collections`.

## No ordered `collections` shape

- **ADR**: none, needs an ADR.
- **Where**: `vm/vm_map.rs` (the address tree, keyed by first address, and
  the gap tree, keyed by gap size with duplicate keys) and `kern/slab.rs`
  (`active_slabs`, keyed by buffer base), which use `intrusive-collections`'
  `RBTree`. They need insertion, removal by node address, and floor and
  ceiling lookups.
- **Done when**: `collections` has an ordered shape, those three trees use
  it, and no `Cargo.toml` in the workspace names `intrusive-collections`.

## `cargo deny` does not run

- **ADR**: ADR 0023.
- **Where**: there is no `deny.toml`, and no CI to run it.
- **Done when**: `deny.toml` exists and CI runs `cargo deny check`.

## No `checked` profile

- **ADR**: ADR 0022.
- **Where**: the workspace `Cargo.toml` has no `[profile.checked]`;
  `arch/x86_64/apic.rs` waits for one to turn a check into a
  `debug_assert!`.
- **Done when**: `[profile.checked]` exists and the ABI suite boots it.

## Gates are not `mise` tasks

- **ADR**: ADR 0024.
- **Where**: `mise.toml` has no task for the ABI suite, the Hurd smoke
  test, `fmt`, clippy or `cargo doc`; its `test-boot-script` task runs
  a `boot-script-tests/` directory that does not exist.
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
