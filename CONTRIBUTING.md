# Contributing

Rules for this project. Follow them unless a PR justifies changing the
rule itself. Every rule is an ADR under [`docs/adr/`](docs/adr/), and
this file is the map. ADRs describe the target; the gap between it and
the code is in [`DEBT.md`](DEBT.md). A replaced ADR is deleted and its
number is never reused, so the list has gaps.

## Scope and shape

- [0001 — A preemptible kernel is a non-goal](docs/adr/0001-preemptible-kernel-is-a-non-goal.md)
  — a thread leaves its CPU in kernel mode only by blocking.
- [0002 — Full GNU Hurd support defines Mach ABI compatibility](docs/adr/0002-full-gnu-hurd-support-defines-mach-abi-compatibility.md)
  — exactly GNU Mach's ABI as the current Debian GNU/Hurd sees it,
  proven by `abi-test/` and the Hurd smoke test; Multiboot v1.
- [0003 — x86_64 is the only target for now](docs/adr/0003-x86-64-is-the-only-target-for-now.md)
  — deliberate deferral; x86_32 is rejected as dead.
- [0013 — GNU Mach is a behaviour reference, not a tracked source](docs/adr/0013-gnu-mach-is-a-behaviour-reference-not-a-tracked-source.md)
  — no upstream sync; translated code is scaffolding.
- [0019 — The kernel drives only what it needs itself](docs/adr/0019-the-kernel-drives-only-what-it-needs-itself.md)
  — disks and networks are userspace drivers; no Linux glue.
- [0020 — SMP is the only build](docs/adr/0020-smp-is-the-only-build.md)
  — CPU count from ACPI, capped by one constant.
- [0021 — No in-kernel debugger](docs/adr/0021-no-in-kernel-debugger.md)
  — GDB through QEMU plus the serial panic line.
- [0050 — The console stays in the kernel](docs/adr/0050-the-console-stays-in-the-kernel.md)
  — kd/com and the kd/kbd/mouse devices are ABI; rumpdisk and netdde are
  storage and network.

## Architecture

- [0006 — Portable subsystems are modularized behind a `Platform` trait](docs/adr/0006-portable-subsystems-are-modularized-behind-a-platform-trait.md)
  — the `lock` / `clock` shape; deviations need an ADR.
- [0014 — The machine-independent core is the `wip-mach` crate](docs/adr/0014-the-machine-independent-core-is-the-wip-mach-crate.md)
  — code moves out of `kernel` when a seam can carry it.
- [0015 — `kern_return_t` exists only at the ABI boundary](docs/adr/0015-kern-return-t-exists-only-at-the-abi-boundary.md)
  — `Result` inside, one conversion at the trap entry and MIG seam.
- [0016 — References are dropped; death is explicit](docs/adr/0016-references-are-dropped-death-is-explicit.md)
  — freeing never sleeps; death does the work that may.
- [0017 — Allocation is fallible, never waits, and has no global allocator](docs/adr/0017-allocation-is-fallible-never-waits-and-has-no-global-allocator.md)
  — `kmem`'s `Alloc` trait with its own `KBox`/`KVec`; no allocation
  in interrupt handlers.
- [0018 — Userspace can never panic the kernel](docs/adr/0018-userspace-can-never-panic-the-kernel.md)
  — errors for bad input and exhaustion, privilege included.
- [0028 — A thread woken early cancels its own timeout](docs/adr/0028-a-thread-woken-early-cancels-its-own-timeout.md)
  — the waker never touches a wheel.

## Toolchain and build

- [0004 — Rust is the implementation language](docs/adr/0004-rust-is-the-implementation-language.md)
  — stable Rust, `cargo build` only; GNU MIG and `cc` at the MIG seam
  alone.
- [0052 — A benchmark may vendor the reference it measures against](docs/adr/0052-a-benchmark-may-vendor-the-reference-it-measures-against.md)
  — frozen and byte-identical below its provenance header; such a crate
  is never linked into the kernel.
- [0007 — Inline assembly only](docs/adr/0007-inline-assembly-only.md)
  — `asm!` / `global_asm!` / `naked_asm!`, `att_syntax`; no `.s`/`.S`
  files.
- [0022 — One feature set, two profiles](docs/adr/0022-one-feature-set-two-profiles.md)
  — no Cargo features; `dev` and `release`.
- [0023 — Third-party runtime crates are the exception](docs/adr/0023-third-party-runtime-crates-are-the-exception.md)
  — `no_std`, pinned, audited, licence-compatible; none today.
- [0024 — What a change must pass](docs/adr/0024-what-a-change-must-pass.md)
  — 100% coverage for portable crates, boots on every profile, all as
  `mise` tasks in CI.

## Code

- [0005 — `unsafe` is allowed but must be justified](docs/adr/0005-unsafe-is-allowed-but-must-be-justified.md)
  — safe abstractions first; every use carries a `// SAFETY:` contract.
- [0008 — Architecture names are `x86` and `x86_64`](docs/adr/0008-architecture-names-are-x86-and-x86-64.md)
  — never `i386`, `i686`, `amd64`, except in ABI names.
- [0025 — Documentation comments](docs/adr/0025-documentation-comments.md)
  — document what the compiler cannot check.
- [0026 — Lint policy](docs/adr/0026-lint-policy.md)
  — pedantic and nursery denied; `#[expect]`, never `#[allow]`.
- [0027 — Kernel Rust idiom](docs/adr/0027-kernel-rust-idiom.md)
  — C only at the MIG seam, no `static mut`, types with methods.

## Licensing and process

- [0010 — SPDX headers and provenance](docs/adr/0010-spdx-headers-and-provenance.md)
  — SPDX per file; the licence follows the crate's content; derived
  files pin their upstream source.
- [0053 — An MIT crate may carry code derived from MIT upstream](docs/adr/0053-an-mit-crate-may-carry-code-derived-from-mit-upstream.md)
  — the crate stays MIT and the file keeps its upstream holders; other
  derived code stays in GPL crates.
- [0011 — AI-assisted contributions](docs/adr/0011-ai-assisted-contributions.md)
  — allowed under accountability, licensing, and disclosure
  conditions.
- [0012 — Docs describe the target; `DEBT.md` describes the gap](docs/adr/0012-docs-describe-the-target-debt-md-describes-the-gap.md)
  — every rule is an ADR, all in `docs/adr/`; one glossary; plans and
  as-is notes are not kept.

## Locks (`crates/lock`)

- [0029 — The lock type decides the interrupt policy](docs/adr/0029-the-lock-type-decides-the-interrupt-policy.md)
  — no spl; spin, irq spin and sleeping locks each fix their own.
- [0030 — Lock waiters queue in a hashed wait table the platform supplies](docs/adr/0030-lock-waiters-queue-in-a-hashed-wait-table.md)
  — every lock stays one word.
- [0031 — Own lock wrappers, not lock_api](docs/adr/0031-own-lock-wrappers-not-lock-api.md)
  — loom-visible cells, platform state in guards.
- [0032 — A contended lock is handed to its first waiter](docs/adr/0032-a-contended-lock-is-handed-to-its-first-waiter.md)
  — handoff in arrival order; no waiter starves.
- [0033 — No priority inheritance, no priority ordering](docs/adr/0033-no-priority-inheritance-no-priority-ordering.md)
  — without preemption, inversion can hardly happen.
- [0034 — The lock set follows Zircon](docs/adr/0034-the-lock-set-follows-zircon.md)
  — no RCU, sequence or spinning reader-writer locks, in the crate or
  the kernel.
- [0035 — One generic lock and guard over raw-lock traits](docs/adr/0035-one-generic-lock-and-guard.md)
  — `Lock<R, T>`; the guard is the only way to the data.
- [0036 — A thread holds at most one lock of a class at a time](docs/adr/0036-a-thread-holds-at-most-one-lock-of-a-class.md)
  — no multi-lock guard; the order checker enforces it.

## Clock (`crates/clock`)

- [0037 — Timer wheels are Scheme 6, not a hierarchy](docs/adr/0037-timer-wheels-are-scheme-6-not-a-hierarchy.md)
  — 256 unsorted buckets; a hierarchy needs new measurements.
- [0038 — One clock per machine, one ticker CPU](docs/adr/0038-one-clock-per-machine-one-ticker-cpu.md)
  — every other use is a read.
- [0039 — `Callout` is the only public arm path](docs/adr/0039-callout-is-the-only-public-arm-path.md)
  — its `Drop` cancels and waits.
- [0040 — The timer record API stays crate-private and unsafe](docs/adr/0040-the-timer-record-api-stays-crate-private-and-unsafe.md)
  — the primitives `Callout` is built from.
- [0041 — A timer wheel owns its lock](docs/adr/0041-a-timer-wheel-owns-its-lock.md)
  — an irq spin lock from `lock`, since the clock interrupt reaches it.
- [0042 — Timer wheels poll from the interrupt and advance deferred](docs/adr/0042-timer-wheels-poll-from-the-interrupt-and-advance-deferred.md)
  — actions run with the lock released.

## Collections (`crates/collections`)

- [0043 — Each `collections` shape shares no code](docs/adr/0043-each-collections-shape-shares-no-code.md)
  — a link belongs to its shape.
- [0044 — The `collections` operation set is closed](docs/adr/0044-the-collections-operation-set-is-closed.md)
  — no `len`; pick the smallest shape.
- [0045 — Lifetimes carry the safety of `collections`](docs/adr/0045-lifetimes-carry-the-safety-of-collections.md)
  — only what a lifetime cannot express is `unsafe`.
- [0046 — Leaving a `collections` structure writes nothing](docs/adr/0046-leaving-a-collections-structure-writes-nothing.md)
  — no unlinked marker, no `Drop`.
- [0047 — Pinned `collections` heads write through `Cell`s](docs/adr/0047-pinned-collections-heads-write-through-cells.md)
  — pointers into the head stay valid.
- [0048 — `collections` adapter macros bind the link field uncast](docs/adr/0048-collections-adapter-macros-bind-the-link-field-uncast.md)
  — a wrongly typed link fails to compile.
- [0049 — `collections` `Debug` prints link pointers only](docs/adr/0049-collections-debug-prints-link-pointers-only.md)
  — no `Node: Debug` bound.
- [0051 — `collections` orders nodes in a red-black tree](docs/adr/0051-collections-orders-nodes-in-a-red-black-tree.md)
  — a three-word link, a one-word head, a compare that never reaches the rebalancing.

Project vocabulary is in [`GLOSSARY.md`](GLOSSARY.md).
