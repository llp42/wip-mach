# Which `kernel` modules can become crates

> **Status (2026-10): research note.** Nothing here is decided or
> landed. It ranks the modules of `crates/kernel/src` by how few things
> they need from the rest of the kernel, tests each module the user
> named against the split test of ADR 0014, and orders a possible
> extraction. It changes no code, no ADR and no `DEBT.md` entry.

Facts carry `file:line` evidence; paths are under `crates/kernel/src`
unless they start with `docs/`, `crates/` or name a root file.
Statements that are a reading rather than a quote say "inference".

## Sources and their limits

- **wip-mach working tree** at `d379b8f` (clean). Primary source for
  every edge, line count and line number below.
- **ADRs** 0002, 0006, 0012, 0014-0019, 0023, 0024, 0027, 0050 (read
  in full) and 0010 (read to its Consequences); 0026, 0034, 0043, 0044
  only through their `CONTRIBUTING.md` lines and the first paragraphs;
  `DEBT.md`,
  `CONTRIBUTING.md`, `GLOSSARY.md`; `crates/{kmem,lock,collections,clock}`
  `README.md`/`Cargo.toml`/`src/platform.rs`; `crates/kmem/RESEARCH.md`
  (section (f)), `RESEARCH-slab-rbtree.md` and
  `RESEARCH-mach-clock-removal.md` (section 5).
- **The dependency graph** is mine, built by a throwaway script
  (kept in the session scratchpad, not in the repo). Method: for each of
  the 193 `.rs` files under `crates/kernel/src` it strips comments and
  strings, parses every `use crate::…`, `use super::…`, `use self::…`
  tree (nested braces expanded) and every inline `crate::…`/`super::…`
  path, and resolves each path to the deepest module file it names. An
  **edge** is "file A names an item of file B"; the counts below are
  distinct files, not references (2,795 references make 1,516 edges).
  Limits:
  - It is file-level. A file that names one type of a big module scores
    one edge, so it overstates coupling when the type is opaque and
    understates it when a function reaches through a raw pointer
    without naming the module (inference: `BootstrapHost` is the
    example, `kern/bootstrap.rs:287,330`).
  - `ipc/mod.rs` is a node with 40 kernel importers because it defines
    `IpcPort`, `IpcSpace` and the other object records, not only
    declares modules.
  - Method calls through values, trait impls and macros that expand to
    paths (`kprint!`, `kpanic!`) are seen only through the `use` that
    brings the macro in.
  - A `use super::` inside an inline `mod` (`kern/slab.rs:212`) resolves
    to the wrong parent; I ignored those four edges.
  - There is no `#[cfg(test)]` anywhere in `crates/kernel/src`, so the
    graph is the image's graph.
- **Classes.** *arch* is `arch/x86_64/**` (63 files). *seam* is `ffi/`,
  every `*_ffi.rs`, `glue/mod.rs`, `glue/mig.rs`, `main.rs`, `panic.rs`,
  `version.rs`: the MIG seam and the entry points (ADR 0027). *found.*
  (foundation) is the 22 files every module uses and that must be
  replaced or moved first rather than split around: `kern/{debug,
  console,types,lock,kmutex,smp,policy,kheap,slab,printf}.rs`,
  `utils/{cell,string,atoi,delay}.rs`, `vm/{error,types}.rs`,
  `glue/time_value.rs`, `device/return.rs`, `config.rs`, `arch.rs`,
  `arch/{types,vm_param}.rs`. *core* is every other file. These classes
  are my cut, not a repo term.
- **Not checked:** no build, boot, coverage run or benchmark; no
  measurement of what a split costs in lines. `.mimocode/plans/*` was
  not read (untracked agent plans, not a primary source). Git history
  is 4 commits and says nothing about extraction intent. The `lock`
  `Platform` was read, not compiled against RCU. I did not diff GNU Mach
  (ADR 0013); "derived" is read from each file's header (ADR 0010).
- **Name check.** ADR 0014 calls the core crate `wip-mach`;
  `crates/wip-mach` does not exist (`DEBT.md`, "The machine-independent
  core is still in `kernel`"), so the core is `kernel` today. "Split"
  below means one of two things: a **mechanism crate** (ADR 0014's
  RCU, radix tree, boot-script parser, ELF loader) or, later, a move
  into `wip-mach`.

## 1. What the graph says

| Measure | Value |
|---|---|
| Files / distinct edges / references | 193 / 1,516 / 2,795 |
| Non-arch files (130): edges / edges into `arch/` | 1,069 / 207 |
| `arch/` (63 files): edges back into non-arch | 173 |
| One strongly connected component, arch included | 136 files, 94,159 lines |
| Same, with arch, seam and the 22 foundation files cut | **59 files, 59,266 lines** (kern 22, vm 10, ipc 18, device 9) |
| Acyclic files left outside it | 20: 4 `mod.rs` hubs, 10 leaf consumers, 6 dependency leaves (below) |

Reading (inference): the kernel is one cycle. What is outside the
59-file cycle after the cut is either a **leaf consumer** (nothing in the
core imports it, but it imports a lot: `kern/bootstrap.rs`,
`kern/startup.rs`, `kern/exception.rs`, `kern/gsync.rs`,
`kern/syscall_sw.rs`, `vm/vm_debug.rs`, `vm/vm_init.rs`,
`ipc/mach_debug.rs`, `device/cons.rs`, `device/subrs.rs`) or a
**dependency leaf** (it imports nothing from the core: `kern/elf_load.rs`,
`kern/rdxtree.rs`, `device/cirbuf.rs`, `vm/vm_external.rs`,
`utils/kd_queue.rs`, and `kern/boot_script.rs` up to one `use` line);
the four `mod.rs` hubs are not modules in this sense.
Only the second kind can be a crate: a crate may be depended on by many
and may depend on few. Fan-in is irrelevant to extractability; fan-out
is not. `kern/bootstrap.rs` has fan-in 1 and a cone of 66 files /
62,386 lines.

**Cone** below means the files reachable from a module along edges, after
the cut. `kern/boot_script.rs` has a cone of 64 files / 61,045 lines
and the whole of it comes from `use crate::kern::task::Task`
(`kern/boot_script.rs:19`); `kern/elf_load.rs`, `kern/rdxtree.rs`,
`device/cirbuf.rs` and `vm/vm_external.rs` have cone 0.

Already host-isolated (zero edges out, compiled verbatim by
`crates/host-tests/src/**/mod.rs` through `#[path]`): `arch/types.rs`,
`arch/vm_param.rs`, `device/return.rs`, `vm/error.rs`, `utils/{atoi,
cell,delay,kd_queue,string}.rs`, `kern/{policy,types}.rs`,
`glue/time_value.rs` (`crates/host-tests/src/utils/mod.rs:6-18`,
`kern/mod.rs:6-9`, `glue/mod.rs:6`). Those files prove the property
already; they are not mechanisms but value types.

## 2. Summary

`in` is kernel / arch / seam importers; `out` is core / foundation / arch
files imported. "Globals" counts `static` items (mut in brackets).
Evidence for each row is in section 3. The full per-file table is the
appendix.

| Module | Lines | in | out | Coupling: arch, seam, globals, alloc | Platform services it would need | Verdict | Blocking `DEBT.md` entries |
|---|---:|---|---|---|---|---|---|
| `kern/elf_load.rs` | 634 | 1 / 0 / 0 | 0 / 2 / 0 | types only (`VmOffset`, `VmSize`, `VmProt`); 0 globals; no alloc; `c_int` error codes | none: the two callbacks become a source and a sink trait | **split now** | core in `kernel`; `kern_return_t` inside; lint allowances |
| `kern/boot_script.rs` | 707 | 1 / 0 / 0 | 1 / 0 / 0 | `Task` pointer only; 0 globals; `alloc::{CString, Vec}` | its own `Host` trait (7 methods, exists) plus an `Alloc` | **split now** (together with dropping `alloc`) | kernel links `alloc`; core in `kernel` |
| `kern/rdxtree.rs` | 1,099 | 5 / 0 / 0 | 0 / 3 / 0 | 0 arch; 1 global (node cache); slab cache | `kmem::Alloc` for 544-byte nodes | **split now** | core in `kernel`; (slab seam is not required if `A: Alloc`) |
| Value-type set (`vm/error`, `kern/types`, `glue/time_value`, `kern/policy`, `device/return`, `arch/types`, `arch/vm_param`, `VmProt`/`VmInherit`) | 22-255 each, about 700 | 5-37 kernel importers each | 0 | none | none | **split now**, after one error enum is chosen | `kern_return_t` inside; host-tests shim |
| `kern/rcu.rs` | 676 | 4 / 0 / 0 | 2 / 6 / 2 | per-CPU id, spl; 5 globals; `alloc::Box`, `try_box`; 1 `extern "C"` | cpu id, online CPUs, irq-quiet, sleep/wake by event, kernel thread entry, `Alloc`, a writer `Mutex` | **split after `lock` adoption** | locks and spl; kernel links `alloc` |
| `device/cirbuf.rs` | 283 | 1 / 0 / 0 | 0 / 2 / 0 | `kalloc`; 0 globals | `kmem::Alloc` | split after slab seam (low value, one user) | none directly |
| `vm/vm_external.rs` | 352 | 4 / 0 / 0 | 0 / 4 / 0 | 3 slab caches; 4 globals | `kmem::Alloc` or a cache handle | split after slab seam (low value, VM-private) | none directly |
| `kern/slab.rs` | 1,806 | 29 / 7 / 2 | 7 / 6 / 2 | `kvtophys`, pmap bounds; 8 globals | page source (about 8 calls) | **stays** (ADR 0017) | slab derived; allocator may sleep; third-party crates; trees |
| `kern/kheap.rs` | 172 | 3 / 0 / 0 | 0 / 1 / 0 | `#[global_allocator]`; `alloc` | none | **stays**, then deleted | kernel links `alloc`; allocator may sleep |
| `kern/bootstrap.rs` | 867 | 1 / 0 / 0 | 12 / 6 / 6 | 6 arch files; 2 atomics; `alloc`; 2 `extern "C"` | about 20 task/thread/ipc/vm calls | **stays whole**; pieces leave (section 3.1) | counted by hand; kernel links `alloc` |
| `kern/printf.rs` | 84 | 1 / 0 / 0 | 1 / 1 / 0 | `device::cons::getc` | none | stays (folds into bootstrap) | none |
| `kern/console.rs` | 137 | 23 / 20 / 0 | 1 / 0 / 0 | `cons::putc` | none | **stays** (ADR 0050) | none |
| `device/chario.rs` | 1,512 | 1 / 3 / 0 | 7 / 4 / 3 | clock wheel, spl, `io_req`; 8 globals | many | **stays** | locks and spl |
| `device/net_io.rs` | 2,366 | 4 / 0 / 0 | 8 / 3 / 2 | 28 statics, 4 locks | many | **stays**; the filter half may be dead (3.7) | none |
| `ipc/ipc_table.rs` | 156 | 3 / 0 / 0 | 1 / 4 / 0 | 1 `static mut`; `kalloc` | none | stays (IPC cluster) | `static mut` |
| `kern/eventcount.rs` | 204 | 2 / 0 / 0 | 2 / 3 / 3 | spl, per-CPU, `locore` | scheduler | stays | locks and spl |
| `kern/gsync.rs` | 823 | 1 / 0 / 1 | 7 / 4 / 2 | `user_access`; 1 `static mut` | scheduler, VM | stays | `static mut` |
| `kern/mach_factor.rs` | 150 | 2 / 0 / 1 | 2 / 0 / 0 | 2 atomics | processor sets | stays | none |
| `kern/priority.rs` | 151 | 1 / 0 / 0 | 5 / 1 / 2 | spl, per-CPU | scheduler | stays | locks and spl |
| `kern/timer.rs` | 207 | 2 / 0 / 2 | 1 / 3 / 0 | `Thread` in `read_times` | none | split after `clock::Timer` | none in `DEBT.md` (clock note section 5 only) |
| `utils/string.rs` | 330 | 2 / 3 / 0 | 0 / 0 / 0 | 12 `no_mangle` mem/str symbols | none | stays (symbol provider) | C-visible symbols |
| `utils/{atoi,delay,kd_queue}.rs` | 65 / 24 / 190 | 0-1 / 1-4 / 0 | 0 / 0-1 / 0 | arch-only users | none | stays, under `arch/` (inference) | none |

## 3. Candidates

### 3.1 `kern/bootstrap.rs`: does it move?

**Verdict: it cannot move whole. As a standalone crate it fails ADR
0014's split test; it needs no crate, because the boot and wiring stay in
`kernel` by design.** Checked, not assumed: `bootstrap.rs` is a one-way
consumer (fan-in 1, no cycle), so nothing about *who uses it* keeps it
in `kernel`. What keeps it there is what it imports.

*Inbound.* One edge: `kern/startup.rs:205` calls `bootstrap::create()`
as the last step before the startup thread becomes the pageout daemon
(`kern/startup.rs:208-215`). Nothing in the 59-file cycle imports it, and
it is not in the cycle (it is a consumer). `arch/` and the seam do not
import it.

*Outbound* (all at `kern/bootstrap.rs:19-40` unless noted):

| Target | What it takes | Lines |
|---|---|---|
| `kern/boot_script` | `Script`, `Host`, `Command` | 28, 89-92, 197-309, 423-459 |
| `kern/elf_load` | `exec_load`, `ExecInfo`, `ExecSectype` | 31, 628-641, 559-620 |
| `kern/printf` | `safe_gets` | 34, 264 |
| `kern/task` | `create_kernel_task`, `set_name`, `max_priority`, `resume`, `terminate`, `deallocate`, `current_task`, `MapSource`, `BASEPRI_USER` | 36, 116-122, 203-225, 238, 354-356, 575 |
| `kern/thread` | `Thread::create/start/resume/deallocate`, `saved.other` | 37, 124-149, 803-824 |
| `kern/sched_prim` | `thread_sleep`, `thread_wakeup_prim` | 35, 816, 857 |
| `kern/host` | `host_self`, `host_priv_self` | 32, 137, 222, 362 |
| `ipc/ipc_port`, `ipc/mach_port`, `ipc/mod` | `make_send`, `insert_right`, `IpcPort`, `IpcSpace` | 25-27, 311-344 |
| `vm/vm_user`, `vm/vm_map` | `allocate`, `protect`, `map`, `round_page`, `trunc_page`, `VmMap` | 38-40, 580-617, 702-717 |
| `device/device_init` | `master_device_port` | 141, 363 |
| `arch/x86_64` | `boot_modules`, `kernel_cmdline` (`model_dep`), `MultibootModule`, `set_user_regs`, `user_stack_low` (`pcb`), `per_cpu::thread`, `user_access::copyout`, `locore::thread_bootstrap_return` | 20-24, 191, 859 |
| foundation | `kprint!`, `kpanic!` (12 sites), `SimpleLock`, `VmProt`/`VmInherit`, `VmOffset` | 29-33, 38 |

Totals: 12 core, 6 arch and 6 foundation files (one of them
`arch/types.rs`); 44 references. It reads fields through raw pointers
it does not name a module for: `(*task).itk_space` (330),
`(*target).itk_sself` (287), `(*thread).saved.other` (145, 162, 809, 839).

*Test against ADR 0014 (`docs/adr/0014-…:11-14`).* A `Platform` trait
could carry this only by listing about 20 operations whose bodies are
Task, Thread, port-right, VM-map and user-copy internals. That is the
"mirroring its internals" case ADR 0014 excludes. As a standalone crate
it **fails**. As a part of the future `wip-mach` it needs no trait at
all, but ADR 0014 gives the boot and wiring to `kernel` ("`kernel` holds
x86_64, boot, the MIG seam and the wiring", `docs/adr/0014-…:7-8`), and
"code that cannot move stays in `kernel`, and that is the target, not
debt" (`:12-14`). `DEBT.md` does not list `kern/bootstrap.rs` among the files to
move (the "core is still in `kernel`" entry names rcu, rdxtree,
boot_script, elf_load). So: **stays in `kernel`**.

*What can leave.* Two files already separate from it and listed by
ADR 0014: `kern/boot_script.rs` (3.2) and `kern/elf_load.rs` (3.3).
Inside `bootstrap.rs` itself, about 100 lines are pure and could ride
along with them in a boot crate (inference; none is required):

- `is_compat` (`:98-108`), `CompatStrings::from_cmdline` (`:478-521`),
  `port_name` (`:525-527`): byte and string work, no kernel call. They
  use `alloc` (`Vec`, `CString`, `format!`, `:41-44`) and three
  `.expect` (`:518,519,526`), so they need the same `alloc` removal as
  `boot_script`.
- The argument-vector and stack layout in `build_args_and_stack`
  (`:682-770`): the arithmetic is pure, but it interleaves
  `vm_user::map` (703), `set_user_regs` (721) and `copyout` (731-769).
  It would be a function over a `UserMemory` trait (map the stack,
  set registers, copy out): 3 methods.

What stays is the `BootstrapHost` impl (`:195-357`), the compat launch
(`:110-192`), `exec_cmd`/`user_bootstrap` (`:783-860`), `read_exec` and
`boot_read` (`:529-620`): roughly 760 of 867 lines. Extracting
`boot_script` and `elf_load` therefore does not shrink `bootstrap.rs`
(they are other files); it only turns two of its imports into crate
imports.

*Fix before any move.* Of 56 `unsafe` sites only 15 carry a `SAFETY`
comment (ADR 0005; grep count, approximate). Two `extern "C"`
continuations (`:158`, `:837`) are the `Thread::Continuation` type
(`kern/thread.rs:93`); `wip-mach` must hold no C-ABI symbols (ADR 0014
consequences, ADR 0027). Failures `kpanic!` on boot paths (ADR 0018
permits it with `#[expect]` and `# Panics`; neither is present).

### 3.2 `kern/boot_script.rs` (707 lines)

- **Inbound:** `kern/bootstrap.rs:28` only (`Script`, `Command`, `Host`).
  Arch 0, seam 0.
- **Outbound:** one edge, `crate::kern::task::Task` (`:19`), used at
  `:124` (`insert_task_port`), `:144` (`free_task`), `:160`
  (`Command::task`), `:184`, `:196` (`Value::Task`, `Resolved::Task`).
  Everything else is the `core` and `alloc` crates.
- **Already a seam.** `trait Host` (`:60-144`) has 7 methods:
  `create_task`, `resume_task`, `prompt_resume_task`, `insert_port`,
  `insert_task_port`, `exec_command`, `free_task`. Its doc says "The
  script itself owns no kernel logic" (`:69-71`). `Error` is already a
  typed enum with `Display` (`:24-52`), so ADR 0015 holds.
- **To make it a crate:** turn `Task`, the `*mut c_void` port
  (`:183`) and module hook (`:155`) into associated types of `Host`
  (inference: this removes the only edge and makes the cone 0).
- **Violations to fix first.**
  - ADR 0017: `use alloc::ffi::CString; use alloc::vec::Vec;`
    (`:20-21`), about a dozen `Vec`/`CString` sites. `kmem` has `KVec<T, A>` but no
    `CString` (grep of `crates/kmem/src`), so a NUL-terminated byte
    string type is needed. It is one of the files that use `alloc`
    (`DEBT.md` counts 9; grep finds `alloc::` in `bootstrap`,
    `boot_script`, `rcu`, `kheap`, `device/intr`, `device/ds_routines`,
    `arch/.../model_dep`, `arch/.../multiboot` and `main.rs`).
  - ADR 0018: indexing `self.symbols[index]` (`:294,310,550`) with
    `indexing_slicing` not yet denied.
  - ADR 0016: `free_task` (`:144`) is explicit release; a `Host::Task`
    with `Drop` is the target, but until `Task` has a reference type
    (`DEBT.md`, "Counted objects are counted by hand") the trait keeps
    `free_task`.
- **ADR 0010:** header is GPL-2.0-or-later with "Derived from GNU Mach"
  (`:1-7`), so the crate is GPL-2.0-or-later, not MIT.
- **Verdict: split now.** It is the cheapest large mechanism: one
  import, an existing trait, no globals.

### 3.3 `kern/elf_load.rs` (634 lines)

- **Inbound:** `kern/bootstrap.rs:31` only.
- **Outbound:** `arch::types::{VmOffset, VmSize}` (`:11`) and
  `vm::types::VmProt` (`:12`): scalar and bit-flag types, no service.
  `VmProt` is in `vm/types.rs`, a file that also defines `VmObject`
  (`vm/types.rs:149`) and is in the cycle (`vm/types.rs ↔ vm/vm_page.rs`),
  so the crate must carry its own protection bits (`ExecSectype` already
  wraps raw bits, `:23-27,41`).
- **Already a seam:** `ReadFn` (`:71`) and `ReadExecFn` (`:91`) are the
  two callbacks (`boot_read`, `read_exec` at `bootstrap.rs:535,559`).
  Zero `Platform` services in ADR 0006's sense; two small traits
  (read bytes; place a section).
- **Violations to fix first.**
  - ADR 0015: `exec_load` returns `c_int` (`:601-606`) with the codes
    6000-6002 (`:236-250`) and `Callback(c_int)`; `bootstrap.rs:633-638`
    prints the number. Return `Result<ExecInfo, ExecError<E>>`.
  - ADR 0027: handles are `*mut c_void`; `ExecInfo` is a `#[repr(C)]`
    mirror (`:105-111`); `Elf32_*` names need
    `#![allow(non_camel_case_types)]` (`:8`). ADR 0026: 11 `#[allow]`.
  - ADR 0005: 20 `unsafe` sites, 2 `SAFETY` comments (grep).
- **ADR 0010:** `SPDX-License-Identifier: HPND` (`:1`), OSF-derived. It
  keeps that licence per file ("never relicensed"); the crate is
  GPL-2.0-or-later (derived code never enters an MIT crate,
  `docs/adr/0010-…:65-67`).
- **Verdict: split now.** It shares no edge with `boot_script`; keep
  them as two crates (ADR 0014 names them separately; different licences,
  inference).

### 3.4 `kern/rdxtree.rs` (1,099 lines)

- **Inbound (5 files):** `ipc/mod.rs:10` (`Rdxtree` held by value in
  `IpcSpaceRecord` at `:478,480`), `ipc/ipc_entry.rs:12`, `ipc/ipc_space.rs:15`,
  `ipc/mach_port.rs:22`, `kern/startup.rs:24,74` (`cache_init`). Arch 0.
- **Outbound:** `kern/slab` (`KmemCache`, `CacheInitFlags`, `:9`),
  `utils/cell::SyncCell` (`:10`), `vm/error::Error` (`:11`). No lock, no
  RCU, no arch (the module is caller-locked).
- **The one real edge** is the node cache: a `static RDXTREE_NODE_CACHE`
  (`:164`) built in `cache_init` (`:169-185`) and used by node `create`
  (`:276-279`) and free (`:308`). ADR 0017 wants each owner to store its
  allocator, so `Rdxtree<A: Alloc>` removes the static; `kmem::Alloc`
  exists and the kernel already implements it (`kern/kheap.rs:40-103`,
  `Kalloc`). With that, the cone is 0 (checked: with `slab`, `SyncCell`
  and `vm::error` cut, no file is reachable).
- **Violations to fix first.**
  - ADR 0027 / 0002: raw `*mut *mut c_void` slots in the API
    (`:596,692`) and `#[repr(C)]` layout asserts (`:154-160`) that mirror
    a C header nothing reads. Inference: the asserts go (the repo already
    drops such asserts, `f6c5ce9 kernel: drop upstream-layout asserts on
    Thread`). Typed `Rdxtree<T>` is the target.
  - ADR 0015: the error is `vm::error::Error`, a `kern_return_t` mirror
    (`:279,605,658`); the crate needs its two variants
    (`ResourceShortage`, `InvalidArgument`) and `ipc` converts.
  - `host_slab_info` (ADR 0002) lists the `rdxtree_node` cache
    (`crates/kmem/RESEARCH.md:147-160`); if nodes come from `Kalloc`
    instead of that cache, that row disappears (inference: check whether
    the Hurd reads it; not checked). Keeping a cache-backed `Alloc` in
    `kernel` avoids the question.
  - ADR 0024: 100% coverage; the module has no test today.
- **`collections` (inference):** not a shape for it. The crate is
  "intrusive ... no structure ever allocates" (`crates/collections/
  README.md:3-4`) and ADR 0043/0044 keep its shapes few and closed; a
  radix tree allocates nodes, so it is its own crate, as ADR 0014 says.
- **ADR 0010:** BSD-2-Clause, derived (Richard Braun, `:1-4`); GPL crate
  hosting a BSD file.
- **Verdict: split now.** Its users are the IPC name tables
  (`ipc/mod.rs:478,480`), a hot path, so it earns host tests and the
  100% gate.

### 3.5 `kern/rcu.rs` (676 lines)

- **Inbound (4):** `kern/machine.rs:23,189` (`note_qs` from
  `tick_accounting`), `kern/sched_prim.rs:979,1270` (`note_qs`),
  `kern/startup.rs:174` (`gp_thread_continue`, the `rcu` kernel thread),
  `vm/memory_object.rs:1164,1219,1339` (the only `Rcu<T>` user, the
  default memory manager). Nothing else calls `call_rcu`,
  `synchronize_rcu`, `rcu_barrier`, `read_lock` or `RcuHead` (grep).
- **Outbound:** `sched_prim` (`assert_wait`, `clear_wait`,
  `thread_block`, `thread_wakeup_prim`, `THREAD_AWAKENED`, `:39`),
  `machine` (`slot(cpu).running` for the online mask, `:333-339`),
  `kmutex::KMutex` (`:36,511,532`), `lock::SimpleLock` (`:37,234`),
  `kheap::try_box` (`:35,539`), `config::MAX_NCPUS` (`:34,55,87`),
  `smp::CpuId`, `utils::cell`; arch `per_cpu::{cpu_id, thread}` (`:32`)
  and `spl::splsched` (`:251,375`).
- **Cycles:** `rcu ↔ sched_prim` (`rcu.rs:39` imports it; `sched_prim.rs:
  979,1270` calls `note_qs`) and `rcu ↔ machine` (`machine.rs:23`).
  Both are call-in hooks, not data: inference that they are `Platform`
  methods the other way round (the kernel calls `note_qs`).
- **Platform surface (inference):** current CPU id and CPU count (const
  generic or `Platform::MAX_CPUS`, ADR 0020), online-CPU mask, an
  irq-quiet section (GLOSSARY), sleep/wake keyed by an event address
  (`:269-276,357-364,383-393`), a way to start the GP thread, `Alloc`,
  and a writer `Mutex`. `lock::Platform` already has `current`,
  `irq_quiet_enter/exit`, `park`, `unpark` (`crates/lock/src/
  platform.rs`) but `unpark` is thread-addressed, while RCU wakes by
  event, so it cannot be reused unchanged.
- **Why it waits.** It uses `KMutex`, `SimpleLock` and `spl`: it cannot
  leave until the kernel adopts `lock` (`DEBT.md`, "The kernel keeps its
  own locks and spl"). `try_box` and `alloc::boxed::Box` (`:35,41`) are
  among the `alloc` uses. ADR 0034 says `lock` holds no RCU
  (`CONTRIBUTING.md`, 0034), so the crate is separate.
- **ADR 0010 (inference):** the file has no `Derived from` block
  (`:1-2`), so it is original; a crate "designed from the literature,
  carrying no derived code" is MIT (`docs/adr/0010-…:14-16`). It would
  match `lock`/`clock`. Not checked: whether QSBR sources it follows
  need citing.
- **Value (inference):** 676 lines for one `Rcu<T>` user.
- **Verdict: split after `lock` adoption** and after the `Platform` is
  sketched.

### 3.6 `kern/slab.rs` and `kern/kheap.rs` versus `crates/kmem`

- **`kmem` today** is the allocator trait and four owning types
  (`KBox`, `KBoxSlice`, `KVec`, `KRawBuf`), MIT, no dependencies
  (`crates/kmem/README.md`, `Cargo.toml`). The kernel uses it in exactly
  one file: `kern/kheap.rs:28` (`Alloc`, `AllocError`).
- **ADR 0017 already decided:** slab and general allocator "stay in the
  `kernel` crate: they are coupled to the page allocator and the VM map"
  (`docs/adr/0017-…:8-10`) and "The slab inside `kmem`" is a rejected
  option (`:48-49`). `kmem/RESEARCH.md` section (f) says typed caches
  "stay in the kernel crate" and lists 37 caches, 90 call sites, the
  cache-specific properties (alignment, `PHYSMEM`, `NOOFFSLAB`,
  `host_slab_info`).
- **`slab.rs` coupling** (`:10-26`): fan-in 38 files (29 kernel, 7 arch,
  2 seam); fan-out 7 core files. Services: grab/release a direct-mapped
  page (`vm_resident::grab`, `release`, `VM_PAGE_DIRECTMAP`, `:1349,
  1401`), wait for a free page (`vm_page::wait`, `:1363`), map pages
  (`vm_kern::kmem_alloc_wired/aligned`, `kmem_free`, `KERNEL_MAP`,
  `:1371-1427`), page to slab lookup through a field of the page record
  (`vm_page::lookup_pa(kvtophys(..))`, `:782,1096,1195,1391`),
  `KERNEL_VIRTUAL_START/END` (`:1411-1412`), a clock read
  (`host_time::elapsed_ticks`, `machine::CLOCK_HZ`, `:1716-1720`), plus
  `SimpleLock`, `kprint!`, `kpanic!`. About 8 page-source calls;
  `lookup_pa` returning a record with a spare word mirrors `VmPage`
  internals (inference), the case ADR 0014 excludes.
- **Two `DEBT.md` entries must close first:** "The slab is derived from
  GNU Mach" (`kern/slab.rs:1-5` is `GPL-2.0-or-later`, derived from
  `kern/slab.c`, Richard Braun) and "The kernel's allocator may sleep"
  (`:1363` loops on `vm_page::wait`; ADR 0017: allocation never waits).
  Only after a non-derived rewrite could the slab be MIT
  (`docs/adr/0010-…:14-16`).
- **`kheap.rs`** is 172 lines: `Kalloc` (`:40-103`, `impl kmem::Alloc`),
  the `#[global_allocator]` (`:105-107`) and `try_box` (users:
  `device/ds_routines.rs:34,653`, `device/intr.rs:25,293`,
  `kern/rcu.rs:35,539`). Its only edge is `slab` (`:23`). Both `DEBT.md`
  entries ("links `alloc` and a global allocator", "may sleep") end with
  "`kern/kheap.rs` are gone".
- **Verdict: both stay.** Slab: stays (ADR 0017), re-test after the two
  entries close, with a `PageSource` trait (inference: the likely own
  crate, not `kmem`). Kheap: stays until deleted. **For the split, the
  slab is the hub that holds back the next tier:** `rdxtree`, `cirbuf` and
  `vm_external` each reach the rest of the kernel only through it
  (3.4, 3.7). An `A: Alloc` parameter lets them avoid it.

### 3.7 `kern/printf.rs`, `kern/console.rs`, `utils/*`, `device/cirbuf.rs`, `device/chario.rs`, `device/net_io.rs`, `ipc/ipc_table.rs`, `vm/vm_external.rs`

**`kern/printf.rs`** (84 lines). Inbound `kern/bootstrap.rs:34` only
(`safe_gets`, `:264`). Outbound `kern/console` (`:8`) and
`device::cons::getc` (`:77`). `get_line` (`:12-60`) is pure. Boot-only
prompt. Stays; folds into whatever holds `prompt_resume_task`.

**`kern/console.rs`** (137 lines, BSD-2-Clause, original). Fan-in 43 files
(23 kernel, 20 arch) because `kprint!` and `CStrArg` live here. One
outbound edge, `device/cons` (`:10`, `cons::putc` at `:22`). The
`CStrArg`/`write_cstr` helpers (`:46-130`) are dependency-free;
`Console` is the global sink. ADR 0050 keeps the `kd`/`com` console and
its devices in the kernel; this file is only the formatter, but its sink
is global and has no seam. **Stays**; the pure helpers are too small for a
crate (inference).

**`utils/string.rs`** (330). Zero edges out; 12 `unsafe extern "C"`
`memcpy`..`strstr` with `cfg_attr(not(test), unsafe(no_mangle))`
(`:17`). These are the symbols the compiler lowers to, so they are the
ADR 0027 exception "symbols … refer"; users `arch/.../com.rs:35`,
`model_dep.rs:377+`, `mp_desc.rs:347`, `device/dev_name.rs:41`,
`kern/thread.rs:48`. **Stays.** `utils/atoi.rs` (users: `arch/.../com.rs:33`
only), `utils/kd_queue.rs` (users: `arch/.../{io_req,kd_event,kd_mouse,
kd/keyboard}.rs`, all arch) and `utils/delay.rs` (`kern/debug.rs:15`,
`arch/.../kd/mod.rs:22`) have zero or one core edge and arch-only or
near-arch-only users: they are `arch` leaves (inference), not crates.
`utils/cell.rs` (15 lines, fan-in 21+4) is the `SyncCell` used for
`static mut` replacement (ADR 0027); it goes when the statics do.

**`device/cirbuf.rs`** (283, CMU-Mach). Inbound `device/chario.rs:15`
only. Outbound `kern/slab::{kalloc, kfree}` (`:10`, used at `:239,259`)
and `arch::types::VmSize`. A circular byte buffer with raw pointers and
`#[repr(C)]` asserts (`:36-49`). Dependency-isolated; one user that
itself stays. **Split after slab seam** (low value); better with a
future tty piece (inference).

**`device/chario.rs`** (1,512). Core 7, foundation 4, arch 3:
`clock_platform::{MachCallout, wheel}`, `io_req`, `spl` (`:12-14`),
`ds_routines`, `vm_map_copyout`, `vm_user` (`:16-25`). Imported *by* arch (`arch/.../com.rs:24`,
`kd/mod.rs:288`, `kd/tty.rs:17`): an arch cycle. ADR 0050/0019: serial
and `kd` consoles are in-kernel drivers. **Stays.**

**`device/net_io.rs`** (2,366, `CMU-Mach AND BSD-4-Clause-Shortened`).
Core 8 (`ipc_kmsg`, `ipc_mqueue`, `ipc_port`, `ast`, `sched_prim`,
`thread`, `ipc/mod`, `vm_map`, `:19-30,2344`). Back-edges from the core
make it part of the cycle: `ipc/ipc_kmsg.rs:1168` (`kmsg_put`),
`vm/vm_pageout.rs:372` (`kmsg_collect`), `kern/ast.rs:250` (`ast`).
Two sub-parts are dependency-free: a BPF interpreter (`:389-930`, about
540 lines, no `crate::` path inside `:330-930`) and the old filter
program interpreter (`:1625-1731`). **But (inference, verify):** the tree
has no `net_set_filter`, no `net_packet` and no in-kernel NIC driver; the
names appear only in comments (`:857,1629`), and ADR 0019 puts network
drivers in userspace. If so the filter half is unreachable and the
decision is deletion, not extraction; `ds_device_set_filter`
(`device/ds_routines.rs:923`) is the MIG-visible entry, so removing it is an
ABI decision (ADR 0002), not a refactor. **Stays.**

**`ipc/ipc_table.rs`** (156). `ipc_table ↔ ipc/mod.rs` is a 2-cycle
(`ipc_table.rs:11` imports `IpcPortRequest`; `ipc/mod.rs:6` imports
`IpcTableSize`). `fill` (`:50-101`) is pure arithmetic; the module also
holds `pub static mut IPC_TABLE_DNREQUESTS` (`:40`) and calls `kalloc`.
Part of the IPC cluster. **Stays.**

**`vm/vm_external.rs`** (352, CMU-Mach). Inbound `vm/vm_object.rs:39`,
`vm_fault.rs:37`, `vm_pageout.rs:28`, `memory_object.rs:29`, all VM core.
Outbound: three slab caches (`:98-107`), `SyncCell`, `PAGE_SHIFT`,
`VmOffset`. Dependency-isolated, VM-private. **Split after slab seam**
(low value, inference: the bitmap belongs to a VM object's pager state).

### 3.8 `kern/eventcount.rs`, `kern/gsync.rs`, `kern/mach_factor.rs`, `kern/priority.rs`, `kern/policy.rs`

All stay except `policy`.

- `eventcount.rs` (204): `sched_prim` (`assert_wait`, `thread_block`),
  `Thread`, spl, per-CPU, and `locore::thread_syscall_return` (`:84`)
  (`:11-17`). Task/thread/sched cluster.
- `gsync.rs` (823): `sched_prim`, `ipc_sched`, `task`, `thread`,
  `vm_kern::KERNEL_MAP`, `vm_map::{VmMap, EnterRequest}`,
  `vm_object::deallocate` (`:10-26,321,555`), `user_access`. A user
  futex over VM objects: scheduler + VM.
- `mach_factor.rs` (150): `processor` (`:11`), `sched::{SCHED_SCALE,
  SCHED_SHIFT}` (`:12`); reads processor-set state. Cluster.
- `priority.rs` (151): `ast`, `machine`, `sched`, `sched_prim`, `thread`,
  spl, per-CPU (`:13-22`); only caller `kern/machine.rs:22`. Cluster.
- `policy.rs` (22): 3 constants and `invalid_policy`, no edges, 6
  kernel importers; already host-compiled
  (`crates/host-tests/src/kern/mod.rs:6`). It belongs in the value-type
  set below, not a crate of its own.

### 3.9 Other low-coupling files the graph shows

- **Value types, zero edges out.** `vm/error.rs` (143, fan-in 16/2/5),
  `kern/types.rs` (117, 23/5/7), `glue/time_value.rs` (255, 5/2/3),
  `kern/policy.rs` (22), `device/return.rs` (90, 6 / 6 / 1),
  `arch/types.rs` (45) and `arch/vm_param.rs` (33). All carry CMU-Mach or
  similar derived headers (`kern/types.rs:1-6`), so the crate is
  GPL-2.0-or-later. These are what the other candidates would import
  (`rdxtree` imports `vm::error::Error`; `elf_load` imports `VmProt`;
  `utils/kd_queue.rs:11` imports `RpcTimeValue`), and the host-tests shim
  already compiles most of them.
  **Fix first (ADR 0015, inference):** there are two error enums that
  both mirror `kern_return_t`: `kern::types::KernError` (`kern/types.rs:
  13`) and `vm::error::Error` (`vm/error.rs:50`, with a `Success`
  variant). One must win before either is the shared error type; the one
  conversion to `c_int` lives with the type (`vm/error.rs:111,124`).
  `VmProt`/`VmInherit` sit in `vm/types.rs`, beside `VmObject` and a
  `kern::lock::SimpleLock` import (`:14`), so they have to be split out
  of that file (`vm/types.rs ↔ vm/vm_page.rs` is a 2-cycle).
- **`kern/timer.rs`** (207). One core edge: `Thread` for
  `read_times(&Thread)` (`:11,170`); users `kern/thread.rs:45`,
  `ffi/task_info.rs:16`, `ffi/thread_info.rs:20`. Not a drop-in for
  `clock::Timer` (`RESEARCH-mach-clock-removal.md`, section 5: `tstamp`
  field and layout asserts at `timer.rs:33-34,192-197`). **Split after
  `clock::Timer`.** `DEBT.md` has no entry for it (that note only).
- **Smaller, in-cluster leaves, not worth a crate:** `kern/sched.rs` (80,
  imports `thread::ThreadQueue`, a cycle with `thread.rs`),
  `ipc/ipc_thread.rs` (325, one edge to `Thread`), `ipc/copy_user.rs` (63),
  `device/subrs.rs` (32, one user: `arch/.../kd_mouse.rs:21`).

## 4. Clusters that stay together

The 59-file cycle (59,266 lines) splits into four areas. Cross-area edges
run both ways (file pairs, over the 68 files of these four areas that sit
in the 136-file cycle, first area importing second):

| Pair | a → b | b → a |
|---|---:|---:|
| sched ↔ ipc | 14 | 26 |
| ipc ↔ vm | 13 | 15 |
| sched ↔ vm | 11 | 15 |
| device → ipc / vm / sched | 22 / 9 / 12 | 2 / 1 / 3 |

"sched" here is the task, thread, scheduler, processor and host group of
`kern/`; "device" is `device/` dispatch.

**Task / thread / scheduler** (`kern/{task,thread,sched_prim,sched,
processor,machine,ast,priority,thread_swap,timer,eventcount,ipc_sched,
syscall_subr,syscall_emulation,host,host_time,ipc_host,ipc_tt,ipc_mig,
mach_factor}.rs`, about 15,000 lines). Mutual imports:
`thread.rs:36` ↔ `sched_prim.rs:27` (18 / 16 refs); `thread.rs:44` ↔
`task.rs:41`; `task.rs:33` ↔ `processor.rs:29`; `ipc_tt.rs` ↔ `task.rs`
(4 / 8) and `ipc_tt.rs` ↔ `thread.rs` (2 / 4); `machine.rs:30` ↔
`sched_prim.rs:19`; `thread.rs:2139-2146` calls `ipc/mach_msg.rs`
continuations while `mach_msg.rs:27` imports `Thread`.

**IPC object model** (`ipc/*`, `kern/ipc_kobject.rs`, about 14,800
lines). `ipc_object.rs:809,812` calls `ipc_port::release_*` while
`ipc_port.rs:14` imports `ipc_object`; `ipc_kmsg.rs:20` ↔ `ipc_port.rs:11`;
`ipc_mqueue ↔ ipc_pset`, `ipc_marequest ↔ ipc_right`,
`ipc_notify ↔ ipc_port` (1 / 1 each); `ipc_port.rs:644` calls
`ipc_kobject::destroy` and `kern/ipc_kobject.rs:13` imports `ipc_port`.

**VM object model** (`vm/*`, about 20,900 lines). `vm_map.rs:39` ↔
`vm_fault.rs:38`; `vm_object.rs:39` ↔ `vm_fault.rs:39`;
`vm_object.rs:34` ↔ `vm_page.rs:30`; `vm_map.rs:40-41` ↔ `vm_kern.rs:26`;
`vm_object.rs:32` ↔ `memory_object.rs:29`; `vm_map.rs:30` ↔
`kern/slab.rs:23-24`.

**Between the areas.** IPC ↔ VM: `kern/ipc_kobject.rs:130,134` calls
`vm_object::{destroy, pager_wakeup}` while `vm_object.rs:24` imports
`ipc_kobject`. Task ↔ VM: `task.rs:45` and `thread.rs:49` import
`vm_map`; `vm_kern.rs` ↔ `task.rs`. These are the cycles ADR 0014 means
by "IPC, VM and tasks refer to each other" (`docs/adr/0014-…:25-26`);
the graph agrees with the ADR rather than adding to it.

**Device dispatch** is mostly a consumer (22 / 9 / 12 edges out, 2 / 1 / 3
back), so it is the area most likely to leave *after* the core exists.
The back edges are the blockers: `ipc/ipc_kmsg.rs:1168`,
`vm/vm_pageout.rs:372`, `kern/ast.rs:250` (all `net_io`);
`kern/ipc_mig.rs:15,415` and `kern/ipc_kobject.rs:184` (`ds_routines`,
`dev_lookup_ffi`); `kern/console.rs:10`, `kern/printf.rs:77` (`cons`);
`kern/startup.rs:15,192` and `kern/bootstrap.rs:141,363`.

**Arch.** 173 edges run from arch back into the rest. ADR 0014's
`Platform` carries the pmap, context switch, per-CPU data, user copy and
interrupt control for the future core; none of the mechanism candidates
above needs more than a handful.

## 5. ADR checks

`✗` is a violation the split has to fix first; `-` means the ADR does not
touch the module.

| ADR | elf_load | boot_script | rdxtree | rcu | slab | bootstrap |
|---|---|---|---|---|---|---|
| 0006 zero arch imports; services through `Platform` | ✗ type imports only (`arch::types`, `VmProt`) | ok after `Task` becomes an associated type | ok after `A: Alloc` | ✗ `per_cpu`, `spl` | ✗ `phys`, `pmap`, `vm_*` | ✗ 6 arch files |
| 0015 no `kern_return_t` inside | ✗ `c_int` codes | ok (`Error`) | ✗ uses `vm::error::Error` | ok | not checked | ✗ `c_int::from(error)` (`:210,246`) |
| 0016 references dropped | - | ✗ `free_task` | - | - | - | ✗ `task::deallocate` (`:356`) |
| 0017 fallible, no `alloc` | ok | ✗ `alloc::{CString, Vec}` | ✗ `KmemCache` static | ✗ `Box`, `try_box` | is the allocator; may sleep | ✗ `Box`, `format!` |
| 0018 no panics from input | - | ✗ indexing | - | ok | 10 `kpanic!` sites, not classified | `kpanic!` on boot paths, no `#[expect]` |
| 0019 drivers | - | - | - | - | - | - |
| 0027 C only at MIG seam; no `static mut` | ✗ `*mut c_void`, `#[repr(C)]` | ✗ `*mut c_void` | ✗ raw slots, layout asserts | ✗ 1 `extern "C"` (`:403`) | ✗ 1 `static mut` | ✗ 2 `extern "C"` |
| 0050 console stays | - | - | - | - | - | uses `kprint!` only |
| 0010 licence | HPND file in a GPL crate | GPL | BSD-2 file in a GPL crate | original: MIT possible (inference) | derived: GPL until rewritten | GPL |
| 0005 `SAFETY` comments / `unsafe` sites (grep) | 2 / 20 | 5 / 5 | 46 / 49 | 28 / 32 | not counted | 15 / 56 |
| 0024 host tests, 100% coverage | none exist | none exist | none exist | none exist | none exist | exempt (stays in `kernel`) |

Notes. ADR 0050 and ADR 0019 touch `kern/console.rs`, `device/cons.rs`,
`device/chario.rs` and `device/net_io.rs`, none of which is a split
candidate here. ADR 0026 (`#[allow]`; `DEBT.md` "Lint allowances")
counts: elf_load 11, rcu 5, net_io 10, rdxtree 3, slab 6. A new crate also
takes the stricter lints `kmem` uses (`unreachable_pub`, `unused_results`,
`missing_debug_implementations`, `crates/kmem/Cargo.toml`) and ADR 0022
(no Cargo features). Every moved file keeps its provenance block and must
not gain upstream file names in prose (ADR 0010; `DEBT.md` "Upstream
names in docs and comments": the headers and the first doc line of
`elf_load.rs`, `boot_script.rs`, `rdxtree.rs` name `.c` files today).

## 6. Mutual independence of the candidates

"A needs B" among the candidates (edges, evidence above):

| needs → | elf_load | boot_script | rdxtree | rcu | cirbuf | vm_external | slab |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| elf_load | | | | | | | |
| boot_script | | | | | | | |
| rdxtree | | | | | | | yes (cache) |
| rcu | | | | | | | via `kheap` |
| cirbuf | | | | | | | yes (`kalloc`) |
| vm_external | | | | | | | yes (caches) |
| slab | | | | | | | |

`elf_load` and `boot_script` share no edge with each other or with any
other candidate; the value types are depended on by all but depend on
nothing. `rdxtree`, `cirbuf` and `vm_external` are independent of each
other and meet only at the slab, which an `A: Alloc` parameter bypasses.
`rcu` is the one tied to the scheduler and to locks.

## 7. Suggested extraction order

Each step keeps the tree bootable and closes part of one `DEBT.md`
entry; none needs another to land first except where stated.

1. **`elf_load`** as a crate. No prerequisite: own protection bits,
   `Result` return, two traits. Closes its share of "core is still in
   `kernel`", "`kern_return_t` is used inside", "Lint allowances".
2. **`boot_script`** as a second crate, together with replacing
   `alloc::{CString, Vec}` by `kmem::KVec<_, Kalloc>` and a NUL-string
   type. Removes it and `bootstrap.rs` from the `alloc` list
   (`bootstrap.rs` still has `Box`, `format!`).
3. **`rdxtree`** as a crate with `Rdxtree<A: Alloc>`; the kernel keeps
   an `Alloc` over the `rdxtree_node` cache (or switches to `Kalloc` and
   checks `host_slab_info`). Needs its own two-variant error.
4. **Value-type crate** (error enums reconciled first; `VmProt`,
   `VmInherit` lifted out of `vm/types.rs`). Lets `host-tests` drop
   its `#[path]` shims for those files (`DEBT.md`, "Host tests compile
   kernel sources through a shim").
5. **Boot helpers** (`is_compat`, `CompatStrings`, argument layout)
   into the `boot_script` crate or beside it, only if a second user
   appears (inference: not needed).
6. **`rcu`** after the kernel depends on `lock` (the "locks and spl"
   entry) and a `Platform` for per-CPU data, irq-quiet and event
   sleep exists.
7. **`cirbuf`, `vm_external`** after the slab seam, if wanted.
8. **Slab** after a non-derived rewrite and fallible page source;
   **device dispatch** after `wip-mach` exists; **`bootstrap.rs`** and
   `startup.rs` never (ADR 0014: boot and wiring stay in `kernel`).

When any of these lands, the "core is still in `kernel`" entry's
"Done when" (`DEBT.md`: "each mechanism has moved to its own crate or has
been found to fail the split test") gets a recorded outcome: elf_load,
boot_script, rdxtree pass; rcu passes after locks; slab and bootstrap
fail as standalone crates.

## Appendix: per-file counts

Non-arch, non-seam files. `in` is distinct importing files; `out` is
distinct imported files by class (core, foundation, arch). `statics` are
`static` items with `static mut` in brackets. `alloc` marks the `alloc`
crate; `slab` marks `kalloc`/`kfree`/`KmemCache`/`try_box`. Seam files
(`ffi/`, `*_ffi.rs`) and the `mod.rs` hubs are left out; `glue/mod.rs`
is the only file that names `mach_mig_sys`.

<details>
<summary>Table</summary>

| file | lines | in (kernel) | in (arch) | in (seam) | out core | out found. | out arch | `extern "C"`+`no_mangle` | statics (of which `mut`) | `alloc` crate | slab/kalloc | MIG sys |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|:-:|:-:|:-:|
| `config.rs` | 41 | 11 | 11 | 2 | 0 | 0 | 0 | 0 | 0 (0) | - | - | - |
| `device/chario.rs` | 1512 | 1 | 3 | 0 | 7 | 4 | 3 | 0 | 8 (2) | - | Y | - |
| `device/cirbuf.rs` | 283 | 1 | 0 | 0 | 0 | 2 | 0 | 0 | 0 (0) | - | Y | - |
| `device/cons.rs` | 289 | 2 | 1 | 0 | 2 | 2 | 3 | 0 | 8 (7) | - | - | - |
| `device/dev_lookup.rs` | 409 | 4 | 1 | 1 | 4 | 2 | 0 | 0 | 4 (3) | - | Y | - |
| `device/dev_name.rs` | 493 | 4 | 0 | 0 | 3 | 4 | 8 | 0 | 2 (0) | - | - | - |
| `device/dev_pager.rs` | 740 | 2 | 0 | 1 | 8 | 7 | 1 | 0 | 10 (7) | - | Y | - |
| `device/device_init.rs` | 79 | 3 | 1 | 0 | 10 | 1 | 0 | 0 | 1 (0) | - | - | - |
| `device/ds_routines.rs` | 2460 | 8 | 4 | 3 | 14 | 11 | 5 | 2 | 9 (7) | Y | Y | - |
| `device/intr.rs` | 681 | 3 | 1 | 0 | 7 | 5 | 5 | 3 | 4 (3) | Y | Y | - |
| `device/kmsg.rs` | 378 | 2 | 0 | 0 | 1 | 3 | 3 | 0 | 8 (6) | - | - | - |
| `device/net_io.rs` | 2366 | 4 | 0 | 0 | 8 | 3 | 2 | 2 | 28 (0) | - | Y | - |
| `device/return.rs` | 90 | 6 | 6 | 1 | 0 | 0 | 0 | 0 | 0 (0) | - | - | - |
| `device/subrs.rs` | 32 | 0 | 1 | 0 | 1 | 1 | 0 | 0 | 0 (0) | - | - | - |
| `glue/time_value.rs` | 255 | 5 | 2 | 3 | 0 | 0 | 0 | 0 | 0 (0) | - | - | - |
| `ipc/copy_user.rs` | 63 | 1 | 0 | 0 | 1 | 0 | 1 | 0 | 0 (0) | - | - | - |
| `ipc/ipc_entry.rs` | 357 | 6 | 0 | 0 | 2 | 3 | 0 | 0 | 1 (1) | - | Y | - |
| `ipc/ipc_init.rs` | 97 | 6 | 1 | 1 | 10 | 2 | 0 | 0 | 3 (2) | - | - | - |
| `ipc/ipc_kmsg.rs` | 3838 | 11 | 0 | 0 | 15 | 6 | 2 | 0 | 1 (1) | - | Y | - |
| `ipc/ipc_marequest.rs` | 454 | 6 | 0 | 0 | 6 | 2 | 0 | 0 | 4 (1) | - | Y | - |
| `ipc/ipc_mqueue.rs` | 801 | 9 | 0 | 0 | 11 | 1 | 1 | 1 | 0 (0) | - | - | - |
| `ipc/ipc_notify.rs` | 344 | 7 | 0 | 0 | 4 | 1 | 0 | 0 | 0 (0) | - | - | - |
| `ipc/ipc_object.rs` | 871 | 12 | 0 | 0 | 5 | 3 | 0 | 0 | 1 (1) | - | Y | - |
| `ipc/ipc_port.rs` | 1051 | 23 | 1 | 1 | 12 | 3 | 0 | 0 | 3 (0) | - | Y | - |
| `ipc/ipc_pset.rs` | 245 | 4 | 0 | 0 | 5 | 1 | 0 | 0 | 0 (0) | - | - | - |
| `ipc/ipc_right.rs` | 1995 | 6 | 0 | 0 | 7 | 2 | 0 | 0 | 0 (0) | - | - | - |
| `ipc/ipc_space.rs` | 362 | 13 | 1 | 0 | 5 | 4 | 0 | 0 | 4 (4) | - | Y | - |
| `ipc/ipc_table.rs` | 156 | 3 | 0 | 0 | 1 | 4 | 0 | 0 | 1 (1) | - | Y | - |
| `ipc/ipc_target.rs` | 41 | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 (0) | - | - | - |
| `ipc/ipc_thread.rs` | 325 | 6 | 0 | 0 | 1 | 0 | 0 | 0 | 0 (0) | - | - | - |
| `ipc/mach_debug.rs` | 234 | 0 | 0 | 1 | 8 | 2 | 0 | 0 | 0 (0) | - | - | - |
| `ipc/mach_msg.rs` | 565 | 3 | 0 | 0 | 9 | 0 | 4 | 3 | 0 (0) | - | - | - |
| `ipc/mach_port.rs` | 1522 | 4 | 0 | 1 | 12 | 7 | 0 | 0 | 4 (1) | - | - | - |
| `kern/ast.rs` | 406 | 7 | 5 | 0 | 5 | 3 | 4 | 1 | 1 (0) | - | - | - |
| `kern/boot_script.rs` | 707 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 (0) | Y | - | - |
| `kern/bootstrap.rs` | 867 | 1 | 0 | 0 | 12 | 6 | 6 | 2 | 2 (0) | Y | - | - |
| `kern/console.rs` | 137 | 23 | 20 | 0 | 1 | 0 | 0 | 0 | 0 (0) | - | - | - |
| `kern/debug.rs` | 112 | 41 | 9 | 3 | 1 | 3 | 3 | 0 | 3 (0) | - | - | - |
| `kern/elf_load.rs` | 634 | 1 | 0 | 0 | 0 | 2 | 0 | 0 | 0 (0) | - | - | - |
| `kern/eventcount.rs` | 204 | 2 | 0 | 0 | 2 | 3 | 3 | 3 | 1 (0) | - | - | - |
| `kern/exception.rs` | 1237 | 0 | 1 | 0 | 15 | 1 | 3 | 5 | 1 (1) | - | - | - |
| `kern/gsync.rs` | 823 | 1 | 0 | 1 | 7 | 4 | 2 | 0 | 1 (1) | - | - | - |
| `kern/host.rs` | 294 | 7 | 0 | 6 | 3 | 5 | 0 | 0 | 1 (1) | - | Y | - |
| `kern/host_time.rs` | 209 | 4 | 2 | 3 | 2 | 2 | 3 | 0 | 1 (1) | - | - | - |
| `kern/ipc_host.rs` | 491 | 4 | 0 | 2 | 7 | 3 | 0 | 1 | 0 (0) | - | - | - |
| `kern/ipc_kobject.rs` | 360 | 9 | 1 | 0 | 7 | 3 | 0 | 0 | 0 (0) | - | - | - |
| `kern/ipc_mig.rs` | 1567 | 3 | 0 | 1 | 14 | 5 | 4 | 17 | 0 (0) | - | - | - |
| `kern/ipc_sched.rs` | 198 | 5 | 0 | 0 | 4 | 1 | 3 | 0 | 0 (0) | - | - | - |
| `kern/ipc_tt.rs` | 906 | 6 | 0 | 2 | 8 | 4 | 1 | 3 | 0 (0) | - | Y | - |
| `kern/kheap.rs` | 172 | 3 | 0 | 0 | 0 | 1 | 0 | 0 | 1 (0) | Y | Y | - |
| `kern/kmutex.rs` | 178 | 2 | 0 | 0 | 1 | 2 | 1 | 0 | 0 (0) | - | - | - |
| `kern/lock.rs` | 452 | 26 | 4 | 0 | 1 | 1 | 1 | 0 | 0 (0) | - | - | - |
| `kern/mach_factor.rs` | 150 | 2 | 0 | 1 | 2 | 0 | 0 | 0 | 2 (0) | - | - | - |
| `kern/machine.rs` | 941 | 13 | 10 | 4 | 5 | 7 | 5 | 4 | 5 (4) | - | - | - |
| `kern/policy.rs` | 22 | 6 | 0 | 1 | 0 | 0 | 0 | 0 | 0 (0) | - | - | - |
| `kern/printf.rs` | 84 | 1 | 0 | 0 | 1 | 1 | 0 | 0 | 0 (0) | - | - | - |
| `kern/priority.rs` | 151 | 1 | 0 | 0 | 5 | 1 | 2 | 0 | 0 (0) | - | - | - |
| `kern/processor.rs` | 1549 | 10 | 2 | 7 | 9 | 8 | 3 | 0 | 8 (6) | - | Y | - |
| `kern/rcu.rs` | 676 | 4 | 0 | 0 | 2 | 6 | 2 | 1 | 5 (0) | Y | Y | - |
| `kern/rdxtree.rs` | 1099 | 5 | 0 | 0 | 0 | 3 | 0 | 0 | 1 (0) | - | Y | - |
| `kern/sched.rs` | 80 | 8 | 0 | 0 | 1 | 1 | 0 | 0 | 0 (0) | - | - | - |
| `kern/sched_prim.rs` | 1832 | 28 | 2 | 2 | 8 | 5 | 6 | 6 | 10 (0) | - | - | - |
| `kern/slab.rs` | 1806 | 29 | 7 | 2 | 7 | 6 | 2 | 0 | 8 (1) | - | Y | - |
| `kern/smp.rs` | 104 | 6 | 9 | 1 | 0 | 1 | 0 | 0 | 1 (0) | - | - | - |
| `kern/startup.rs` | 276 | 1 | 2 | 0 | 20 | 4 | 7 | 3 | 1 (0) | - | - | - |
| `kern/syscall_emulation.rs` | 463 | 1 | 0 | 1 | 4 | 3 | 0 | 0 | 0 (0) | - | Y | - |
| `kern/syscall_subr.rs` | 389 | 3 | 0 | 1 | 7 | 3 | 3 | 7 | 0 (0) | - | - | - |
| `kern/syscall_sw.rs` | 870 | 0 | 1 | 0 | 6 | 2 | 0 | 4 | 3 (0) | - | - | - |
| `kern/task.rs` | 1653 | 20 | 3 | 8 | 13 | 8 | 4 | 0 | 6 (6) | - | Y | - |
| `kern/thread.rs` | 2875 | 28 | 8 | 8 | 18 | 10 | 5 | 8 | 14 (13) | - | Y | - |
| `kern/thread_swap.rs` | 207 | 3 | 0 | 0 | 2 | 3 | 2 | 1 | 3 (1) | - | - | - |
| `kern/timer.rs` | 207 | 2 | 0 | 2 | 1 | 3 | 0 | 0 | 2 (0) | - | - | - |
| `kern/types.rs` | 117 | 23 | 5 | 7 | 0 | 0 | 0 | 0 | 0 (0) | - | - | - |
| `utils/atoi.rs` | 65 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 (0) | - | - | - |
| `utils/cell.rs` | 15 | 21 | 4 | 0 | 0 | 0 | 0 | 0 | 0 (0) | - | - | - |
| `utils/delay.rs` | 24 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 (0) | - | - | - |
| `utils/kd_queue.rs` | 190 | 0 | 4 | 0 | 0 | 1 | 0 | 0 | 0 (0) | - | - | - |
| `utils/string.rs` | 330 | 2 | 3 | 0 | 0 | 0 | 0 | 12 | 0 (0) | - | - | - |
| `vm/error.rs` | 143 | 16 | 2 | 5 | 0 | 0 | 0 | 0 | 0 (0) | - | - | - |
| `vm/memory_object.rs` | 1492 | 5 | 0 | 1 | 12 | 5 | 2 | 0 | 1 (0) | - | - | - |
| `vm/memory_object_proxy.rs` | 339 | 4 | 0 | 1 | 4 | 5 | 0 | 0 | 1 (1) | - | Y | - |
| `vm/types.rs` | 491 | 19 | 6 | 8 | 1 | 3 | 1 | 0 | 0 (0) | - | - | - |
| `vm/vm_debug.rs` | 765 | 0 | 0 | 1 | 7 | 5 | 2 | 0 | 0 (0) | - | - | - |
| `vm/vm_external.rs` | 352 | 4 | 0 | 0 | 0 | 4 | 0 | 0 | 4 (0) | - | Y | - |
| `vm/vm_fault.rs` | 2383 | 3 | 1 | 0 | 10 | 7 | 3 | 1 | 5 (1) | - | Y | - |
| `vm/vm_init.rs` | 84 | 1 | 0 | 0 | 8 | 2 | 1 | 0 | 0 (0) | - | Y | - |
| `vm/vm_kern.rs` | 826 | 14 | 12 | 2 | 5 | 7 | 2 | 0 | 7 (3) | - | - | - |
| `vm/vm_map.rs` | 6656 | 25 | 7 | 8 | 10 | 8 | 2 | 3 | 5 (0) | - | Y | - |
| `vm/vm_object.rs` | 2564 | 12 | 0 | 2 | 12 | 9 | 3 | 0 | 17 (7) | - | Y | - |
| `vm/vm_page.rs` | 3098 | 12 | 3 | 0 | 6 | 8 | 2 | 1 | 2 (0) | - | - | - |
| `vm/vm_pageout.rs` | 516 | 6 | 0 | 0 | 12 | 6 | 2 | 0 | 2 (0) | - | - | - |
| `vm/vm_resident.rs` | 1040 | 12 | 0 | 0 | 5 | 8 | 2 | 0 | 18 (7) | - | Y | - |
| `vm/vm_user.rs` | 1018 | 11 | 0 | 3 | 10 | 4 | 1 | 0 | 1 (1) | - | - | - |

</details>
