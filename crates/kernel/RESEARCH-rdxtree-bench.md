# `Rdxtree` vs an XNU-style entry table: benchmark plan

> **Status (2026-10): plan.** Nothing here is implemented. This note fixes
> the question, the contenders, the workloads taken from our IPC call
> sites, the harness and the commands to run it, so the benchmark can be
> built in one pass. It changes no code, no ADR and no `DEBT.md` entry.

The question is cost only: does the Minix/Mach rdxtree
(`crates/kernel/src/kern/rdxtree.rs`, radix 6, 544-byte nodes) cost more
on the IPC-space mix than the flat name-indexed table XNU uses
(`ipc_entry` rows, free list, an embedded Robin Hood hash for the reverse
map)? The benchmark cannot settle the ADR 0002 questions the switch also
raises — LIFO name allocation and a hard name-index cap — and does not
try.

## 1. What the contenders model

**A. `Rdxtree` as it is.** One name → entry tree and a second object →
entry tree, both holding `NonNull<c_void>`; entries come from the
`IPC_ENTRY_CACHE` slab (`ipc_entry.rs:344-355`); node allocation is the
`RDXTREE_NODE_CACHE` slab (`rdxtree.rs:163-185,276-309`). A lookup walks
up to six 6-bit levels; `insert_alloc` takes the lowest free slot from the
per-node bitmask (`rdxtree.rs:384-393,689-784`); `lookup(Slot)` hands out
a stable `*mut *mut c_void` that `alloc_name` rewrites in place
(`ipc_entry.rs:283-323`).

**B. XNU's current space**, modeled from `~/Codebases/xnu`:

- one growable array of 24-byte `ipc_entry` rows, name = index
  (`ipc_entry.h:75-110`, `ipc_entry.c:80,160-180`);
- free rows threaded by `ie_next` with row 0 as head; allocation pops the
  list, newest first (`ipc_entry.c:218-268`);
- object → name is an open-addressed Robin Hood hash embedded in the rows
  (`ie_dist`, `ie_index`), load factor kept at 7/8 (`ipc_entry.c:213`);
- growth is a new table plus copy/re-scan, capped at
  `CONFIG_IPC_TABLE_ENTRIES_SIZE_MAX` = 3 MiB (131072 rows) or 7 MiB
  (305834 rows) (`config/MASTER:291-292`, `ipc_entry.c:624-828`);
- `mach_port_names` scans the whole table and sizes its buffers by table
  count (`mach_port.c:266-330`), against our walk of live entries
  (`mach_port.rs:449-485`).

**C. A + reverse hash** (stretch, only if B's reverse-map win is the only
win): keep the rdxtree for names, replace `reverse_map` with an embedded
hash. Not measured unless A vs B shows reverse ops dominate.

## 2. Workloads, from our call sites

| id | operation | call site | proposed mix |
|---|---|---|---|
| `lookup` | name → entry | `ipc/mod.rs:1308` (every message) | 55% |
| `lookup_slot_replace` | reuse a dead entry in place | `ipc_entry.rs:283-310` | 10% |
| `insert_alloc` | lowest-free name | `ipc_entry.rs:243` | 5% |
| `insert_named` | explicit name (incl. key 0) | `ipc_entry.rs:313`, `ipc_space.rs:236` | 5% |
| `remove` | dealloc | `ipc_entry.rs:186` | 5% |
| `reverse_insert/lookup/remove` | object address → entry; callers `ipc_right.rs`, `ipc_kmsg.rs:3434` | `ipc_space.rs:96-141` | 10% |
| `walk` | `mach_port_names`, `set_members` | `mach_port.rs:476,1112` | 5% |
| `destroy` | free entries + drop both trees | `ipc_space.rs:314-340` | 5% |

The mix is a proposal; no boot counter exists to weigh it (that is a
separate, later run). Sizes: `64`, `1024`, `32768`, `131072` — the last is
XNU's small-table cap and the point where B stops growing.

Semantics differ after a removal: A hands back the lowest free name, B the
most recently freed. The bench compares cost, never the name sequence, and
both contenders receive the same key set where the API allows it.

## 3. Phase 0 — make A host-buildable without forking it

The real `rdxtree.rs` needs three kernel items:
`crate::kern::slab::{CacheInitFlags, KmemCache}` (`init`, `alloc`, `free`,
`zeroed`), `crate::utils::cell::SyncCell`, and
`crate::vm::error::Error::{InvalidArgument, ResourceShortage}`.

The bench crate declares those three modules as small host shims and
compiles the kernel file verbatim:

```rust
#[path = "../../kernel/src/kern/rdxtree.rs"]
mod rdxtree;
```

The shims: `KmemCache` wraps a free list of fixed-size `Box`-like
allocations with atomic counters; `SyncCell` is the kernel's
`UnsafeCell` wrapper; `Error` is a two-variant enum. No copy of the
algorithm exists, so the bench cannot drift from `kern/rdxtree.rs`.

Crate home: `crates/rdxtree-bench/`, license `GPL-2.0-or-later` (the
workspace default; it compiles a BSD-2-Clause file and is not a portable
crate). It is scaffolding: after ADR 0014 extracts `rdxtree`, the bench
moves beside the extracted crate and this scaffold goes away. It is a
workspace member so `cargo bench -p` finds it, but it carries no coverage
gate (ADR 0024 gates portable crates, not benches).

## 4. Phase 1 — the XNU-style table

`crates/rdxtree-bench/src/table.rs`, an `Entry` of 24 bytes with
`object: NonNull<c_void>`, `bits: u32`, `next_or_request: u32`,
`dist: u32`, `index: u32`; a `Vec<Entry>`; row 0 the free-list head; a
Robin Hood hash over `object` with linear probing and a 7/8 load cap;
growth to the next size, copied and re-scanned, clamped at 131072 rows.
This mirrors `ipc_entry.c` policy, not its exact `next_size` arithmetic
(named in the plan, matched in the code where it matters: min 32 rows,
bitmask-able sizes, cap).

Both contenders expose the same driver trait:

```rust
trait Space {
    fn insert_alloc(&mut self, object: NonNull<c_void>) -> u32;
    fn insert_named(&mut self, name: u32, object: NonNull<c_void>) -> bool;
    fn lookup(&self, name: u32) -> Option<NonNull<c_void>>;
    fn lookup_slot_replace(&mut self, name: u32, object: NonNull<c_void>);
    fn remove(&mut self, name: u32) -> Option<NonNull<c_void>>;
    fn reverse_insert(&mut self, object: NonNull<c_void>, name: u32);
    fn reverse_lookup(&self, object: NonNull<c_void>) -> Option<u32>;
    fn reverse_remove(&mut self, object: NonNull<c_void>);
    fn walk(&self, visit: &mut dyn FnMut(u32, NonNull<c_void>));
    fn destroy(self);
}
```

A's entries live in a shared arena with a free list so both contenders pay
the same entry-storage cost; A additionally pays its node slab through the
shim, B pays table growth.

## 5. Phase 2 — criterion harness

`crates/rdxtree-bench/benches/vs_table.rs`, criterion 0.8.2,
`harness = false`, one workload per id (`rdxtree/<workload>/<size>`,
`table/<workload>/<size>`), following `crates/collections/benches/
rb_tree.rs`: state built before timing, the whole workload inside one
timed call, a checksum returned, `black_box`, and an xorshift key
generator with a fixed seed so both contenders see the same keys.

Bench ids: `lookup`, `lookup_slot_replace`, `insert_alloc`,
`insert_named`, `remove`, `reverse_insert`, `reverse_lookup`,
`reverse_remove`, `walk`, `churn`, `destroy`.

## 6. Phase 3 — memory and growth tail

Two example binaries, because criterion times correctly but does not
report bytes or tails:

- `examples/memory.rs`: a counting `#[global_allocator]`; prints live and
  peak bytes per entry after filling each size. Expected shape: A = entry
  arena + ~8.5 B/slot of node overhead; B = 24 B × table index, with the
  3 MiB cap.
- `examples/grow_tail.rs`: fills 1..=131072, recording p99/max for the
  single grow call (B copies and re-hashes; A allocates one node).

## 7. Phase 4 — wiring

Add to `mise.toml`, next to `bench::clock`:

```toml
[tasks."bench::rdxtree"]
description = "Time the kernel radix tree against an XNU-style entry table"
run = "cargo bench -p rdxtree-bench --target x86_64-unknown-linux-gnu --bench vs_table"
```

Run:

```sh
# build only
cargo bench -p rdxtree-bench --target x86_64-unknown-linux-gnu --bench vs_table --no-run

# a quiet machine, one core, same binary for both contenders
taskset -c 2 cargo bench -p rdxtree-bench --target x86_64-unknown-linux-gnu --bench vs_table

# save/compare runs
cargo bench -p rdxtree-bench --target x86_64-unknown-linux-gnu --bench vs_table -- --save-baseline table
cargo bench -p rdxtree-bench --target x86_64-unknown-linux-gnu --bench vs_table -- --baseline table
```

Report: `target/criterion/report/index.html`, plus one summary table in a
follow-up `RESEARCH-rdxtree-bench-results.md` (op × size, A/B ratio,
memory, grow p99).

## 8. What would justify a switch

Provisional, to be confirmed before any ADR work:

- `lookup` p50 at 131072 rows at least 1.3× faster on B, and no size worse
  than parity;
- reverse ops at least 1.5× faster (this is the embedded hash's home turf);
- memory at 131072 rows no worse than 1.2×, with the cap stated as a cost;
- `walk`/`destroy` regressions accepted explicitly (B scans the table);
- and, outside this benchmark, ADR 0002 sign-off on LIFO names and the
  name-index cap. If A wins or ties, close the question and record it.

## 9. Limits

- Single-threaded: no space lock, no SMR, no grower protocol. XNU's table
  is fastest exactly where its SMR read path lives; this bench cannot see
  that.
- Host allocator and host page cache, not the kernel slab or pmap; only
  relative numbers are meaningful.
- B is a policy model, not XNU's code; the bench measures the design, not
  Apple's implementation.
- ADR 0024: a benchmark is evidence, not a gate. The kernel stays proven
  by booting.
- The throwaway crate must not become a permanent home; the extraction
  (ADR 0014) is the end state.

## 10. Deliverables

- [ ] `crates/rdxtree-bench/` crate: shims, `table.rs`, `Space` driver
- [ ] `benches/vs_table.rs` with the ids of section 5
- [ ] `examples/memory.rs`, `examples/grow_tail.rs`
- [ ] `mise run bench::rdxtree`
- [ ] one results table in `RESEARCH-rdxtree-bench-results.md`
- [ ] a decision: keep `Rdxtree`, switch, or adopt C
