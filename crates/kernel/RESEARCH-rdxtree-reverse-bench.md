# Reverse map: `Rdxtree` vs a Robin Hood hash — benchmark plan

> **Status (2026-10): plan.** Nothing here is implemented. This note
> isolates the `IpcSpaceRecord.reverse_map` question — keep the second
> `Rdxtree`, or replace it with an open-addressed Robin Hood hash — so it
> can be built and run in one pass. The forward name map is out of scope;
> it stays a tree either way. This note changes no code, no ADR and no
> `DEBT.md` entry.

It shares the host-benchmark scaffold with
[`RESEARCH-rdxtree-bench.md`](RESEARCH-rdxtree-bench.md), which compares the
whole space (name map included) against XNU's flat table. Run that one
first if both are built: this one reuses its Phase 0 shims and adds the
reverse slice.

## 1. Why this is not the XNU plan

XNU's reverse hash is free storage-wise because the hash buckets **are**
the `ipc_entry` table rows: an entry's row is also its bucket
(`ipc_hash.c:158-190`), so the table, the entries and the hash are one
allocation. Our entries are 24-byte slab objects referenced from a radix
(`ipc/mod.rs:401-419`), so a hash must own a separate bucket array. This
benchmark measures the real cost, not XNU's storage trick.

## 2. Contenders

**A. Status quo.** `reverse_map: Rdxtree` (`ipc/mod.rs:480`), keyed by
`reverse_key(object) = (addr - VM_MIN_KERNEL_ADDRESS) >> 3` truncated to
`u32` (`ipc_space.rs:145-152`), operations at `ipc_space.rs:91-142`,
teardown through `remove_all` (`ipc_space.rs:340`). Nodes are 544 bytes
per 64 slots (`rdxtree.rs:144-161`); a lookup walks 1–6 levels; a remove
frees nodes.

**B. `RobinHash`.** Open addressing, linear probing, Robin Hood
displacement with the displacement field XNU pins at
`IPC_ENTRY_DIST_MAX` (12 bits, `ipc_entry.h:75-84`); backward-shift
deletion as in `ipc_hash_table_delete` (`ipc_hash.c:319-420`); buckets of
`(key: u64, entry: *mut IpcEntry)`; power-of-two sizes, load at most 7/8
(`ipc_entry.c:213`); fallible grow and rehash.

**C. Chained hash.** Bucket heads plus a `next` threaded through
`IpcEntry`. Sketch only: it costs 8 bytes per entry and touches the C
mirror, so B is preferred if either hash wins.

Both implement one trait mirroring today's API:

```rust
trait ReverseMap {
    fn insert(&mut self, object: *mut c_void, entry: NonNull<IpcEntry>)
        -> Result<(), Error>;
    fn lookup(&self, object: *mut c_void) -> Option<NonNull<IpcEntry>>;
    fn remove(&mut self, object: *mut c_void) -> Option<NonNull<IpcEntry>>;
    fn remove_all(&mut self);
}
```

## 3. Semantics to preserve

- one entry per object; insert fails when the object is present (the
  rdxtree `insert` error maps through `map_error`, `ipc_entry.rs:104-110`);
- only send rights are inserted (`ipc_right.rs:1450-1465` checks
  `MACH_PORT_TYPE_SEND`); inserts at `ipc_right.rs:1462,1839,1953`,
  removes at `:358,548,723,1093,1587,1733,1869,1950`, lookups at
  `ipc_right.rs:171` and `ipc_kmsg.rs:3434`;
- no iteration: destroy frees entries through the **forward** walk
  (`ipc_space.rs:314-336`) and then `remove_all`s the reverse map
  (`ipc_space.rs:340`), so B can free its bucket array in one step;
- keying stays `reverse_key`; the truncated `u32` aliasing is part of the
  behavior, so B keys on the same value. A variant keyed on the full
  pointer (`os_hash_kernel_pointer`, `ipc_hash.c:188-189`) is a second
  run, not a replacement;
- all operations run under the space write lock; the bench is
  single-threaded.

Static traffic is mutation-heavy (11 inserts/removes versus 2 lookups), so
the mix is measured, not assumed: proposed 9% insert, 45% remove, 23%
lookup, 23% transfer sequences, to be corrected from a boot counter later.

## 4. Workloads

| axis | values |
|---|---|
| n (send rights) | 64, 1024, 32768 |
| key pattern | dense (stride 8), page-spaced (stride 4096), random in 2^32 |
| hash load | 0.50, 0.75, 0.875, 0.95 (A has no load knob; pad n) |
| sequences | create-all, destroy-all, churn, lookup hit/miss, transfer |

Bench ids: `rdxtree_reverse/<sequence>/<n>/<pattern>` and the same under
`robin_hash/`, for `insert`, `lookup_hit`, `lookup_miss`, `remove`,
`churn`, `transfer`, `destroy`. Each timed call runs the whole sequence
over state built before timing and returns a checksum, following
`crates/collections/benches/rb_tree.rs`; keys come from a fixed-seed
xorshift so both contenders see the same sequence.

## 5. Memory and growth tail

- `examples/reverse_memory.rs`: a counting `#[global_allocator]`; prints
  bytes per live entry and peak for both. Expected shape: A ≈ 8.5 bytes
  per slot of node overhead over the entry arena; B ≈ 16 bytes per bucket
  at 7/8 load, likely 2–4× A at small n.
- `examples/reverse_grow_tail.rs`: p99/max of the single grow step while
  filling to 32768 (A allocates one node; B allocates and rehashes).

## 6. Harness and commands

Reuse the scaffold of `RESEARCH-rdxtree-bench.md` Phase 0 (which compiles
`kern/rdxtree.rs` verbatim on the host through three shim modules); add
`src/robin_hash.rs` and `benches/reverse.rs`. If that plan has not run
yet, this one builds the same scaffold with only the reverse slice.

```sh
# build only
cargo bench -p rdxtree-bench --target x86_64-unknown-linux-gnu --bench reverse --no-run

# a quiet machine, one core
taskset -c 2 cargo bench -p rdxtree-bench --target x86_64-unknown-linux-gnu --bench reverse

# memory and tail
cargo run -p rdxtree-bench --target x86_64-unknown-linux-gnu --example reverse_memory
cargo run -p rdxtree-bench --target x86_64-unknown-linux-gnu --example reverse_grow_tail
```

Add to `mise.toml`, next to `bench::clock`:

```toml
[tasks."bench::rdxtree-reverse"]
description = "Time the IPC reverse map: radix tree against a Robin Hood hash"
run = "cargo bench -p rdxtree-bench --target x86_64-unknown-linux-gnu --bench reverse"
```

Report: `target/criterion/report/index.html`, plus one summary table in a
follow-up results note (sequence × n × pattern, A/B ratio, memory, grow
p99).

## 7. Decision criteria

Switch only if, at n ≥ 1024, lookup is at least 1.5× faster, or
remove/churn at least 1.2× faster, **and** memory is at most 2× A, **and**
the grow p99 is accepted. Otherwise keep the tree and record it.

Note the asymmetry before deciding: the forward map still ships the
rdxtree, so adopting B **adds** a mechanism to `kern/` rather than
retiring one. The win has to pay for a second structure, not just beat the
reverse tree.

## 8. If B wins — switch sketch

- `kern/reverse_hash.rs`: bucket array allocated fallibly (ADR 0017),
  grow on 7/8 load with rehash, `remove_all` frees the array; keep
  `reverse_key`.
- `IpcSpaceRecord.reverse_map` becomes the new type;
  `IpcSpace::{reverse_insert,reverse_lookup,reverse_remove}` keep their
  signatures, so callers do not change. The record asserts at
  `ipc/mod.rs:485-497` move from the 16-byte tree to pointer + count +
  capacity.
- No `IpcEntry` layout change with B as specified (buckets store key and
  pointer).
- Kernel has no host tests (ADR 0024); behavior is held by the boot gate.

## 9. Limits

- Single-threaded, space lock held, no SMR; XNU's read-side advantage is
  not visible here.
- Host allocator and synthetic address patterns. The truncated `u32` key
  makes results distribution-sensitive, which is why key pattern is an
  axis.
- Benchmarks are evidence, not a gate (ADR 0024); the kernel is proven by
  booting.
- B is a policy model, not XNU's code, and its storage trick is
  deliberately not applicable to our slab entries.

## 10. Deliverables

- [ ] scaffold with `src/robin_hash.rs` and `benches/reverse.rs`
- [ ] `examples/reverse_memory.rs`, `examples/reverse_grow_tail.rs`
- [ ] `mise run bench::rdxtree-reverse`
- [ ] one results table in `RESEARCH-rdxtree-reverse-results.md`
- [ ] a decision: keep `Rdxtree` or switch to `RobinHash`
