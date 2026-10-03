# `rdxtree-bench` — the C tree against `kmem::RadixTree`

The kernel's IPC name table is a radix tree, and `kmem::RadixTree` is the
MIT rewrite that replaced the C one. This crate is how the rewrite is
argued for: it times both, on the workloads the kernel puts them
through, and prints the numbers side by side.

```sh
mise run bench::rdxtree
cargo run -p rdxtree-bench --target x86_64-unknown-linux-gnu --example nodes
```

Ids read `<tree>/<workload>/<entries>`: `c` is the reference, `new` is
`kmem::RadixTree`. Criterion writes its reports under `target/criterion/`,
so `--save-baseline` and `--baseline` compare two runs as usual.

## What it compares

`crates/kmem` is designed from the literature and carries no derived
code, so the tree it holds is not the C tree reshaped — it is a second
answer to the same problem. That only means something if the first
answer is measured, not remembered, which is what the frozen C copy is
for (ADR 0052).

The two store the same values under the same 32-bit keys. The kernel
builds the reference with 32-bit keys, and the crate's build script
refuses to compile it without them, because the keys are what a radix
tree's shape is made of and comparing across key widths compares
nothing.

## The reference

`src/old` holds the C tree: the three files of its implementation and
headers, byte-identical below the provenance header each one carries, and
`src/old/shim`, which is this crate's own code and stands in for the
kernel environment the reference expects — a node cache, the assertion
header, two result codes and three macros. The cache keeps what it is
given back, as the kernel's does, so neither tree pays the host allocator
for a node the other reuses.

Updating the copy is not a thing this crate does. A baseline that moves
is not a baseline; if the reference ever has to change, it is a new
decision with its own reasons, not a sync.

One thing about it is worth knowing before writing a workload. At the
32-bit key width the kernel builds it with, a key at or above `2^30`
grows its tree to a sixth level, and its walk then advances the seek key
past the end through a shift wider than the key itself: undefined in C,
compiled to a shift by four, and seconds where below `2^30` it is
nothing. The kernel cannot reach it — its window is under `2^30` bytes
and a key is a word offset into it — so no workload here may either.
`reverse_map` derives its keys from addresses, which is exactly how to
walk into this, and it bounds them for that reason.

## Running it

Every workload is an action the kernel performs on an IPC space's name
table, or on the reverse map beside it; the crate's module documentation
maps each id to its call site. `reverse_map` is the address-keyed second
map, which is the one workload whose keys ascend, as they do when the
objects they name are carved out of slabs.

The matrix is 13 workloads × 4 sizes × 2 trees, so a full run is
minutes. Criterion's own flags cut it down:

```sh
cargo bench -p rdxtree-bench --target x86_64-unknown-linux-gnu -- \
    --measurement-time 0.5 --warm-up-time 0.2 --sample-size 10
cargo bench -p rdxtree-bench --target x86_64-unknown-linux-gnu -- lookup/1024
```

## Keeping the comparison honest

A difference the harness introduced is not a result, so three things are
held equal and the fourth is named:

- **One allocator lifetime.** Both draw nodes from a process-global free
  list that survives between iterations, as the kernel's node cache
  does. A per-tree list would hand its blocks back when the tree is
  dropped, and the tree that reuses them would be timed as the faster
  one.
- **The same teardown.** Each routine takes its tree by value, so its
  destructor runs inside the timed window. `CTree` drops through the
  reference's bulk removal and `NewTree` through `RadixTree::drop`;
  both free every node, inside the measurement.
- **The same assertions.** The reference is compiled with `NDEBUG`
  because the contender's `debug_assert!`s are compiled out in this
  profile.
- **One difference is the trees'**: replacing an *absent* key inserts it
  in `new` and answers null in `c`. No workload rewrites a key that is
  not there, so this shows up as nothing — but a new workload that does
  would be measuring the difference, not the cost.

Only relative numbers mean anything. This is a host process, not the
kernel, and the reference is built by whatever `cc` the host has, at the
optimisation level the rest of the build uses.

## Safety

The crate is `unsafe` at the boundary with the reference and nowhere
else: the C tree is a value this crate allocates and hands across, and
every call into it carries a `// SAFETY:` naming the invariant that makes
it sound. The two structures the Rust side mirrors are pinned by
`_Static_assert` in `src/old/shim/bridge.c` and by `const _: () =
assert!(...)` beside the mirror, so a layout that drifts fails the build
rather than the run.

## License

`GPL-2.0-or-later` for this crate's own code. The reference under
`src/old` keeps the `BSD-2-Clause` identifier in its header and is not
relicensed.
