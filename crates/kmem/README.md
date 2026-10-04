# `kmem` — fallible owning heap types

The kernel links no `alloc` crate ([ADR 0017](../../docs/adr/0017-allocation-is-fallible-never-waits-and-has-no-global-allocator.md)).
`kmem` defines the allocator trait the kernel implements and the owning
types over it. Nothing here waits, and nothing has an infallible
constructor.

| Type | Owns | Freed by |
|---|---|---|
| `KBox<T, A>` | one `T` | `T`'s layout |
| `KBoxSlice<T, A>` | a fixed run of `T` | the array layout |
| `KVec<T, A>` | a growable run of `T` | the array layout of its capacity |
| `KRawBuf<A>` | untyped bytes | its size, at 8-byte alignment |
| `RadixTree<T, A>` | nodes indexing `NonNull<T>` by 64-bit key | nodes, through `A` |

`A: Alloc` is stored in each owner. A zero-sized `T` or an empty buffer
never reaches the allocator.

## `RadixTree`

A radix tree of `NonNull<T>` under 64-bit keys: 6 key bits per level,
and only as many levels as the largest key needs, so a 32-bit key is at
most 6 node chases. Leaves are four-byte-aligned pointers the tree never
dereferences or frees; nodes come from `A` and are freed on removal,
shrinking, `clear` and drop. `RadixTree::new(alloc, key_alloc)` decides
whether nodes keep the free-slot bitmaps `insert_alloc` follows. A node
clears its bit once all its slots are occupied, so allocation can pass
over a free key until a removal below it sets the bit again. `insert` on
an occupied key is `Error::Busy` and leaves the old pointer; `get_slot`
and the `*_slot` insertions hand back a `Slot` that replaces it in place.
`iter` walks in key order.

The tree is derived code under the MIT licence: its file keeps the
upstream holders and provenance header
([ADR 0053](../../docs/adr/0053-an-mit-crate-may-carry-code-derived-from-mit-upstream.md)).

## Failure

A constructor returns `Result<_, AllocError>` and drops the value it was
given. To keep a value across a failure, reserve first and write after:

```text
let slot = KBox::try_new_uninit(alloc)?;   // may fail; no value yet
let boxed = KBox::write(slot, value);      // cannot fail
```

`KVec` does the same with `try_reserve` and `push_within_capacity`, and
`into_boxed_slice` hands the vector back when the shrink cannot allocate.

## Implementing `Alloc`

`alloc(layout)` and `free(ptr, layout)` are sized and fallible, and the
size passed to `free` is the one `alloc` got. An implementation must never
sleep and is never called from an interrupt handler.

## Tests

`cargo test -p kmem --target x86_64-unknown-linux-gnu` (`mise run
test::kmem`) runs the host tests against a mock allocator that fails the
Nth call, checks every free against its allocation's layout, and panics on
a leak. `mise run cov::kmem` holds the crate at 100% line, region and
function coverage. Miri is a manual check, not a gate: it needs nightly
(ADR 0004).

[`RESEARCH.md`](RESEARCH.md) is the survey of GNU Mach's and the kernel's
allocation sites that shaped the type list.
