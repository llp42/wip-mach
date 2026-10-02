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
| `RadixTree<T, A>` | values under 32-bit keys | nodes, through `A` |

`A: Alloc` is stored in each owner. A zero-sized `T` or an empty buffer
never reaches the allocator.

## `RadixTree`

A dense integer radix tree: 6 key bits per level, at most 6 node chases
for a 32-bit key. Leaves hold `T` inline; nodes come from `A` and are
freed on removal and on drop. The lowest free key is one descent
(`insert_alloc`). `insert` on an occupied key is `Error::Exists` and
leaves the old value. `iter` walks in key order.

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
