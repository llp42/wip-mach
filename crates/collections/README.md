# `collections` — intrusive lists, queues and a tree

Five intrusive structures for a `no_std` kernel. The links live inside
caller-owned nodes, so no structure ever allocates or frees. Each shape
is a small, fixed-size head plus one link field per node.

| Shape | Head | Link | Walk | Pinned head | Removal by address |
|---|---|---|---|---|---|
| [`SinglyList`](src/singly_list/mod.rs) | 1 word | 1 word | forward | no | O(n), safe |
| [`List`](src/list/mod.rs) | 1 word | 2 words | forward | yes | O(1) without the head, `unsafe` |
| [`SimpleQueue`](src/simple_queue/mod.rs) | 2 words | 1 word | forward | yes | O(n), safe |
| [`TailQueue`](src/tail_queue/mod.rs) | 2 words | 2 words | both ways | yes | O(1), `unsafe` |
| [`RbTree`](src/rb_tree/mod.rs) | 3 words | 3 words | both ways, in key order | no | no search, `unsafe` |

Pick the smallest shape that has the operations you need:

- **`SinglyList`** — a stack or a free list.
- **`List`** — an unordered set that nodes leave from their own
  address, such as hash buckets or timers.
- **`SimpleQueue`** — a FIFO.
- **`TailQueue`** — anything walked backwards, or removed from the
  middle given the head, such as a run queue.
- **`RbTree`** — nodes kept in key order, with floor and ceiling
  lookups, such as a map of address ranges. Equal keys are allowed.

## Quick start

```rust
use collections::tail_queue::{self, Link, TailQueue};
use core::pin::pin;

struct Thread {
    id: u32,
    link: Link,
}

tail_queue::adapter!(ThreadAdapter = Thread { link });

let mut a = Thread { id: 1, link: Link::new() };
let mut b = Thread { id: 2, link: Link::new() };

let mut run_queue = pin!(TailQueue::<ThreadAdapter>::new());
run_queue.as_mut().push_back(&mut a);
run_queue.as_mut().push_back(&mut b);

assert_eq!(run_queue.front().unwrap().id, 1);
let next = run_queue.as_mut().cursor_front_mut().remove_current();
assert_eq!(next.unwrap().id, 1);
```

## How it works

### Nodes, links and adapters

A node embeds one `Link` for each structure it can join. The link type
belongs to its shape: `list::Link` joins only a `List`. Each shape has an
`adapter!` macro that declares a zero-sized adapter mapping the link
field to its node and back:

```rust
list::adapter!(pub(crate) TimerAdapter = Timer { link });
```

The macro requires the field to be exactly that shape's `Link`. Any other
field type fails to compile. An `RbTree` adapter also names the key that
orders the nodes:

```rust
rb_tree::adapter!(pub(crate) RegionAdapter = Region { link } key(usize) = |region| region.start);
```

 `Adapter` is an `unsafe trait`, so a
hand-written adapter has to promise the same mapping itself.

### Lifetimes do the safety work

Every head carries the lifetime `'nodes` of the nodes it holds, e.g.
`List<'nodes, A>`. A push takes `&'nodes mut Node`, and pops and cursor
removals hand the node back as `&'nodes mut Node`. Cursors also carry
`'head`, the borrow of the head they walk. The borrow checker therefore
proves, at no runtime cost:

- a linked node stays alive and in place;
- nothing reaches a linked node except through its structure, which
  hands out only `&Node`;
- a node is never linked twice, and never onto two structures at once.

A structure never hands out `&mut Node` while the node is linked,
because safe code could then overwrite its link.

### What stays `unsafe`

The `unsafe` parts are the ones a lifetime can't express.

| API | Why |
|---|---|
| `push_front_ptr`, `push_back_ptr`, `insert_*_ptr`, `replace_current_ptr` | They take a raw pointer, for nodes whose lifetime isn't `'nodes` (freed after removal) or that sit on several structures at once. The caller promises the node stays live, in place and unshared until it leaves. |
| `List::remove_ptr`, `TailQueue::remove_ptr`, `RbTree::remove_ptr` | They follow the node's own pointers, so the node must be on that structure. |
| `cursor_mut_from_ptr` | The node must be on that structure. |

`RbTree::insert_ptr` is the `_ptr` form of `insert`.

`SinglyList::remove_ptr` and `SimpleQueue::remove_ptr` are safe. They
walk from the front comparing addresses and return
`Result<(), NotFound>`.

No `remove_ptr` returns the node. The caller already holds its pointer,
and can push it back with a `_ptr` push. Returning a `&'nodes mut` would
force it to be rebuilt from the pointer the walk just loaded, and a
caller that pushes the node straight back would then wait on that load.

### Pinned heads

`List`, `SimpleQueue` and `TailQueue` store pointers back into their own
head, so the head must not move while it holds nodes. These three heads
are `!Unpin` and mutate through `Pin<&mut Self>`. You pin one with
`pin!`, `Box::pin`, or by keeping it in a `static`. A head inside a
`static` lock guard is pinned with `Pin::new_unchecked`, justified by
the static never moving. `SinglyList` points only at nodes and moves
freely.

`new()` is `const` on every head and needs no address. An empty tail is
stored as null, meaning "the head itself".

`RbTree` points only at nodes, never back into its head, so like
`SinglyList` it is not pinned and moves freely. Its head holds the root and
the first and last nodes.

### Leaving writes nothing

In release builds, removing a node never writes to that node. There's
no "unlinked" mark, no `is_linked`, and no `Drop` on any head. `clear()`
is O(1): it forgets the nodes and leaves their stale link words behind,
which the next push overwrites. A node pushed as `&'nodes mut` stays
borrowed until `'nodes` ends, even after `clear()`.

In debug builds, `List`, `TailQueue` and `RbTree` check before every
operation that a link's neighbours point back at it. They also fill a leaving
link with dangling pointers, so a stale use faults on a recognisable
address. `RbTree` checks more: that a link is on the tree it is used with,
that its cached first and last nodes are the tree's ends, that a slot is
empty before a node joins it, that the root is black after a rebalance, and
that its adapter maps a link back to its node. None walks the whole tree.

### Threads

Every `Link` is `Send + Sync`: its words are private and reached only
through its head, under `&` for reads and `&mut`/`Pin<&mut>` for writes.
A head is `Send + Sync` when `Node: Send + Sync`, so it can sit in a
locked `static`.

Every public type implements `Debug`. Heads, cursors and iterators print
their link pointers, never the nodes, so they need no `Node: Debug`.

## Operations

The operation set is deliberately the classic kernel queue-macro set,
with names taken from `std::collections::LinkedList`. Cursors stand in
for element pointers.

| | `SinglyList` | `List` | `SimpleQueue` | `TailQueue` | `RbTree` |
|---|:-:|:-:|:-:|:-:|:-:|
| `new`, `is_empty`, `clear`, `front`, `iter` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `back` | | | ✓ | ✓ | ✓ |
| `iter().rev()` | | | | ✓ | ✓ |
| `push_front` (+ `_ptr`) | ✓ | ✓ | ✓ | ✓ | |
| `push_back` (+ `_ptr`) | | | ✓ | ✓ | |
| `insert` (+ `_ptr`), after equal keys | | | | | ✓ |
| `insert_after_ptr`, `insert_before_ptr`, no search | | | | | `unsafe` |
| `lower_bound(_mut)`, `upper_bound(_mut)` | | | | | ✓ |
| `pop_front` | ✓ | | ✓ | | |
| `remove_ptr` | safe, O(n) | `unsafe`, O(1) | safe, O(n) | `unsafe`, O(1) | `unsafe`, no search |
| `append` (O(1)) | | | ✓ | ✓ | |
| `move_into` | | ✓ | | | |
| `cursor_front(_mut)`, `cursor_mut_from_ptr` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `cursor_back(_mut)` | | | | ✓ | ✓ |

On a `List`, `TailQueue` or `RbTree`, you pop the front with
`cursor_front_mut().remove_current()`.

`RbTree` orders its nodes by `Adapter::key`. `lower_bound(Included(k))`
finds the first node with a key `>= k`, `Excluded(k)` the first `> k`;
`upper_bound(Included(k))` finds the last node with a key `<= k`,
`Excluded(k)` the last `< k`; `Unbounded` is the front or the back. Equal
keys stay in insertion order. The key of a linked node must not change:
a change misorders lookups, and nothing else.

A cursor insert (`insert_after`, `insert_before`) links a node beside the
cursor's node without searching, and so do the head's `insert_after_ptr` and
`insert_before_ptr`, which skip the cursor too, for a caller that already holds the
neighbour, such as a map that keeps its entries in a list as well. The
node's key must lie between its two new neighbours' keys; debug builds
check it, and a node out of order only misorders the lookups that cross it.

### Cursors

A cursor rests on a node or on the **ghost**, the empty position before
the front and after the back. Moving past either end reaches the ghost,
and moving on from it wraps to the other end.

| Cursor method | `SinglyList` | `List` | `SimpleQueue` | `TailQueue` | `RbTree` |
|---|:-:|:-:|:-:|:-:|:-:|
| `current`, `current_ptr`, `move_next`, `peek_next` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `insert_after` (+ `_ptr`); at the ghost, at the front | ✓ | ✓ | ✓ | ✓ | ✓, no search |
| `remove_next`; at the ghost, the front | ✓ | | ✓ | | |
| `insert_before` (+ `_ptr`) | | ✓, panics at the ghost | | ✓, at the ghost at the back | ✓, at the ghost at the back, no search |
| `remove_current` | | ✓ | | ✓ | ✓ |
| `replace_current` (+ `_ptr`) | | ✓ | | ✓ | |
| `move_prev`, `peek_prev` | | | | ✓ | ✓ |

The singly linked shapes keep no predecessor, so their cursors act on
the node *after* them. `replace_current` returns `Err(node)` at the
ghost, handing your node back.

Removing nodes while walking is done with `CursorMut`, not with an
iterator.

`current` gives a `&Node`, and a pointer made from it only reads.
`current_ptr` gives the node's raw pointer, the one the node was pushed
with, for callers that write through it or carry it across a point where
the head is reached again. A cursor must not cross such a point: keep the
pointer and re-derive a cursor with `cursor_mut_from_ptr`.

## Working on the crate

The rules are ADRs 0043 to 0051 in the repository's
[`docs/adr/`](../../docs/adr/), on top of the ones every crate follows.
The ones the code relies on most:

- **No shared code between shapes.** Each module has its own link,
  adapter trait, macro, cursors and iterator, even where they look
  alike. Only the `#[cfg(test)]` item in `src/test_items.rs` is shared.
- **The tree's rebalancing sees links only.** `rb_tree/balance.rs` never
  reads a key or names a node type, so one copy serves every tree. The key
  compare lives in the descent, which is monomorphised through
  `Adapter::key`.
- **No new operations outside the set above.** For example, no `len`,
  `contains` or `pop_back`. Add one only when there's a reason to.
- **Hand back the structure's own pointer.** Anything that returns
  `&'nodes mut Node`, and `current_ptr`, builds it from the pointer stored
  at push time, never from a caller's pointer, which may only allow reads.
  `cursor_mut_from_ptr` re-derives it from the neighbouring slot.
- **Pinned heads write through `Cell`s.** Their methods turn
  `Pin<&mut Self>` into `&Self` and never take `&mut` to a head field,
  so pointers into the head stay valid.
- **Keep the adapter macros' uncast field binding.** It is what makes a
  wrongly typed link field fail to compile.
- **Comments** follow ADR 0025: `// SAFETY:` names the real
  precondition, every `unsafe fn` has `# Safety`, and there are no
  doctests (`no_std`).

### Lints

The crate denies Clippy's `all`, `pedantic`, `nursery`, `cargo` and
`restriction` groups, plus a set of strict rustc lints, in its own
`Cargo.toml`. Test-only relaxations (`unwrap`, `expect`, indexing and
panics in tests) live in the crate's `clippy.toml`. The few
`restriction` lints that are allowed each have their reason next to
them. Some contradict another lint (`implicit_return`, one of each
semicolon or visibility pair). The rest go against plain Rust idiom or
the repository's comment rules: `?`, `pub use`, `mod.rs`, a SAFETY
comment inside an `unsafe fn`, or docs that respell a private name.
Everything else is fixed in the code, not silenced. The one local
`#[expect]` in the library is `insert_before_ptr`'s documented panic at
the ghost; the other sits on the shared test fixture.

### Tests, coverage and benchmarks

```sh
mise run test::collections   # host unit tests
mise run cov::collections    # must stay at 100% lines, regions, functions
cargo clippy -p collections --target x86_64-unknown-linux-gnu --all-targets
cargo bench -p collections --target x86_64-unknown-linux-gnu --bench shapes
cargo bench -p collections --target x86_64-unknown-linux-gnu --bench rb_tree
```

Gate debug-only code with `#[cfg(debug_assertions)]`, not
`if cfg!(debug_assertions)`, which leaves a dead `else` region in the
coverage report. Tests of the debug checks are `#[should_panic]` and
gated on `debug_assertions`.

The benchmark times each shape on the workloads that tell the shapes
apart: `lifo`, `fifo`, `walk`, `walk_rev`, `churn` (remove by address,
push back) and `concat`, at 16, 1024 and 65536 nodes. The `rb_tree`
benchmark times the tree on `insert`, `insert_asc`, `dups`, `floor`,
`ceil`, `churn`, `walk`, `walk_rev` and `drain`, at the same sizes.

## License

MIT. Every file in the crate carries `SPDX-License-Identifier: MIT`:
the crate is original work, carries no derived code and names no
upstream ([ADR 0010](../../docs/adr/0010-spdx-headers-and-provenance.md)).
