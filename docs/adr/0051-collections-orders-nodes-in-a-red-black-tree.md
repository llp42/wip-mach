# `collections` orders nodes in a red-black tree

`collections::rb_tree` is the one ordered shape: an intrusive red-black
tree keyed by a value the node's adapter extracts. Its head is three words,
the root and the first and last nodes, and its link three, so a node costs
what a `List` node and a `TailQueue` node cost together. The head is not
pinned: nothing points back into it, so it moves like a `SinglyList`.

- **The compare is the adapter's.** `Adapter::key` returns the node's
  key by value and `Key: Ord` orders it. The descent is monomorphised,
  with no function pointer, no context word and no generated code per
  type. Equal keys are allowed and stay in insertion order.
- **Rebalancing never sees a key.** `balance.rs` works on links alone:
  fix-up after an insert, removal, rotations, and the step to a
  neighbour. One copy serves every tree, and sharing it costs nothing,
  since it makes no compare. It is private to this shape (ADR 0043).
- **The colour is a bit of the parent word.** A link is three words:
  the parent, tagged with the colour, and two children. A removal
  relinks a successor into the removed node's place; it never copies
  node data.
- **Neighbours come from parent pointers.** Cursors and iterators keep
  no stack and never recurse, so a walk costs bounded kernel stack and
  O(1) amortised per step.
- **The operation set is closed** (ADR 0044): `insert`, `remove_ptr`,
  `lower_bound` and `upper_bound` with a `Bound`, `front`, `back`,
  `iter`, cursors that step and remove, and the `_ptr` forms. There is
  no `len`, no `find`, no `pop_front` and no `replace_current`.
- **A cursor insert skips the search.** `insert_after` and
  `insert_before` place a node from the tree's shape, for a caller that
  already holds the neighbour: a map that keeps its entries in a list as
  well links each one right after its list predecessor. A search costs a
  chain of dependent loads that grows with the tree and is the worst
  case for keys that arrive in order; the cursor insert costs none. The
  node's key must lie between its neighbours' keys, checked in debug
  builds; a node out of order misorders lookups and breaks no memory
  safety, as with a key that changes while linked.
- **Leaving writes nothing** (ADR 0046). In debug builds every
  operation checks that the parent's child slot and the children's
  parent words point back at the link, and a leaving link is filled
  with dangling words.

The key is read only through `&Node`, and a linked node is reachable
only as `&Node` (ADR 0045), so a key changes while linked only through
interior mutability. That misorders lookups but breaks no memory
safety: no fix-up reads a key.

## Considered Options

- **Type-specialised code generated per tree by a macro**: fastest
  compare, but a generated copy of the rebalancing code for every tree,
  and a fourth word per link once the colour is a separate field.
- **One untyped implementation with a table of function pointers**:
  one copy of the code, but an indirect call for every compare in every
  descent, and a context word to carry the key's offset.
- **A hash table**: no ordered lookup, and it must resize.
- **A B-tree**: fewer cache misses, but its nodes hold arrays of
  elements, which an intrusive structure cannot give.
- **Another balanced tree (AA, WAVL, treap)**: the red-black tree is the
  standard kernel choice, its fix-up is bounded at two rotations per
  insert and three per removal, and the callers it replaces use one.
- **A "which child am I" bit, a length**: each adds a write on every
  insert and removal, for an operation the callers use once or never.
- **No cached first and last node**: the head stays one word, but a key
  that passes the last node must be searched for, and the search is a
  chain of dependent loads that a predicted branch would not pay. For
  keys that arrive in order it was 2x slower than a branchy tree, and
  the benchmark asked for the fix. The head now caches both ends: an
  insert compares its key with them first, and a key at or past the
  last, or below the first, joins under that end with no search. The
  price is two head words, a write when an end is removed, and two
  predictable compares on every other insert; `front` and `back` become
  O(1).

## Consequences

- A node's link is the size the kernel's existing layout assertions rely
  on; the head grows from one word to three, which moves the fields after
  an `RbTree` in a struct that asserts offsets.
- The benchmark `rb_tree` times the shape on the workloads that tell a
  tree apart: insert, floor lookup, churn, duplicates and walks.
