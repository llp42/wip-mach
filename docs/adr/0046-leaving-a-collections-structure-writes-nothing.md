# Leaving a `collections` structure writes nothing

In release builds, removing a node from a `collections` structure never
writes to it. There is no unlinked mark, no `is_linked` and no `Drop`
on any head; `clear()` is O(1) and leaves the nodes' stale link words
for the next push to overwrite. In debug builds, `List` and `TailQueue`
check before every operation that a link's neighbours point back at
it, and fill a leaving link with dangling pointers so a stale use
faults on a recognisable address. Debug-only code is gated with
`#[cfg(debug_assertions)]`, never `if cfg!(…)`.

## Considered Options

- **An unlinked marker**: a write on every removal, a `Drop` on every
  link, and a marker that must be right before every insert — so an
  object filled in over recycled memory can carry a stale "linked"
  mark into its first push.
