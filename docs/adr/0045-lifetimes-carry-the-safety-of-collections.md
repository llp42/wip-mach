# Lifetimes carry the safety of `collections`

Every `collections` head is `Shape<'nodes, A>`. A safe push takes
`&'nodes mut Node`, and pops and cursor removals hand it back as
`&'nodes mut Node`, so the borrow checker proves, at no runtime cost,
that a linked node stays alive and in place, is reached only through
its structure, and is never linked twice or onto two structures at
once. Nothing hands out `&mut Node` while the node is linked, since
safe code could then overwrite its link.

Only the entry points a lifetime cannot express are `unsafe`: the
`_ptr` pushes and inserts, `cursor_mut_from_ptr`, and `remove_ptr` on
`List` and `TailQueue`, which follow the node's own back pointer.
`remove_ptr` on the singly linked shapes walks from the front, so it
is safe and returns `Result<(), NotFound>`.

- **`remove_ptr` returns no node.** The caller already holds its
  pointer; returning `&'nodes mut` would rebuild it from the pointer
  the walk just loaded, and a caller pushing the node straight back
  would wait on that load.
- **The structure's own pointer comes back.** Anything that returns
  `&'nodes mut Node`, and a cursor's `current_ptr`, builds it from the
  pointer stored at push time, never from a caller's pointer, which may
  only allow reads. `current_ptr` is for callers that keep raw node
  pointers across a point where the head is reached again; a pointer made
  from `current()` only reads.
