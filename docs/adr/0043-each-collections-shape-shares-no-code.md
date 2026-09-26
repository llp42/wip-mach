# Each `collections` shape shares no code

`collections`' `singly_list`, `list`, `simple_queue` and `tail_queue`
each keep their own link, adapter trait, adapter macro, cursors and
iterator, even where they look alike. A link belongs to its shape:
`list::Link` joins only a `List`. Only `src/test_items.rs` is shared,
and only under `#[cfg(test)]`.

## Considered Options

- **A generic core shared by the shapes**: one link type would let a
  node join a structure of the wrong shape, and a change made for one
  shape would move the code of all four.
