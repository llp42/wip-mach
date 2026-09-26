# The `collections` operation set is closed

Each `collections` shape offers only the operations in the crate's
README tables: the classic kernel queue set. There is no `len`,
`contains`, `split_off` or `pop_back`, and no `pop_front` on `List` or
`TailQueue`, whose front is popped through a cursor. An operation is
added only when a caller needs it. The rule for users is the mirror
image: pick the smallest shape that has the operations you need.

## Consequences

- A head stays one or two words: `len` alone would add a count word
  to every head and a write to every push and removal.
- Every operation is code held to 100% coverage and a safety argument
  (ADR 0024), so an unused one is cost without use.
