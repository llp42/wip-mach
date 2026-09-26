# Timer wheels are Scheme 6, not a hierarchy

A `clock` timer wheel is Scheme 6 of Varghese and Lauck, *Hashed and
Hierarchical Timing Wheels* (SOSP 1987): 256 unsorted
`collections::list::List` buckets, indexed by the low bits of a
record's absolute expiry tick. Records are caller-owned; the wheel only
links and unlinks them, so there is no allocation. A hierarchy
(Scheme 7) is not used: at the tens of timers a kernel holds per CPU it
cannot buy more than a few nanoseconds per 10 ms tick, and it loses
again once most timeouts are cancelled early. Any second structure
needs new measurements against a real workload first.

## Considered Options

- **Scheme 7 hierarchy**: a Scheme 6 record whose interval is T ticks
  is revisited about ⌈T/256⌉ times — 24 times for a 60 s timeout at
  100 Hz — and a hierarchy bounds that by its level count. Pure
  Scheme 4, which never revisits, bounds what a hierarchy could save:
  under 3 ns per 10 ms tick at up to 1024 long timers. Proposed and
  not adopted, 2026-09-30.
- **Scheme 4, or Scheme 4 in front of Scheme 6, a sorted list or a
  red-black tree**: gain at most tens of nanoseconds per tick at
  thousands of timers and pay O(log n) or O(n) on every start and
  cancel; measured out 2026-09-30.
- **`TailQueue` buckets**: no win over one-word `List` heads.
