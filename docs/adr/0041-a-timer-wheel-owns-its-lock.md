# A timer wheel owns its lock

Each `clock` wheel owns its buckets, cursor and an irq spin lock from
`lock` (ADR 0029), since the clock interrupt reaches the wheel. Any CPU
may arm or cancel; nothing is shared between wheels.
`HashedWheel::new` is `const`, so a wheel can be a `static` and mutates
through `Pin<&Self>` because the buckets point back into it. The
clock's own mutable state uses an irq spin lock too, so an interrupt
that wants it cannot deadlock the holder.

## Considered Options

- **A lock outside the wheel**: callers must agree on one lock per
  wheel and on the irq-quiet nesting; easy to get wrong at a call
  site.
- **Per-record locks**: no gain when every mutation is already a
  constant-time link or unlink under one bucket table.
