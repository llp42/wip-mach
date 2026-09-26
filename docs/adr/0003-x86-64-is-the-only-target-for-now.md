# x86_64 is the only target for now

x86_64 is the sole supported architecture. That is a deliberate
deferral to keep the kernel tractable, not an identity boundary: a
future aarch64 or riscv port is not planned and is not blocked by this
decision. x86_32 and 32-bit compatibility are rejected as a dead
architecture and will not be supported.

## Considered Options

- **x86_64 by identity, forever**: the kernel assumes x86_64 freely
  and other arches are out of scope permanently. Rejected: it bakes a
  scope limit into the code's shape for no present gain.
- **Multi-arch from the start**: keep x86_32 and a second 64-bit port
  alive alongside x86_64. Rejected: x86_32 is dead, and a second live
  port doubles every low-level change.

## Consequences

- No multi-arch work — no cfg-gated second architecture, no porting
  layer for an arch nobody is porting.
- The `Platform` of the `wip-mach` crate (ADR 0014) is a seam for host
  testing, shaped by x86_64. It is not a porting layer and does not
  pretend to be arch-neutral.
- "Dead arch" here names x86_32 and 32-bit compat specifically; they
  are rejected outright. Other architectures are merely deferred.
- Architecture spelling in names and prose is `x86_64`, never `amd64`
  (ADR 0008).
