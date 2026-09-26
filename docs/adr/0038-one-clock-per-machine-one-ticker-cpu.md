# One clock per machine, one ticker CPU

Exactly one `Clock` runs on a machine, and exactly one CPU calls
`Clock::tick`; every other use is a read. The tick count is the hard
time wheels derive their deadlines from, so a missed or extra `tick`
miscounts time. Wheels never count CPUs: each is an independent
object, and where wheels live (per CPU, per subsystem, one for the
machine) is the caller's choice.

## Considered Options

- **One clock per CPU**: each would need its own tick source and a
  reconciliation story for wall time; the kernel has one machine clock.
- **Wheels that know their CPU**: couples placement policy into a
  structure that only needs a tick source and an irq spin lock.
