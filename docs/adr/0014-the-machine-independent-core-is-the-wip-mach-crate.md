# The machine-independent core is the `wip-mach` crate

Machine-independent Mach — IPC, VM above the pmap, tasks, threads,
scheduling and device dispatch — lives in the `wip-mach` crate. It
receives the machine through its `Platform` trait (ADR 0006): the
pmap, context switch, per-CPU data, user copy and interrupt control.
`kernel` holds x86_64, boot, the MIG seam and the wiring. This is
Mach's own machine-independent / machine-dependent split, drawn as a
crate boundary.

The final map is not fixed; the test is. Code moves out of `kernel`
when a `Platform` seam can carry what it needs without mirroring its
internals. Code that cannot move stays in `kernel`, and that is the
target, not debt. Mechanisms with no Mach semantics — the radix tree,
the boot-script parser, the ELF loader, the ACPI table reader — take
the same test and move to crates of their own. A planned move is a
`DEBT.md` entry (ADR 0012); code that stays needs no record.

## Considered Options

- **The Mach core stays in `kernel` as modules**: only small reusable
  pieces become crates, and the object model is tested only by
  booting. Rejected: the largest and most intricate code would be the
  only code without host tests.
- **One crate per subsystem** (`ipc`, `vm`, `sched`): IPC, VM and
  tasks refer to each other, and crates must form an acyclic graph, so
  every cycle would need a trait that exists only to break it.

## Consequences

- `wip-mach` is host-testable against a fake machine and held to the
  gates of ADR 0024; the `host-tests` shim that compiles kernel
  sources on the host shrinks as code moves out.
- Its `Platform` is a seam for testing, shaped by x86_64 (ADR 0003).
- The MIG seam stays in `kernel`, so `wip-mach` holds no C-visible
  symbols (ADR 0027).
- It carries code derived from GNU Mach, so it is GPL-2.0-or-later
  (ADR 0010).
