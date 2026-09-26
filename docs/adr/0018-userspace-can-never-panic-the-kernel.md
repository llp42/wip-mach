# Userspace can never panic the kernel

Every path reachable from a trap or a message meets bad input and
exhausted resources by returning an error to its caller (ADR 0015); it
never panics. Privilege is no exception: a task holding the privileged
host port halts the machine only through `host_reboot`, never by
reaching a panic. A panic means a broken kernel invariant or a failed
boot, nothing else.

`host_reboot` with `RB_DEBUGGER` — there is no in-kernel debugger
(ADR 0021) — parks every CPU the way the panic halt does, prints a
`debugger requested` line on the serial console and waits for GDB: a
requested stop, not a panic.

`kernel` and `wip-mach` deny clippy's `unwrap_used`, `expect_used`,
`indexing_slicing` and `panic`. A boot path or an invariant check opts
out one site at a time with a reasoned `#[expect]` (ADR 0026), and
documents it under `# Panics` (ADR 0025).

## Considered Options

- **Panics on exhaustion**, treated as a tuning problem: any task that
  can make the kernel allocate can then halt it.
- **Local advice** in the allocator's module docs: nothing checks it,
  and it covers allocation only, not indexing or unwrapping user data.

## Consequences

- A `# Panics` section names a kernel invariant, never an input.
- A panic a task can trigger is a security bug, not a robustness one.
- Allocation needs no lint of its own: `kmem` has no infallible path
  (ADR 0017).
