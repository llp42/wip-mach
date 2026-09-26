# GNU Mach is a behaviour reference, not a tracked source

GNU Mach defines *what* the kernel does at the Mach ABI (ADR 0002);
*how* it does it is this project's design. There is no upstream sync
process. A GNU Mach change matters here only when it changes the ABI
or fixes a behaviour the Hurd depends on, and then it is carried over
as new work, not merged. Subsystems are designed from the literature
and from kernels whose shape fits better, as `lock` follows Zircon and
`clock` follows Varghese and Lauck. Code translated line by line from
GNU Mach is scaffolding to be replaced, and all of it is debt
(ADR 0012).

## Considered Options

- **A faithful port that tracks upstream**: keep a file-for-file
  match so upstream diffs keep applying. Rejected: it freezes the C
  shape — `static mut`, `kern_return_t` everywhere, hand-counted
  references, spl — to serve a sync the project does not need, since
  the ABI it must match is stable.
- **Snapshot, then refactor in place**: the pinned commit is the base
  and is reshaped step by step. Rejected: a refactor inherits the
  structure decisions the new subsystems already replaced, as `lock`
  replaced spl and simple locks rather than wrapping them.

## Consequences

- A GNU Mach bug is not a task here unless the Hurd can observe it.
- Derived files keep their provenance header (ADR 0010) and may change
  shape freely; nothing in code or docs answers to the upstream
  layout.
- Kernel code is held to the idiom of ADR 0027, not to the translation.
