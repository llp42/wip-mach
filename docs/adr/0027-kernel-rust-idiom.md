# Kernel Rust idiom

Kernel code is written as Rust, not as C spelled in Rust (ADR 0013):

- **C-visible symbols only at the MIG seam.** `extern "C"` and
  `#[no_mangle]` appear only in the one MIG seam module in `kernel`,
  and on symbols inline assembly refers to. Each seam function
  converts the C types, calls the Rust API and converts the result
  (ADR 0015).
- **No `static mut`.** Global state sits behind a lock type, in
  per-CPU storage, or in atomics.
- **Objects are types with methods.** Module files drop upstream
  prefixes (`ipc/port.rs`, not `ipc/ipc_port.rs`), and names follow
  Rust's API guidelines everywhere except ABI names (ADR 0008,
  ADR 0010).
- **No lint allowances for mirroring C.** Crate-wide allowances of
  `cast_*` lints or `inline_always`, justified by matching the C one
  for one, do not exist; each cast or `#[inline(always)]` stands on
  its own reason where it is (ADR 0026).
- **Data lives inside its lock**, and the guard is the only way to it
  (ADR 0035).

## Considered Options

- **Keep the translated C shape** until it hurts: every new subsystem
  would have to call through it, and the shape spreads faster than it
  is removed.

## Consequences

- The MIG seam is the only place the kernel speaks C; `wip-mach` never
  does (ADR 0014).
