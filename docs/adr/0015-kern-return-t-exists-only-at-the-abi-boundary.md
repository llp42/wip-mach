# `kern_return_t` exists only at the ABI boundary

Inside the kernel and its crates, a fallible operation returns
`Result<T, E>` with a typed error. A `kern_return_t`, or any other C
integer result, is produced only at the trap entry and the MIG seam,
by one conversion from the error type, and read only there.

## Considered Options

- **`kern_return_t` everywhere** (GNU Mach's shape, and what a port
  keeps): errors are integers the compiler cannot check, success must
  be tested by hand at every call, and `?` does not apply.

## Consequences

- The conversion from error type to `kern_return_t` is part of the
  Mach ABI (ADR 0002): which error a caller sees is decided there, in
  one place.
- An error type carries enough to choose the `kern_return_t` each RPC
  must return; two RPCs that report one failure differently get two
  variants, not a flag at the seam.
