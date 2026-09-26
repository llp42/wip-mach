# Architecture names are `x86` and `x86_64`

In file names, target names, and prose, 32-bit is `x86` and 64-bit is
`x86_64`. Never `i386`, `i686`, `amd64`.

Exceptions keep the spelling someone else defined:

- identifiers the toolchain defines itself: target triples such as
  `x86_64-unknown-none`, ELF format names;
- ABI names: identifiers the Mach ABI publishes, such as the
  `mach_i386` MIG subsystem or the `i386_THREAD_STATE` flavour, which
  userspace compiles against and the kernel cannot rename.

## Consequences

- A name like `arch/i686`, "the amd64 port", or a file named after
  `i386` that is not an ABI name is a defect even when it would be
  understood.
- The spelling matches ADR 0003: the live target is `x86_64`, and
  `x86` is the name for the 32-bit family that is not being ported.
