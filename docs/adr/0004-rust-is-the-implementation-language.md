# Rust is the implementation language

Rust is the implementation language. `cargo build` is the only entry
point that produces the final kernel ELF: no separate assembler or
linker step, no build system beyond Cargo. The linker is `rust-lld`,
not GNU `ld`. The kernel builds with stable Rust only: no
`#![feature]`, and no `RUSTC_BOOTSTRAP` to unlock one; a nightly
feature needs its own ADR. The target is the official prebuilt
`x86_64-unknown-none`; a custom target-spec JSON, which needs
`-Z build-std`, falls under the same rule.

Hand-written C code (`.c` / `.S` bodies) and checked-in generated C
are forbidden, with one exception at the MIG seam. There, the build
script runs GNU MIG to generate C into `OUT_DIR` and compiles it with
the host C compiler; that output is never checked in. The generated C
compiles against shim headers: hand-written C headers in
`mach-mig-sys` that declare types only, and are permanent. GNU MIG and
a host C compiler are build dependencies for that seam alone. Inline
assembly is allowed on the terms of ADR 0007.

## Considered Options

- **Rust with a C/assembly build system around it** (the GNU Mach
  shape): keep the make/ld pipeline and drop Rust into it. Rejected:
  two toolchains and two sources of link truth for one kernel image.
- **A Rust MIG**: an in-tree generator that reads the same `.defs` and
  writes Rust stubs, so no C and no headers at all. Rejected: it means
  writing and keeping a MIG that must reproduce GNU MIG's message
  layouts byte for byte, where GNU MIG already produces them.
- **Nightly Rust**, as Rust-for-Linux does through `RUSTC_BOOTSTRAP`:
  every toolchain bump can break the build, and the features used
  become part of what a contributor must track.

## Consequences

- Nothing but the MIG seam calls a second tool while building the
  kernel.
- A shim header holds type declarations only; one that grows logic,
  or declares anything but types, is a defect.
- A second language is a decision for an ADR, not a local convenience.
