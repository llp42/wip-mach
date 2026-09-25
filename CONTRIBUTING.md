# Contributing

Rules for this project. Follow them unless a PR justifies changing the rule
itself.

## Build

- `cargo build` alone must produce the final kernel ELF. No separate
  assembler/linker step, no build system beyond Cargo.
- Prefer official, prebuilt Rust targets (e.g. `x86_64-unknown-none`). Only
  reach for a custom target-spec JSON / `-Z build-std` if no official target
  covers the architecture.
- Linker: `rust-lld`. Don't switch to GNU `ld` without a concrete reason.

## Assembly

- Inline only, via `core::arch::asm!` / `global_asm!` / `naked_asm!` with
  `options(att_syntax)`. No separate `.s`/`.S` files.

## Naming

- Architectures are always `x86` (32-bit) / `x86_64` (64-bit) — in file
  names, target names, and prose. Never `i686`, `i386`, `amd64`.
- Exception: identifiers the toolchain defines itself (target triples, ELF
  format names) — leave those as-is.

## Licensing

- Every source file starts with:
  ```
  SPDX-License-Identifier: <license>
  SPDX-FileCopyrightText: <year> <name> <email>
  ```
- Non-copyrightable files (JSON, data) are exempt.
