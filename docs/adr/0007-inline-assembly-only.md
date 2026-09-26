# Inline assembly only

Assembly is written inline, via `core::arch::asm!` / `global_asm!` /
`naked_asm!` with `options(att_syntax)`. No separate `.s` / `.S`
files. This keeps the toolchain story Cargo-only (ADR 0004): a
separate assembler step would reintroduce a second build path into
the kernel image.

## Consequences

- Assembly lives beside the Rust that reads it, with the `// SAFETY:`
  contract of ADR 0005 where the block needs one.
- AT&T syntax is fixed so the inline fragments match the GNU Mach
  sources the port reads, and so one syntax is used everywhere.
