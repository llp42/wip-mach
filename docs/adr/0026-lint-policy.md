# Lint policy

Every crate denies clippy's `all`, `pedantic`, `nursery` and `cargo`
groups, plus strict rustc lints such as `missing_docs` and
`unsafe_op_in_unsafe_fn`. Each crate keeps its own lint table in its
`Cargo.toml`, because Cargo cannot merge `[workspace.lints]` with lints
a crate adds; a crate may be stricter than the baseline, as
`collections` denies `restriction` and `kernel` and `wip-mach` deny
the panic lints of ADR 0018.

A local exception is `#[expect(lint, reason = "…")]`, never
`#[allow]`: every crate denies `allow_attributes` and
`allow_attributes_without_reason`. Test-only relaxations — `unwrap`,
`expect`, indexing, panics in tests — live in the crate's
`clippy.toml`, never in the library. A crate-wide exception needs the
same reason a local one does; "the C did it this way" is not one
(ADR 0027).

A crate that denies `restriction`, as `collections` does, lists the few
`restriction` lints it allows in its `Cargo.toml`, each with its reason
beside it, and every reason is one of three kinds: the lint contradicts
another lint (`implicit_return`, one of each semicolon or visibility
pair), it goes against plain Rust idiom (`?`, `pub use`, `mod.rs`), or
it goes against the comment rules of ADR 0025 (a SAFETY comment inside
an `unsafe fn`, docs that respell a private name). A new allowance
needs a reason of the same kind; everything else is fixed in the code.

## Considered Options

- **`#[allow]` with a comment**: it outlives its reason silently,
  while an `#[expect]` that stops firing fails the build.
- **One workspace lint table**: it cannot vary per crate, and the
  crates differ on purpose.

## Consequences

- Clean means zero warnings on every clippy run the gates list
  (ADR 0024).
