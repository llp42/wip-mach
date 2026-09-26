# Documentation comments

Comments document what the compiler cannot check; everything else is
left to the code.

- **Redundancy** — never write what the code already says: if a reader
  could reconstruct it from the signature and body, leave it out.
  Prefer no doc over one that respells the name. Document what the
  compiler cannot check: which lock guards what, the locking order,
  whether a path may sleep, what must hold at interrupt level, the
  invariants a type relies on.
- **Grammar** — `//!` opens every file, after the license header,
  saying what the module is. `///` documents items. Plain `//` is for
  the license and provenance header, `// SAFETY:`, and in-body
  rationale — never to document an item.
- **In-body** — never comment a variable assignment; rename instead. A
  comment earns its place only by saying something the code does not,
  as why an ordering matters.
- **`unsafe`** — `# Safety` on an `unsafe fn`, `// SAFETY:` naming the
  actual lock or precondition on an `unsafe {}` in a safe fn, nothing
  on an `unsafe {}` the fn's own contract already covers (ADR 0005).
- **Sections** — in the order `# Examples`, `# Panics`, `# Errors`,
  `# Safety`; `# Panics` wherever the kernel halts, naming the
  invariant (ADR 0018). No doctests (`no_std`/`no_main`): examples are
  fenced `text` or `ignore`.
- **Names** — a comment may cite an ABI name; it never cites an
  upstream internal name or an upstream source path (ADR 0010).
- **`#[repr(C)]` layouts** — a
  `#[expect(missing_docs, reason = "…")]` (ADR 0026), not a doc per
  field. Document a field only where the name does not say it, as
  ``/// `msgh_bits`: the two port dispositions and the complex flag.``
  The same goes for an `impl` of bitfield accessors: the bit constants
  carry the docs.
- **Summary** — one sentence, blank line, then detail. Third person
  indicative: `Returns the…`, never `Return the…`. Link with
  ``[`Ident`]``. Wrap at 79 columns, per `rustfmt.toml`.

## Considered Options

- **Doc every item**, as `missing_docs` alone would push: docs that
  respell names bury the few that carry a lock rule or an invariant.

## Consequences

- A comment that restates the code is a review defect, as is a missing
  `# Panics` or `// SAFETY:`.
