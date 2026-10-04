# An MIT crate may carry code derived from MIT upstream

ADR 0010 lets a crate's licence follow its content, and keeps derived code
out of the MIT crates so that no GPL, BSD or CMU file changes what those
crates may be used for. Code derived from an MIT-licensed upstream changes
nothing of the kind: the crate stays MIT, and the one obligation the
upstream licence adds, keeping its copyright notice, is what ADR 0010's
header already does. Such code may therefore enter an MIT crate. The
first is `kmem`'s radix tree, a port of Richard Braun's MIT radix tree from
librbraun, the same author's later release of the tree GNU Mach's IPC name
tables use.

## Considered Options

- **Keep the rule absolute**: every MIT-derived import would need a crate
  of its own, as ADR 0014 already plans for mechanisms with no Mach
  semantics. Rejected: the rule protects the crate's licence, which an MIT
  upstream cannot change, and a crate per import adds a dependency edge
  without adding any clarity.
- **Admit any permissive upstream**: BSD and CMU-Mach notices carry
  conditions of their own wording, and a crate that mixes them is no
  longer described by its one `license` field. Rejected; they stay in the
  GPL crates.

## Consequences

- A derived file in an MIT crate carries the full ADR 0010 header: the
  upstream holders first, the `MIT` identifier, and the provenance block.
  The provenance header, not the crate, tells derived files from original
  ones.
- The ban on upstream file paths and internal names in code, comments and
  READMEs applies to these files as to any other derived file.
- Derived code under any other licence still never enters an MIT crate.
