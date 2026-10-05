# Docs describe the target; `DEBT.md` describes the gap

ADRs, glossaries, READMEs and `AGENTS.md` files describe the kernel as
it is meant to be, never as it is. The one exception is the top-level
`README.md`, which names the GNU Mach calls the kernel does not
implement: a user of the kernel meets those before any rule. Apart
from that list, the one document that describes the present is
`DEBT.md` at the repository root, the debt register: one register for
every crate, holding one entry per gap between the code and an ADR:

```
## <the gap>

- **ADR**: the ADR the code falls short of, or "none, needs an ADR"
  for an open design question.
- **Where**: the crates, modules or files.
- **Done when**: a check anyone can run, such as "no `spl`
  identifier in `crates/`".
```

An entry is per gap, not per file, and carries no ID. Work in progress
is an entry too. Code carries no `TODO`, `FIXME` or `XXX` markers: a
gap the code knows of is an entry. A change that closes a gap deletes
its entry; a change that opens one adds it.

Every rule is an ADR, style and lint conventions included; an
`AGENTS.md` points at the ADRs and holds only agent workflow. Every ADR
lives in `docs/adr/`, in one numbering space, whatever crate it
concerns, and the project has one glossary, `GLOSSARY.md`, with a
subheading per area. A
decision that no longer holds is deleted by the change that replaces
it, and lives on only in git history; its number is never reused. The
replacing ADR names the old choice under Considered Options when it is
worth remembering. ADRs carry no status.

## Considered Options

- **Unimplemented calls in `DEBT.md` only**: someone running software
  on the kernel would have to read the developers' register to learn
  that a GNU Mach call fails, and a failing simple routine reports
  nothing at run time.
- **As-is notes inside ADRs** (the earlier practice): every ADR mixed
  its rule with a running account of how far the code had got, and a
  reader could not tell which sentences bind.
- **The issue tracker only**: the gap lives outside the repository and
  does not travel with the code through review.
- **`// DEBT:` markers in code**: the register is scattered, and code
  comments narrate the code's own shortcomings.
- **Status frontmatter** (`superseded`, `amended by`): dead text kept
  beside live text, with a flag to say which is which.
- **ADRs and glossaries per crate**: each crate had its own numbering,
  so references needed a crate qualifier, and decisions that shape
  other crates — the lock type's interrupt policy, `Callout` as the
  only arm path — sat where readers of those crates would not look.
  The crates are unpublished parts of one kernel, not products of
  their own.

## Consequences

- Code that contradicts an ADR is either listed in `DEBT.md` or a
  defect.
- An unimplemented call is listed twice: in the README for the
  kernel's users, and as a `DEBT.md` entry for its developers. The
  change that implements it deletes both.
- Plans are not kept as documents: their decided parts become ADRs and
  the rest become entries.
- Numbers have gaps where ADRs were deleted; `CONTRIBUTING.md` lists
  the live ones.
