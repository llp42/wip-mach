# A benchmark may vendor the reference it measures against

A crate whose only product is a benchmark may keep a frozen copy of a
third-party implementation to measure against, and compile it with the host
C compiler from its build script. ADR 0004 forbids C bodies everywhere else,
and is unchanged: such a crate is never a dependency of the kernel or of any
product crate, so the image still builds from Rust alone.

- **The copy is frozen.** Its code is byte-identical to the file it was
  taken from, below a provenance header that pins the commit and names the
  originals (ADR 0010). Nothing syncs it, because a comparison whose
  baseline moves is not a comparison. The upstream licence block stays, as a
  permissive licence requires, and upstream's own markers come with it: the
  marker ban (ADR 0012) is a rule for code this project maintains, and
  cannot be one for a file it deliberately does not.
- **The shims are ours and are not the MIG seam's.** A vendored file
  includes headers the kernel provides, and the crate supplies small
  stand-ins for them. They are not the shim headers of ADR 0004, which
  "hold type declarations only": a C file needs macros to compile at all,
  and these exist to make one compile on the host and for nothing else.
- **The flags are the benchmark's, not the kernel's.** A reference built the
  way the kernel builds its own code — freestanding, no standard library,
  the kernel code model — is not the program being compared, and neither is
  one whose assertions are on while the contender's are off.
- **The comparison is like for like or it is not reported.** The reference
  and the contender answer to the same allocator lifetime, the same
  teardown, and the same side of the benchmark's timing window. A
  difference the harness introduced is not a result.
- **Nothing is linked but the benchmark.** The vendored objects never leave
  the benchmark's `OUT_DIR`.

## Considered Options

- **Amend "Rust is the implementation language"**: the exception would sit
  where the kernel's rule is stated, and that rule would have to be read
  with a carve-out for a crate that implements nothing.
- **Compile from a checkout outside the repository**: nothing third-party
  enters the tree, but the benchmark reports one column unless a path is
  set, the baseline drifts with whatever checkout the machine has, and no
  gate can run it.
- **Measure against the project's own translation of the reference**: it
  answers neither question, since it measures the translation as much as the
  rewrite.

## Consequences

- A benchmark's result is reproducible from a checkout, so it can be a gate.
- A review of such a crate checks two things no test can: that the vendored
  code is still byte-identical below its header, and that the crate is still
  unreachable from the kernel.
