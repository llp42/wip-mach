# `unsafe` is allowed but must be justified

`unsafe` is allowed, but it is not the best choice. Safe abstractions
are the default. `unsafe` is permitted where the kernel genuinely needs
it — FFI, raw pointers, inline asm, `ptr::write` of a whole value
into fresh storage — and is discouraged in ordinary logic. No crate sets
`#![forbid(unsafe_code)]`.

Every use carries a written contract:

- `unsafe fn` — `# Safety` states what the *caller* must guarantee,
  private ones included.
- `unsafe {}` in a safe fn — `// SAFETY:` names the actual lock or
  precondition. Write `// SAFETY: the port is live and locked.`;
  never `// SAFETY: as above.` or `// SAFETY: the caller's contract.`
- `unsafe {}` in an `unsafe fn` — no comment: the body may assume
  the fn's own contract. Comment only what the contract does not
  cover, as `// SAFETY: the lock was taken above.`

## Considered Options

- **Allowlist of modules**: ban `unsafe` outside named low-level
  modules. Rejected: the hardware boundary moves, and a ban either
  chases it or forces worse abstractions to smuggle around it.
- **Justify-by-comment only**: no preference gradient, any `unsafe`
  is fine with a good comment. Rejected: it does not say what to
  reach for first.

## Consequences

- A `// SAFETY:` comment that does not name a concrete lock or
  precondition is a review-blocking defect, not a style nit.
- The checkable bar is the comment contract and review, not
  prohibition. Introducing `unsafe` where a safe API would do is the
  thing to argue against in review.
