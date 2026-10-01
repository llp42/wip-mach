# What a change must pass

A change merges only when every gate passes:

- **Static**: `cargo fmt --check`; clippy clean on the host target and
  on `x86_64-unknown-none`, in `dev` and `release`; `cargo doc` with
  `-D warnings`.
- **Portable crates** — `lock`, `clock`, `collections`, `kmem`,
  `wip-mach` and any other: host tests in debug and release, loom for
  concurrency protocols, and 100% line, region and function coverage.
- **`kernel`**: no host tests; it is proven by booting.
- **Boots**: the ABI suite on `dev` and `release` (ADR 0022); the
  Hurd smoke test (ADR 0002) on `dev` and `release`.

Every gate is a `mise` task. CI calls those tasks and runs every gate
on every PR; the KVM-backed boot gates may move to a nightly run if
they are too slow for every PR.

## Considered Options

- **Full coverage for leaf crates only**: `wip-mach` would be held to
  less than `lock` and `clock`, and the split of ADR 0014 would buy
  less than it costs.
- **A manual Hurd boot, checked by eye**: not a gate anyone else can
  run.

## Consequences

- Debug-only code is gated with `#[cfg(debug_assertions)]`, never
  `if cfg!(debug_assertions)`, which leaves a dead region in the
  coverage report; every debug check has a `#[should_panic]` test
  gated on `debug_assertions`.
- A gate that exists only as a command in a README is a `DEBT.md`
  entry until it is a `mise` task.
