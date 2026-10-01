# One feature set, two profiles

`kernel` has no Cargo features and no environment-variable knobs.
Tunables such as the CPU cap, the number of serial ports and the
number of interrupt lines are constants in one `config` module. The
kernel builds in two profiles:

- `dev` — the everyday build, with debug assertions and overflow checks
  on, so a `debug_assert!` runs in a booted kernel and not only in host
  tests;
- `release` — what runs the Hurd and what the benchmarks time, with
  both off.

Both boot the ABI suite (ADR 0024). A timing is taken on `release`: a
number from `dev` includes the checks.

## Considered Options

- **GNU Mach's configure matrix** (kdb, NCPUS, driver groups): every
  knob doubles what must be tested, and ADRs 0019, 0020 and 0021
  remove the reasons those knobs existed.
- **Checks off in `dev`**: kernel debug assertions would run only in
  host tests, and a `debug_assert!` no booted kernel runs is dead
  code. The reason given, the ABI suite's boot-time budget, did not
  hold: the Hurd smoke boot took 29 s with the checks on and 32 s with
  them off.
- **A third profile with the checks on**: a build to remember and a
  second boot to run for the same suite, to keep a `dev` that the
  checks do not slow.

## Consequences

- A behaviour that differs between builds is a profile difference —
  assertions and overflow checks — never a feature.
- A `debug_assert!` in the kernel runs in every `dev` boot, so it must
  hold on every path the ABI suite reaches.
- Backends are chosen by who implements `Platform`, not by a feature
  (ADR 0006).
