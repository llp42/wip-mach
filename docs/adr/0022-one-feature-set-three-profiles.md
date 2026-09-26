# One feature set, three profiles

`kernel` has no Cargo features and no environment-variable knobs.
Tunables such as the CPU cap, the number of serial ports and the
number of interrupt lines are constants in one `config` module. The
kernel builds in three profiles:

- `dev` — the everyday build, with debug assertions off so the ABI
  suite boots within its time budget;
- `checked` — debug assertions and overflow checks on;
- `release` — what runs the Hurd.

Every profile boots the ABI suite (ADR 0024), so a `debug_assert!` in
the kernel runs in a booted kernel, not only in host tests.

## Considered Options

- **GNU Mach's configure matrix** (kdb, NCPUS, driver groups): every
  knob doubles what must be tested, and ADRs 0019, 0020 and 0021
  remove the reasons those knobs existed.
- **No `checked` profile**: kernel debug assertions would run only in
  host tests, and a `debug_assert!` no booted kernel runs is dead
  code.

## Consequences

- A behaviour that differs between builds is a profile difference —
  assertions and overflow checks — never a feature.
- Backends are chosen by who implements `Platform`, not by a feature
  (ADR 0006).
