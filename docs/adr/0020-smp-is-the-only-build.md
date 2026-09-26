# SMP is the only build

The kernel is built one way for any number of CPUs. The CPU count comes
from the ACPI tables at boot, capped by one constant; a uniprocessor
machine is the case N = 1, with no uniprocessor configuration and no
`cfg` for it. Every subsystem is designed for N CPUs, as `lock`, the
single ticker CPU of `clock` and the RCU already are.

## Considered Options

- **Uniprocessor by default, SMP opt-in** (GNU Mach's NCPUS option):
  two kernels to test, and uniprocessor shortcuts rot the SMP path.

## Consequences

- CPUs beyond the cap are left offline at boot; they are not an
  error.
- Raising the cap is a constant change, not a new build.
