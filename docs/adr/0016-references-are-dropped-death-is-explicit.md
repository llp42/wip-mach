# References are dropped; death is explicit

A counted kernel object — port, task, thread, map, VM object — is
held through a reference: an owning type whose `Clone` takes a count
and whose `Drop` releases it. Explicit take and release exist only at
the MIG seam, where the generated C moves references by convention.

An object's life has two ends that never merge. **Death** is explicit
and synchronous — the receive right is destroyed, the task
terminates — and does everything that may sleep or send a message,
such as notifications. **Freeing** happens on the last `Drop`: it only
returns memory to its cache and never sleeps, so a reference may be
dropped while a spin lock is held.

## Considered Options

- **Explicit reference and release calls** (GNU Mach's shape): a
  missed release leaks and an extra one frees a live object, and
  review is the only check.
- **A last `Drop` that runs the teardown**: dropping any reference
  could then sleep or send a message, which a spin lock holder must
  never do.

## Consequences

- A dead object is still valid memory while references to it remain;
  every operation checks, under the object's lock, that it is alive.
- Freeing never blocks, which allocation never does either
  (ADR 0017).
