# The lock type decides the interrupt policy

Locks carry no spl. Each lock type fixes its own policy: a spin lock
leaves interrupts alone, an irq spin lock holds an irq-quiet section, and
sleeping locks (Mutex, RwLock) never touch interrupts, so interrupt
code that needs them runs in threaded handlers. How the platform makes a
section irq-quiet (masking, as FreeBSD does, or deferral, as DragonFly
does) is its own business. The type is the easiest thing for the order
checker to verify and the hardest to get wrong at a call site.

## Considered Options

- **Call site decides** (Linux `spin_lock_irqsave`): every user of a lock
  must agree on the variant, and only a runtime checker catches one that
  does not.
- **Instance decides** (FreeBSD `MTX_SPIN` at `mtx_init`): one type
  hides two contracts, so the type system cannot tell a lock safe to
  share with an interrupt handler from one that sleeps.
