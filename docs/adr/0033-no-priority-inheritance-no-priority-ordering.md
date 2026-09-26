# No priority inheritance, no priority ordering

Lock waiters are served first come, first served, and the lock
platform has no priority hooks. Priority inversion needs a lock holder
that loses its CPU while it holds the lock. With no preemption
(ADR 0001) a kernel thread leaves its CPU only by blocking, and Mach
never holds a simple lock across a block: `check_simple_locks()`
asserts it, and simple locks are 82% of GNU Mach's lock sites. Only
holders that sleep can be inverted, chiefly `vm_map` and `ipc_space`,
and only when a medium-priority CPU-bound thread starves the woken
holder, which needs threads at different priorities. Zircon has
priority inheritance because its kernel is preemptible and has a
deadline scheduler; neither holds here.

## Considered Options

- **Priority inheritance under one global lock**: a per-thread record of
  the threads blocked on locks it owns, updated along the chain of owners
  under a single irq-quiet lock, with `Platform::base_priority`,
  `set_inherited` and `priority_record`. It was built and passed its
  tests; withdrawn for about 230 lines in the wait table, four platform
  items, a record in every kernel thread and a global lock on every
  contended path, all to fix an inversion the kernel can hardly have.
- **Priority-ordered service without inheritance**: serve the most urgent
  waiter first, needing only `Platform::base_priority`. Rejected for the
  same reason: a hook whose benefit needs threads at different
  priorities.

## Consequences

If servers come to run at different priorities across locks whose holders
sleep, this is the decision to revisit. The owner is already in the lock
word, and the wait table's `pick` and `grant` callbacks are where ordering
by priority would go.
