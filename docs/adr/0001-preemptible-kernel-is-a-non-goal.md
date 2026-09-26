# A preemptible kernel is a non-goal

The kernel is non-preemptible: a thread leaves its CPU in kernel mode
only by blocking. Every design decision takes that as given. The
non-preemptive shape is the design, not a special case of a preemptive
one: no adaptation layer and no no-op flag stand in for a future
preemptible kernel. A thread still leaves the CPU at a trap or an AST
check when a higher-priority thread is runnable; that is scheduling,
not kernel preemption.

## Considered Options

- **Design for a preemptible kernel with hooks that do nothing today**:
  every API carries a preemption section or flag that is a no-op until
  kernel preemption arrives. Rejected: those hooks and flags shape
  every design for a kernel that does not exist, and a no-op flag
  hides the real contract.

## Consequences

- Locks, RCU quiescent states, callouts and irq-quiet sections are
  sized for a CPU that keeps its kernel context until the thread blocks
  or an interrupt returns.
- The lock crate has no no-preempt sections, no preemption hooks in its
  `Platform` and no preemption-aware lock variants, not even as no-ops
  kept for later; spin locks hold no section at all. Adaptive spinning
  stays: it depends on whether an owner is on a CPU, not on whether
  kernel code can be preempted.
- Making the kernel preemptible later is a new decision, not a
  configuration change. It reopens the lock crate — spin locks would
  need a section that holds off preemption, and a mutex that defers its
  holder's preemption, like Zircon's `CriticalMutex`, would come back
  into question — the RCU quiescent-state definition, and every
  assumption that there is no preemption point between a load and its
  use.
