# Timer wheels poll from the interrupt and advance deferred

The clock interrupt calls `HashedWheel::poll`, which moves the cursor
over ticks on which nothing expires and says whether work is due. A
deferred pass then calls `HashedWheel::advance` once per tick until it
returns `false`. `advance` collects the due records under the lock,
then runs each action with the lock released, in the order the records
were armed, so an action may start or stop any callout on the wheel,
its own included. A nested or concurrent `advance` returns `false`.

Liveness is `is_idle`, not `stop`: a record re-armed while its action
runs is not idle until that action returns, whatever `stop` says. A
zero interval is one tick.

An action must not block. Cancelling a callout spins until its action
returns, and the kernel is non-preemptible (ADR 0001): nothing takes
the CPU from the spinner, so an action that blocked may never get a CPU
back to return on.

## Considered Options

- **Running actions under the lock**: an action could not re-arm or
  cancel without deadlock or a second code path.
- **`stop` as the wait**: returns while the action still runs, so the
  caller may free the callout too early (see ADR 0039).
- **A cancel that sleeps until the action returns**: actions could
  block, but every callout drop could sleep, including drops under a
  spin lock or in an interrupt handler, and the clock platform would
  need a sleep and wakeup it does not have.
