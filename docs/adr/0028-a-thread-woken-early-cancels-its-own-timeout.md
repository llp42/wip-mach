# A thread woken early cancels its own timeout

How the kernel uses `clock`'s callouts for timed sleeps: when a thread
sleeping with a timeout is woken by its event, the woken thread stops
its own `Callout` on the way out of the sleep, as DragonFly's `tsleep`
does. The waker never touches a wheel. The callout belongs to the
sleeping thread, `Callout`'s safe API expects its owner to stop it
(ADR 0039), and the wakeup path takes no wheel lock, which may
belong to another CPU.

If the timeout action is already running, `stop` returns `false` and
the thread waits until the callout is idle; the action's wakeup of a
thread that is already running does nothing.

## Considered Options

- **The waker cancels the timeout** (GNU Mach's shape): every timed
  wakeup reaches into another thread's timer and takes a wheel lock on
  the waker's path.

## Consequences

- A wakeup costs no timer work; a timed sleep that ends early pays one
  constant-time `stop` on the way out.
