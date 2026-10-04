# `clock` — the machine clock and Scheme 6 timer wheels

`clock` owns the machine-independent half of the kernel's timing, in two
parts:

- one **machine clock**: the monotonic and wall domains, the tick count,
  the `adjtime`-style adjustment and the mapped time page;
- any number of **timer wheels**: hashed timeout queues that take their
  tick count from the clock.

The wheel is Scheme 6 of Varghese and Lauck, *Hashed and Hierarchical
Timing Wheels* (SOSP 1987): a power-of-two table of unsorted lists, one
list per bucket.  There is no heap allocation anywhere: records are
caller-owned and only linked and unlinked.  The hard-to-reverse choices
are ADRs 0037 to 0042 in the repository's
[`docs/adr/`](../../docs/adr/).

## What it provides

| Item | Purpose |
|---|---|
| `Clock<P>` | machine time source: domains, ticks, adjustment, page |
| `TickSource` | what a wheel reads time from |
| `HashedWheel<P>` | one independent, locked, hashed timer queue |
| `Callout<'w, P, T>` | a timer: record, action and data, bound to one wheel |
| `CalloutAction` | the expiry callback of a callout |
| `hashed_wheel::Stats` | debug-build wheel counters |
| `Ticks`, `Instant`, `WallTime` | tick counts, uptime, epoch time |
| `HZ`, `TICK`, `TICK_NANOS` | the 100 Hz tick: rate and periods |
| `Timer`, `TimerSave`, `TIMER_RATE` | per-thread user/system accounting |
| `Platform` traits | counter, lock platform, RTC, time page |

## Implementing a platform

The clock needs four machine capabilities:

| Trait | Method | x86 meaning |
|---|---|---|
| `TimeCounter` | `counter`, `counter_period_nsec` | HPET counter and period |
| `Locking` | `type Lock` | the `lock::Platform` whose irq spin locks guard the clock and wheel state |
| `Calendar` | `set_rtc` | program the RTC with epoch seconds |
| `TimePage` | `publish` | write the mapped time page |

```rust,ignore
use clock::{
    Calendar, Clock, Instant, Locking, TimeCounter, TimePage, WallTime,
};

struct Platform;

// `Platform` also implements `lock::Platform`; its irq-quiet section
// masks the clock interrupt.
impl Locking for Platform {
    type Lock = Self;
}

impl TimeCounter for Platform {
    fn counter(&self) -> u32 {
        read_hpet()
    }

    fn counter_period_nsec(&self) -> u32 {
        hpet_period_nsec()
    }
}

impl Calendar for Platform {
    fn set_rtc(&self, seconds: i64) {
        write_rtc(seconds);
    }
}

impl TimePage for Platform {
    fn publish(&self, wall: WallTime, uptime: Instant) {
        write_time_page(wall.as_nanos(), uptime.as_nanos());
    }
}
```

## The clock

One `Clock` per machine; exactly one CPU calls `tick`.

```rust,ignore
static CLOCK: Clock<Platform> = Clock::new(Platform);

// The designated CPU, from its clock interrupt:
CLOCK.tick(TICK);

// Any CPU, any time:
let now: Instant = CLOCK.mono();
let wall: WallTime = CLOCK.wall();
let ticks: Ticks = CLOCK.elapsed_ticks();
```

`tick` advances both domains by the adjusted tick delta, counts one
tick, and publishes the time page.  `set_wall` replaces the wall clock,
programs the RTC and publishes the time page; `set_adjustment` is the
gradual `adjtime` correction, applied by `tick`.  `Clock<P>` is a
`TickSource` and names its platform's `Locking`, so wheels can borrow it
directly.

## The wheels

The type is `HashedWheel` — Scheme 6 of Varghese and Lauck: 256
buckets of unsorted `collections::list::List`s, indexed by the low 8
bits of a record's expiry tick.  A wheel keeps its buckets behind its
own `lock::IrqSpinLock`, so any CPU may arm or cancel on it, and each
call site of `new` builds a lock class of its own.  It reads time
through one platform value, `P: TickSource + Locking`, which also names
its lock platform; a `&Clock` is one.  Where wheels live — one per
CPU, per subsystem, or one for the machine — is the caller's choice.

A wheel is `!Unpin` (its buckets point back into it).  Arming and
driving take `Pin<&Self>` (`start`, `stop`, `advance`); reads take
`&self` (`cursor`, `behind`, `poll`, `stats`).  `new` is `const`, so a
wheel can be a `static`:

```rust,ignore
static CLOCK: Clock<Platform> = Clock::new(Platform);
static WHEEL: HashedWheel<&Clock<Platform>> = HashedWheel::new(&CLOCK, Ticks::ZERO);

let wheel = Pin::static_ref(&WHEEL);
```

### Callouts

A `Callout` is the only way to arm a wheel, and a safe one.  It owns its record, is
bound to one wheel for its whole life, and carries the data its action
works on.  The action gets the callout pinned, so it may read the data
or restart it:

```rust,ignore
fn expired(callout: Pin<&Callout<'_, &Clock<Platform>, Tty>>) {
    callout.data().push();
    callout.start(Ticks::new(50));
}

static TTY_TIMER: Callout<'static, &Clock<Platform>, Tty> =
    Callout::new(Pin::static_ref(&WHEEL), expired, Tty::new());

// Arm for 50 ticks (500 ms at 100 Hz) from the clock's current tick:
Pin::static_ref(&TTY_TIMER).start(Ticks::new(50));

// Returns whether that prevented the action:
let prevented = TTY_TIMER.stop();
```

`start` needs the callout pinned (`Pin::static_ref`, `pin!`,
`Box::pin`), so it cannot move while armed, and its `'w` borrow of the
wheel means it cannot outlive the wheel.  Dropping a callout runs
`cancel`: it stops the callout and, if its action is running on
another CPU, spins until it returns.  So a callout must not be dropped
or cancelled from its own action, or from an interrupt taken during
the `advance` running it: that wait never ends.  `start` requires
`Callout: Sync`, since the action may run on another CPU.  `hashed_wheel`
returns the wheel the callout is bound to.

A callout cannot move between wheels; one armed on another CPU's wheel
is a second callout.

`stop` returns `false` when the callout was already stopped, or when
its action has started and has not re-armed it; a callout that re-armed
while its action runs is stopped again and `stop` returns `true`.
`is_idle` is the converse of still being live: it says the callout is
stopped and no action of it is running.
The wheel's record and its `unsafe` arming functions are private to
the crate: memory the kernel frees without running `Drop` (a zone
allocation) holds a callout too, and the code that pins it there, with
`Pin::new_unchecked`, promises to drop it before freeing.

### Driving the wheel

The clock interrupt calls `poll`, which moves the cursor over ticks on
which nothing expires and says whether work is due.  A deferred pass
then calls `advance`, once per tick until it returns `false`:

```rust,ignore
// Clock interrupt:
if wheel.poll() {
    schedule_softclock();
}

// Softclock:
while wheel.advance() {}
```

`advance` visits one tick: under the lock it moves the records due on
that tick to a private list, then runs each action with the lock
released, in the order the records were armed.  An action may start or
stop any callout on the wheel, its own included, so periodic timers
re-arm from their action.  A nested or concurrent `advance` returns
`false`.

An action must not block.  Cancelling its callout spins until it
returns, and the kernel is non-preemptible
([ADR 0001](../../docs/adr/0001-preemptible-kernel-is-a-non-goal.md)):
nothing takes the CPU from the spinner, so an action that blocked may
never get a CPU back to return on
([ADR 0042](../../docs/adr/0042-timer-wheels-poll-from-the-interrupt-and-advance-deferred.md)).

A zero interval is one tick.  A record whose bucket comes round before
its tick stays linked and is passed over; that revisit is the only cost
Scheme 6 pays that a bounded table would not.

Debug builds keep `Stats` — records armed now, the peak, and a
histogram of intervals — to size the wheel against a real workload.
The workspace's `dev` profile builds with debug assertions, so the
kernel's `dev` build keeps them; `release` does not.

### Why Scheme 6

The design was chosen by measurement (September 2026) against Scheme 4
(one bucket per tick), Scheme 4 in front of Scheme 6 or of a Scheme 2
sorted list or a Scheme 3 red-black tree, and `TailQueue` buckets.
Per CPU a kernel holds tens of timers (a Linux desktop showed about 40
per CPU, 87% of them threads sleeping with a timeout), where every
design is within a few nanoseconds per 10 ms tick.  At thousands of
timers the alternatives gain at most tens of nanoseconds per tick and
lose it again once most timeouts are cancelled early; the trees and
sorted lists pay O(log n) or O(n) on every start and cancel.  Scheme 6
on a one-word `List` head keeps any interval in 2 KiB per wheel.

## Accounting timers

`Timer` keeps whole seconds plus microseconds since the low word last
filled.  `bump` adds one tick's microseconds and runs once per tick per
thread; `zeroed`, `init` and `normalize` set or fold the reading:

```rust,ignore
timer.bump(10_000); // one tick in microseconds
let total = timer.read();
```

`TimerSave` holds a reading so `delta` can return the microseconds
elapsed since it.  The timer and its save are one thread's pair, and
updates must be serialized by the lock protecting that thread, hence
the `unsafe`.

## Testing

The crate is covered on the host by a `#[cfg(test)]` fake platform:

```sh
mise run test::clock   # cargo test -p clock --target x86_64-unknown-linux-gnu
mise run cov::clock    # enforces 100% lines, regions and functions
```

`mise run test::unit` runs the crate together with the host suite.
Every new branch is expected to arrive with a host test; `cov::clock`
is the gate.

The Criterion harness in `benches/timers.rs` measures the wheel at 64
to 4096 callouts — start, stop, expiry, an empty tick through `advance`
and `poll`, and steady states with self-re-arming timers drawn from
`benches/intervals.txt`, with and without early cancels — plus the
clock reads, `Clock::new`, and the accounting timers' `bump`/`read`/
`delta`:

```sh
mise run bench::clock
```

## Safety

- `Callout` is safe: pinning keeps its address, its `'w` borrow keeps
  the wheel alive, and its `Drop` keeps the memory until the wheel
  cannot reach it.  A leaked callout stays valid forever.
- Code that pins a callout itself (`Pin::new_unchecked`) must drop it
  before its memory is reused.
- An expiry action runs with the wheel unlocked, in whatever context
  calls `advance`.
- `TimerSave::delta` requires the caller to serialize the thread's
  timer pair.

## License

MIT.  Every file in the crate carries `SPDX-License-Identifier: MIT`:
the crate is designed from the literature and carries no derived code
([ADR 0010](../../docs/adr/0010-spdx-headers-and-provenance.md)).  The
transcription of the paper, `varghese-lauck-1987-timing-wheels.md`, is
not covered: it
is the authors' and the ACM's work, kept for reference.
