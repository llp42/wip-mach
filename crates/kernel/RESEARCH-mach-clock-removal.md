# Deleting `kern/mach_clock.rs`: what remains

> **Status (2026-10): landed.** `kern/mach_clock.rs` is gone. Constants
> live in `kern/machine.rs`, host time + stamps in `kern/host_time.rs`,
> the mapped page and `tick`/`softclock` in `arch/x86_64/clock_platform.rs`,
> CPU accounting in `machine::tick_accounting`, `/dev/time` stubs in
> `device/dev_name.rs`. This note is the inventory that planned the move.

What still has to move before the old `mach_clock` module can be
deleted, and what the new `crates/clock` crate already owns. Facts
carry `file:line` evidence. Statements that are a reading rather than
a quote say "inference". This note changes no code and no ADR; it is
evidence for a future removal change, not that change.

## Sources and their limits

- **wip-mach working tree** (`crates/kernel/src`, `crates/clock/src`,
  `DEBT.md`, `docs/adr/`). Primary source. `mach_clock` is one module
  (`crates/kernel/src/kern/mach_clock.rs`, 460 lines, declared at
  `crates/kernel/src/kern/mod.rs:27`), not a crate.
- **Prior plan** `.mimocode/plans/1790805760148-cosmic-eagle.md`
  ("Replace mach_clock with `clock` v0"). Its Phase 0/1 landed: the
  legacy timeout wheel and `Timeout` pool are gone, and that plan's
  "deleting `mach_clock` entirely" was explicitly out of scope
  (plan:27-29). This note is the follow-on inventory.
- **ADRs** 0028 and 0037–0042 (clock group in `CONTRIBUTING.md`), plus
  0002 (MIG-visible types), 0012 (DEBT is the gap), 0027 (kernel
  idiom), 0040 (zone free drops callouts).
- **`crates/clock/README.md` and `src/lib.rs`** for the public surface
  of the replacement crate.
- **Not checked:** whether host-tests need any update after a future
  move (they compile `glue/time_value` only; `crates/host-tests/src/
  glue/mod.rs:6`, `tests.rs:66-119`). Git history is shallow (4
  commits) and does not name the clock work.

## 1. Status: the hard part already landed

`mach_clock` is already a **façade** over `clock`. Its module docs say
so (`mach_clock.rs:10-12`). Verified in the tree:

| Claim | Evidence |
|---|---|
| No legacy `Timeout` / `TIMEOUT_TIMERS` / `set_timeout` pool | `grep` over `crates/` finds none of those identifiers |
| Timeouts are `clock::Callout`s on one wheel | `MachCallout` at `clock_platform.rs:96`; users in `thread.rs:307-309`, `sched_prim.rs:102`, `chario.rs:204`, `com.rs:1223`, `kd/esc.rs:65` |
| One machine clock, one ticker CPU | `CLOCK`/`WHEEL` at `clock_platform.rs:82-86`; `CLOCK.tick` only under `my_cpu == CpuId::BOOT` (`mach_clock.rs:204-206`); ADR 0038 |
| Softclock advances the wheel | `mach_clock.rs:253-255` (`while wheel().advance() {}`); ADR 0042 |
| DEBT "The kernel runs the legacy clock" | **gone** from `DEBT.md` (closed when the wheel went) |

So "remove all old mach_clock" is **not** unfinished timekeeping. It
is rehoming the façade and deleting the C-named module.

## 2. What still lives in `mach_clock`

Public surface (`pub` / `pub(crate)`):

| Group | Items | Lines |
|---|---|---|
| Constants | `CLOCK_HZ`, `TICK`, `CPU_STATE_IDLE`/`USER`/`SYSTEM` | 35-49 |
| Interrupt | `interrupt`, `softclock` | 161-220, 253-255 |
| Mapped page | `publish_mapped_time`, `mapable_time_init`, `mapped_time_page`, private `update_mapped_*` | 51-53, 83-144, 417-455 |
| Stamps / boot offset | `record_time_stamp`, `read_time_stamp`, private `CLOCK_BOOTTIME_OFFSET`, `clock_boottime_update` | 74-79, 146-157, 272-295 |
| Host time | `get_time`, `get_time64`, `get_uptime64`, `set_time64`, `adjust_time` | 298-414 |
| Wall / ticks | `wallclock`, `set_wallclock`, `elapsed_ticks` | 436-459 |
| `/dev/time` | `timeopen`, `timeclose` | 258-263 |
| Boot hook | `init_timeout` (empty) | 69-70 |
| Accounting helper | private `timer_bump` into `kern::timer::Timer` | 55-62 |

Call sites (all under `crates/kernel/src`):

| File:line | Use |
|---|---|
| `ffi/mach_host.rs:32,594-1048` | `use … mach_clock as clock` — host get/set/adjust/uptime |
| `ffi/task_info.rs:14,117` | `read_time_stamp` |
| `ffi/thread_info.rs:13,109,185` | `read_time_stamp`, `TICK` |
| `ffi/host_info.rs:14,100` | `TICK` |
| `arch/x86_64/hardclock.rs:37,39` | `interrupt(TICK, …)` |
| `arch/x86_64/clock_platform.rs:59` | `publish_mapped_time` (TimePage hook) |
| `arch/x86_64/model_dep.rs:183,198` | `mapped_time_page`, `set_wallclock` |
| `arch/x86_64/spl.rs:29,115,224` | drains `softclock()` |
| `arch/x86_64/rtc.rs:384` | `wallclock()` |
| `arch/x86_64/{pit,ioapic,com,kd/esc}.rs` | `CLOCK_HZ` / callouts |
| `kern/startup.rs:19,80,82,204` | `init_timeout`, `mapable_time_init`, `record_time_stamp` |
| `kern/task.rs:31,526,1520` | `record_time_stamp`, `CLOCK_HZ` |
| `kern/thread.rs:29,860,1664` | `TICK`, `record_time_stamp` |
| `kern/slab.rs:18,1715,1719` | `elapsed_ticks`, `CLOCK_HZ` |
| `kern/sched_prim.rs:18,347,1832,1843` | `CLOCK_HZ` |
| `kern/ipc_sched.rs:14,28` | `CLOCK_HZ` |
| `kern/priority.rs:16,76` | `CPU_STATE_IDLE` |
| `device/dev_name.rs:31,178-179` | `timeopen`/`timeclose` |
| `device/{chario,intr}.rs`, `vm/vm_pageout.rs` | `CLOCK_HZ` |

MIG types stay put: `glue/time_value.rs` (`TimeValue`, `TimeValue64`,
`MappedTimeValue`, `MACH_ADJTIME_NSECS_OMIT`) are ADR 0002
MIG-visible; host-tests compile that file via `#[path]`.

## 3. What `crates/clock` already provides

Public surface (`crates/clock/src/lib.rs:26-30`): `Clock`, `Callout`,
`CalloutAction`, `HashedWheel`, `TickSource`, `Platform` + `TimeCounter`
/ `Critical` / `Calendar` / `TimePage`, `Timer`/`TimerSave`/`TIMER_RATE`,
`HZ`, `TICK`, `TICK_NANOS`, `Ticks`, `Instant`, `WallTime`.

- Domains + ticks + `set_wall` / `set_adjustment` live on `Clock`
  (`lib.rs:51-148`). Callers should use `CLOCK.wall()` etc. directly.
- `clock::HZ: u64 = 100` and `clock::TICK: Duration`
  (`types.rs:9-15`) **replace** `CLOCK_HZ: c_int` / `TICK: c_int` µs
  but are **not type-compatible** — call sites need `as` casts or a
  deliberate kernel-side alias (inference: a one-line re-export in the
  new home of the constants is fine if the casts get noisy).
- `TimePage::publish` is the hook the mapped page already uses
  (`clock_platform.rs:57-63`).
- Statistical `clock::Timer` exists but is **not** what
  `kern/timer.rs` is (see §5).

## 4. Remaining work to delete the module

Six rehome groups. Nothing here requires new `crates/clock` API
except possibly an `Adjustment` getter (§5).

### 4.1 Constants

- `CPU_STATE_*` are **processor** accounting, not clock. They belong
  with `machine.rs:45` `CPU_STATE_MAX` and `cpu_ticks`. Only
  `priority.rs` imports `CPU_STATE_IDLE` from `mach_clock`.
- `CLOCK_HZ` / `TICK` → `clock::HZ` / `clock::TICK` (or a thin kernel
  alias). This is the bulk of the coupling (~15 files).

### 4.2 Host-time façade

`get_time` / `get_time64` / `get_uptime64` / `set_time64` /
`adjust_time` already call `CLOCK.*` and keep the C bind-to-boot-CPU +
spl shape. Consumers are the MIG seam (`ffi/mach_host.rs`).

**Where:** `ffi/mach_host.rs` itself, or a small `kern/host_time.rs`.
Do **not** push these into `crates/clock` — host RPC and `TimeValue`
are kernel/MIG, not machine-independent timekeeping.

### 4.3 Boot-time offset + stamps

`CLOCK_BOOTTIME_OFFSET` and `record_time_stamp` / `read_time_stamp`
translate boot-time frames to real time (task/thread creation stamps,
`task_info` / `thread_info`). Same home as §4.2 (kernel boot policy),
not `crates/clock`.

### 4.4 Mapped time page

`MTIME`, `update_mapped_time`/`uptime`, `publish_mapped_time`,
`mapable_time_init`, `mapped_time_page`. Today
`clock_platform.rs:59` calls back into `mach_clock`, so the two
modules depend on each other.

**Where:** `clock_platform.rs` (or `arch/x86_64/time_page.rs`). The
`MappedTimeValue` layout stays in `glue/time_value.rs`. This is the
move that breaks the cycle.

### 4.5 Tick interrupt / softclock / CPU accounting

`interrupt` (`mach_clock.rs:161-220`) does three jobs:

1. per-CPU `timer_bump` into `Thread.user_timer` / `system_timer`
   (`kern::timer::Timer`);
2. `cpu_ticks[state]++` + `priority::thread_quantum_update`;
3. on cpu0 only: `CLOCK.tick` + `wheel().poll` / `softclock`.

**Where:** (3) is timekeeping → `clock_platform` / `hardclock`.
(1)+(2) are scheduler/processor accounting → `kern/timer.rs`,
`priority`, or `machine` — **not** `crates/clock`. `spl.rs` keeps
draining softclock; point it at whoever owns `wheel().advance()`.

### 4.6 Thin wrappers and dead names

| Item | Action |
|---|---|
| `wallclock`, `set_wallclock`, `elapsed_ticks` | Call `CLOCK.wall()` / `set_wall()` / `elapsed_ticks()` at `slab.rs`, `rtc.rs`, `model_dep.rs` |
| `init_timeout` | Delete (empty boot hook, `startup.rs:80`) |
| `timeopen` / `timeclose` | `/dev/time` stubs; keep the device switch entries in `dev_name.rs`, drop the `mach_clock` names |
| `pub mod mach_clock` | Remove from `kern/mod.rs:27` once empty |

## 5. Out of scope (not "remove mach_clock")

These are real gaps but separate DEBT items. A module-delete change
must not claim to close them.

| Item | Why separate | Evidence |
|---|---|---|
| ADR 0028 sleeper stops its own callout | Wakeup path still cancels the woken thread's timer | DEBT.md:26-33; `sched_prim.rs:645,710` `Thread::stop_timer` |
| `clock` `CriticalLock` → `lock::IrqSpinLock` | Crate lock policy (ADRs 0029/0041) | DEBT.md:16-24; `clock/src/critical.rs` |
| `kern/timer.rs` → `clock::Timer` | v0 left it out (cosmic-eagle plan:27-28). **Not a drop-in:** `kern/timer.rs` `Timer` has a `tstamp` field and C layout asserts (`timer.rs:33-34,192-197`); `clock::Timer` has private fields and no `tstamp` | `kern/timer.rs`, `clock/src/timer.rs` |
| `host_adjust_time64` query arm | `MACH_ADJTIME_NSECS_OMIT` returns zero; `Clock` has no `Adjustment` getter | DEBT.md:35-42; `mach_clock.rs:390-395` |

## 6. Stale pointers to fix when the module goes

- `DEBT.md:156-158` still lists `kern/mach_clock.rs` and
  `arch/x86_64/ioapic.rs` under third-party crates for "the legacy
  timeout wheel's `Timeout.chain`". That wheel is deleted; `grep`
  finds no `Timeout.chain` or `intrusive_collections` in either file
  (`intrusive-collections` remains only in `vm_map.rs` and `slab.rs`).
  Shrink that clause (inference: this is stale after v0, not a live
  gap).
- `crates/kmem/RESEARCH.md:192,292` cites `mach_clock.rs:970` and the
  "legacy timeout wheel" — line number and subject no longer exist.

## 7. Suggested order for a future removal change

Keep the tree bootable; each step is independently greppable.

1. Constants: `CPU_STATE_*` → `machine`/`priority`; `CLOCK_HZ`/`TICK`
   → `clock::HZ`/`TICK` (or a kernel alias).
2. Mapped page → `clock_platform` (breaks the `clock_platform` ↔
   `mach_clock` cycle).
3. Host time + boottime offset + stamps → `ffi/mach_host` or
   `kern/host_time`.
4. Split `interrupt`: accounting vs `CLOCK.tick` / wheel.
5. Point thin wrappers at `CLOCK`; delete `init_timeout`; drop
   `timeopen`/`timeclose` from `mach_clock`.
6. Delete `kern/mach_clock.rs` and `kern/mod.rs:27`; fix §6 pointers.
7. Gates: `mise run test::abi` + Hurd smoke to login; `grep -r
   mach_clock crates` is empty.

**Unchanged in this scope:** `glue/time_value.rs`, `crates/clock/*`
(as long as §5 is out of scope), `Thread` timer callout shape.

## 8. Done bar for the removal change (not this note)

- No `mach_clock` identifier under `crates/`.
- Boot reaches login; timed paths still fire (sleep, tty timeout,
  serial watchdog, bell).
- DEBT/RESEARCH stale pointers from §6 are gone or rewritten.
- Out-of-scope DEBT items in §5 are **not** deleted.
