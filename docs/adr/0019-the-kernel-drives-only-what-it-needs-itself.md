# The kernel drives only what it needs itself

The kernel carries drivers only for hardware it needs to run: the
interrupt controllers, the timers, the RTC, the serial ports, the `kd`
console with its keyboard and mouse — which the Hurd opens as
devices — and what boot needs. Disks, network cards, USB and sound are
driven by userspace drivers such as rumpdisk and netdde, through
interrupt delivery to userspace, contiguous physical allocation and
I/O-port permissions. There is no Linux driver glue, ever.

## Considered Options

- **An in-kernel disk driver**, so boot does not depend on rumpdisk: a
  second driver path for hardware the Hurd already drives from
  userspace.
- **GNU Mach's Linux driver glue**: a large body of old Linux drivers
  running in kernel mode, with its own emulation layer to keep alive.

## Consequences

- The interfaces userspace drivers use are load-bearing ABI; the Hurd
  smoke test exercises them, with root mounted through rumpdisk and
  network through netdde (ADR 0002).
- A new in-kernel driver needs an ADR.
