# The console stays in the kernel

The kernel's console stays on the `kd` driver — VGA display and PS/2
keyboard — with `com` the console a boot line selects instead. The `kd`,
`kbd`, `mouse` and `console` devices and their `getstat`/`setstat`
flavors are Mach ABI: the Hurd's console server drives them from
userspace, and the reference image's stock boot reaches its `console`
getty through `kd`. `rumpdisk` and `netdde` are storage and network and
no substitute — with the image's default entry, which names no
`console=`, `com` probes dead and `kd` wins.

## Considered Options

- **Delete the `kd` console as superseded by the rump kernel**: the rump
  kernel here drives disks and network cards only; display and input
  would lose their driver, and the Hurd console server would have no
  devices to open.
- **Move display and keyboard to a userspace driver**: the kernel prints
  its banner and its panic line before any server exists, and the
  reference image ships no such driver.

## Consequences

- Removing a `kd`, `kbd` or `mouse` device operation or flavor needs an
  ADR, as a new in-kernel driver does (0019).
- `console=com0`, in the ABI suite and the smoke test, selects the
  console through the indirect `console` entry; the kd devices remain,
  and a smoke pass proves nothing about the display and input paths.
- The kernel console is `kd` when the boot line names none, so a kernel
  booted without a display shows nothing and a panic reaches VGA text,
  not serial.
- The in-kernel debugger hooks in `kd` go (0021); the debt entry that
  records them closes with the change.
