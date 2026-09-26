# Full GNU Hurd support defines Mach ABI compatibility

The kernel aims at 100% Mach ABI compatibility with GNU Mach, and no
more. The ABI surface is exactly what the current stock Debian
GNU/Hurd userland observes: trap numbers, argument and return register
conventions, `mach_msg` header and message layouts, and type sizes as
seen from userspace — plus MIG: stubs compiled against GNU Mach
headers must work against this kernel without regeneration. The
kernel adds no traps, RPCs, MIG subsystems or behaviour of its own;
when the Hurd adopts a new GNU Mach interface, the kernel follows.
Kernel-internal Rust representation is free except where MIG stub
compatibility pins it.

The boot protocol is part of the surface: Multiboot v1 through GRUB,
with boot modules and the boot script, as the Hurd's GRUB entries use
it. Multiboot2, UEFI or any other loader protocol needs an ADR.

Compatibility is proven two ways:

- the frozen `abi-test/` suite passes — the minimum;
- the **Hurd reference image** boots and runs. The image is a pinned
  Debian GNU/Hurd snapshot, fetched by a script that checks its
  sha256, never committed, and moved to a newer snapshot only by a
  deliberate change. "Runs" is the Hurd smoke test: it boots to a
  login prompt on the serial console, with root mounted through
  rumpdisk and network through netdde reaching QEMU's user-network
  gateway, runs a fixed list of commands, and halts cleanly.

## Considered Options

- **Extensions under a project subsystem range**, each with its own
  ADR: userspace would come to depend on interfaces no other Mach
  offers, for a kernel whose only client is the Hurd.

## Consequences

- "100%" is a checkable bar, not a slogan: the suite and the smoke
  test are the definition of done for the ABI surface.
- `#[repr(C)]` and layout asserts stay where a userspace- or
  MIG-visible type is involved; elsewhere the representation may
  change shape freely.
- `abi-test/` is frozen. A failing test is a compatibility bug in
  this kernel, not a reason to edit the pack.
- Which GNU Mach counts is settled by the Hurd: the ABI target moves
  with the reference image, and the frozen suite stays the floor.
