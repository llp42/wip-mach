# wip-mach

A Mach microkernel in Rust for the GNU Hurd on x86_64.

## Goals

- **A microkernel.** IPC, virtual memory, tasks, threads, and scheduling
  live in the kernel, alongside only the drivers it needs itself. Disk
  and network drivers run in userspace.
- **GNU Mach compatible.** Match the Mach ABI used by stock Debian
  GNU/Hurd, without kernel-specific extensions. MIG stubs built against
  GNU Mach headers run unchanged.
- **x86_64 only.** Another port is not planned and not blocked.
- **SMP only.** The CPU count comes from the ACPI tables, capped by one
  constant; a uniprocessor is the case N = 1, with no configuration and
  no `cfg` of its own. Every subsystem is designed for N CPUs.
- **Non-preemptible.** A thread leaves its CPU in kernel mode only when
  it blocks. A trap or AST check can still schedule another thread.
- **Stable Rust.** Cargo builds the kernel without nightly features.
- **Small crates.** Each subsystem is a crate behind a small `Platform`
  trait, so it can be read, tested, and replaced independently.

The x86_64-only, SMP-only, and non-preemptible choices simplify
development by avoiding separate ports, uniprocessor configurations,
and preemption in kernel mode.

## Not implemented

`i386_set_ldt` and `i386_get_ldt` return `WIPMACH_DEPRECATED` (`-399`).
The x86_64 Hurd does not use these calls or a thread-programmable LDT.

## Build

The Rust toolchain file selects stable Rust and `x86_64-unknown-none`.
Building also requires GNU MIG and a host C compiler.

```sh
cargo build
```

This produces `target/x86_64-unknown-none/debug/mach`. The frozen GNU
Mach ABI suite is in
[`abi-test/`](abi-test/README.md).

## Boot Debian GNU/Hurd

Run the [boot script](tools/boot-hurd.sh) from the repository root:

```sh
./tools/boot-hurd.sh
```

It downloads the
[2026-03-14 Debian GNU/Hurd amd64 image](https://cdimage.debian.org/cdimage/ports/latest/hurd-amd64/debian-hurd-amd64-20260314.img.gz),
builds wip-mach, replaces the image's kernel in a working copy, and
starts QEMU with the image's existing GRUB configuration. The
downloaded image is cached under `target/hurd-boot/`. Each run makes
a temporary copy, modifies that copy, and removes it when QEMU exits.

This also requires `curl`, `gzip`, `debugfs`,
`qemu-system-x86_64`, and read/write access to `/dev/kvm`.

## Crate layers

Crates depend only on crates in lower layers. The layers run from
foundations to the kernel.

| Layer | Crate | Holds |
|---|---|---|
| 0 | `collections` | intrusive lists, queues and a red-black tree |
| 0 | `kmem` | fallible owning heap types and the radix tree |
| 0 | `acpi` | the ACPI static tables |
| 0 | `elf-load` | the ELF images the bootstrap loads, read through the `elf` crate |
| 0 | `mach-kd` | the console's terminal, keyboard and mouse decoders |
| 0 | `mach-mig-sys` | MIG's generated interfaces and the shim headers |
| 1 | `lock` | spin, irq spin, mutex, reader-writer lock, condition variable |
| 2 | `clock` | the machine clock and timer wheels |
| 2 | `mach-page` | the physical pages: the descriptor, the boot memory map, the segments and their buddy allocator, the per-CPU pools |
| 3 | `mach-pmap` | the x86_64 physical map and TLB shootdown |
| 3 | `mach-slab` | the object-caching allocator and the general allocator above it |
| 3 | `mach-sched` | run queues, priorities, scheduling policies, ASTs and the scheduling timers |
| 4 | `mach-vm` | virtual memory above the pmap |
| 5 | `mach-ipc` | ports, spaces, messages and `mach_msg` |
| 5 | `mach-gsync` | address-based synchronization |
| 5 | `mach-emulation` | a task's system-call emulation vector |
| 6 | `mach-task` | the task record |
| 7 | `mach-thread` | threads, the operations on tasks and threads, the dispatch, processors and their sets, and their ports |
| 8 | `mach-host` | the host, its ports and time, machine slots, reboot |
| 8 | `mach-boot` | the bootstrap and the boot script |
| 8 | `mach-device` | device dispatch |
| 9 | `mach-tty` | the tty layer |
| 9 | `mach-trap` | the trap bodies and the exception up-call |
| 10 | `mach` | the machine, the MIG seam and the wiring |

`mach-fake` is a test crate outside the layers.

## License and attribution

The project is licensed under GPL-2.0-or-later. See
[`COPYRIGHT`](COPYRIGHT) for the upstream authors and sources.
