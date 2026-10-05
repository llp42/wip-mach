# wip-mach

A Mach microkernel in Rust for the GNU Hurd, on x86-64. It aims at the
Mach ABI of GNU Mach and no more: a stock Debian GNU/Hurd userland, and
MIG stubs built against GNU Mach headers, run on it unchanged.

## Not implemented

These GNU Mach calls exist but fail:

- `gsync_requeue` fails with `KERN_FAILURE` and moves no waiter. It is
  a simple routine, so the caller never sees the failure: threads
  waiting on the source address stay asleep there.

The rules the code follows are mapped in
[`CONTRIBUTING.md`](CONTRIBUTING.md); every other gap between them and
the code is in [`DEBT.md`](DEBT.md).
