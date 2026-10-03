---
name: debug-vm
description: Use when debugging wip-mach on the Hurd reference image in debug/ — installing a fresh kernel into the image, booting it in QEMU, watching the serial console from tmux, driving the console from a script, or inspecting a panic under GDB. Not for the non-interactive gate (mise test::abi) or the bare-kernel ISO path.
---

# Debugging on the Hurd reference image

Run everything below from the repo root. The helper scripts live in
`.claude/skills/debug-vm/scripts/` and are written as full paths here; copy
those paths.

This is the interactive path. `mise test::abi` stays the non-interactive gate —
nothing here replaces it, and a green interactive boot does not substitute for
it.

## Layout

Two different `debug` directories:

- `.claude/skills/debug-vm/` — this skill, tracked in git.
- `debug/` — the working directory at the repo root, gitignored. Holds the Hurd
  reference image (`debian-hurd-amd64-*.img`, ~4 GB; the pristine tarball is
  `debian-hurd.img.tar.gz`), the kernel-swap script `replace-gnumach.sh`, and
  every runtime artifact: `serial.sock`, `mon.sock`, `qemu.pid`, `qemu.log`,
  `serial.log`.

`debug/qemu.sh` is an older launcher and is unused here; `launch.sh` supersedes
it. `debug/replace-gnumach.sh` is the kernel-swap authority and is called, not
rewritten.

## Prerequisites

`qemu-system-x86_64` (KVM if `/dev/kvm` is writable), `sfdisk`, `fuse2fs`,
`fusermount3`, `debugfs`, `gzip`, `md5sum`, `openssl`, `tmux`, **`socat`**,
`python3`, `gdb`. A `debug/debian-hurd-amd64-*.img` must exist; unpack
`debug/debian-hurd.img.tar.gz` if it does not.

## The debug loop

1. **Build.** `cargo build` — `target/x86_64-unknown-none/debug/kernel` exists.
2. **Install into the image.**
   `.claude/skills/debug-vm/scripts/prepare-image.sh` — prints matching md5s and
   `prepared …`. Do this after every kernel change; it is the only step that
   mutates the image.
3. **Boot.** `.claude/skills/debug-vm/scripts/launch.sh` — `debug/qemu.pid` is
   alive and `debug/serial.log` is growing. To restart the VM: `stop.sh`, then
   `launch.sh` again.
4. **Console.** `.claude/skills/debug-vm/scripts/console.sh`, then
   `tmux attach -t hurd-console`. You should see the GRUB entry, the Hurd boot
   and `login:`. Root's password is `debug`. Confirmation without the console:
   `ssh -p 2222 root@127.0.0.1`, then `uname -a` shows `GNU … WIP-Mach`.
5. **Watch and poke.** Use `drive.py` for scripted work. Reach for GDB only
   when a panic has to be explained.
6. **Stop.** `.claude/skills/debug-vm/scripts/stop.sh` — pidfile gone. Go back
   to step 1.

The image is opened with `-snapshot`, so a hard kill never dirties it. Guest
state does not survive a restart — that is deliberate.

## Console (tmux)

One line: `.claude/skills/debug-vm/scripts/console.sh`. Under the hood it runs
`socat -,raw,echo=0 UNIX-CONNECT:debug/serial.sock` in a detached tmux session
`hurd-console`. Never connect any other way; without a raw tty the guest's
arrow keys and GRUB editing misbehave.

```
tmux attach -t hurd-console        # detach with C-b d
tmux kill-session -t hurd-console  # release the socket
```

**Socket handoff.** Only one client holds `debug/serial.sock` at a time.
`console.sh` holds it until the session ends; `drive.py` takes it for one
invocation. Kill the tmux session before scripted runs, and let `drive.py`
exit before re-attaching. The VM keeps running either way, and whatever you
missed is in `debug/serial.log` — a client sees only what arrives while it is
connected.

## Scripted serial

`.claude/skills/debug-vm/scripts/drive.py` takes one verb per invocation.
Options (`--sock`, `--timeout`) come before the verb:

```
…/drive.py read --seconds 10           # whatever the guest prints next
…/drive.py --timeout 20 expect 'login: '   # 0 on match, 1 on timeout
…/drive.py send 'halt'                 # send a line
…/drive.py run 'uname -a'              # run it in a shell, print the output
```

`run` is for a logged-in shell; it exits with the guest's status. A client sees
only what arrives while it is connected, so poke getty before waiting for a
prompt that may already be on screen:

```sh
s=.claude/skills/debug-vm/scripts
$s/drive.py send ''                # poke getty to repaint the prompt
$s/drive.py --timeout 20 expect 'login: '
$s/drive.py send root
$s/drive.py --timeout 20 expect 'Password:'
$s/drive.py send debug
$s/drive.py --timeout 30 expect '[#$] '   # shell prompt
$s/drive.py run 'uname -a'         # GNU debian 0.9 WIP-Mach 0.1.0/Hurd-0.9 x86_64 GNU
$s/drive.py send halt
```

Waiting for a panic on a bad build: `$s/drive.py --timeout 120 expect 'panic '`.
On a good boot this times out and prints the recent buffer — that is the success
signal, not a bug.

## GDB and panics

A boot panic reaches the serial console as `panic {cpu0} <file>:<line>:
<message>`. Read it as text from the console or from `debug/serial.log`. A VGA
screendump is not usable.

`panic_fmt` spins about a second, then `halt_all_cpus` reboots through the
keyboard controller. With `-no-reboot` that exits QEMU, so a late attach finds
nothing. Expecting a panic, start frozen and break first:

```sh
.claude/skills/debug-vm/scripts/launch.sh --freeze
gdb -q target/x86_64-unknown-none/debug/kernel \
    -ex 'set pagination off' \
    -ex 'target remote :1235' \
    -ex 'hb kernel::kern::debug::panic_fmt' \
    -ex continue \
    -ex 'bt 30'
```

Inspect in that same session — `frame N`, `info args`, `p *head`, `x/24gx ptr`.
Do not disconnect and reconnect to look at the same panic.

- **One GDB connection.** A second `target remote` makes QEMU exit.
- `1235` is deliberate: `1234` is QEMU's default and another QEMU may hold it.
- `force-frame-pointers=yes` in `.cargo/config.toml` makes `bt` walk. The
  frames above the library are the interesting ones.
- Trust a backtrace only after `prepare-image.sh`'s md5 line matched: the ELF
  you have symbols for must be the kernel inside the image.
- Serial quiet but the machine clearly alive means the console is `kd`, not
  com0. Dump the VGA text page through the monitor:
  `socat - UNIX-CONNECT:debug/mon.sock`, then `xp /2000xh 0xb8000`.
- For exception and triple-fault text, add `-d int,cpu_reset -D
  debug/qemu-int.log` to the QEMU line.

## Pitfalls

- **Panics invisible on serial** → the multiboot line lacks `console=com0`
  (ADR 0050). Keep the entry `prepare-image.sh` installs from
  `hurd-smoke/custom.cfg`; if serial is empty anyway, dump `0xb8000` via
  `mon.sock`.
- **QEMU exits when GDB attaches a second time** → one session only; open a new
  one only after the previous `target remote` is gone.
- **Late GDB finds a reboot stack** → set `hb kernel::kern::debug::panic_fmt`
  before `continue`, and inspect before that session ends.
- **Stale sockets after a crash** → `stop.sh` before `launch.sh`.
- **`drive.py` cannot connect** → the tmux console holds the socket;
  `tmux kill-session -t hurd-console`. History is in `debug/serial.log`.
- **QEMU will not die** → `stop.sh` (it reads `debug/qemu.pid`). Its fallback
  kills only the qemu whose command line names this `debug/serial.sock`.
  Never `pkill -f`; `pgrep -x qemu-system-x86_64` also never matches — Linux
  truncates the process name to `qemu-system-x86`.
- **Image suspect after an interrupted `prepare-image.sh`** → `e2fsck -fy` the
  type-83 partition before trusting results. Ordinary hard kills are safe under
  `-snapshot`.
- **Backtrace that cannot be true** → the ELF and the image's kernel differ;
  re-run `prepare-image.sh` and check the md5s.
- **`Inappropriate file type` on a file just written** → its Hurd
  passive-translator field got bumped; `prepare-image.sh` clears it. By hand:
  `debugfs -w -R "set_inode_field /path translator 0" "img?offset=N"`.
- **Interactive keys dead** → you are not on a raw tty; attach through
  `console.sh`.

## Cross-refs

- `AGENTS.md` Debugging — the bare-kernel ISO GDB recipe (abi-test module ISO),
  and the panic line format. This skill is the Hurd reference image path.
- `docs/adr/0021-no-in-kernel-debugger.md` — GDB through QEMU plus the serial
  panic line is the whole toolkit.
- `docs/adr/0050-the-console-stays-in-the-kernel.md` — why `console=com0` has
  to be on the multiboot line.
- `hurd-smoke/` and `mise test::abi` — the non-interactive gate. Interactive
  debugging never substitutes for a run of it.
- `GLOSSARY.md` — the term is "Hurd reference image".
- `debug/debug-note-*.md` — a worked session this skill encodes.
