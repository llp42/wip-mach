#!/usr/bin/env bash
# Boot the Hurd reference image in QEMU with the serial console on a Unix socket.
#
# Usage: launch.sh [--freeze]
#
#   --freeze   hold the guest at reset until GDB continues (adds -S)
#
# Writes debug/qemu.pid, debug/qemu.log, debug/serial.sock, debug/mon.sock and
# debug/serial.log.  The image is opened with -snapshot, so guest writes never
# reach it.  The gdbstub listens on 1235 and the guest's ssh on 2222.
#
# The tool needed is qemu-system-x86_64.
set -euo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../../../.." && pwd)
debug=$root/debug
pidfile=$debug/qemu.pid
sock=$debug/serial.sock
mon=$debug/mon.sock
serial_log=$debug/serial.log
qemu_log=$debug/qemu.log

die() { echo "error: $*" >&2; exit 1; }

freeze=no
while [ $# -gt 0 ]; do
    case $1 in
        --freeze)   freeze=yes ;;
        -h|--help)  sed -n '2,14p' "$0"; exit 0 ;;
        *)          echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

img=
for cand in "$debug"/debian-hurd-amd64-*.img; do
    [ -f "$cand" ] || continue
    img=$cand
    break
done
[ -n "$img" ] || die "no Hurd reference image in $debug"
[ -f "$img" ] || die "disk image not found: $img"
command -v qemu-system-x86_64 >/dev/null || die "missing tool: qemu-system-x86_64"

if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    die "already running (pid $(cat "$pidfile")); run stop.sh first"
fi

rm -f "$sock" "$mon" "$pidfile" "$serial_log"

accel=()
if [ -w /dev/kvm ]; then accel=(-enable-kvm -cpu host); fi

freeze_flag=()
if [ "$freeze" = yes ]; then freeze_flag=(-S); fi

setsid qemu-system-x86_64 "${accel[@]}" -m 2G -smp 1 \
    -drive "format=raw,cache=writeback,file=$img" -snapshot \
    -no-reboot -no-shutdown "${freeze_flag[@]}" \
    -net user,hostfwd=tcp:127.0.0.1:2222-:22 -net nic,model=e1000 \
    -display none \
    -chardev "socket,id=ser0,path=$sock,server=on,wait=off,logfile=$serial_log" \
    -serial chardev:ser0 \
    -monitor "unix:$mon,server,nowait" \
    -gdb tcp::1235 \
    -pidfile "$pidfile" \
    > "$qemu_log" 2>&1 &

for _ in $(seq 1 50); do
    [ -f "$pidfile" ] && break
    sleep 0.1
done
[ -f "$pidfile" ] || die "qemu did not start; see $qemu_log"
pid=$(cat "$pidfile")
kill -0 "$pid" 2>/dev/null || die "qemu exited at once; see $qemu_log"

echo "qemu running (pid $pid)"
echo "  image:        $img"
echo "  serial socket: $sock"
echo "  monitor:      $mon"
echo "  serial log:   $serial_log"
if [ "$freeze" = yes ]; then
    echo
    echo "the guest is frozen at reset; GDB holds it until you continue"
fi
echo
echo "next:"
echo "  $here/console.sh"
echo "  $here/drive.py read --seconds 5"
echo "  ssh -p 2222 root@127.0.0.1"
