#!/usr/bin/env bash
# Tear down the debug VM and its console.
#
# Usage: stop.sh
#
# Frees the serial socket, then asks the qemu named by debug/qemu.pid to exit,
# escalating to SIGKILL after five seconds.  With no usable pidfile, kills only
# the qemu whose command line names this debug/serial.sock.  (Linux truncates
# a process name to 15 characters, so that is `qemu-system-x86`.)
set -euo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../../../.." && pwd)
debug=$root/debug
pidfile=$debug/qemu.pid
sock=$debug/serial.sock

tmux kill-session -t hurd-console 2>/dev/null || true

if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$pid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
        echo "stopped qemu (pid $pid)"
    else
        echo "stale pidfile: pid $pid is already gone"
    fi
else
    echo "no pidfile at $pidfile"
fi

for pid in $(pgrep -x qemu-system-x86 2>/dev/null || true); do
    [ -r "/proc/$pid/cmdline" ] || continue
    tr '\0' ' ' < "/proc/$pid/cmdline" | grep -Fq "$sock" || continue
    kill "$pid" 2>/dev/null || true
    echo "stopped the qemu holding $sock (pid $pid)"
done

rm -f "$sock" "$debug/mon.sock" "$pidfile"
echo "removed debug/serial.sock debug/mon.sock debug/qemu.pid"
