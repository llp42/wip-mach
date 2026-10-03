#!/usr/bin/env bash
# Put the debug VM's serial console in a tmux pane.
#
# Usage: console.sh
#
# Starts a detached tmux session `hurd-console` running socat against
# debug/serial.sock.  Attach with `tmux attach -t hurd-console`, detach with
# `C-b d`, release the socket with `tmux kill-session -t hurd-console`.
#
# The tools needed are socat and tmux.
set -euo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../../../.." && pwd)
debug=$root/debug
sock=$debug/serial.sock
session=hurd-console

die() { echo "error: $*" >&2; exit 1; }

for tool in socat tmux; do
    command -v "$tool" >/dev/null || die "missing tool: $tool"
done
[ -S "$sock" ] || die "no serial socket at $sock; run launch.sh first"

if tmux has-session -t "$session" 2>/dev/null; then
    echo "console already running in tmux session $session"
else
    tmux new-session -d -s "$session" "socat -,raw,echo=0 UNIX-CONNECT:$sock"
    echo "console started in tmux session $session"
fi

echo
echo "  tmux attach -t $session        # detach with C-b d"
echo "  tmux kill-session -t $session  # release the socket for drive.py"
