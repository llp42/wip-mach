#!/usr/bin/env python3
"""Drive the debug VM's serial console from the command line.

Usage:
  drive.py read [--seconds N]   tail whatever the guest prints
  drive.py expect PATTERN       exit 0 when the regex matches
  drive.py send LINE            send LINE and a carriage return
  drive.py run CMD              run CMD in a logged-in shell, print its output

Each verb opens one short connection to debug/serial.sock.  The tmux console
must not be holding that socket; anything printed before the connection is in
debug/serial.log.
"""
import argparse
import os
import re
import socket
import sys
import time


class Serial:
    def __init__(self, sock):
        self.sock, self.buf = sock, ""

    def read(self, deadline):
        self.sock.settimeout(max(0.1, min(1.0, deadline - time.time())))
        try:
            data = self.sock.recv(4096)
        except socket.timeout:
            return True
        if not data:
            return False
        self.buf += data.decode(errors="replace")
        return True

    def expect(self, pattern, timeout):
        rx = re.compile(pattern)
        deadline = time.time() + timeout
        while time.time() < deadline:
            m = rx.search(self.buf)
            if m:
                out, self.buf = self.buf[: m.end()], self.buf[m.end():]
                return out
            if not self.read(deadline):
                break
        raise TimeoutError(
            f"timed out waiting for {pattern!r}\n"
            f"--- recent output ---\n{self.buf[-2000:]}"
        )

    def send(self, line):
        self.sock.sendall(line.encode() + b"\r")


def default_sock():
    root = os.path.abspath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..")
    )
    return os.path.join(root, "debug", "serial.sock")


def connect(path):
    if not os.path.exists(path):
        sys.exit(f"error: no serial socket at {path}; run launch.sh first")
    sock = socket.socket(socket.AF_UNIX)
    try:
        sock.connect(path)
    except OSError as e:
        sys.exit(
            f"error: cannot connect to {path}: {e}\n"
            "the tmux console may be holding the socket; "
            "kill it with `tmux kill-session -t hurd-console`"
        )
    return sock


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--sock", default=None, help="serial socket (default debug/serial.sock)")
    ap.add_argument("--timeout", type=float, default=60.0, help="seconds to wait (default 60)")
    sub = ap.add_subparsers(dest="verb", required=True)
    p = sub.add_parser("read", help="tail whatever the guest prints")
    p.add_argument("--seconds", type=float, default=3.0)
    sub.add_parser("expect", help="wait for a regex").add_argument("pattern")
    sub.add_parser("send", help="send a line").add_argument("line")
    sub.add_parser("run", help="run a command in a logged-in shell").add_argument("cmd")
    args = ap.parse_args()

    ser = Serial(connect(args.sock or default_sock()))
    try:
        if args.verb == "read":
            deadline = time.time() + args.seconds
            while time.time() < deadline:
                before = len(ser.buf)
                if not ser.read(deadline):
                    break
                sys.stdout.write(ser.buf[before:])
                sys.stdout.flush()
            return 0

        if args.verb == "expect":
            out = ser.expect(args.pattern, args.timeout)
            sys.stdout.write(out)
            return 0

        if args.verb == "send":
            ser.send(args.line)
            return 0

        marker = "<<END"
        ser.send(f'{args.cmd}; echo "{marker}$?>>"')
        out = ser.expect(re.escape(marker) + r"(\d+)>>", args.timeout)
        status = re.search(r"(\d+)>>$", out).group(1)
        sys.stdout.write(out[: out.rfind(marker)])
        return int(status)
    except TimeoutError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
