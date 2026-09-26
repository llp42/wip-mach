#!/usr/bin/env python3
"""Boot the Hurd image under QEMU and drive its serial console.

Waits for the login prompt, logs in as root, runs a fixed list of commands
checking each output, halts, and exits 0 only if everything held.
"""
import argparse
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

# (command, regex the output must match)
COMMANDS = [
    ("uname -a", r"GNU"),
    ("echo smoke-$((6*7))", r"smoke-42"),
    ("ls /servers", r"socket"),
    ("cat /etc/hostname", r"\S"),
]


class Serial:
    def __init__(self, sock, log):
        self.sock, self.log, self.buf = sock, log, ""

    def read(self, deadline):
        self.sock.settimeout(max(0.1, min(1.0, deadline - time.time())))
        try:
            data = self.sock.recv(4096)
        except socket.timeout:
            return True
        if not data:
            return False
        text = data.decode(errors="replace")
        self.log.write(text)
        self.log.flush()
        self.buf += text
        return True

    def expect(self, pattern, timeout, what):
        """Wait for `pattern`; return the text before and including it."""
        rx = re.compile(pattern)
        deadline = time.time() + timeout
        while time.time() < deadline:
            m = rx.search(self.buf)
            if m:
                out, self.buf = self.buf[: m.end()], self.buf[m.end():]
                return out
            if not self.read(deadline):
                break
        raise RuntimeError(f"timed out waiting for {what}")

    def send(self, line):
        self.sock.sendall(line.encode() + b"\r")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--password", required=True)
    args = ap.parse_args()

    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "serial.sock")
    accel = ["-enable-kvm", "-cpu", "host"] if os.access("/dev/kvm", os.W_OK) else []
    qemu = subprocess.Popen(
        ["qemu-system-x86_64", *accel, "-m", "2G", "-smp", "1",
         "-drive", f"format=raw,file={args.image}", "-snapshot",
         "-no-reboot", "-nic", "user,model=e1000",
         "-display", "none", "-monitor", "none",
         "-serial", f"unix:{path},server,nowait"])
    failed = None
    try:
        for _ in range(100):
            if os.path.exists(path):
                break
            time.sleep(0.1)
        sock = socket.socket(socket.AF_UNIX)
        sock.connect(path)
        with open(args.log, "w") as log:
            ser = Serial(sock, log)
            t = args.timeout
            ser.expect(r"login: ", t, "the login prompt")
            ser.send("root")
            ser.expect(r"Password:", t, "the password prompt")
            ser.send(args.password)
            ser.expect(r"[#$] ", t, "a shell prompt")
            for n, (cmd, want) in enumerate(COMMANDS):
                marker = f"<<END{n}:"
                ser.send(f'{cmd}; echo "{marker}$?>>"')
                out = ser.expect(re.escape(marker) + r"(\d+)>>", t, f"`{cmd}`")
                status = re.search(r"(\d+)>>$", out).group(1)
                body = out[: out.rfind(marker)]
                if status != "0" or not re.search(want, body):
                    raise RuntimeError(f"`{cmd}` failed (status {status}): {body.strip()!r}")
                print(f"ok: {cmd}")
            ser.send("halt")
            deadline = time.time() + t
            while qemu.poll() is None and time.time() < deadline:
                ser.read(time.time() + 1)
            if qemu.poll() is None:
                raise RuntimeError("the guest did not halt")
            print("ok: halted")
    except Exception as e:  # noqa: BLE001
        failed = e
    finally:
        if qemu.poll() is None:
            qemu.kill()
        qemu.wait()
    if failed:
        print(f"FAIL: {failed}\nserial log: {args.log}", file=sys.stderr)
        return 1
    print("PASS: hurd smoke test")
    return 0


if __name__ == "__main__":
    sys.exit(main())
