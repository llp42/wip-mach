#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-FileCopyrightText: 2026 Leonardo Lopes Pereira <leonardolopespereira@outlook.com>
set -euo pipefail

missing=()
for tool in dirname pwd mkdir curl gzip mv cargo cp mktemp debugfs cmp rm \
    qemu-system-x86_64; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ "${#missing[@]}" -ne 0 ]; then
    printf 'Missing required commands: %s\n' "${missing[*]}" >&2
    exit 1
fi
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
    printf 'KVM requires read/write access to /dev/kvm\n' >&2
    exit 1
fi

here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/.." && pwd)
name=debian-hurd-amd64-20260314
cache=$root/target/hurd-boot
image=$cache/$name.img
kernel=$root/target/x86_64-unknown-none/debug/mach
kernel_dest=/boot/gnumach-1.8-amd64-up.gz

mkdir -p "$cache"
if [ ! -f "$image" ]; then
    curl -fL --retry 3 -o "$cache/$name.img.gz" \
        "https://cdimage.debian.org/cdimage/ports/latest/hurd-amd64/$name.img.gz"
    gzip -dc "$cache/$name.img.gz" > "$image.part"
    mv -- "$image.part" "$image"
fi

(cd "$root" && cargo build --locked)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
work=$tmp/$name.img
cp --reflink=auto -- "$image" "$work"

# The pinned image's root partition starts at sector 1953792 (512-byte sectors).
filesystem=$work?offset=1000341504
gzip -9n -c "$kernel" > "$tmp/gnumach.gz"
debugfs -w -R "rm $kernel_dest" "$filesystem" >/dev/null
debugfs -w -R "write $tmp/gnumach.gz $kernel_dest" "$filesystem" >/dev/null
debugfs -R "dump $kernel_dest $tmp/installed.gz" "$filesystem" >/dev/null
gzip -dc "$tmp/installed.gz" | cmp -s - "$kernel"

echo "Booting $work"
qemu-system-x86_64 -enable-kvm -cpu host -m 2G -smp 1 \
    -drive "format=raw,file=$work" -no-reboot \
    -nic user,model=e1000
