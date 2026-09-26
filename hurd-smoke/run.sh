#!/usr/bin/env bash
# Hurd smoke test (ADR 0002): fetch the pinned Debian GNU/Hurd image, swap
# in the kernel under test, boot it on the serial console, log in, run a
# fixed list of commands and halt.
#
# Usage: hurd-smoke/run.sh [--release] [--fresh] [--no-build] [--timeout SECS]
#
#   --release     test target/x86_64-unknown-none/release/kernel
#   --fresh       discard the working image and copy the pristine one again
#   --no-build    use the kernel already built
#   --timeout N   seconds to wait for each step of the boot (default 300)
#
# Environment: HURD_CACHE (default target/hurd-smoke) holds the download,
# the pristine image, the working image and the logs.  The tools needed are
# curl, tar, sfdisk, fuse2fs, fusermount3, gzip, qemu-system-x86_64, python3.
set -euo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/.." && pwd)

snapshot=20260314
name=debian-hurd-amd64-$snapshot
url=https://cdimage.debian.org/cdimage/ports/latest/hurd-amd64/$name.img.tar.gz
tarball_sha256=6598f1f8dd7d543b768355e185b0906a8d779f71f8ae4dbeb4113502cc882e06
kernel_dest=/boot/gnumach-1.8-amd64-up.gz
smoke_password=hurd-smoke

cache=${HURD_CACHE:-$root/target/hurd-smoke}
profile=debug
fresh=no
build=yes
timeout=300

while [ $# -gt 0 ]; do
    case $1 in
        --release)  profile=release ;;
        --fresh)    fresh=yes ;;
        --no-build) build=no ;;
        --timeout)  shift; timeout=${1:?--timeout needs a value} ;;
        -h|--help)  sed -n '2,15p' "$0"; exit 0 ;;
        *)          echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

step() { printf '\n==> %s\n' "$*"; }
die()  { echo "error: $*" >&2; exit 1; }

for tool in openssl debugfs curl tar sfdisk fuse2fs fusermount3 gzip qemu-system-x86_64 python3 sha256sum; do
    command -v "$tool" >/dev/null || die "missing tool: $tool"
done

pristine=$cache/$name.img
work=$cache/$name.work.img
mkdir -p "$cache"

step "fetch the $snapshot snapshot"
if [ -f "$pristine" ]; then
    echo "have $pristine"
else
    tarball=$cache/$name.img.tar.gz
    curl -fL --retry 3 -C - -o "$tarball" "$url"
    echo "$tarball_sha256  $tarball" | sha256sum -c - \
        || die "checksum mismatch; the snapshot is pinned, see this script"
    tar -xzf "$tarball" -C "$cache" "$name.img"
    rm -f "$tarball"
fi

step "build the kernel ($profile)"
kernel=$root/target/x86_64-unknown-none/$profile/kernel
if [ "$build" = yes ]; then
    flags=()
    [ "$profile" = release ] && flags+=(--release)
    (cd "$root" && cargo build "${flags[@]}")
fi
[ -f "$kernel" ] || die "kernel not found: $kernel"

step "prepare the working image"
if [ "$fresh" = yes ] || [ ! -f "$work" ]; then
    cp --reflink=auto "$pristine" "$work"
fi

sector_size=$(sfdisk -d "$work" | awk -F': *' '/^sector-size:/ {print $2; exit}')
offset=$(sfdisk -d "$work" | awk -v ss="${sector_size:-512}" -F'[=,]' '
    /type=83/ {
        for (i = 1; i <= NF; i++)
            if ($i ~ /start$/) {
                n = $(i + 1); gsub(/[^0-9]/, "", n)
                print n * ss; exit
            }
    }')
[ -n "$offset" ] || die "no Linux partition found in $work"

step "put the kernel and a serial boot entry into the image"
tmp=$(mktemp -d)
mnt=$tmp/mnt
mkdir "$mnt"
mounted=no
cleanup() {
    if [ "$mounted" = yes ]; then fusermount3 -u "$mnt" || true; fi
    rm -rf -- "$tmp"
}
trap cleanup EXIT

gzip -9n -c "$kernel" > "$tmp/gnumach.gz"
fuse2fs -o "offset=$offset,fakeroot" "$work" "$mnt"
mounted=yes
cp "$tmp/gnumach.gz" "$mnt$kernel_dest"
chown 0:0 "$mnt$kernel_dest"
chmod 644 "$mnt$kernel_dest"
install -m 644 "$here/custom.cfg" "$mnt/boot/grub/custom.cfg"
# The working image is a disposable copy: give root a known password so the
# driver can log in and halt.  Written in place to keep each file's owner.
hash=$(openssl passwd -6 "$smoke_password")
awk -F: -v OFS=: -v h="$hash" '$1 == "root" { $2 = h } { print }' \
    "$mnt/etc/shadow" > "$tmp/shadow"
cat "$tmp/shadow" > "$mnt/etc/shadow"
sync
fusermount3 -u "$mnt"
mounted=no

# Rewriting a file from Linux bumps its inode version, which is the Hurd's
# passive-translator field: the Hurd would then see a translator where
# there is none and fail the file with "Inappropriate file type".  Clear it
# on everything touched.
for path in /etc /etc/shadow /boot /boot/grub /boot/grub/custom.cfg "$kernel_dest"; do
    debugfs -w -R "set_inode_field $path translator 0" "$work?offset=$offset" >/dev/null 2>&1
done
echo "installed $(basename -- "$kernel") as $kernel_dest"

step "boot and run the smoke commands"
log_dir=$cache/logs
mkdir -p "$log_dir"
python3 "$here/drive.py" --image "$work" --log "$log_dir/serial-$profile.log" \
    --timeout "$timeout" --password "$smoke_password"
