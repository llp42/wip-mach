#!/usr/bin/env bash
# Put a fresh kernel and a serial boot entry into the Hurd reference image.
#
# Usage: prepare-image.sh [IMAGE]
#
# IMAGE defaults to the first debug/debian-hurd-amd64-*.img.  Calls
# debug/replace-gnumach.sh to install target/x86_64-unknown-none/debug/kernel
# as /boot/gnumach-1.8-amd64-up.gz, installs hurd-smoke/custom.cfg as the
# serial GRUB entry, gives root the password `debug`, clears the Hurd
# passive-translator field on everything written, and checks that the kernel
# inside the image is the one just built.
#
# The tools needed are sfdisk, fuse2fs, fusermount3, debugfs, gzip, md5sum,
# openssl.
set -euo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../../../.." && pwd)
debug=$root/debug
kernel=$root/target/x86_64-unknown-none/debug/kernel
kernel_dest=/boot/gnumach-1.8-amd64-up.gz
password=debug

step() { printf '\n==> %s\n' "$*"; }
die()  { echo "error: $*" >&2; exit 1; }

img=${1:-}
if [ -z "$img" ]; then
    for cand in "$debug"/debian-hurd-amd64-*.img; do
        [ -f "$cand" ] || continue
        img=$cand
        break
    done
fi
[ -n "$img" ] || die "no Hurd reference image in $debug"
[ -f "$img" ] || die "disk image not found: $img"

for tool in sfdisk fuse2fs fusermount3 debugfs gzip md5sum openssl; do
    command -v "$tool" >/dev/null || die "missing tool: $tool"
done
[ -f "$kernel" ] || die "kernel not found: $kernel (run cargo build first)"
[ -x "$debug/replace-gnumach.sh" ] || die "missing $debug/replace-gnumach.sh"

step "install the kernel into the image"
"$debug/replace-gnumach.sh" "$img"

sector_size=$(sfdisk -d "$img" | awk -F': *' '/^sector-size:/ {print $2; exit}')
offset=$(sfdisk -d "$img" | awk -v ss="${sector_size:-512}" -F'[=,]' '
    /type=83/ {
        for (i = 1; i <= NF; i++)
            if ($i ~ /start$/) {
                n = $(i + 1); gsub(/[^0-9]/, "", n)
                print n * ss; exit
            }
    }')
[ -n "$offset" ] || die "no Linux partition found in $img"

step "install the serial boot entry and give root the password '$password'"
tmp=$(mktemp -d)
mnt=$tmp/mnt
mkdir "$mnt"
mounted=no
cleanup() {
    if [ "$mounted" = yes ]; then fusermount3 -u "$mnt" || true; fi
    rm -rf -- "$tmp"
}
trap cleanup EXIT

fuse2fs -o "offset=$offset,fakeroot" "$img" "$mnt"
mounted=yes
install -m 644 "$root/hurd-smoke/custom.cfg" "$mnt/boot/grub/custom.cfg"
chown 0:0 "$mnt/boot/grub/custom.cfg"
hash=$(openssl passwd -6 "$password")
awk -F: -v OFS=: -v h="$hash" '$1 == "root" { $2 = h } { print }' \
    "$mnt/etc/shadow" > "$tmp/shadow"
cat "$tmp/shadow" > "$mnt/etc/shadow"
sync
fusermount3 -u "$mnt"
mounted=no

# Rewriting a file from Linux bumps its inode version, which is the Hurd's
# passive-translator field: the Hurd would then see a translator where there
# is none and fail the file with "Inappropriate file type".  Clear it on
# everything touched.
step "clear the Hurd translator field on everything written"
for path in /etc /etc/shadow /boot /boot/grub /boot/grub/custom.cfg "$kernel_dest"; do
    debugfs -w -R "set_inode_field $path translator 0" "$img?offset=$offset" >/dev/null 2>&1
done

step "check the installed kernel against the build"
debugfs -R "dump $kernel_dest $tmp/installed.gz" "$img?offset=$offset" >/dev/null
built_md5=$(md5sum "$kernel" | awk '{print $1}')
installed_md5=$(zcat "$tmp/installed.gz" | md5sum | awk '{print $1}')
echo "built:     $built_md5  $kernel"
echo "installed: $installed_md5  $img:$kernel_dest"
[ "$built_md5" = "$installed_md5" ] || die "the image holds a different kernel than the build"

echo
echo "prepared $img"
echo "log in as root with the password '$password'"
