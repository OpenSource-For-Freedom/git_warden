#!/bin/sh
# From alpinelinux/aports (the Alpine Linux ports tree), which confirmed AUTO on the
# 2026-07-21 hunt via "credential_harvest:shadow-read". The path is inside a rootfs
# being BUILT under $tmp, not the running host, and `sed -i` writes rather than
# reads. Distro and image tooling does this constantly.
set -e

tmp="$(mktemp -d)"
mkdir -p "$tmp"/etc

# Lock the root account in the generated image.
sed -i -e 's/^root::/root:*:/' "$tmp"/etc/shadow
install -m 0640 shadow.template "${DESTDIR}/etc/shadow"

tar -c -C "$tmp" etc | gzip -9n > rootfs.tar.gz
