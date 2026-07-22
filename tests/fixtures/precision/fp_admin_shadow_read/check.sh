#!/usr/bin/env bash
# From photoprism/photoprism's DigitalOcean setup check, which confirmed AUTO on the
# 2026-07-21 hunt. The read is real, so the shadow-read rule is right to fire; what
# was wrong is the TIER. Reading a credential file is only theft when the code also
# sends it somewhere, and nothing here leaves the box. A lone read belongs in review
# for a human, never in Discord gold or the submit queue.
set -e

SHADOW=$(cat /etc/shadow)

if echo "$SHADOW" | grep -q '^root:\*:'; then
  echo "ok: root password is locked"
else
  echo "warning: root account has a password set"
fi
