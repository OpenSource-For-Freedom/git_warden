#!/bin/bash
# Scanner sandbox: a REGEX enumerating sensitive paths to block/flag. This is a
# pattern definition, not an actual read of /etc/shadow.
SENSITIVE='\.npmrc|\.ssh/|\.aws/|\.env|/etc/passwd|/etc/shadow|\.gitconfig|\.bash_history'
grep -E "$SENSITIVE" "$1" && echo "blocked"
