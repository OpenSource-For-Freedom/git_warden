#!/bin/bash
# Legit hardening AUDIT: check whether /etc/shadow is world-readable and warn. The
# `2>/dev/null` discards stderr; it does not exfiltrate the file. (arry8/openclaw-edge)
ls /etc/shadow 2>/dev/null && echo "[!] WARNING: /etc/shadow is readable!" || echo "ok: not readable"
