#!/bin/bash
# Legit health check: poll a LOCAL service and pretty-print the JSON. Not a dropper.
# curl to localhost is never attacker C2; `python3 -m json.tool` formats stdin, it
# does not execute it. (siragpt-app / full-scene-agents / hermes-agent, 2026-07-07)
PORT="${PORT:-8188}"
curl -fsS "http://127.0.0.1:$PORT/system_stats" | python3 -m json.tool 2>/dev/null || true
