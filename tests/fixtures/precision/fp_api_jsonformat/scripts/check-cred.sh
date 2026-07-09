#!/bin/bash
# Legit: query an API and pretty-print the JSON response. `python3 -m json.tool`
# reads stdin as DATA and formats it; it never executes the fetched bytes, so this
# is not download-and-run. (bankrbot/skills, 2026-07-07)
AGENT_ID="${AGENT_ID:-demo}"
curl -s "https://api.helixa.xyz/api/v2/cred/${AGENT_ID}" | python3 -m json.tool
