#!/usr/bin/env bash
# From adityavanjre/project-k, the highest-scoring false positive of the
# 2026-07-21 hunt (score 90, "exfiltration:secret-exfil"). Nothing here sends a
# secret anywhere: curl's `-o` WRITES the response to disk, so this fetches a
# template. It matched only because the upload flag `-F` was compared
# case-insensitively and so also matched curl's ubiquitous benign `-f`.
set -euo pipefail

RAW_BASE="https://raw.githubusercontent.com/example/project-k/main"
install_dir="${HOME}/.project-k"

mkdir -p "$install_dir"
curl -fsSL "$RAW_BASE/.env.example" -o "$install_dir/.env.example"
curl -fsSL "$RAW_BASE/config.yaml" --output "$install_dir/config.yaml"

echo "Copy .env.example to .env and fill in your keys."
