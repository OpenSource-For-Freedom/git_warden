"""Minimal .env loader (stdlib only -- no python-dotenv dependency).

Loads KEY=VALUE lines from a .env file into ``os.environ`` so credentials don't
have to be exported by hand each shell. Real environment variables always win:
a key already set in the environment is never overwritten by the file.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_env_file(path: Path | str) -> dict[str, str]:
    """Load KEY=VALUE pairs from ``path`` into os.environ. Returns what was set.

    Ignores blank lines and ``#`` comments, tolerates a leading ``export``, and
    strips one layer of surrounding single/double quotes from values.
    """
    p = Path(path)
    if not p.exists():
        return {}

    loaded: dict[str, str] = {}
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :]
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value
            loaded[key] = value
    return loaded
