"""Malware code-signature discovery (the novel-repo engine).

A confirmed obfuscated payload carries a *reusable* signature. The DPRK
"Contagious Interview" lures inject ``eval(atob('<base64>'))`` into a build config
(``postcss.config.js`` etc.); the LEADING region of that base64 encodes the
deobfuscator stub, which the campaign reuses across many repos while the trailing
data differs. A chunk of that stub is a high-precision GitHub code-search term
that surfaces SIBLING infected repos; including ones OSM never catalogued.

This is the learning loop applied to code signatures: mine a stub from a confirmed
repo (:func:`extract_code_signatures`), then search GitHub for it (via the same
code-search path as IOCs) to find novel campaign members. Curated seed signatures
live in ``config/malware_signatures.json`` so the first hunt has something to fire.

Static only: we never execute the payload; the stub is searched as an opaque
string. Proven live: CoreX's stub surfaced 6 novel infected repos, 4+ confirmed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .bash_scanner import is_ignored_path

# eval(atob('<base64>')) / eval(atob("<base64>")) with a long payload.
_EVAL_ATOB = re.compile(r"eval\s*\(\s*atob\s*\(\s*['\"]([A-Za-z0-9+/=]{96,})['\"]")
_SOURCE_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".astro"}
# A stable chunk of the deobfuscator stub: skip the per-repo header bytes, take a
# window from the shared function region. 48+ chars keeps it specific.
_STUB_START = 16
_STUB_LEN = 64
_MAX_BYTES = 2_000_000


def extract_code_signatures(root) -> list[str]:
    """Mine distinctive, searchable code signatures from a confirmed repo.

    Returns base64 stub chunks (from ``eval(atob(...))`` payloads) suitable as
    GitHub code-search terms to find sibling infected repos. Empty if none.
    """
    sigs: set[str] = set()
    root = Path(root)
    for path in root.rglob("*"):
        if not path.is_file() or is_ignored_path(path):
            continue
        if path.suffix.lower() not in _SOURCE_EXT:
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in _EVAL_ATOB.finditer(text):
            b64 = m.group(1)
            chunk = b64[_STUB_START:_STUB_START + _STUB_LEN]
            if len(chunk) >= 48:
                sigs.add(chunk)
    return sorted(sigs)


def load_seed_signatures(path) -> list[str]:
    """Load curated malware-signature search queries from a JSON file.

    Format: a JSON array of objects ``{"name", "query", "note"?}``. Returns the
    list of ``query`` strings; missing/invalid file yields an empty list.
    """
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out: list[str] = []
    for entry in raw if isinstance(raw, list) else []:
        if isinstance(entry, dict) and isinstance(entry.get("query"), str):
            q = entry["query"].strip()
            if q:
                out.append(q)
    return list(dict.fromkeys(out))
