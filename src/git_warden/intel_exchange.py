"""Shared breadcrumb bus between git_warden (repos) and knorr (containers).

Both tools hunt the same campaigns from opposite ends: warden finds a malicious
repo, knorr finds a malicious image, and the campaign that ships both uses the same
C2 hosts, the same malicious packages, and often links a repo to its image. Neither
tool could see the other's leads, so a breadcrumb one earned was wasted on the
other. This is the bus that carries them across.

Each tool WRITES its confirmed breadcrumbs (C2 hosts, malicious packages, dropper
path fingerprints, code signatures, repo<->image links, and what it submitted to
OSM) and READS the other tool's as discovery seeds and submission dedup. It is an
append-only JSONL file at a path both tools default to (``<dev>/shared_intel/``),
so there is no shared database, no lock contention, and either tool runs fine when
the other has never written. Every write is best effort and never raises: the bus
must not be able to break a hunt.

The JSONL line shape is the contract; knorr ships the same module against the same
format. One object per line::

    {"kind": "c2_host", "value": "task-hrec.vercel.app", "tool": "warden",
     "artifact": "owner/repo", "tags": ["dprk"], "ts": 1234.5}

Kinds: ``c2_host``, ``package`` (``npm/name@version``), ``path_fp`` (a dropper URL
path), ``code_sig``, ``link`` (repo<->image, the counterpart in ``extra``), and
``submitted`` (``value`` = ``domain:host`` / ``repository:url`` / ``container:image``,
``threat_id`` in ``extra``).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path

log = logging.getLogger(__name__)

TOOL = "warden"

# Both tools default under <dev>/shared_intel so a co-located checkout just works;
# GW_SHARED_INTEL (warden) and KN_SHARED_INTEL (knorr) point at the same file.
_DEV_ROOT = Path(__file__).resolve().parents[3]
SHARED_INTEL_PATH = Path(
    os.environ.get("GW_SHARED_INTEL", _DEV_ROOT / "shared_intel" / "breadcrumbs.jsonl"))

_KINDS = ("c2_host", "package", "path_fp", "code_sig", "link", "submitted")
_MAX_BYTES = 5_000_000
_KEEP_LINES = 20_000
_lock = threading.Lock()
_writes = 0


def _compact() -> None:
    """Keep the newest lines when the log passes its cap. Best effort."""
    try:
        lines = SHARED_INTEL_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
        SHARED_INTEL_PATH.write_text("\n".join(lines[-_KEEP_LINES:]) + "\n", encoding="utf-8")
    except OSError:
        pass


def record(kind: str, value: str, *, tool: str = TOOL, artifact: str | None = None,
           tags: list[str] | None = None, **extra) -> None:
    """Append one breadcrumb. Never raises; the bus must not break a hunt."""
    global _writes
    value = (value or "").strip()
    if kind not in _KINDS or not value:
        return
    row = {"kind": kind, "value": value, "tool": tool, "ts": time.time()}
    if artifact:
        row["artifact"] = artifact
    if tags:
        row["tags"] = list(tags)
    row.update(extra)
    try:
        with _lock:
            SHARED_INTEL_PATH.parent.mkdir(parents=True, exist_ok=True)
            with SHARED_INTEL_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, default=str) + "\n")
            _writes += 1
            if _writes % 200 == 0 and SHARED_INTEL_PATH.exists():
                if SHARED_INTEL_PATH.stat().st_size > _MAX_BYTES:
                    _compact()
    except Exception:                                    # pragma: no cover - defensive
        log.debug("shared intel write failed", exc_info=True)


def record_many(kind: str, values, *, tool: str = TOOL, artifact: str | None = None,
                tags: list[str] | None = None) -> int:
    """Append several breadcrumbs of one kind. Returns how many were written."""
    n = 0
    for v in values or []:
        record(kind, v, tool=tool, artifact=artifact, tags=tags)
        n += 1
    return n


def _read_rows() -> list[dict]:
    if not SHARED_INTEL_PATH.exists():
        return []
    try:
        text = SHARED_INTEL_PATH.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue                                     # torn line, skip
    return out


def read(kind: str | None = None, *, exclude_tool: str | None = None,
         only_tool: str | None = None) -> list[dict]:
    """Deduplicated breadcrumbs, newest write per (kind, value) kept.

    ``exclude_tool`` drops a tool's own rows so a reader seeds only from the OTHER
    tool; ``only_tool`` keeps just one. Both may be combined with ``kind``.
    """
    seen: dict[tuple, dict] = {}
    for r in _read_rows():
        if kind and r.get("kind") != kind:
            continue
        if exclude_tool and r.get("tool") == exclude_tool:
            continue
        if only_tool and r.get("tool") != only_tool:
            continue
        seen[(r.get("kind"), r.get("value"))] = r          # later line wins
    return list(seen.values())


def values(kind: str, *, exclude_tool: str | None = None) -> list[str]:
    """Just the distinct values for a kind, e.g. every C2 host the other tool found."""
    return sorted({r["value"] for r in read(kind, exclude_tool=exclude_tool) if r.get("value")})


def mark_submitted(target_kind: str, value: str, *, tool: str = TOOL,
                   threat_id: str | None = None) -> None:
    """Record an OSM submission so the other tool never re-submits the same IOC.

    ``target_kind`` is ``domain`` / ``repository`` / ``container``; it is stored as
    ``value`` = ``"<target_kind>:<value>"`` under the ``submitted`` kind.
    """
    record("submitted", f"{target_kind}:{value}", tool=tool, threat_id=threat_id or "")


def submitted_targets() -> set[str]:
    """The set of ``"<kind>:<value>"`` already submitted by EITHER tool."""
    return {r["value"] for r in read("submitted")}


def is_submitted(target_kind: str, value: str) -> bool:
    """True if either tool already submitted this domain/repository/container to OSM."""
    return f"{target_kind}:{value}" in submitted_targets()
