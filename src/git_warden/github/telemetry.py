"""Live search telemetry for the dashboard.

The GitHub client holds its pacing state in memory, so a running hunt could not
show the operator what it was actually doing against the API. This records one
line per code search to an append-only JSONL file that the dashboard reads.

A file rather than a table on purpose. The hunt already holds the SQLite write
lock for its own inserts, and a dashboard poll must never queue behind that (a
read-write dashboard open is what stalled the database on Windows before). An
append to a text file is cheap, crash safe, and readable while it is being
written.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path

from ..config import DATA_DIR

log = logging.getLogger(__name__)

SEARCH_LOG = Path(os.environ.get("GW_SEARCH_LOG", DATA_DIR / "search_telemetry.jsonl"))

# Keep the file bounded. Checked by size rather than by counting lines so the
# common path stays one append with no read.
_MAX_BYTES = 2_000_000
_KEEP_LINES = 1_500
_lock = threading.Lock()
_writes = 0


def _trim() -> None:
    """Drop the oldest lines once the log grows past its cap."""
    try:
        lines = SEARCH_LOG.read_text(encoding="utf-8", errors="ignore").splitlines()
        SEARCH_LOG.write_text("\n".join(lines[-_KEEP_LINES:]) + "\n", encoding="utf-8")
    except OSError:
        pass


def record(**event) -> None:
    """Append one telemetry event. Never raises: telemetry must not break a hunt."""
    global _writes
    event.setdefault("ts", time.time())
    try:
        with _lock:
            SEARCH_LOG.parent.mkdir(parents=True, exist_ok=True)
            with SEARCH_LOG.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, default=str) + "\n")
            _writes += 1
            if _writes % 50 == 0 and SEARCH_LOG.exists():
                if SEARCH_LOG.stat().st_size > _MAX_BYTES:
                    _trim()
    except Exception:                                    # pragma: no cover - defensive
        log.debug("search telemetry write failed", exc_info=True)


def recent(limit: int = 60) -> list[dict]:
    """The most recent events, newest first. Tolerates a partially written line."""
    if not SEARCH_LOG.exists():
        return []
    try:
        lines = SEARCH_LOG.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    out: list[dict] = []
    for ln in reversed(lines):
        if len(out) >= limit:
            break
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue                                     # torn last line, skip it
    return out


def summary(window_seconds: int = 900) -> dict:
    """Aggregate the recent window into the numbers an operator watches."""
    events = recent(limit=_KEEP_LINES)
    now = time.time()
    win = [e for e in events if now - float(e.get("ts") or 0) <= window_seconds]
    searched = [e for e in win if e.get("event") == "search"]
    throttled = [e for e in searched if e.get("throttled")]
    hits = sum(int(e.get("results") or 0) for e in searched)
    last = events[0] if events else {}
    span = max(1.0, now - min((float(e.get("ts") or now) for e in win), default=now))
    return {
        "window_seconds": window_seconds,
        "searches": len(searched),
        "throttled": len(throttled),
        "results": hits,
        "searches_per_min": round(len(searched) / (span / 60.0), 2) if searched else 0.0,
        "interval": last.get("interval"),
        "last_ts": last.get("ts"),
        "last_query": last.get("query"),
        "idle_seconds": round(now - float(last.get("ts") or now), 1) if last else None,
    }
