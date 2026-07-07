"""Structured logging for auditable per-run records (PRD section 13.1)."""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC, datetime


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per line so runs are machine-parseable for audit."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # Allow callers to attach structured context via `extra={"context": {...}}`.
        context = getattr(record, "context", None)
        if context:
            payload["context"] = context
        return json.dumps(payload, default=str)


def configure_logging(level: int = logging.INFO, *, json_output: bool = True) -> None:
    """Configure the root logger once. Idempotent across repeated calls.

    ``GW_LOG_LEVEL`` (DEBUG/INFO/WARNING/...) overrides the default level, so an
    operator can turn on full-verbosity monitoring (network calls, retries, every
    decision) for a run without a code change: ``GW_LOG_LEVEL=DEBUG git-warden hunt``.
    """
    env_level = os.environ.get("GW_LOG_LEVEL", "").strip().upper()
    if env_level:
        level = getattr(logging, env_level, level)
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = logging.StreamHandler(stream=sys.stdout)
    if json_output:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
    root.addHandler(handler)
    # Transport libraries are pure noise at DEBUG (every header, redirect, retry);
    # keep the signal on git_warden's own discovery/decision logs.
    for noisy in ("urllib3", "requests", "git", "asyncio", "charset_normalizer", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
