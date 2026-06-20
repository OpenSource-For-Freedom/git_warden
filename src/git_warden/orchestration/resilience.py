"""Self-healing call wrapper (doc 05 section 5).

"Anyone can make an API call, but not many can handle it." This classifies each
failure via the playbook and responds per class; backoff+retry, queue/defer,
skip, or flag for manual intervention; instead of one blanket retry. Error
counts are tracked against thresholds; a breach fires an alert (doc 05 5.3).
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .playbook import Playbook

log = logging.getLogger(__name__)


class ManualInterventionRequired(RuntimeError):
    """Raised for an auth failure or other class that must not be auto-retried."""


@dataclass
class RunHealth:
    """Per-run error tally, compared against settings.yaml thresholds."""

    errors: Counter = field(default_factory=Counter)
    alerted: set = field(default_factory=set)

    def record(self, class_name: str) -> None:
        self.errors[class_name] += 1

    def newly_breached(self, thresholds: dict[str, int]) -> list[str]:
        """Classes that just crossed their threshold (each reported once)."""
        out = []
        for name, limit in thresholds.items():
            if self.errors.get(name, 0) >= limit and name not in self.alerted:
                self.alerted.add(name)
                out.append(name)
        return out


def resilient_call(
    fn: Callable[[], Any],
    *,
    playbook: Playbook,
    health: RunHealth | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    on_alert: Callable[[str], None] | None = None,
    label: str = "",
) -> Any:
    """Call ``fn`` with playbook-driven self-healing. Returns fn's result.

    ``skip_and_log`` returns None (handled); ``flag_manual`` raises
    :class:`ManualInterventionRequired`; backoff classes retry up to their
    ``max_retries`` then re-raise; an unclassified error re-raises immediately.
    """
    health = health or RunHealth()
    attempt = 0
    while True:
        attempt += 1
        try:
            return fn()
        except ManualInterventionRequired:
            raise
        except Exception as exc:  # noqa: BLE001
            message = f"{type(exc).__name__}: {exc}"
            ec = playbook.classify(message)
            cls = ec.name if ec else "unknown"
            health.record(cls)
            for breached in health.newly_breached(playbook.thresholds):
                log.warning("threshold breached", extra={"context": {"class": breached}})
                if on_alert:
                    on_alert(f"⚠️ threshold breached: {breached} = {health.errors[breached]}")

            if ec is None:
                log.warning("unclassified error",
                            extra={"context": {"label": label, "err": message}})
                raise
            if ec.response == "flag_manual":
                if on_alert:
                    on_alert(f"🚨 manual intervention: {label}: {message}")
                raise ManualInterventionRequired(message) from exc
            if ec.response == "skip_and_log":
                log.info("skip_and_log",
                         extra={"context": {"label": label, "class": cls, "err": message}})
                return None
            # backoff_retry / queue_or_defer
            if ec.backoff is None or attempt > ec.backoff.max_retries:
                log.warning("retries exhausted",
                            extra={"context": {"label": label, "class": cls}})
                raise
            delay = ec.backoff.delay(attempt)
            log.info("backing off",
                     extra={"context": {"label": label, "class": cls,
                                        "attempt": attempt, "delay": delay}})
            sleeper(delay)
