"""Load the YAML orchestration playbooks (doc 05 section 5.1/5.2).

``trigger.yaml`` classifies errors and chooses a self-healing response;
``settings.yaml`` holds run config and the alert thresholds. Together they drive
:mod:`git_warden.orchestration.resilience`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..config import PROJECT_ROOT

DEFAULT_TRIGGER = PROJECT_ROOT / "config" / "trigger.yaml"
DEFAULT_SETTINGS = PROJECT_ROOT / "config" / "settings.yaml"


@dataclass
class Backoff:
    base_seconds: float = 5.0
    factor: float = 2.0
    max_retries: int = 3

    def delay(self, attempt: int) -> float:
        """Delay before retry ``attempt`` (1-based): base * factor^(attempt-1)."""
        return self.base_seconds * (self.factor ** max(0, attempt - 1))


@dataclass
class ErrorClass:
    name: str
    match: list[str]
    response: str  # backoff_retry | queue_or_defer | flag_manual | skip_and_log
    backoff: Backoff | None = None
    alert: bool = False

    def matches(self, message: str) -> bool:
        low = message.lower()
        return any(pat.lower() in low for pat in self.match)


@dataclass
class Playbook:
    error_classes: list[ErrorClass] = field(default_factory=list)
    thresholds: dict[str, int] = field(default_factory=dict)

    def classify(self, message: str) -> ErrorClass | None:
        """First matching error class (order in trigger.yaml is the priority)."""
        for ec in self.error_classes:
            if ec.matches(message):
                return ec
        return None


def load_playbook(
    trigger: Path | str = DEFAULT_TRIGGER, settings: Path | str = DEFAULT_SETTINGS
) -> Playbook:
    """Parse trigger.yaml + settings.yaml into a Playbook."""
    trig = yaml.safe_load(Path(trigger).read_text(encoding="utf-8")) or {}
    sett = yaml.safe_load(Path(settings).read_text(encoding="utf-8")) or {}

    classes: list[ErrorClass] = []
    for name, spec in (trig.get("error_classes") or {}).items():
        bo = spec.get("backoff")
        classes.append(
            ErrorClass(
                name=name,
                match=list(spec.get("match", [])),
                response=spec.get("response", "skip_and_log"),
                backoff=Backoff(**bo) if bo else None,
                alert=bool(spec.get("alert", False)),
            )
        )
    thresholds = dict(((sett.get("alerting") or {}).get("thresholds")) or {})
    return Playbook(error_classes=classes, thresholds=thresholds)
