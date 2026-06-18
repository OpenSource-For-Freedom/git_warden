"""Load the version-controlled threat-actor seed list."""

from __future__ import annotations

import json
from pathlib import Path

from .config import SEED_ACTORS_PATH
from .models import SeedActor


def load_seeds(path: Path | str = SEED_ACTORS_PATH) -> list[SeedActor]:
    """Parse and validate the seed-actor JSON file into SeedActor models."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"seed file {path} must contain a JSON array")
    return [SeedActor.model_validate(entry) for entry in raw]
