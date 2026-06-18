"""Load the known-good red-team tooling registry (doc 02 section 5)."""

from __future__ import annotations

import json
from pathlib import Path

from .config import REDTEAM_TOOLS_PATH
from .models import RedTeamTool


def load_redteam_tools(path: Path | str = REDTEAM_TOOLS_PATH) -> list[RedTeamTool]:
    """Parse and validate the red-team registry JSON into RedTeamTool models."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"red-team registry {path} must contain a JSON array")
    return [RedTeamTool.model_validate(entry) for entry in raw]


def known_good_repos(tools: list[RedTeamTool]) -> set[str]:
    """All pinned canonical repo full-names, lowercased, across the registry."""
    return {repo.casefold() for tool in tools for repo in tool.repos}
