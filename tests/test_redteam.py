"""Tests for the known-good red-team registry loader."""

from __future__ import annotations

import json

from git_warden.config import REDTEAM_TOOLS_PATH
from git_warden.models import RedTeamTool
from git_warden.redteam import known_good_repos, load_redteam_tools


def test_match_terms_dedup_and_strip():
    tool = RedTeamTool(name="Sliver", aliases=["sliver", "Sliver", " SLIVER "])
    assert tool.match_terms == ["Sliver"]


def test_known_good_repos_lowercased():
    tools = [
        RedTeamTool(name="A", repos=["BishopFox/Sliver"]),
        RedTeamTool(name="B", repos=[]),
    ]
    assert known_good_repos(tools) == {"bishopfox/sliver"}


def test_loader_parses_tmp_registry(tmp_path):
    path = tmp_path / "rt.json"
    path.write_text(
        json.dumps([{"name": "Sliver", "org": "BishopFox", "repos": ["BishopFox/sliver"]}]),
        encoding="utf-8",
    )
    tools = load_redteam_tools(path)
    assert tools[0].name == "Sliver"
    assert tools[0].org == "BishopFox"


def test_shipped_registry_is_valid():
    # Guards the committed config/redteam_tools.json against schema/JSON errors.
    tools = load_redteam_tools(REDTEAM_TOOLS_PATH)
    assert len(tools) >= 10
    assert all(t.name for t in tools)
    # Sliver is a pinned anchor with a canonical repo.
    sliver = next(t for t in tools if t.name == "Sliver")
    assert "BishopFox/sliver" in sliver.repos
