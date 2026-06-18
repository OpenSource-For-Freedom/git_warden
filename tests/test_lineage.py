"""Offline tests for red-team clone/lineage detection (fake client)."""

from __future__ import annotations

from datetime import UTC, datetime

from git_warden.models import RedTeamTool
from git_warden.scanning import find_lineage_candidates


def _repo(full, *, fork=False, stars=0, pushed=None, desc=None):
    return {
        "full_name": full,
        "owner": {"login": full.split("/", 1)[0]},
        "fork": fork,
        "stargazers_count": stars,
        "pushed_at": pushed,
        "description": desc,
        "html_url": f"https://github.com/{full}",
    }


class FakeClient:
    def __init__(self, forks=None, search=None):
        self._forks = forks or {}
        self._search = search or {}

    def list_forks(self, owner, name, per_page=100, sort="newest"):
        return self._forks.get(f"{owner}/{name}", [])

    def search_repositories(self, query, per_page=10):
        term = query.split(" in:")[0]
        return self._search.get(term, [])


NOW = datetime(2026, 6, 18, tzinfo=UTC)
TOOL = RedTeamTool(name="Sliver", org="BishopFox", repos=["BishopFox/sliver"], aliases=["sliver"])
KNOWN_GOOD = {"bishopfox/sliver"}


def test_forks_become_candidates_excluding_known_good():
    client = FakeClient(
        forks={
            "BishopFox/sliver": [
                _repo("mallory/sliver", fork=True, stars=1, pushed="2026-06-01T00:00:00Z"),
                _repo("BishopFox/sliver"),  # the original showing up -> excluded
            ]
        }
    )
    cands = find_lineage_candidates(client, TOOL, known_good=KNOWN_GOOD, now=NOW)
    names = {c.full_name for c in cands}
    assert "mallory/sliver" in names
    assert "BishopFox/sliver" not in names
    fork = next(c for c in cands if c.full_name == "mallory/sliver")
    assert fork.relation == "fork"
    assert "recently-pushed" in fork.signals
    assert "low-stars" in fork.signals


def test_name_match_excludes_legit_org_and_dedups():
    client = FakeClient(
        search={
            "Sliver": [
                _repo("BishopFox/sliver"),  # known-good -> excluded
                _repo("BishopFox/sliver-docs"),  # legit org -> excluded
                _repo("attacker/sliver-weaponized", stars=0, desc=None),  # candidate
            ]
        }
    )
    cands = find_lineage_candidates(client, TOOL, known_good=KNOWN_GOOD, now=NOW)
    names = {c.full_name for c in cands}
    assert names == {"attacker/sliver-weaponized"}
    cand = cands[0]
    assert cand.relation == "name_match"
    assert "renamed" in cand.signals  # short name differs from "sliver"
    assert "no-description" in cand.signals


def test_fork_and_search_dedupe_to_single_candidate():
    shared = _repo("mallory/sliver", fork=True, stars=2)
    client = FakeClient(
        forks={"BishopFox/sliver": [shared]},
        search={"Sliver": [shared], "sliver": [shared]},
    )
    cands = find_lineage_candidates(client, TOOL, known_good=KNOWN_GOOD, now=NOW)
    assert len(cands) == 1
    assert cands[0].relation == "fork"  # fork relation wins over name_match
