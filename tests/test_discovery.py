"""Offline tests for IOC-driven discovery (fake code search)."""

from __future__ import annotations

from git_warden.scanning.discovery import RepoHit, classify_hit, search_iocs


def _item(full_name, path="src/x.js"):
    owner = full_name.split("/", 1)[0]
    return {
        "repository": {
            "full_name": full_name,
            "owner": {"login": owner},
            "html_url": f"https://github.com/{full_name}",
        },
        "path": path,
    }


class FakeClient:
    def __init__(self, by_term):
        self.by_term = by_term
        self.calls = []

    def search_code(self, query, per_page=20):
        self.calls.append(query)
        return self.by_term.get(query, [])


def test_finds_new_repos_excluding_known():
    client = FakeClient({
        "flipboxstudio.info": [_item("attacker/new-evil"), _item("BishopFox/sliver")],
    })
    hits = search_iocs(client, ["flipboxstudio.info"], known={"bishopfox/sliver"})
    names = {h.full_name for h in hits}
    assert names == {"attacker/new-evil"}  # known repo filtered out


def test_dedupes_repo_across_iocs_and_aggregates_matches():
    shared = _item("attacker/new-evil", path="a.js")
    shared2 = _item("attacker/new-evil", path="b.js")
    client = FakeClient({"webhook-id-123": [shared], "evil.example.com": [shared2]})
    hits = search_iocs(client, ["webhook-id-123", "evil.example.com"], known=set())
    assert len(hits) == 1
    hit = hits[0]
    assert hit.matched_iocs == ["webhook-id-123", "evil.example.com"]
    assert len(hit.paths) == 2  # both files recorded


def test_one_failing_ioc_does_not_abort():
    class Boom(FakeClient):
        def search_code(self, query, per_page=20):
            if query == "bad":
                raise RuntimeError("rate limited")
            return super().search_code(query, per_page)

    client = Boom({"good.example": [_item("attacker/x")]})
    hits = search_iocs(client, ["bad", "good.example"], known=set())
    assert {h.full_name for h in hits} == {"attacker/x"}


def test_classify_defensive_by_name():
    hit = RepoHit("ossf/malicious-packages", "ossf", "", paths=["data/x.js"])
    assert classify_hit(hit) == "defensive"  # name wins despite a .js match


def test_classify_suspicious_when_used_in_source():
    hit = RepoHit("attacker/aguara", "attacker", "", paths=["src/index.js"])
    assert classify_hit(hit) == "suspicious"


def test_classify_defensive_when_only_in_data_files():
    hit = RepoHit("someone/notes", "someone", "", paths=["iocs.txt", "README.md"])
    assert classify_hit(hit) == "defensive"
