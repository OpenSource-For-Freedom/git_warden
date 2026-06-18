"""Offline tests for IOC-driven discovery (fake code search)."""

from __future__ import annotations

from collections import Counter

from git_warden.scanning.discovery import RepoHit, build_search_terms, classify_hit, search_iocs
from git_warden.scanning.ioc import IocSet


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


def test_classify_source_use_overrides_defensive_name():
    # eval #1: a match in executable source means the IOC is USED -> suspicious,
    # even under a defensive-sounding name (attacker can't evade by naming).
    hit = RepoHit("ossf/malicious-packages", "ossf", "", paths=["src/x.js"])
    assert classify_hit(hit) == "suspicious"


def test_classify_config_use_is_suspicious():
    # eval #11: exfil endpoint in config/markup also counts as use.
    hit = RepoHit("attacker/neutral-name", "attacker", "", paths=["config.json"])
    assert classify_hit(hit) == "suspicious"


def test_classify_owner_token_does_not_force_defensive():
    # eval #1: defensive tokens in the OWNER must not veto; repo-name only.
    hit = RepoHit("security-research/evil-stealer", "security-research", "",
                  paths=["main.py"])
    assert classify_hit(hit) == "suspicious"


def test_classify_defensive_when_defensive_name_and_only_data_files():
    hit = RepoHit("ossf/malicious-packages", "ossf", "", paths=["list.txt", "README.md"])
    assert classify_hit(hit) == "defensive"


def test_build_search_terms_selects_attacker_domains_and_webhook_ids():
    iocs = IocSet(
        webhooks=Counter(["https://discord.com/api/webhooks/123456/tok"]),
        domains=Counter({"foo.workers.dev": 2, "docs.example.com": 1}),
    )
    terms = build_search_terms(iocs, 10)
    assert "foo.workers.dev" in terms       # attacker-host kept
    assert "123456" in terms                # webhook id extracted
    assert "docs.example.com" not in terms  # benign domain dropped


def test_build_search_terms_caps_at_max():
    iocs = IocSet(domains=Counter({f"h{i}.workers.dev": 10 - i for i in range(10)}))
    assert len(build_search_terms(iocs, 3)) == 3
