"""Safety tests for unattended OSM submission."""

from __future__ import annotations

import pytest

from git_warden import osm_automation as auto


class _Response:
    def __init__(self, status_code: int, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.content = b"{}"

    def json(self):
        return self._payload


def test_resource_key_normalizes_repo_variants():
    assert auto._resource_key("https://github.com/Owner/Repo/") == "owner/repo"
    assert auto._resource_key("github.com/owner/repo?x=1") == "owner/repo"


def test_full_history_precheck_fails_closed_on_http_error(monkeypatch):
    monkeypatch.setattr(auto.config, "OSM_API_KEY", "osm_test")
    monkeypatch.setattr(
        auto.requests,
        "get",
        lambda *a, **k: _Response(503),
    )
    with pytest.raises(auto.OSMPrecheckError):
        auto._search_full_history("https://github.com/evil/dropper")


def test_existing_repo_matches_any_canonical_spelling(monkeypatch):
    monkeypatch.setattr(
        auto,
        "_search_full_history",
        lambda term: (
            [{"resource_identifier": "https://github.com/Evil/Dropper/", "id": "t1"}]
            if term.endswith("evil/dropper/")
            else []
        ),
    )
    hit = auto._existing_repo("evil/dropper")
    assert hit and hit["id"] == "t1"

def test_versioned_policy_keeps_all_fail_closed_guards():
    policy = auto.load_policy()
    assert policy["fail_closed"] is True
    assert policy["required_confidence"] == "auto"
    assert policy["require_docker_sandbox"] is True
    assert policy["require_positive_liveness"] is True
    assert policy["osm_full_history_prechecks"] >= 2
    assert policy["require_shared_intel_dedup"] is True
    assert policy["submit_domains"] is False
    assert policy["pace_seconds"] >= 6


def test_policy_rejects_weakened_precheck_count():
    policy = auto.load_policy().copy()
    policy["osm_full_history_prechecks"] = 1
    with pytest.raises(RuntimeError):
        auto._validate_policy(policy)


def test_policy_rejects_unattended_domain_submission():
    policy = auto.load_policy().copy()
    policy["submit_domains"] = True
    with pytest.raises(RuntimeError):
        auto._validate_policy(policy)

def test_policy_rejects_disabled_shared_intel_dedup():
    policy = auto.load_policy().copy()
    policy["require_shared_intel_dedup"] = False
    with pytest.raises(RuntimeError):
        auto._validate_policy(policy)


def test_second_osm_precheck_closes_race_before_post(monkeypatch):
    row = {"full_name": "evil/dropper"}
    policy = auto.load_policy().copy()
    checks = iter([None, {"id": "race", "status": "pending"}])

    monkeypatch.setattr(auto, "load_policy", lambda: policy)
    monkeypatch.setattr(auto, "gold_for_submission", lambda db, limit=0: [row])
    monkeypatch.setattr(auto.bus, "is_submitted", lambda kind, value: False)
    monkeypatch.setattr(auto, "_existing_repo", lambda name: next(checks))
    monkeypatch.setattr(auto, "_deep_validate", lambda name: (True, "AUTO"))
    monkeypatch.setattr(auto, "repo_payload_live", lambda finding: True)
    monkeypatch.setattr(auto, "submit_threat", lambda report: pytest.fail("must not POST"))

    sent = auto.run(object(), limit=1, pace=0)
    assert sent == 0
