"""Tests for the per-run findings CSV and the README registry table."""

from __future__ import annotations

import pytest
from conftest import utcnow

from git_warden.artifacts import (
    update_readme_registry_table,
    write_findings_csv,
)
from git_warden.db import Database
from git_warden.enums import DetectionMethod, RepoFindingStatus
from git_warden.models import RepoFinding


@pytest.fixture
def db(tmp_path):
    database = Database.open(tmp_path / "f.sqlite")
    database.start_run("run-1", utcnow())
    yield database
    database.close()


def _finding(full_name, status=RepoFindingStatus.CANDIDATE, **kw) -> RepoFinding:
    return RepoFinding(
        full_name=full_name,
        detection_method=kw.pop("detection_method", DetectionMethod.IOC_SEARCH),
        status=status,
        **kw,
    )


def test_findings_for_run_returns_every_touched_repo(db):
    db.upsert_finding(_finding("a/confirmed", status=RepoFindingStatus.CONFIRMED), "run-1")
    db.upsert_finding(_finding("b/screened", status=RepoFindingStatus.SCREENED), "run-1")
    db.upsert_finding(_finding("c/rejected", status=RepoFindingStatus.REJECTED), "run-1")
    names = {r["full_name"] for r in db.findings_for_run("run-1")}
    assert names == {"a/confirmed", "b/screened", "c/rejected"}  # all statuses, full audit


def test_write_findings_csv_has_full_columns(tmp_path, db):
    db.upsert_finding(
        _finding("evil/repo", status=RepoFindingStatus.CONFIRMED, score=9,
                 actor_key=None, reasoning="eval(atob()) in postcss.config.js"),
        "run-1",
    )
    path = write_findings_csv(db, "run-1", artifacts_dir=tmp_path)
    assert path.name == "run-1_findings.csv"
    text = path.read_text(encoding="utf-8")
    header = text.splitlines()[0]
    for col in ("full_name", "owner", "status", "detection_method", "score",
                "novel", "attribution", "url", "first_seen_run", "last_seen_run"):
        assert col in header
    assert "evil/repo" in text and "confirmed" in text


def test_write_findings_csv_always_written_even_when_empty(tmp_path, db):
    path = write_findings_csv(db, "run-1", artifacts_dir=tmp_path)
    assert path.exists()
    assert path.read_text(encoding="utf-8").splitlines()[0].startswith("full_name,")


def _readme(tmp_path):
    p = tmp_path / "README.md"
    p.write_text(
        "# X\n\n<!-- git-warden:registry:start -->\nold\n<!-- git-warden:registry:end -->\nend\n",
        encoding="utf-8",
    )
    return p


def test_readme_lists_confirmed_repos(tmp_path, db):
    # Every confirmed repo is posted each run; screened/rejected never appear.
    db.upsert_finding(_finding("evil/repo", status=RepoFindingStatus.CONFIRMED,
                               score=8, reasoning="eval(atob()) in postcss.config.js"), "run-1")
    db.upsert_finding(_finding("noisy/screened", status=RepoFindingStatus.SCREENED), "run-1")
    db.upsert_finding(_finding("clean/rejected", status=RepoFindingStatus.REJECTED), "run-1")

    readme = _readme(tmp_path)
    assert update_readme_registry_table(db, readme_path=readme) is True
    out = readme.read_text(encoding="utf-8")
    assert "evil/repo" in out                 # confirmed -> posted
    assert "noisy/screened" not in out        # screened -> not posted
    assert "clean/rejected" not in out        # rejected (false positive) -> dropped
    assert out.endswith("end\n")              # content outside the markers preserved
    assert "1 repositories confirmed malicious" in out


def test_readme_empty_when_no_confirmed(tmp_path, db):
    readme = _readme(tmp_path)
    assert update_readme_registry_table(db, readme_path=readme) is True
    out = readme.read_text(encoding="utf-8")
    assert "_none yet_" in out
    assert "0 repositories confirmed malicious" in out


def test_redteam_lineage_never_published_or_gold(tmp_path, db):
    # A cloned/forked red-team tool is a breadcrumb, never compromise provenance:
    # excluded from the Wall of Shame AND the gold feed even when confirmed.
    db.upsert_finding(_finding("evil/sliver-fork", status=RepoFindingStatus.CONFIRMED,
                               detection_method=DetectionMethod.REDTEAM_LINEAGE,
                               score=99, reasoning="fork of pinned red-team tool Sliver"), "run-1")
    db.upsert_finding(_finding("attacker/dropper", status=RepoFindingStatus.CONFIRMED,
                               score=8, reasoning="references confirmed IOC"), "run-1")

    assert {r["full_name"] for r in db.published_findings()} == {"attacker/dropper"}
    assert all(r["full_name"] != "evil/sliver-fork" for r in db.undelivered_gold())

    readme = _readme(tmp_path)
    update_readme_registry_table(db, readme_path=readme)
    out = readme.read_text(encoding="utf-8")
    assert "evil/sliver-fork" not in out      # red-team clone kept off the wall
    assert "attacker/dropper" in out


def test_readme_why_shows_proven_evidence_not_association(tmp_path, db):
    # The "Why" leads with the PROVEN confirming signature (file:line + rule),
    # not the discovery breadcrumb (the IOC/association reasoning text).
    f = _finding("attacker/dropper", status=RepoFindingStatus.CONFIRMED, score=8,
                 detection_method=DetectionMethod.IOC_SEARCH,
                 reasoning="Code references OSM IOC(s) ['evil.tld'] in ['x.py']")
    f.raw_payload = {"bash_findings": [
        {"file": "setup.py", "line": 42, "category": "exfiltration", "rule": "secret-exfil"}]}
    db.upsert_finding(f, "run-1")

    readme = _readme(tmp_path)
    update_readme_registry_table(db, readme_path=readme)
    out = readme.read_text(encoding="utf-8")
    assert "setup.py:42 exfiltration/secret-exfil" in out   # proof is the headline
    assert "references OSM IOC" not in out                  # discovery breadcrumb is NOT


def test_readme_caps_to_top_ten_most_dangerous(tmp_path, db):
    # Public wall shows only the 10 highest-severity confirmed repos; the rest
    # live in the CSV artifact + Discord, not the README.
    for i in range(15):
        db.upsert_finding(
            _finding(f"evil/repo{i:02d}", status=RepoFindingStatus.CONFIRMED, score=i),
            "run-1")
    readme = _readme(tmp_path)
    assert update_readme_registry_table(db, readme_path=readme) is True
    out = readme.read_text(encoding="utf-8")

    body = out.split("registry:start -->")[1].split("registry:end")[0]
    assert body.count("](https://github.com/evil/repo") == 10  # exactly 10 rows
    assert "Top 10 of 15 repositories confirmed malicious" in out
    assert "evil/repo14" in out and "evil/repo05" in out  # highest scores kept
    assert "evil/repo04" not in out and "evil/repo00" not in out  # lowest dropped


def test_update_readme_idempotent(tmp_path, db):
    db.upsert_finding(_finding("evil/repo", status=RepoFindingStatus.CONFIRMED), "run-1")
    readme = _readme(tmp_path)
    assert update_readme_registry_table(db, readme_path=readme) is True
    assert update_readme_registry_table(db, readme_path=readme) is False  # no churn


def test_update_readme_missing_file_is_noop(tmp_path, db):
    assert update_readme_registry_table(db, readme_path=tmp_path / "nope.md") is False
