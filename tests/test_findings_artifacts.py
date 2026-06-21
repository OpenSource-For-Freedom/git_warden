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


def test_update_readme_registry_table_publishes_validated_only(tmp_path, db):
    # Public-safety invariant: ONLY analyst-validated findings reach the public
    # README. Machine-confirmed-but-unreviewed must never leak out.
    db.upsert_finding(_finding("good/validated", status=RepoFindingStatus.VALIDATED,
                               score=8, reasoning="malicious obfuscator"), "run-1")
    db.upsert_finding(_finding("machine/confirmed", status=RepoFindingStatus.CONFIRMED), "run-1")
    db.upsert_finding(_finding("noisy/screened", status=RepoFindingStatus.SCREENED), "run-1")
    readme = tmp_path / "README.md"
    readme.write_text(
        "# X\n\n<!-- git-warden:registry:start -->\nold\n<!-- git-warden:registry:end -->\nend\n",
        encoding="utf-8",
    )
    changed = update_readme_registry_table(db, readme_path=readme)
    assert changed is True
    out = readme.read_text(encoding="utf-8")
    assert "good/validated" in out           # analyst-approved is published
    assert "machine/confirmed" not in out    # machine-confirmed, unreviewed -> internal only
    assert "noisy/screened" not in out       # screened never public
    assert out.endswith("end\n")             # content outside the markers preserved
    assert "1 analyst-validated malicious repositories" in out


def test_update_readme_registry_table_idempotent(tmp_path, db):
    db.upsert_finding(_finding("good/confirmed", status=RepoFindingStatus.CONFIRMED), "run-1")
    readme = tmp_path / "README.md"
    readme.write_text(
        "<!-- git-warden:registry:start -->\n<!-- git-warden:registry:end -->\n",
        encoding="utf-8",
    )
    assert update_readme_registry_table(db, readme_path=readme) is True
    assert update_readme_registry_table(db, readme_path=readme) is False  # no churn


def test_update_readme_registry_table_missing_file_is_noop(tmp_path, db):
    assert update_readme_registry_table(db, readme_path=tmp_path / "nope.md") is False
