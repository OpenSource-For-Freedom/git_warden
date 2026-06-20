"""Tests for the malicious-repo registry (the product)."""

from __future__ import annotations

import pytest
from conftest import utcnow

from git_warden.db import Database
from git_warden.enums import (
    ArtifactType,
    DetectionMethod,
    FeedSource,
    Platform,
    RepoFindingStatus,
)
from git_warden.models import MaliciousArtifact, RepoFinding


@pytest.fixture
def db(tmp_path):
    database = Database.open(tmp_path / "f.sqlite")
    database.start_run("run-1", utcnow())
    yield database
    database.close()


def _finding(full_name="evil/repo", status=RepoFindingStatus.CANDIDATE, **kw) -> RepoFinding:
    return RepoFinding(
        full_name=full_name,
        detection_method=DetectionMethod.IOC_SEARCH,
        status=status,
        **kw,
    )


def test_full_name_normalized():
    assert _finding(full_name="Evil/Repo/").full_name == "evil/repo"


def test_upsert_and_dedup(db):
    db.upsert_finding(_finding(score=4), "run-1")
    db.upsert_finding(_finding(score=7, status=RepoFindingStatus.CONFIRMED), "run-1")
    rows = db.findings_by_status("confirmed")
    assert len(rows) == 1
    assert rows[0]["score"] == 7


def test_rejected_is_sticky(db):
    db.upsert_finding(_finding(status=RepoFindingStatus.REJECTED), "run-1")
    db.upsert_finding(_finding(status=RepoFindingStatus.CONFIRMED), "run-1")
    assert not db.findings_by_status("confirmed")
    assert len(db.findings_by_status("rejected")) == 1


def test_gold_delivery_queue(db):
    db.upsert_finding(_finding(status=RepoFindingStatus.CONFIRMED), "run-1")
    assert len(db.undelivered_gold()) == 1
    db.mark_gold_delivered("evil/repo")
    assert not db.undelivered_gold()


def test_actor_attribution_not_cleared_on_reupsert(db):
    db.ensure_actor("apt-x", "APT-X", "apt", "run-1")
    db.upsert_finding(_finding(actor_key="apt-x"), "run-1")
    db.upsert_finding(_finding(actor_key=None), "run-1")  # later sighting lacks attribution
    row = db.findings_by_status("candidate")[0]
    assert row["actor_key"] == "apt-x"


def test_cross_platform_clusters_group_by_code_hash(db):
    # eval #6 / doc 04 6: same code hash across platforms = one tracked entity.
    db.upsert_finding(_finding("gh/evil", status=RepoFindingStatus.CONFIRMED,
                               platform=Platform.GITHUB, code_hash="abc"), "run-1")
    db.upsert_finding(_finding("gl/evil", status=RepoFindingStatus.CONFIRMED,
                               platform=Platform.GITLAB, code_hash="abc"), "run-1")
    db.upsert_finding(_finding("x/solo", status=RepoFindingStatus.CONFIRMED,
                               code_hash="zzz"), "run-1")
    clusters = db.cross_platform_clusters()
    assert set(clusters["abc"][0].keys()) == {"platform", "full_name", "url"}
    assert len(clusters["abc"]) == 2
    assert "zzz" not in clusters  # single location is not a cross-platform cluster


def test_known_repo_names_unions_artifacts_and_findings(db):
    db.upsert_artifact(MaliciousArtifact(
        artifact_type=ArtifactType.REPO, name="evil/repo", ecosystem="github",
        source=FeedSource.OPEN_SOURCE_MALWARE,
        raw_payload={"resource_identifier": "https://github.com/evil/repo"}), "run-1")
    db.upsert_finding(_finding("other/found"), "run-1")
    known = db.known_repo_names()
    assert "evil/repo" in known       # from OSM artifact
    assert "other/found" in known     # from prior finding


def test_open_migrates_legacy_repo_findings(tmp_path):
    # A pre-cross-platform store (no platform/code_hash) must migrate on open,
    # not crash on the code_hash index (regression guard for the readiness bug).
    import sqlite3
    path = tmp_path / "legacy.sqlite"
    raw = sqlite3.connect(path)
    # The real v1 repo_findings schema -- everything except platform/code_hash.
    raw.executescript(
        """
        CREATE TABLE runs (run_id TEXT PRIMARY KEY);
        CREATE TABLE repo_findings (
            full_name TEXT PRIMARY KEY, url TEXT, detection_method TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'candidate', score INTEGER NOT NULL DEFAULT 0,
            actor_key TEXT, reasoning TEXT, signals TEXT NOT NULL DEFAULT '[]',
            matched_iocs TEXT NOT NULL DEFAULT '[]', first_seen_run TEXT,
            last_seen_run TEXT, raw_payload TEXT NOT NULL DEFAULT '{}',
            delivered_gold INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO repo_findings (full_name, detection_method)
            VALUES ('old/repo', 'ioc_search');
        """
    )
    raw.commit()
    raw.close()

    db = Database.open(path)  # must not raise
    cols = {r[1] for r in db.conn.execute("PRAGMA table_info(repo_findings)")}
    assert "platform" in cols and "code_hash" in cols
    assert db.conn.execute("SELECT COUNT(*) FROM repo_findings").fetchone()[0] == 1
    db.close()


def test_set_finding_status_validate_and_reject(db):
    db.upsert_finding(_finding("evil/repo", status=RepoFindingStatus.CONFIRMED), "run-1")
    assert db.set_finding_status("Evil/Repo", "validated") == 1   # casefold-normalized
    assert db.findings_by_status("validated")[0]["full_name"] == "evil/repo"
    assert db.set_finding_status("missing/repo", "rejected") == 0  # no such finding
