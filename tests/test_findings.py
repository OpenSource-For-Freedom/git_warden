"""Tests for the malicious-repo registry (the product)."""

from __future__ import annotations

import pytest
from conftest import utcnow

from git_warden.db import Database
from git_warden.enums import DetectionMethod, RepoFindingStatus
from git_warden.models import RepoFinding


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
