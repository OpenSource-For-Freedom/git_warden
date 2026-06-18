"""Tests for malicious-artifact persistence (OSM destination / scan list)."""

from __future__ import annotations

import pytest
from conftest import utcnow

from git_warden.db import Database
from git_warden.enums import ActorCategory, ArtifactStatus, ArtifactType, FeedSource
from git_warden.models import MaliciousArtifact, ThreatActor


@pytest.fixture
def db(tmp_path):
    database = Database.open(tmp_path / "art.sqlite")
    database.start_run("run-1", utcnow())
    yield database
    database.close()


def _artifact(name: str, ecosystem: str = "npm", actor_key: str | None = None) -> MaliciousArtifact:
    return MaliciousArtifact(
        artifact_type=ArtifactType.PACKAGE,
        name=name,
        ecosystem=ecosystem,
        source=FeedSource.OPEN_SOURCE_MALWARE,
        actor_key=actor_key,
        raw_payload={"verdict": "malicious"},
    )


def test_upsert_artifact_inserts_and_dedups(db):
    id1 = db.upsert_artifact(_artifact("evil-pkg"), "run-1")
    id2 = db.upsert_artifact(_artifact("evil-pkg"), "run-1")  # same (type, ecosystem, name)
    assert id1 == id2
    rows = db.conn.execute("SELECT COUNT(*) AS n FROM malicious_artifacts").fetchone()
    assert rows["n"] == 1


def test_upsert_artifact_distinguishes_ecosystem(db):
    db.upsert_artifact(_artifact("shared-name", ecosystem="npm"), "run-1")
    db.upsert_artifact(_artifact("shared-name", ecosystem="pypi"), "run-1")
    rows = db.conn.execute("SELECT COUNT(*) AS n FROM malicious_artifacts").fetchone()
    assert rows["n"] == 2


def test_artifact_links_to_actor(db):
    db.ensure_actor("lazarus group", "Lazarus Group", ActorCategory.NATION_STATE.value, "run-1")
    art_id = db.upsert_artifact(_artifact("evil-pkg", actor_key="lazarus group"), "run-1")
    row = db.conn.execute(
        "SELECT actor_key, status FROM malicious_artifacts WHERE id = ?", (art_id,)
    ).fetchone()
    assert row["actor_key"] == "lazarus group"
    assert row["status"] == ArtifactStatus.LABELED.value


def test_upsert_backfills_actor_without_clobbering(db):
    db.ensure_actor("lazarus group", "Lazarus Group", ActorCategory.NATION_STATE.value, "run-1")
    # First seen with no attribution, later seen WITH an actor -> backfilled.
    db.upsert_artifact(_artifact("evil-pkg"), "run-1")
    db.upsert_artifact(_artifact("evil-pkg", actor_key="lazarus group"), "run-1")
    row = db.conn.execute(
        "SELECT actor_key FROM malicious_artifacts WHERE name = ?", ("evil-pkg",)
    ).fetchone()
    assert row["actor_key"] == "lazarus group"


def test_threat_actor_model_still_constructs():
    # Guard: the new imports didn't disturb the actor contract.
    actor = ThreatActor(actor_key="apt-x", canonical_name="APT-X")
    assert actor.corroboration_count == 0
