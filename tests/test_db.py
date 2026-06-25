"""Tests for the SQLite ingestion store."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from git_warden.db import Database
from git_warden.enums import (
    ActorCategory,
    ActorStatus,
    FeedSource,
    IdentifierType,
    Platform,
    RunStatus,
)
from git_warden.models import ActorIdentifier, Campaign, SourceObservation, ThreatActor


def _now() -> datetime:
    return datetime(2026, 6, 18, tzinfo=UTC)


@pytest.fixture
def db(tmp_path):
    database = Database.open(tmp_path / "test.sqlite")
    yield database
    database.close()


def _observation(source: FeedSource, run_id: str = "run-1") -> SourceObservation:
    return SourceObservation(
        run_id=run_id,
        source=source,
        observed_at=_now(),
        actor_name="APT-X",
        category=ActorCategory.APT,
        identifiers=[
            ActorIdentifier(
                identifier_type=IdentifierType.USERNAME,
                value="apt-x-dev",
                platform=Platform.GITHUB,
            )
        ],
        campaigns=[Campaign(name="GridStorm", targets=["power grid"])],
        raw_payload={"headline": "APT-X targets utilities"},
    )


def test_init_is_idempotent(tmp_path):
    path = tmp_path / "x.sqlite"
    Database.open(path).close()
    Database.open(path).close()  # second open must not raise


def test_record_observation_returns_rowid(db):
    db.start_run("run-1", _now())
    obs = _observation(FeedSource.GOOGLE_RSS)
    rowid = db.record_observation(obs)
    assert rowid >= 1


def test_corroboration_counts_distinct_feeds_only(db):
    db.start_run("run-1", _now())
    actor = ThreatActor(actor_key="apt-x", canonical_name="APT-X", category=ActorCategory.APT)
    db.upsert_actor(actor)

    # Two sightings from the SAME feed must count as one corroborating source.
    id1 = db.record_observation(_observation(FeedSource.GOOGLE_RSS))
    db.link_actor_source("apt-x", FeedSource.GOOGLE_RSS.value, id1)
    id2 = db.record_observation(_observation(FeedSource.GOOGLE_RSS))
    db.link_actor_source("apt-x", FeedSource.GOOGLE_RSS.value, id2)
    assert db.corroborating_source_count("apt-x") == 1

    # A second, independent feed makes it two.
    id3 = db.record_observation(_observation(FeedSource.NVD))
    db.link_actor_source("apt-x", FeedSource.NVD.value, id3)
    assert db.corroborating_source_count("apt-x") == 2


def test_prune_observations_keeps_recent_and_preserves_corroboration(db):
    # Observations are disposable audit data; pruning old ones must NOT touch the
    # corroboration ledger (actor_sources) and must reclaim space.
    old, new = "run-20260101T000000Z", "run-20260601T000000Z"
    db.start_run(old, _now())
    db.start_run(new, _now())
    db.upsert_actor(ThreatActor(actor_key="apt-x", canonical_name="APT-X",
                                category=ActorCategory.APT))
    oid = db.record_observation(_observation(FeedSource.GOOGLE_RSS, run_id=old))
    db.link_actor_source("apt-x", FeedSource.GOOGLE_RSS.value, oid)  # first_obs -> oid
    nid = db.record_observation(_observation(FeedSource.NVD, run_id=new))
    db.link_actor_source("apt-x", FeedSource.NVD.value, nid)
    assert db.corroborating_source_count("apt-x") == 2

    deleted = db.prune_observations(keep_recent_runs=1)
    db.vacuum()

    assert deleted == 1
    runs_left = {r["run_id"] for r in db.conn.execute(
        "SELECT DISTINCT run_id FROM source_observations").fetchall()}
    assert runs_left == {new}                              # only the recent run kept
    assert db.corroborating_source_count("apt-x") == 2     # corroboration intact
    fobs = {r[0] for r in db.conn.execute(
        "SELECT first_observation_id FROM actor_sources WHERE actor_key='apt-x'").fetchall()}
    assert fobs == {None, nid}                             # dangling pointer nulled


def test_upsert_actor_updates_status(db):
    db.start_run("run-1", _now())
    db.upsert_actor(ThreatActor(actor_key="apt-x", canonical_name="APT-X"))
    db.upsert_actor(
        ThreatActor(actor_key="apt-x", canonical_name="APT-X", status=ActorStatus.PROMOTED)
    )
    row = db.get_actor("apt-x")
    assert row["status"] == ActorStatus.PROMOTED.value


def test_identifiers_and_campaigns_dedup(db):
    db.start_run("run-1", _now())
    db.upsert_actor(ThreatActor(actor_key="apt-x", canonical_name="APT-X"))
    ident = ActorIdentifier(
        identifier_type=IdentifierType.USERNAME, value="apt-x-dev", platform=Platform.GITHUB
    )
    db.add_identifier("apt-x", ident)
    db.add_identifier("apt-x", ident)  # duplicate ignored
    rows = db.conn.execute(
        "SELECT COUNT(*) AS n FROM actor_identifiers WHERE actor_key = ?", ("apt-x",)
    ).fetchone()
    assert rows["n"] == 1

    camp = Campaign(name="GridStorm", targets=["power grid"])
    db.add_campaign("apt-x", camp)
    db.add_campaign("apt-x", camp)  # duplicate link ignored
    rows = db.conn.execute("SELECT COUNT(*) AS n FROM actor_campaigns").fetchone()
    assert rows["n"] == 1


def test_finish_run_records_status_and_counts(db):
    db.start_run("run-1", _now())
    db.finish_run("run-1", _now(), RunStatus.COMPLETED, counts={"observations": 3})
    row = db.conn.execute("SELECT * FROM runs WHERE run_id = ?", ("run-1",)).fetchone()
    assert row["status"] == RunStatus.COMPLETED.value
    assert '"observations": 3' in row["counts"]
