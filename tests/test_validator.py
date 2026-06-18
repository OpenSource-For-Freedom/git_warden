"""Tests for the corroboration validator (PRD section 11)."""

from __future__ import annotations

import pytest
from conftest import utcnow

from git_warden.db import Database
from git_warden.enums import ActorCategory, ActorStatus, FeedSource
from git_warden.models import SourceObservation, ThreatActor
from git_warden.validator import validate_actors


@pytest.fixture
def db(tmp_path):
    database = Database.open(tmp_path / "v.sqlite")
    database.start_run("run-1", utcnow())
    yield database
    database.close()


def _seen_by(db: Database, actor_key: str, source: FeedSource) -> None:
    db.ensure_actor(actor_key, actor_key.upper(), ActorCategory.APT.value, "run-1")
    obs = SourceObservation(
        run_id="run-1", source=source, observed_at=utcnow(), actor_name=actor_key.upper()
    )
    obs_id = db.record_observation(obs)
    db.link_actor_source(actor_key, source.value, obs_id)


def test_single_source_is_quarantined(db):
    _seen_by(db, "apt-x", FeedSource.GOOGLE_RSS)
    result = validate_actors(db, ["apt-x"])
    assert result["apt-x"] is ActorStatus.QUARANTINED
    assert db.get_actor("apt-x")["status"] == ActorStatus.QUARANTINED.value


def test_two_independent_sources_promote(db):
    _seen_by(db, "apt-x", FeedSource.GOOGLE_RSS)
    _seen_by(db, "apt-x", FeedSource.FBI_CISA)
    result = validate_actors(db, ["apt-x"])
    assert result["apt-x"] is ActorStatus.PROMOTED


def test_same_source_twice_does_not_promote(db):
    _seen_by(db, "apt-x", FeedSource.GOOGLE_RSS)
    _seen_by(db, "apt-x", FeedSource.GOOGLE_RSS)
    result = validate_actors(db, ["apt-x"])
    assert result["apt-x"] is ActorStatus.QUARANTINED


def test_rejected_is_sticky(db):
    _seen_by(db, "apt-x", FeedSource.GOOGLE_RSS)
    _seen_by(db, "apt-x", FeedSource.FBI_CISA)
    db.upsert_actor(
        ThreatActor(actor_key="apt-x", canonical_name="APT-X", status=ActorStatus.REJECTED)
    )
    # Even with two corroborating sources, a manual rejection is not revived.
    result = validate_actors(db, ["apt-x"])
    assert result["apt-x"] is ActorStatus.REJECTED
    assert db.get_actor("apt-x")["status"] == ActorStatus.REJECTED.value
