"""Tests for the ingestion data contract."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from git_warden.enums import ActorCategory, FeedSource, IdentifierType, Platform
from git_warden.models import ActorIdentifier, SourceObservation, ThreatActor


def _now() -> datetime:
    return datetime(2026, 6, 18, tzinfo=UTC)


def test_actor_key_normalizes_case_and_whitespace():
    obs = SourceObservation(
        run_id="r1",
        source=FeedSource.GOOGLE_RSS,
        observed_at=_now(),
        actor_name="  Shai-Hulud   Cluster ",
    )
    assert obs.actor_key == "shai-hulud cluster"


def test_identifier_rejects_blank_value():
    with pytest.raises(ValidationError):
        ActorIdentifier(identifier_type=IdentifierType.USERNAME, value="   ")


def test_identifier_strips_value():
    ident = ActorIdentifier(
        identifier_type=IdentifierType.ORGANIZATION,
        value="  evil-org  ",
        platform=Platform.GITHUB,
    )
    assert ident.value == "evil-org"


def test_threat_actor_rejects_unnormalized_key():
    with pytest.raises(ValidationError):
        ThreatActor(actor_key="NotNormalized", canonical_name="NotNormalized")


def test_corroboration_count_tracks_distinct_sources():
    actor = ThreatActor(
        actor_key="apt-x",
        canonical_name="APT-X",
        category=ActorCategory.APT,
        corroborating_sources={FeedSource.NVD, FeedSource.FBI_CISA, FeedSource.NVD},
    )
    assert actor.corroboration_count == 2
