"""Offline tests for the MITRE ATT&CK adapter (fixture bundle, no network)."""

from __future__ import annotations

import json

from conftest import FakeHttpClient

from git_warden.enums import ActorCategory, FeedSource, IdentifierType
from git_warden.feeds.mitre import MitreAttackFeed, parse_attack_groups
from git_warden.models import SeedActor

BUNDLE = {
    "objects": [
        {
            "type": "intrusion-set",
            "name": "Lazarus Group",
            "aliases": ["Lazarus Group", "HIDDEN COBRA", "ZINC", "Labyrinth Chollima"],
            "external_references": [
                {"source_name": "mitre-attack", "url": "https://attack.mitre.org/groups/G0032"}
            ],
            "description": "DPRK state-sponsored group.",
        },
        {
            "type": "intrusion-set",
            "name": "APT1",
            "aliases": ["APT1", "Comment Crew"],
            "external_references": [
                {"source_name": "mitre-attack", "url": "https://attack.mitre.org/groups/G0006"}
            ],
        },
        {
            "type": "intrusion-set",
            "name": "Deprecated Group",
            "aliases": ["Deprecated Group"],
            "x_mitre_deprecated": True,
        },
        {"type": "malware", "name": "Not a group"},
    ]
}


def test_parse_skips_non_groups_and_deprecated():
    groups = parse_attack_groups(BUNDLE)
    names = {g.name for g in groups}
    assert names == {"Lazarus Group", "APT1"}
    lazarus = next(g for g in groups if g.name == "Lazarus Group")
    assert lazarus.url == "https://attack.mitre.org/groups/G0032"


def test_feed_matches_seed_and_enriches_aliases(tmp_path):
    seed = SeedActor(
        name="Lazarus Group", category=ActorCategory.NATION_STATE, aliases=["Hidden Cobra"]
    )
    http = FakeHttpClient(json.dumps(BUNDLE))
    feed = MitreAttackFeed(http=http, cache_path=tmp_path / "m.json")

    observations = feed.collect("run-1", [seed])

    assert len(observations) == 1
    obs = observations[0]
    assert obs.source is FeedSource.MITRE_ATTACK
    assert obs.actor_key == "lazarus group"
    assert str(obs.url) == "https://attack.mitre.org/groups/G0032"
    # Aliases enriched as ALIAS identifiers, excluding the seed's own name.
    alias_values = {i.value for i in obs.identifiers if i.identifier_type is IdentifierType.ALIAS}
    assert "HIDDEN COBRA" in alias_values
    assert "Lazarus Group" not in alias_values


def test_feed_no_match_for_unknown_actor(tmp_path):
    seed = SeedActor(name="Totally Unknown Crew")
    http = FakeHttpClient(json.dumps(BUNDLE))
    feed = MitreAttackFeed(http=http, cache_path=tmp_path / "m.json")
    assert feed.collect("run-1", [seed]) == []


def test_cache_is_written_then_reused(tmp_path):
    seed = SeedActor(name="APT1")
    http = FakeHttpClient(json.dumps(BUNDLE))
    cache = tmp_path / "m.json"

    MitreAttackFeed(http=http, cache_path=cache, max_age_days=7).collect("run-1", [seed])
    assert cache.exists()
    assert len(http.calls) == 1

    # A fresh feed instance against the same fresh cache must not re-download.
    MitreAttackFeed(http=http, cache_path=cache, max_age_days=7).collect("run-1", [seed])
    assert len(http.calls) == 1
