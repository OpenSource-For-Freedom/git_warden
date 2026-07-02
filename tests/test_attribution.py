"""Tests for shared threat-actor attribution (fixtures, no network).

The core correctness property: the SAME real actor, named by two DIFFERENT
sources (OSM's tags vs. a Hacker News writeup), must resolve to the SAME
``actor_key`` so it links to one canonical ``threat_actors`` row instead of
fragmenting into per-source duplicates (the 2026-07-02 bug).
"""

from __future__ import annotations

from git_warden.attribution import (
    attribution_for_tags,
    attribution_for_text,
    load_actor_terms,
    match_actors_in_text,
)
from git_warden.models import _normalize_name


def test_specific_actor_key_matches_seed_actor_normalization():
    terms = load_actor_terms()
    attr = attribution_for_text("Researchers linked the campaign to Lazarus Group", terms)
    assert attr is not None
    assert attr.key == _normalize_name("Lazarus Group") == "lazarus group"
    assert attr.label == "Lazarus Group"


def test_same_actor_from_two_sources_yields_same_key():
    # OSM tags this "lazarus"; a news writeup names "Lazarus Group" in prose.
    # Both must resolve to the identical key -- the exact fragmentation bug.
    terms = load_actor_terms()
    from_osm = attribution_for_tags(["lazarus"])
    from_news = attribution_for_text(
        "North Korea's Lazarus Group was blamed for the intrusion", terms)
    assert from_osm is not None and from_news is not None
    assert from_osm.key == from_news.key


def test_alias_resolves_to_canonical_name():
    terms = load_actor_terms()
    attr = attribution_for_text("Attributed to Fancy Bear based on TTPs", terms)
    assert attr is not None
    assert attr.label == "APT28"          # alias resolves to the canonical name
    assert attr.key == "apt28"


def test_specific_group_wins_over_generic_nation_mention():
    terms = load_actor_terms()
    attr = attribution_for_text(
        "A North Korean group, identified as Kimsuky, ran the campaign", terms)
    assert attr is not None
    assert attr.label == "Kimsuky"        # specific group beats bare "North Korea"


def test_apt_number_not_confused_with_bare_apt():
    terms = load_actor_terms()
    names = match_actors_in_text("Confirmed as APT28 activity", terms)
    assert names == ["APT28"]


def test_no_actor_mention_returns_none():
    terms = load_actor_terms()
    assert attribution_for_text("Just a routine dependency bump", terms) is None
    assert attribution_for_tags(["unrelated-tag"]) is None
