"""Offline tests for feed parsing and attribution (fixtures, no network)."""

from __future__ import annotations

from conftest import FakeHttpClient

from git_warden.enums import ActorCategory, FeedSource
from git_warden.feeds.rss import CisaAdvisoriesFeed, GoogleNewsFeed, parse_feed
from git_warden.models import SeedActor

RSS_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <item>
    <title>Lazarus Group linked to bank intrusions</title>
    <link>https://news.example.com/lazarus-banks</link>
    <pubDate>Wed, 18 Jun 2026 10:00:00 GMT</pubDate>
    <description>Hidden Cobra activity reported against financial targets.</description>
  </item>
</channel></rss>
"""

ATOM_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Advisory: APT29 targeting cloud tenants</title>
    <link href="https://cisa.example.gov/aa26-001"/>
    <updated>2026-06-18T10:00:00Z</updated>
    <summary>Cozy Bear techniques against identity providers.</summary>
  </entry>
  <entry>
    <title>Unrelated phishing advisory</title>
    <link href="https://cisa.example.gov/aa26-002"/>
    <updated>2026-06-17T10:00:00Z</updated>
    <summary>Generic credential phishing campaign.</summary>
  </entry>
</feed>
"""


def test_parse_feed_rss():
    items = parse_feed(RSS_FIXTURE)
    assert len(items) == 1
    assert items[0].title == "Lazarus Group linked to bank intrusions"
    assert items[0].link == "https://news.example.com/lazarus-banks"
    assert items[0].published is not None


def test_parse_feed_atom():
    items = parse_feed(ATOM_FIXTURE)
    assert len(items) == 2
    assert items[0].link == "https://cisa.example.gov/aa26-001"
    assert items[0].published is not None


def test_google_news_feed_attributes_to_seed():
    seed = SeedActor(
        name="Lazarus Group", category=ActorCategory.NATION_STATE, aliases=["Hidden Cobra"]
    )
    http = FakeHttpClient(RSS_FIXTURE)
    feed = GoogleNewsFeed(http=http)

    observations = feed.collect("run-1", [seed])

    # Two query terms (name + alias) -> two fetches -> two observations.
    assert len(observations) == 2
    assert all(o.source is FeedSource.GOOGLE_RSS for o in observations)
    assert all(o.actor_key == "lazarus group" for o in observations)
    assert all(o.category is ActorCategory.NATION_STATE for o in observations)
    assert len(http.calls) == 2


def test_cisa_feed_matches_only_named_seeds():
    seeds = [
        SeedActor(name="APT29", category=ActorCategory.NATION_STATE, aliases=["Cozy Bear"]),
        SeedActor(name="Sandworm Team", category=ActorCategory.NATION_STATE),
    ]
    http = FakeHttpClient(ATOM_FIXTURE)
    feed = CisaAdvisoriesFeed(http=http)

    observations = feed.collect("run-1", seeds)

    # Only the APT29 advisory matches; Sandworm and the phishing item do not.
    assert len(observations) == 1
    assert observations[0].actor_key == "apt29"
    assert observations[0].source is FeedSource.FBI_CISA
    assert http.calls[0][0] == feed.feed_url
