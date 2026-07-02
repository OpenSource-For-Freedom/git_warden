"""Offline tests for the Hacker News / Google News discovery pivot (fixtures,
no network)."""

from __future__ import annotations

import json

from conftest import FakeHttpClient

from git_warden.scanning.newsdiscovery import (
    extract_repo_mentions,
    search_google_news,
    search_hackernews,
)

HN_FIXTURE = json.dumps({
    "hits": [
        {
            "title": "Malicious npm package steals AWS credentials",
            "url": "https://blog.example.com/evil-pkg-writeup",
            "story_text": "The payload lives at https://github.com/attacker-corp/evil-pkg "
                           "and exfiltrates via a Discord webhook.",
            "objectID": "12345",
        },
        {
            "title": "Ask HN: best static site generators?",
            "url": "https://example.com/unrelated",
            "story_text": "",
            "objectID": "99999",
        },
    ],
})

RSS_FIXTURE = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <item>
    <title>Supply chain attack traced to github.com/badactor/malware-repo</title>
    <link>https://news.example.com/supply-chain</link>
    <pubDate>Wed, 18 Jun 2026 10:00:00 GMT</pubDate>
    <description>Researchers found the dropper in the repo's install script.</description>
  </item>
</channel></rss>
"""


def test_extract_repo_mentions_pulls_clean_slugs():
    text = (
        "See https://github.com/owner-name/repo-name.git and also "
        "github.com/Other/Thing/issues/4 for the report."
    )
    assert extract_repo_mentions(text) == {"owner-name/repo-name", "Other/Thing"}


def test_extract_repo_mentions_ignores_non_repo_text():
    assert extract_repo_mentions("just a normal sentence about malware") == set()


def test_search_hackernews_extracts_repo_and_skips_unrelated_hit():
    http = FakeHttpClient(HN_FIXTURE)
    hits = search_hackernews(["npm supply chain attack"], http=http, hits_per_term=20)
    assert len(hits) == 1
    assert hits[0].full_name == "attacker-corp/evil-pkg"
    assert hits[0].source_title == "Malicious npm package steals AWS credentials"


def test_search_hackernews_respects_known_filter():
    http = FakeHttpClient(HN_FIXTURE)
    hits = search_hackernews(["npm supply chain attack"], http=http,
                             known={"attacker-corp/evil-pkg"})
    assert hits == []


def test_search_google_news_extracts_repo_mention():
    http = FakeHttpClient(RSS_FIXTURE)
    hits = search_google_news(["supply chain malware github"], http=http)
    assert len(hits) == 1
    assert hits[0].full_name == "badactor/malware-repo"
    assert hits[0].source_url == "https://news.example.com/supply-chain"


def test_search_hackernews_failed_request_does_not_raise():
    class BoomHttp:
        def get_text(self, url, *, params=None, headers=None):
            raise RuntimeError("network down")

    assert search_hackernews(["term"], http=BoomHttp()) == []
