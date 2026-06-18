"""RSS/Atom feed adapters.

``parse_feed`` is a pure function (no network) so it can be unit-tested against
fixture XML. It handles both RSS ``<item>`` and Atom ``<entry>`` shapes since
public threat feeds use both.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from bs4 import BeautifulSoup

from ..config import CISA_FEED_URL, GOOGLE_NEWS_RSS_URL
from ..enums import FeedSource
from ..models import SeedActor, SourceObservation
from .base import Feed

log = logging.getLogger(__name__)


@dataclass
class FeedItem:
    """A single normalized entry from an RSS/Atom feed."""

    title: str
    link: str | None
    summary: str
    published: datetime | None
    raw: dict = field(default_factory=dict)


def _text(node) -> str:
    return node.get_text(strip=True) if node is not None else ""


def _parse_date(value: str | None) -> datetime | None:
    """Parse RFC-822 (RSS) or ISO-8601 (Atom) dates; None if unparseable."""
    if not value:
        return None
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError):
        pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_feed(xml: str) -> list[FeedItem]:
    """Parse RSS items or Atom entries into FeedItem records."""
    soup = BeautifulSoup(xml, "xml")
    items: list[FeedItem] = []

    for node in soup.find_all("item"):  # RSS
        link = _text(node.find("link")) or None
        items.append(
            FeedItem(
                title=_text(node.find("title")),
                link=link,
                summary=_text(node.find("description")),
                published=_parse_date(_text(node.find("pubDate")) or None),
                raw={"format": "rss"},
            )
        )

    for node in soup.find_all("entry"):  # Atom
        link_node = node.find("link")
        link = (link_node.get("href") if link_node else None) or None
        date_text = _text(node.find("updated")) or _text(node.find("published")) or None
        published = _parse_date(date_text)
        items.append(
            FeedItem(
                title=_text(node.find("title")),
                link=link,
                summary=_text(node.find("summary")) or _text(node.find("content")),
                published=published,
                raw={"format": "atom"},
            )
        )

    return items


def _now() -> datetime:
    return datetime.now(UTC)


def _observation(
    run_id: str,
    source: FeedSource,
    seed: SeedActor,
    item: FeedItem,
) -> SourceObservation:
    """Build an observation attributing a feed item to a seed actor."""
    return SourceObservation(
        run_id=run_id,
        source=source,
        observed_at=item.published or _now(),
        actor_name=seed.name,
        category=seed.category,
        source_record_id=item.link or item.title or None,
        url=item.link,
        identifiers=list(seed.identifiers),
        raw_payload={
            "title": item.title,
            "summary": item.summary,
            "link": item.link,
            "published": item.published.isoformat() if item.published else None,
            **item.raw,
        },
    )


class GoogleNewsFeed(Feed):
    """Query-per-actor: search Google News RSS for each seed term."""

    source = FeedSource.GOOGLE_RSS

    def __init__(self, http=None, search_url: str = GOOGLE_NEWS_RSS_URL) -> None:
        super().__init__(http)
        self.search_url = search_url

    def collect(self, run_id: str, seeds: list[SeedActor]) -> list[SourceObservation]:
        observations: list[SourceObservation] = []
        for seed in seeds:
            for term in seed.query_terms():
                params = {
                    "q": f'"{term}"',
                    "hl": "en-US",
                    "gl": "US",
                    "ceid": "US:en",
                }
                xml = self.http.get_text(self.search_url, params=params)
                for item in parse_feed(xml):
                    observations.append(
                        _observation(run_id, self.source, seed, item)
                    )
        return observations


class CisaAdvisoriesFeed(Feed):
    """Bulk-pull-and-match: fetch CISA advisories once, match seed names."""

    source = FeedSource.FBI_CISA

    def __init__(self, http=None, feed_url: str = CISA_FEED_URL) -> None:
        super().__init__(http)
        self.feed_url = feed_url

    def collect(self, run_id: str, seeds: list[SeedActor]) -> list[SourceObservation]:
        xml = self.http.get_text(self.feed_url)
        items = parse_feed(xml)
        # Pre-lower each seed's terms once for cheap substring matching.
        seed_terms = [(seed, [t.casefold() for t in seed.query_terms()]) for seed in seeds]

        observations: list[SourceObservation] = []
        for item in items:
            haystack = f"{item.title} {item.summary}".casefold()
            for seed, terms in seed_terms:
                if any(term in haystack for term in terms):
                    observations.append(_observation(run_id, self.source, seed, item))
        return observations
