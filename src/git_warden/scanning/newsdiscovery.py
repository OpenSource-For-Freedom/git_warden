"""News/discussion-driven discovery: search Hacker News and Google News for
malware/supply-chain-attack write-ups, extract any GitHub repo they name, and
feed those as new candidates. Both sources are free and keyless -- HN's
Algolia search API and Google News RSS need no API key and no paid tier.

A journalist or researcher naming a specific repo as malicious is real signal,
but weaker than a code-level IOC match: the article could name a LEGITIMATE
project in passing (e.g. "the compromised package's upstream, mastra-ai/mastra,
is unaffected"). So these hits are NOT auto-escalated to Tier-2 confirmation
the way package_ref/osm_repository are (see hunt.py's ``intel`` set); they go
through ordinary Tier-1 README/name scoring first, same as a cold GitHub
search result.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass

from ..feeds.http import HttpClient, RequestsHttpClient

log = logging.getLogger(__name__)

_GITHUB_REPO_RE = re.compile(
    r"github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)/([A-Za-z0-9._-]+)", re.I
)
# Paths that follow a repo slug on github.com but are not part of it (issues,
# pulls, actions, wiki, .git suffix, ...); trimmed so the extracted full_name
# is clean.
_TRAILING_JUNK = re.compile(
    r"\.git$|/(?:issues|pull|pulls|actions|wiki|releases|tree|blob|commit|compare)$",
    re.I,
)

HN_SEARCH_URL = "https://hn.algolia.com/api/v1/search"

# Generic, source-agnostic terms; broad enough to surface fresh supply-chain
# writeups without needing per-actor scoping or an API key. Ordered so the first
# --max-news (default 6) stay high-value; the rest widen family/actor coverage.
DEFAULT_NEWS_TERMS = (
    # supply chain (the core)
    "npm supply chain attack",
    "malicious npm package",
    "malicious pypi package",
    "github malware repository",
    "compromised github repository",
    "supply chain malware github",
    # broader families, so hunts surface more than the one DPRK config loader
    "info stealer github",
    "crypto wallet drainer github",
    "malicious vscode extension",
    "malicious github action",
    "credential stealer open source",
    "typosquat package malware",
    # actor-anchored: a writeup naming a NON-DPRK group surfaces its repos, and the
    # attribution engine can then name the country (Russia / China / Iran / ...)
    "apt github repository malware",
    "state sponsored github malware",
)


@dataclass
class NewsHit:
    """A repo mentioned in a news/discussion post about malware."""

    full_name: str
    source_title: str
    source_url: str | None
    source: str = ""       # "Hacker News" | "Google News"
    context: str = ""      # full text the mention was found in (title + body)


def extract_repo_mentions(text: str) -> set[str]:
    """Pull distinct ``owner/repo`` slugs out of free text (pure, no network)."""
    out: set[str] = set()
    for m in _GITHUB_REPO_RE.finditer(text or ""):
        owner, repo = m.group(1), m.group(2)
        repo = _TRAILING_JUNK.sub("", repo)
        if owner and repo:
            out.add(f"{owner}/{repo}")
    return out


def search_hackernews(
    terms=DEFAULT_NEWS_TERMS,
    *,
    http: HttpClient | None = None,
    known: set[str] | None = None,
    hits_per_term: int = 20,
    pace_seconds: float = 1.0,
) -> list[NewsHit]:
    """Search Hacker News (Algolia API, free/keyless) for terms; extract repos."""
    http = http or RequestsHttpClient()
    known = known or set()
    seen: dict[str, NewsHit] = {}
    for i, term in enumerate(terms):
        if i:
            time.sleep(pace_seconds)
        try:
            text = http.get_text(
                HN_SEARCH_URL,
                params={"query": term, "tags": "story", "hitsPerPage": str(hits_per_term)},
            )
            payload = json.loads(text)
        except Exception as exc:  # noqa: BLE001
            log.warning("hackernews: search failed",
                        extra={"context": {"term": term, "err": str(exc)}})
            continue
        for hit in payload.get("hits") or []:
            blob = " ".join(str(hit.get(k) or "") for k in ("title", "url", "story_text"))
            for full in extract_repo_mentions(blob):
                if full.casefold() in known:
                    continue
                seen.setdefault(full.casefold(), NewsHit(
                    full_name=full,
                    source_title=hit.get("title") or "",
                    source_url=hit.get("url")
                    or f"https://news.ycombinator.com/item?id={hit.get('objectID', '')}",
                    source="Hacker News",
                    context=blob,
                ))
    return list(seen.values())


def search_google_news(
    terms=DEFAULT_NEWS_TERMS,
    *,
    http: HttpClient | None = None,
    known: set[str] | None = None,
    search_url: str | None = None,
    pace_seconds: float = 1.0,
) -> list[NewsHit]:
    """Search Google News RSS (free/keyless) for terms; extract repo mentions."""
    from ..config import GOOGLE_NEWS_RSS_URL
    from ..feeds.rss import parse_feed

    http = http or RequestsHttpClient()
    known = known or set()
    search_url = search_url or GOOGLE_NEWS_RSS_URL
    seen: dict[str, NewsHit] = {}
    for i, term in enumerate(terms):
        if i:
            time.sleep(pace_seconds)
        try:
            xml = http.get_text(search_url, params={
                "q": f'"{term}"', "hl": "en-US", "gl": "US", "ceid": "US:en"})
        except Exception as exc:  # noqa: BLE001
            log.warning("google_news: search failed",
                        extra={"context": {"term": term, "err": str(exc)}})
            continue
        for item in parse_feed(xml):
            blob = f"{item.title} {item.summary}"
            for full in extract_repo_mentions(blob):
                if full.casefold() in known:
                    continue
                seen.setdefault(full.casefold(), NewsHit(
                    full_name=full, source_title=item.title, source_url=item.link,
                    source="Google News", context=blob))
    return list(seen.values())
