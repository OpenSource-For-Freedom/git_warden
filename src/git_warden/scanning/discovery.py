"""IOC-driven discovery: mirror OSM's IOCs into GitHub code search.

The multiplier. OSM tells us a known-malicious repo exfiltrates to, say, a
specific Discord webhook id or a ``*.workers.dev`` endpoint. We search GitHub
*code* for that same IOC -- any repo whose code references it is very likely
part of the same campaign, including repos OSM never catalogued. Those become
new candidate malicious repos for Tier-1/Tier-2 confirmation.

``search_iocs`` takes any client exposing ``search_code``, so it is unit-tested
offline with a fake.
"""

from __future__ import annotations

import logging
import os
import re
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

# IOC code search surfaces defenders cataloging the IOC as well as attackers
# using it. Repo names like these mark a defensive aggregator/feed/detector.
_DEFENSIVE_NAME = re.compile(
    r"detect|guard|blocklist|blacklist|hosts|malicious|malware|vuln|threat|"
    r"\bioc[s]?\b|awesome|mirror|attack-data|supply.?chain|vigil|maltrail|"
    r"indicator|sandbox|honeypot|research|dataset|feed|scanner|analysis",
    re.IGNORECASE,
)
# Attackers reference the IOC from executable source; defenders list it in data.
_SOURCE_EXT = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".go", ".rb", ".php",
    ".sh", ".ps1", ".bat", ".rs", ".java", ".lua", ".c", ".cpp",
}


@dataclass
class RepoHit:
    """A repo discovered via an IOC code-search match."""

    full_name: str
    owner: str
    html_url: str
    matched_iocs: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)


def build_search_terms(iocs, max_terms: int) -> list[str]:
    """Select code-search terms from an IocSet: attacker domains + webhook ids."""
    from .ioc import is_attacker_host

    ids = []
    for webhook in iocs.webhooks:
        m = re.search(r"webhooks/(\d+)", webhook)
        if m:
            ids.append(m.group(1))
    domains = [d for d, _ in iocs.domains.most_common(50) if is_attacker_host(d)]
    return list(dict.fromkeys(domains + ids))[:max_terms]


def classify_hit(hit: RepoHit) -> str:
    """'defensive' if the repo merely catalogs the IOC; 'suspicious' if it uses it.

    Heuristic: a defensive-sounding repo name wins immediately; otherwise a match
    inside executable source code is treated as use (suspicious), while a match
    only in data/list/doc files is treated as a catalog (defensive).
    """
    if _DEFENSIVE_NAME.search(hit.full_name):
        return "defensive"
    exts = {os.path.splitext(p)[1].lower() for p in hit.paths}
    return "suspicious" if exts & _SOURCE_EXT else "defensive"


def search_iocs(
    client,
    terms: list[str],
    *,
    known: set[str],
    per_term: int = 20,
    pace_seconds: float = 0.0,
) -> list[RepoHit]:
    """Code-search each IOC term; return NEW repos (not already known), deduped.

    ``known`` is the lowercased set of repos we already track (OSM repos +
    pinned tools), so results are genuinely new discoveries. ``pace_seconds``
    spaces calls to respect code search's ~10/min limit (0 in tests).
    """
    by_repo: dict[str, RepoHit] = {}
    for index, term in enumerate(terms):
        if pace_seconds and index:
            time.sleep(pace_seconds)
        try:
            items = client.search_code(term, per_page=per_term)
        except Exception as exc:  # one IOC failing must not abort the sweep
            log.warning("code search failed", extra={"context": {"term": term, "err": str(exc)}})
            continue
        for item in items:
            repo = item.get("repository") or {}
            full = repo.get("full_name")
            if not full or full.casefold() in known:
                continue
            hit = by_repo.get(full)
            if hit is None:
                hit = RepoHit(
                    full_name=full,
                    owner=(repo.get("owner") or {}).get("login", ""),
                    html_url=repo.get("html_url", ""),
                )
                by_repo[full] = hit
            if term not in hit.matched_iocs:
                hit.matched_iocs.append(term)
            if item.get("path"):
                hit.paths.append(item["path"])
    return list(by_repo.values())
