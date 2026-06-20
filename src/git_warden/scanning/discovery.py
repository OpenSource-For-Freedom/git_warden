"""IOC-driven discovery: mirror OSM's IOCs into GitHub code search.

The multiplier. OSM tells us a known-malicious repo exfiltrates to, say, a
specific Discord webhook id or a ``*.workers.dev`` endpoint. We search GitHub
*code* for that same IOC; any repo whose code references it is very likely
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
# using it. These tokens (matched on the REPO short-name only, word-boundaried)
# mark a defensive aggregator/feed/detector. Kept tight and specific: generic
# words (research/analysis/scanner/mirror/hosts/feed/dataset/sandbox) were
# dropped because they over-matched and let attackers evade by naming
# (eval finding #1). Defensive-name is NOT an absolute veto; a match inside
# executable/config SOURCE always wins (the IOC is used, not just catalogued).
_DEFENSIVE_NAME = re.compile(
    r"blocklist|blacklist|allowlist|malware|malicious|\bvuln|\bioc[s]?\b|"
    r"threat[-_]?intel|detection|detector|honeypot|maltrail|awesome[-_]|"
    r"osint|advisor|attack[-_]data|supply[-_.]?chain",
    re.IGNORECASE,
)
# Attackers reference the IOC from executable source...
_SOURCE_EXT = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".go", ".rb", ".php",
    ".sh", ".ps1", ".bat", ".rs", ".java", ".lua", ".c", ".cpp",
}
# ...or from config/markup that legitimately carries an exfil endpoint in a
# malicious repo (eval finding #11). These also count as "use".
_CONFIG_EXT = {
    ".json", ".yml", ".yaml", ".toml", ".env", ".cfg", ".ini", ".html", ".ipynb",
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


# Broader name-based defender/sample/catalog check used as a CLONE gate: when we
# auto-escalate an intelligence-driven candidate to Tier-2 on its discovery
# signal (not its name), this keeps us from cloning a repo that merely *catalogs*
# malware (advisory DBs, IOC feeds, malware-sample collections, our own tooling).
_DEFENSIVE_REPO = re.compile(
    r"malicious|malware|advisor|\bosv\b|\bcve\b|vuln|\bioc[s]?\b|sample|yara|sigma|"
    r"detection|detector|threat[-_]?intel|awesome|blocklist|blacklist|honeypot|"
    r"security[-_]?research|sandbox|maltrail|feed|dataset|git[-_]?warden",
    re.IGNORECASE,
)


def is_defensive_repo(full_name: str) -> bool:
    """True if the repo owner/name marks a defender/sample/catalog (don't clone)."""
    return bool(_DEFENSIVE_REPO.search(full_name))


def classify_hit(hit: RepoHit) -> str:
    """'defensive' if the repo merely catalogs the IOC; 'suspicious' if it uses it.

    Order matters (eval finding #1): a match inside executable/config SOURCE is
    *use* and wins over a defensive-looking name; an attacker can't evade by
    naming their repo 'security-research'. Only a defensive repo short-name with
    matches confined to data/list files (.txt/.md/.csv) is treated as a catalog.
    """
    exts = {os.path.splitext(p)[1].lower() for p in hit.paths}
    if exts & (_SOURCE_EXT | _CONFIG_EXT):
        return "suspicious"  # the IOC is used in code/config, regardless of name
    short_name = hit.full_name.split("/", 1)[-1]  # repo name only, not the owner
    # Data/list-only matches: a defensive repo NAME marks a catalog (drop); a
    # non-defensive name with a high-specificity IOC is still worth a look
    # (eval verify finding; the two branches must differ).
    return "defensive" if _DEFENSIVE_NAME.search(short_name) else "suspicious"


def _code_query(term: str) -> str:
    """Quote package-name-like terms so ``@``/``/`` are literal, not operators.

    GitHub code search tokenizes ``@scope/name`` oddly (often 0 hits); quoting it
    as an exact phrase improves the match. Plain IOCs (domains, webhook ids) are
    left unquoted so substring/subdomain matches still surface.
    """
    return f'"{term}"' if ("@" in term or "/" in term) else term


def search_iocs(
    client,
    terms: list[str],
    *,
    known: set[str],
    per_term: int = 20,
    pace_seconds: float = 0.0,
    max_backoff: float = 90.0,
    sleeper=time.sleep,
) -> list[RepoHit]:
    """Code-search each IOC term; return NEW repos (not already known), deduped.

    ``known`` is the lowercased set of repos we already track (OSM repos +
    pinned tools), so results are genuinely new discoveries. ``pace_seconds``
    spaces calls to respect code search's ~10/min limit (0 in tests). On a
    rate-limit (an exception carrying ``retry_after``), we wait the requested
    time; capped at ``max_backoff``; and retry the term once before moving on,
    so a burst throttle no longer silently drops IOCs.
    """
    by_repo: dict[str, RepoHit] = {}
    for index, term in enumerate(terms):
        if pace_seconds and index:
            sleeper(pace_seconds)
        items = None
        for attempt in range(2):  # initial try + one retry after a backoff
            try:
                items = client.search_code(_code_query(term), per_page=per_term)
                break
            except Exception as exc:  # one IOC failing must not abort the sweep
                retry_after = getattr(exc, "retry_after", None)
                if retry_after is not None and attempt == 0:
                    wait = min(float(retry_after), max_backoff)
                    log.info("code search rate-limited; backing off",
                             extra={"context": {"term": term, "wait": round(wait, 1)}})
                    sleeper(wait)
                    continue
                level = "rate-limited" if retry_after is not None else "failed"
                log.warning(f"code search {level}",
                            extra={"context": {"term": term, "err": str(exc)}})
                break
        for item in items or ():
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
