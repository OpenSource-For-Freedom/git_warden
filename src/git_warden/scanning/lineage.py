"""Red-team tooling repurposing detection (doc 02 section 5).

For each pinned legitimate tool, find repos that share its lineage but sit under
a different owner -- the renamed/re-hosted copies that are the repurposing
surface:

* **forks** of a pinned anchor repo, and
* **same-name/alias repos** under owners other than the legitimate project.

This is the *candidate-finding* stage (metadata only, no cloning). It narrows
the field and attaches lightweight signals; confirming that a candidate's code
or intent actually changed is Tier-2's job (clone + code-hash + scanners). Every
candidate is explicitly "needs Tier-2 verification" -- accuracy over volume.

``find_lineage_candidates`` takes any client exposing ``list_forks`` and
``search_repositories``, so it is unit-tested offline with a fake.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..models import RedTeamTool

log = logging.getLogger(__name__)


@dataclass
class LineageCandidate:
    """A repo that may be a repurposed clone of a pinned red-team tool."""

    full_name: str
    owner: str
    relation: str  # "fork" | "name_match"
    anchor_tool: str
    anchor_repo: str | None
    stars: int
    is_fork: bool
    pushed_at: str | None
    description: str | None
    html_url: str
    signals: list[str] = field(default_factory=list)


def _short_name(full_name: str) -> str:
    return full_name.split("/", 1)[-1].casefold()


def _recent(pushed_at: str | None, now: datetime, days: int) -> bool:
    if not pushed_at:
        return False
    try:
        ts = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (now - ts).days <= days


def _signals(item: dict, anchor_short: str | None, now: datetime, recent_days: int) -> list[str]:
    signals: list[str] = []
    if anchor_short and _short_name(item.get("full_name", "")) != anchor_short:
        signals.append("renamed")
    if item.get("fork"):
        signals.append("is-fork")
    if (item.get("stargazers_count") or 0) < 50:
        signals.append("low-stars")
    if _recent(item.get("pushed_at"), now, recent_days):
        signals.append("recently-pushed")
    if not item.get("description"):
        signals.append("no-description")
    return signals


def _candidate(item: dict, relation: str, tool: RedTeamTool, anchor_repo: str | None,
               now: datetime, recent_days: int) -> LineageCandidate:
    anchor_short = _short_name(anchor_repo) if anchor_repo else None
    return LineageCandidate(
        full_name=item.get("full_name", ""),
        owner=(item.get("owner") or {}).get("login", ""),
        relation=relation,
        anchor_tool=tool.name,
        anchor_repo=anchor_repo,
        stars=item.get("stargazers_count") or 0,
        is_fork=bool(item.get("fork")),
        pushed_at=item.get("pushed_at"),
        description=item.get("description"),
        html_url=item.get("html_url", ""),
        signals=_signals(item, anchor_short, now, recent_days),
    )


def find_lineage_candidates(
    client,
    tool: RedTeamTool,
    *,
    known_good: set[str],
    now: datetime | None = None,
    per_term: int = 15,
    recent_days: int = 120,
) -> list[LineageCandidate]:
    """Find lineage candidates for one pinned tool, deduped by repo full-name.

    ``known_good`` is the set of all pinned repo full-names (lowercased) across
    the whole registry, so legitimate originals are never flagged as clones.
    """
    now = now or datetime.now(UTC)
    legit_owner = (tool.org or "").casefold()
    by_name: dict[str, LineageCandidate] = {}

    # 1) Forks of each pinned anchor repo (forks always sit under another owner).
    for anchor_repo in tool.repos:
        owner, _, name = anchor_repo.partition("/")
        try:
            forks = client.list_forks(owner, name)
        except Exception as exc:  # one anchor failing must not lose the rest
            log.warning("lineage: fork lookup failed",
                        extra={"context": {"repo": anchor_repo, "err": str(exc)}})
            forks = []
        for item in forks:
            full = item.get("full_name", "")
            if not full or full.casefold() in known_good:
                continue
            by_name[full.casefold()] = _candidate(item, "fork", tool, anchor_repo, now, recent_days)

    # 2) Same-name/alias repos under owners other than the legitimate project.
    for term in tool.match_terms:
        try:
            results = client.search_repositories(f"{term} in:name", per_page=per_term)
        except Exception as exc:
            log.warning("lineage: search failed",
                        extra={"context": {"term": term, "err": str(exc)}})
            continue
        for item in results:
            full = item.get("full_name", "")
            key = full.casefold()
            if not full or key in known_good or key in by_name:
                continue
            owner_login = (item.get("owner") or {}).get("login", "").casefold()
            if owner_login and owner_login == legit_owner:
                continue  # legitimate org's own repos
            anchor_repo = tool.repos[0] if tool.repos else None
            by_name[key] = _candidate(item, "name_match", tool, anchor_repo, now, recent_days)

    return list(by_name.values())
