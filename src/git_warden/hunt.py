"""The hunt pipeline: discover -> Tier-1 screen -> registry -> Tier-2 -> gold.

Ties the Week-2 stages into one run that produces malicious-GitHub-repo findings
(the product). Discovery sources (all breadcrumb-driven):

* IOC search -- mirror OSM IOCs into GitHub code search (the multiplier).
* Red-team lineage -- forks/renames of pinned tools.

Each candidate is Tier-1 screened (name + README), persisted to the registry,
optionally Tier-2 scanned (clone + bash scanner + OSS scanners) to confirm, and
confirmed findings are delivered to Discord as gold.

Network/git-bound steps take injectable clients so the orchestration is
unit-tested offline.
"""

from __future__ import annotations

import json
import logging
import tempfile
from datetime import UTC, datetime

from .db import Database
from .enums import DetectionMethod, RepoFindingStatus, RunStatus
from .models import RedTeamTool, RepoFinding
from .scanning import (
    IocSet,
    build_search_terms,
    classify_hit,
    extract_iocs,
    find_actor_account_repos,
    find_lineage_candidates,
    scan_candidate,
    score_repo,
    search_iocs,
)
from .scanning.actor_search import AccountRepo
from .scanning.discovery import RepoHit

log = logging.getLogger(__name__)


def _osm_iocs(db: Database) -> IocSet:
    agg = IocSet()
    for row in db.list_artifacts():
        payload = json.loads(row["raw_payload"])
        text = "\n".join(
            [payload.get("payload_description") or "", payload.get("threat_description") or ""]
        )
        agg.merge(extract_iocs(text))
    return agg


def _finding_from_hit(hit: RepoHit) -> RepoFinding:
    return RepoFinding(
        full_name=hit.full_name,
        url=hit.html_url or None,
        detection_method=DetectionMethod.IOC_SEARCH,
        matched_iocs=list(hit.matched_iocs),
        reasoning=f"Code references OSM IOC(s) {hit.matched_iocs} in {hit.paths[:3]}",
        raw_payload={"paths": hit.paths},
    )


def _finding_from_lineage(cand, tool: RedTeamTool) -> RepoFinding:
    return RepoFinding(
        full_name=cand.full_name,
        url=cand.html_url or None,
        detection_method=DetectionMethod.REDTEAM_LINEAGE,
        signals=list(cand.signals),
        reasoning=f"{cand.relation} of pinned red-team tool {tool.name}",
        raw_payload={"anchor": tool.name, "relation": cand.relation},
    )


def _finding_from_account(ar: AccountRepo) -> RepoFinding:
    return RepoFinding(
        full_name=ar.full_name,
        url=ar.html_url or None,
        detection_method=DetectionMethod.ACTOR_ACCOUNT,
        actor_key=ar.actor_key,
        reasoning=f"repository under known threat-actor account {ar.owner}",
    )


def hunt(
    db: Database,
    client,
    tools: list[RedTeamTool],
    *,
    run_id: str,
    now: datetime | None = None,
    do_ioc: bool = True,
    do_lineage: bool = True,
    do_actor: bool = True,
    do_tier2: bool = False,
    max_iocs: int = 8,
    limit: int = 0,
    scan_min_score: int = 4,
    gold: bool = False,
    notifier=None,
    clone=None,
) -> dict:
    """Run the hunt and return a summary. Persists findings into the registry."""
    now = now or datetime.now(UTC)
    db.start_run(run_id, now, config={"stage": "hunt", "tier2": do_tier2})
    known = {r.casefold() for tool in tools for r in tool.repos}
    candidates: dict[str, RepoFinding] = {}

    if do_ioc:
        terms = build_search_terms(_osm_iocs(db), max_iocs)
        hits = search_iocs(client, terms, known=known, per_term=15)
        for hit in hits:
            if classify_hit(hit) == "suspicious":
                candidates[hit.full_name.casefold()] = _finding_from_hit(hit)

    if do_lineage:
        for tool in tools:
            for cand in find_lineage_candidates(client, tool, known_good=known, now=now):
                key = cand.full_name.casefold()
                candidates.setdefault(key, _finding_from_lineage(cand, tool))

    if do_actor:
        for ar in find_actor_account_repos(client, db.actor_github_logins(), known=known):
            candidates.setdefault(ar.full_name.casefold(), _finding_from_account(ar))

    # Bound the run: keep the strongest candidates (most signals/IOC matches)
    # before the expensive Tier-1 README fetches + Tier-2 clones.
    if limit and len(candidates) > limit:
        ranked = sorted(candidates.values(),
                        key=lambda f: -(len(f.signals) + len(f.matched_iocs)))
        candidates = {f.full_name.casefold(): f for f in ranked[:limit]}

    # Tier-1 screen: fetch README, score name + README jointly.
    all_terms = {t for tool in tools for t in tool.match_terms}
    screened_count = 0
    for finding in candidates.values():
        owner, _, name = finding.full_name.partition("/")
        readme = None
        try:
            readme = client.get_readme(owner, name)
        except Exception:  # noqa: BLE001
            pass
        result = score_repo(
            name=finding.full_name, full_name=finding.full_name, readme=readme,
            known_terms=all_terms,
            renamed_fork=(finding.detection_method is DetectionMethod.REDTEAM_LINEAGE
                          and "renamed" in finding.signals),
        )
        finding.score = result.score
        finding.signals = sorted(set(finding.signals) | set(result.signal_names))
        finding.status = RepoFindingStatus.SCREENED if result.tier2 else RepoFindingStatus.CANDIDATE
        if result.tier2:
            screened_count += 1
        db.upsert_finding(finding, run_id)

    confirmed = 0
    if do_tier2:
        screened = [f for f in candidates.values()
                    if f.score >= scan_min_score or f.status is RepoFindingStatus.SCREENED]
        with tempfile.TemporaryDirectory() as workdir:
            for finding in screened:
                kwargs = {"clone": clone} if clone else {}
                result = scan_candidate(finding.full_name, workdir, **kwargs)
                if result and result.confirmed:
                    finding.status = RepoFindingStatus.CONFIRMED
                    finding.score += result.bash_score
                    finding.signals = sorted(set(finding.signals) | set(result.signal_summary()))
                    finding.reasoning = (finding.reasoning or "") + \
                        f" | Tier-2 confirmed (bash score {result.bash_score})"
                    finding.raw_payload["code_hash"] = result.code_hash
                    db.upsert_finding(finding, run_id)
                    confirmed += 1

    delivered = 0
    if gold and notifier is not None:
        for row in db.undelivered_gold():
            if notifier(row):
                db.mark_gold_delivered(row["full_name"])
                delivered += 1

    counts = {
        "candidates": len(candidates),
        "screened": screened_count,  # passed Tier-1 (cumulative, pre-Tier-2)
        "confirmed": confirmed,
        "gold_delivered": delivered,
    }
    db.finish_run(run_id, datetime.now(UTC), RunStatus.COMPLETED, counts)
    summary = {"run_id": run_id, "counts": counts}
    log.info("hunt finished", extra={"context": summary})
    return summary
