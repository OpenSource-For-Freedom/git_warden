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

from . import config
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
    find_owner_repos,
    scan_candidate,
    score_repo,
    search_iocs,
)
from .scanning.actor_search import AccountRepo
from .scanning.discovery import RepoHit
from .scanning.enrichment import OwnerRepo
from .scanning.tier2 import WEAPONIZATION_CATEGORIES, _force_rmtree

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
        raw_payload={
            "anchor": tool.name,
            "anchor_repo": cand.anchor_repo,
            "relation": cand.relation,
            "fork_branch": cand.default_branch or "HEAD",
        },
    )


def _intent_gate(client, finding: RepoFinding, anchor_default: dict) -> tuple[bool, set | None]:
    """Red-team lineage intent check (P1, doc 02 5).

    Returns (proceed, restrict_paths). An unmodified fork (ahead_by == 0) is a
    benign mirror -> (False, None) drops it. A diverged fork -> (True, changed
    files) so Tier-2 only weighs the fork's additions. Best-effort: if compare
    can't be made, proceed without restriction.
    """
    rp = finding.raw_payload
    if rp.get("relation") != "fork" or not rp.get("anchor_repo"):
        return True, None  # name_match has no upstream to diff; categories gate it
    anchor = rp["anchor_repo"]
    if anchor not in anchor_default:
        owner, _, name = anchor.partition("/")
        try:
            ar = client.get_repo(owner, name)
        except Exception:  # noqa: BLE001
            ar = None
        anchor_default[anchor] = (ar or {}).get("default_branch") or "HEAD"
    try:
        cmp = client.compare(anchor, anchor_default[anchor], finding.full_name,
                             rp.get("fork_branch") or "HEAD")
    except Exception:  # noqa: BLE001
        cmp = None
    if cmp is None:
        return True, None
    if cmp.get("ahead_by", 0) == 0:
        return False, None  # unmodified mirror of the red-team tool
    return True, set(cmp.get("files") or []) or None


def _finding_from_account(ar: AccountRepo) -> RepoFinding:
    return RepoFinding(
        full_name=ar.full_name,
        url=ar.html_url or None,
        detection_method=DetectionMethod.ACTOR_ACCOUNT,
        actor_key=ar.actor_key,
        reasoning=f"repository under known threat-actor account {ar.owner}",
    )


def _finding_from_owner(ar: OwnerRepo) -> RepoFinding:
    return RepoFinding(
        full_name=ar.full_name,
        url=ar.html_url or None,
        detection_method=DetectionMethod.MALICIOUS_OWNER,
        reasoning=f"repository under owner {ar.owner} of a known-malicious repo",
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
    do_enrich: bool = True,
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
    # Repos we already track (OSM artifacts + prior findings) plus pinned tools,
    # so discovery reports only genuinely-new repos (eval finding #2).
    known = db.known_repo_names() | {r.casefold() for tool in tools for r in tool.repos}
    candidates: dict[str, RepoFinding] = {}

    if do_ioc:
        # Enrichment corpus (expand core search beyond red-team): learned IOCs
        # from prior confirmed repos, OSM IOCs, AND distinctive malicious package
        # names (a repo referencing known malware is a candidate).
        learned = db.learned_search_terms()
        base = build_search_terms(_osm_iocs(db), max_iocs)
        packages = db.malicious_package_terms(limit=max_iocs)
        package_set = set(packages)
        terms = list(dict.fromkeys(learned + base + packages))[:max_iocs]
        hits = search_iocs(client, terms, known=known, per_term=15)
        for hit in hits:
            if classify_hit(hit) == "suspicious":
                finding = _finding_from_hit(hit)
                if any(m in package_set for m in hit.matched_iocs):
                    finding.detection_method = DetectionMethod.PACKAGE_REF
                candidates[hit.full_name.casefold()] = finding

    if do_enrich:
        # Owner pivot -- the strongest enrichment: other repos by owners who have
        # already shipped a known-malicious repo (still Tier-1/Tier-2 gated).
        for ar in find_owner_repos(client, db.malicious_repo_owners(), known=known):
            candidates.setdefault(ar.full_name.casefold(), _finding_from_owner(ar))

    if do_lineage:
        for tool in tools:
            for cand in find_lineage_candidates(client, tool, known_good=known, now=now):
                key = cand.full_name.casefold()
                candidates.setdefault(key, _finding_from_lineage(cand, tool))

    if do_actor:
        for ar in find_actor_account_repos(client, db.actor_github_logins(), known=known):
            candidates.setdefault(ar.full_name.casefold(), _finding_from_account(ar))

    # Bound the run: keep the strongest candidates before the expensive Tier-1
    # README fetches + Tier-2 clones. Ranking is method-aware (eval finding #13)
    # so high-trust actor-account leads (which carry no signals/IOCs yet) are not
    # starved by noisy multi-signal lineage hits.
    if limit and len(candidates) > limit:
        method_base = {
            DetectionMethod.ACTOR_ACCOUNT: 3,
            DetectionMethod.MALICIOUS_OWNER: 3,  # owner of a known-malicious repo
            DetectionMethod.PACKAGE_REF: 2,
            DetectionMethod.OSM_REPOSITORY: 2,
            DetectionMethod.IOC_SEARCH: 1,
            DetectionMethod.REDTEAM_LINEAGE: 1,
        }
        ranked = sorted(
            candidates.values(),
            key=lambda f: -(method_base.get(f.detection_method, 0)
                            + len(f.signals) + len(f.matched_iocs)),
        )
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
        # Tier-2 STATICALLY analyzes each clone (never executes it). Scratch goes
        # to config.WORK_DIR when set, to keep large/ephemeral clones off a
        # near-full system drive; dir=None uses system temp (correct for CI/Linux).
        # Force-removed in finally so git's read-only pack files don't leave husks.
        workdir = tempfile.mkdtemp(dir=config.WORK_DIR)
        anchor_default: dict[str, str] = {}
        try:
            for finding in screened:
                kwargs = {"clone": clone} if clone else {}
                restrict = None
                confirm_cats = None
                # P1: red-team forks confirm only on weaponization (added install
                # hooks / exfil / obfuscation), never the tool's own code; and an
                # unmodified mirror is dropped outright.
                if finding.detection_method is DetectionMethod.REDTEAM_LINEAGE:
                    confirm_cats = WEAPONIZATION_CATEGORIES
                    proceed, restrict = _intent_gate(client, finding, anchor_default)
                    if not proceed:
                        finding.status = RepoFindingStatus.REJECTED
                        finding.reasoning = (finding.reasoning or "") + \
                            " | unmodified fork of red-team tool (no intent change)"
                        db.upsert_finding(finding, run_id)
                        continue
                result = scan_candidate(finding.full_name, workdir,
                                        restrict_paths=restrict, confirm_categories=confirm_cats,
                                        **kwargs)
                if result and result.confirmed:
                    finding.status = RepoFindingStatus.CONFIRMED
                    finding.score += result.bash_score
                    finding.signals = sorted(set(finding.signals) | set(result.signal_summary()))
                    finding.reasoning = (finding.reasoning or "") + \
                        f" | Tier-2 confirmed (bash score {result.bash_score})"
                    finding.code_hash = result.code_hash
                    finding.raw_payload["code_hash"] = result.code_hash
                    # Provenance for the gold message (doc 02 6): file:line + rule
                    # per bash finding, and which scanners fired.
                    finding.raw_payload["bash_findings"] = [
                        {"file": bf.file, "line": bf.line, "category": bf.category, "rule": bf.rule}
                        for bf in result.bash_findings[:20]
                    ]
                    finding.raw_payload["scanners"] = result.scanners
                    db.upsert_finding(finding, run_id)
                    confirmed += 1
                    # Compounding loop: mine this confirmed repo's IOCs into the
                    # search corpus so future hunts find more like it.
                    li = result.learned_iocs
                    for wh in li.webhooks:
                        db.record_learned_ioc(wh, "webhook", finding.full_name, run_id)
                    for tg in li.telegram:
                        db.record_learned_ioc(tg, "telegram", finding.full_name, run_id)
                    for dom in li.domains:
                        db.record_learned_ioc(dom, "domain", finding.full_name, run_id)
        finally:
            _force_rmtree(workdir)

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
