"""The hunt pipeline: discover -> Tier-1 screen -> registry -> Tier-2 -> gold.

Ties the Week-2 stages into one run that produces malicious-GitHub-repo findings
(the product). Discovery sources (all breadcrumb-driven):

* IOC search; mirror OSM IOCs into GitHub code search (the multiplier).
* Red-team lineage; forks/renames of pinned tools.

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
from collections import Counter
from datetime import UTC, datetime

from . import config
from .attribution import attribution_for_tags, attribution_for_text, load_actor_terms
from .db import Database
from .enums import DetectionMethod, RepoFindingStatus, RunStatus
from .models import RedTeamTool, RepoFinding
from .notify import cluster_findings
from .progress import NullProgress
from .scanning import (
    IocSet,
    build_search_terms,
    classify_hit,
    extract_iocs,
    find_actor_account_repos,
    find_lineage_candidates,
    find_owner_repos,
    is_defensive_repo,
    matches_known_tool,
    scan_candidate,
    score_repo,
    search_google_news,
    search_hackernews,
    search_iocs,
)
from .scanning.actor_search import AccountRepo
from .scanning.discovery import RepoHit, is_security_tool
from .scanning.enrichment import OwnerRepo
from .scanning.newsdiscovery import DEFAULT_NEWS_TERMS, NewsHit
from .scanning.package_resolver import find_package_source_repos
from .scanning.signatures import load_seed_signatures
from .scanning.tier2 import WEAPONIZATION_CATEGORIES, _force_rmtree

log = logging.getLogger(__name__)


def _decide(finding, decision: str, reason: str, **extra) -> None:
    """Emit a per-candidate Tier-2 decision to the run log.

    This is the FP/gap audit trail: an operator (or a later grep of the run log)
    sees every CONFIRMED (possible false positive to review), NOT_CONFIRMED
    (near-miss / possible false negative), REJECTED / SCREENED (a guard fired, and
    why), and CLONE_FAILED, each with its reason -- the decisions that were
    previously only written to finding.reasoning in the DB and never surfaced live.
    """
    tail = (" " + " ".join(f"{k}={v}" for k, v in extra.items())) if extra else ""
    # Detail goes in the MESSAGE (not just context) so the human-readable
    # --pretty-logs formatter shows it, not only the JSON formatter.
    log.info("decision %-13s %s :: %s%s", decision, finding.full_name, reason, tail,
             extra={"context": {"repo": finding.full_name, "decision": decision,
                                "reason": reason, **extra}})


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


# Discovery-source rank (lower = kept first) and hard caps, by EMPIRICAL precision
# from tonight's source_yield: signature_match ~100%, osm_repository ~43%,
# package_ref 0% (0 confirmed / 22 rejected), redteam_lineage ~3%. The old
# ranking summed matched_iocs, letting a package_ref hit with many name-matches
# (mem0 matched 7) outrank a signature_match repo and devour the budget (run-4:
# 120/120 package_ref). Rank by precision first; matched signals only break ties.
_METHOD_RANK = {
    DetectionMethod.SIGNATURE_MATCH: 0,
    DetectionMethod.OSM_REPOSITORY: 1,
    DetectionMethod.MALICIOUS_OWNER: 2,
    DetectionMethod.ACTOR_ACCOUNT: 2,
    DetectionMethod.IOC_SEARCH: 3,
    DetectionMethod.NEWS_MENTION: 3,
    DetectionMethod.PACKAGE_REF: 4,
    DetectionMethod.REDTEAM_LINEAGE: 5,
}


def rank_and_cap_candidates(candidates: list[RepoFinding], limit: int) -> list[RepoFinding]:
    """Select up to ``limit`` candidates by precision rank, capping noisy sources.

    High-precision methods are kept first and are never dropped for a low-
    precision one. package_ref / redteam_lineage are hard-capped so they cannot
    starve signature_match / osm_repository; the capped remainder only backfills
    if the high-precision sources left the budget unfilled (an empty slot is
    worse than a capped-source lead).
    """
    if limit <= 0 or len(candidates) <= limit:
        return candidates
    method_cap = {
        DetectionMethod.PACKAGE_REF: max(15, limit // 4),
        DetectionMethod.REDTEAM_LINEAGE: max(10, limit // 6),
    }
    ordered = sorted(candidates, key=lambda f: (
        _METHOD_RANK.get(f.detection_method, 3),
        -(len(f.signals) + len(f.matched_iocs))))
    kept: list[RepoFinding] = []
    used: Counter = Counter()
    for f in ordered:
        cap = method_cap.get(f.detection_method)
        if cap is not None and used[f.detection_method] >= cap:
            continue
        kept.append(f)
        used[f.detection_method] += 1
        if len(kept) >= limit:
            return kept
    keptset = {id(f) for f in kept}
    for f in ordered:  # backfill capped remainder only to fill leftover budget
        if id(f) not in keptset:
            kept.append(f)
            if len(kept) >= limit:
                break
    return kept


def _finding_from_news(hit: NewsHit, actor_terms: dict[str, str], db: Database,
                       run_id: str) -> RepoFinding:
    # Attribute the SAME way OSM does: check the writeup's own text for a
    # named threat actor/group first (Lazarus Group, APT28, Kimsuky, ...),
    # falling back to a bare nation/threat-class mention (DPRK, APT). The
    # KEY is source-agnostic (links to the one real threat_actors row); the
    # source only appears in the display text.
    attribution = attribution_for_text(hit.context or hit.source_title, actor_terms)
    reason = f"Named in a news/discussion writeup: {hit.source_title!r}"
    if attribution:
        reason += f" [{attribution.label} (per {hit.source or 'news'})]"
        # actor_key is a strict FK: register the actor BEFORE the finding is
        # upserted, or a nation-level attribution with no seed_actors.json
        # entry (and no campaign to propagate through) silently nulls out.
        # A pre-registered real actor (e.g. ingest-promoted "Lazarus Group")
        # is left untouched -- ensure_actor never clobbers status/category.
        db.ensure_actor(attribution.key, attribution.label, "news-attribution", run_id)
    return RepoFinding(
        full_name=hit.full_name,
        url=f"https://github.com/{hit.full_name}",
        detection_method=DetectionMethod.NEWS_MENTION,
        actor_key=attribution.key if attribution else None,
        reasoning=reason,
        raw_payload={"source_title": hit.source_title, "source_url": hit.source_url,
                     "source": hit.source},
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


def _intent_gate(
    client, finding: RepoFinding, anchor_default: dict
) -> tuple[bool, set | None, bool]:
    """Red-team lineage intent check (P1, doc 02 5).

    Red-team tooling is a breadcrumb: we flag a derivative only when it ADDED an
    attack vector that hurts a user / pushes supply-chain or machine attacks, not
    for the tool's own offensive purpose. That judgement needs the intent DELTA --
    the fork's diff against its upstream.

    Returns (proceed, restrict_paths, compared). ``compared`` is True only when we
    successfully diffed the fork against its upstream. A name_match (shares the
    tool's NAME, not a fork) has no upstream, and a fork whose compare fails has
    no obtainable diff: both yield compared=False, and the caller keeps them as
    breadcrumbs (no delta to judge). An unmodified fork (ahead_by == 0) is a
    benign mirror -> (False, None, True) drops it. A diverged fork ->
    (True, changed files, True) so Tier-2 weighs only the fork's additions.
    """
    rp = finding.raw_payload
    if rp.get("relation") != "fork" or not rp.get("anchor_repo"):
        return True, None, False  # name_match: no upstream to diff
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
        return True, None, False  # compare failed: no obtainable delta
    if cmp.get("ahead_by", 0) == 0:
        return False, None, True  # unmodified mirror of the red-team tool
    return True, set(cmp.get("files") or []) or None, True


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


def _finding_from_package_source(pr) -> RepoFinding:
    reason = (f"GitHub source of known-malicious {pr.ecosystem} package '{pr.package}'"
              + (f" (author {pr.author})" if pr.author else ""))
    return RepoFinding(
        full_name=pr.full_name,
        url=f"https://github.com/{pr.full_name}",
        detection_method=DetectionMethod.PACKAGE_SOURCE,
        reasoning=reason,
        matched_iocs=[pr.package],
    )


def _finding_from_osm_repo(full_name: str, url: str, intel: dict, db: Database,
                           run_id: str) -> RepoFinding:
    intel = intel or {}
    severity = (intel.get("severity") or "").upper()
    threat = (intel.get("threat") or "").strip()
    tags = intel.get("tags") or []
    attribution = attribution_for_tags(tags)
    reason = "OSM-flagged malicious repository"
    if severity:
        reason += f" (severity {severity})"
    if attribution:
        reason += f" [{attribution.label} (per OSM)]"
        # actor_key is a strict FK: register before upsert (see _finding_from_news).
        db.ensure_actor(attribution.key, attribution.label, "osm-attribution", run_id)
    if threat:
        reason += f": {threat[:160]}"
    return RepoFinding(
        full_name=full_name,
        url=url or None,
        detection_method=DetectionMethod.OSM_REPOSITORY,
        actor_key=attribution.key if attribution else None,
        reasoning=reason,
        raw_payload={"osm": {"source": intel.get("source") or "open_source_malware",
                             "severity": intel.get("severity"), "tags": tags}},
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
    do_osm: bool = True,
    do_signature: bool = True,
    do_news: bool = True,
    do_package_repos: bool = True,
    do_tier2: bool = False,
    max_iocs: int = 8,
    max_packages: int = 8,
    max_osm: int = 60,
    max_signatures: int = 14,
    max_news: int = 6,
    max_package_repos: int = 40,
    search_pace: float = 0.0,
    limit: int = 0,
    scan_min_score: int = 4,
    gold: bool = False,
    notifier=None,
    clone=None,
    news_http=None,
    pkg_http=None,
    osm_live_known: set[str] | None = None,
    progress=None,
) -> dict:
    """Run the hunt and return a summary. Persists findings into the registry.

    ``progress`` is an optional human-facing reporter (see ``progress.py``);
    it is display only and defaults to a no-op, so the pipeline logic and the
    audit log are identical whether or not a human is watching.
    """
    now = now or datetime.now(UTC)
    progress = progress or NullProgress()
    db.start_run(run_id, now, config={"stage": "hunt", "tier2": do_tier2})
    # Repos we already track (OSM artifacts + prior findings) plus pinned tools,
    # so discovery reports only genuinely-new repos (eval finding #2).
    known = db.known_repo_names() | {r.casefold() for tool in tools for r in tool.repos}
    candidates: dict[str, RepoFinding] = {}

    progress.phase("Discover",
                   "mining intel feeds + GitHub code search for candidate repos")
    _seen = 0

    def _src(name: str) -> None:
        # Net-new candidates this source contributed (dedup is by full_name, so
        # the len delta is exactly the fresh repos). Emitted after every source
        # so the paced code-search phase visibly advances instead of hanging.
        nonlocal _seen
        progress.source(name, len(candidates) - _seen, len(candidates))
        _seen = len(candidates)

    if do_ioc:
        # IOC code search: learned IOCs (prior confirmed repos) + OSM IOCs.
        learned = db.learned_search_terms()
        base = build_search_terms(_osm_iocs(db), max_iocs)
        ioc_terms = list(dict.fromkeys(learned + base))[:max_iocs]
        for hit in search_iocs(client, ioc_terms, known=known, per_term=10,
                               pace_seconds=search_pace):
            if classify_hit(hit) == "suspicious":
                candidates.setdefault(hit.full_name.casefold(), _finding_from_hit(hit))
        _src("IOC code search")

    if do_enrich:
        # Package pivot; dedicated budget for the strongest OSM signal: repos
        # that reference a confirmed-malicious package. Every term tried this
        # run is recorded so the NEXT run advances into untried names instead
        # of re-searching the same static leading slice (eval finding,
        # 2026-07-02).
        pkg_terms = db.malicious_package_terms(limit=max_packages)
        for hit in search_iocs(client, pkg_terms,
                               known=known, per_term=10, pace_seconds=search_pace):
            if classify_hit(hit) == "suspicious":
                finding = _finding_from_hit(hit)
                finding.detection_method = DetectionMethod.PACKAGE_REF
                finding.reasoning = f"References known-malicious package(s) {hit.matched_iocs}"
                candidates.setdefault(hit.full_name.casefold(), finding)
        if pkg_terms:
            db.record_searched_package_terms(pkg_terms, run_id)
        _src("package pivot")

        # Owner pivot; enumerate other repos of owners we PROVED malicious (a
        # confirmed Tier-2 finding), never OSM impersonation-target owners.
        for ar in find_owner_repos(client, db.malicious_repo_owners(), known=known):
            candidates.setdefault(ar.full_name.casefold(), _finding_from_owner(ar))
        _src("owner pivot")

    if do_package_repos:
        # HIGH-RECALL package -> repo: resolve known-malicious packages (OSM + any
        # ingested advisory feed) to their GitHub SOURCE repos via public registry
        # metadata. Reuses intel we already hold; each is Tier-2-eligible but still
        # has to confirm on its own code (a typosquat pointing at the legit repo
        # never confirms).
        pkg_client = pkg_http
        if pkg_client is None:
            from .feeds.http import RequestsHttpClient
            pkg_client = RequestsHttpClient()
        for pr in find_package_source_repos(db, pkg_client, known=known,
                                            limit=max_package_repos):
            candidates.setdefault(pr.full_name.casefold(), _finding_from_package_source(pr))
        _src("package source repos")

    if do_news:
        # News/discussion pivot: Hacker News + Google News RSS, both free and
        # keyless. A repo NAMED in a malware writeup is real but weaker signal
        # than a code-level IOC match (the article could name a legitimate
        # project in passing), so these candidates are NOT added to the
        # `intel` set below -- they go through ordinary Tier-1 scoring first,
        # same as a cold GitHub search hit, never an automatic Tier-2 bypass.
        news_terms = list(DEFAULT_NEWS_TERMS)[:max_news]
        news_hits = search_hackernews(news_terms, http=news_http, known=known,
                                      hits_per_term=20, pace_seconds=search_pace) + \
            search_google_news(news_terms, http=news_http, known=known,
                              pace_seconds=search_pace)
        actor_terms = load_actor_terms()
        for hit in news_hits:
            if is_defensive_repo(hit.full_name):
                continue
            candidates.setdefault(hit.full_name.casefold(),
                                  _finding_from_news(hit, actor_terms, db, run_id))
        _src("news / discussion")

    if do_lineage:
        for tool in tools:
            for cand in find_lineage_candidates(client, tool, known_good=known, now=now):
                key = cand.full_name.casefold()
                candidates.setdefault(key, _finding_from_lineage(cand, tool))
        _src("red-team lineage")

    if do_actor:
        for ar in find_actor_account_repos(client, db.actor_github_logins(), known=known):
            candidates.setdefault(ar.full_name.casefold(), _finding_from_account(ar))
        _src("actor accounts")

    if do_osm:
        # Validate OSM-labeled malicious repos directly: clone + Tier-2 confirm a
        # malware signature or known-malicious dependency, rather than trusting
        # the label. Most lure repos are ephemeral (gone), but survivors confirm.
        for full, url, intel in db.osm_repo_targets(limit=max_osm):
            if is_defensive_repo(full):
                continue
            candidates.setdefault(full.casefold(),
                                  _finding_from_osm_repo(full, url, intel, db, run_id))
        _src("OSM-labeled repos")

    if do_signature:
        # NOVEL-repo engine: code-search GitHub for a confirmed malware's reusable
        # signature (a deobfuscator stub mined from prior confirmations + curated
        # seeds) to find sibling infected repos OSM never catalogued.
        sig_terms = list(dict.fromkeys(
            db.learned_signatures() + load_seed_signatures(config.MALWARE_SIGNATURES_PATH)
        ))[:max_signatures]
        for hit in search_iocs(client, sig_terms, known=known, per_term=20,
                               pace_seconds=search_pace):
            if classify_hit(hit) == "suspicious":
                finding = _finding_from_hit(hit)
                finding.detection_method = DetectionMethod.SIGNATURE_MATCH
                finding.reasoning = (
                    f"Shares a confirmed-malware code signature {hit.matched_iocs}")
                candidates.setdefault(hit.full_name.casefold(), finding)
        _src("malware code signatures")

    # Bound the run: keep the strongest candidates before the expensive Tier-1
    # README fetches + Tier-2 clones, ordered by empirical precision and capping
    # the noisy sources so they can't starve the good ones.
    if limit and len(candidates) > limit:
        candidates = {f.full_name.casefold(): f
                      for f in rank_and_cap_candidates(list(candidates.values()), limit)}

    # Observability: prove which sources are actually contributing candidates
    # (the enrichment check; not "just red-team").
    by_method = Counter(f.detection_method.value for f in candidates.values())
    log.info("hunt discovery", extra={"context": {
        "total_candidates": len(candidates), "by_method": dict(by_method)}})
    progress.discovery(dict(by_method), len(candidates))

    # Tier-1 screen: fetch README, score name + README jointly.
    progress.phase("Screen (Tier-1)", "name + README triage, no clone")
    progress.screen_start(len(candidates))
    all_terms = {t for tool in tools for t in tool.match_terms}
    screened_count = 0
    confirmed_by_method: Counter = Counter()
    rejected_mirrors = 0
    redteam_breadcrumbs = 0  # red-team tooling kept as a breadcrumb, not confirmed
    _total = len(candidates)
    for _idx, finding in enumerate(candidates.values(), start=1):
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
        # Flag legitimate offensive-security / research tools from their README so
        # Tier-2 keeps them a breadcrumb instead of confirming their (purposeful)
        # attack code (the karmaz95/crimson FP, 2026-07-07).
        if is_security_tool(readme):
            finding.signals = sorted(set(finding.signals) | {"security-tool"})
        # Intelligence-driven candidates (reference a known IOC / malicious
        # package / are under a repeat-offender owner) reach Tier-2 on their
        # discovery signal, NOT their (often benign) name; unless they are a
        # defender/sample/catalog repo, which we must not clone+confirm.
        intel = finding.detection_method in (
            DetectionMethod.IOC_SEARCH, DetectionMethod.PACKAGE_REF,
            DetectionMethod.PACKAGE_SOURCE, DetectionMethod.MALICIOUS_OWNER,
            DetectionMethod.ACTOR_ACCOUNT, DetectionMethod.OSM_REPOSITORY,
            DetectionMethod.SIGNATURE_MATCH,
        )
        # A well-known-legit org (microsoft, freebsd, ...) never reaches Tier-2:
        # its huge codebase legitimately contains tasks.json/eval/env-read patterns
        # that would otherwise confirm (the microsoft/vscode FP, 2026-07-07). Apply
        # the allowlist DURING the hunt, not only at the reconcile sweep.
        good_owner = finding.full_name.split("/", 1)[0].casefold() in config.KNOWN_GOOD_OWNERS
        to_tier2 = (not good_owner) and (
            result.tier2 or (intel and not is_defensive_repo(finding.full_name)))
        finding.status = RepoFindingStatus.SCREENED if to_tier2 else RepoFindingStatus.CANDIDATE
        if to_tier2:
            screened_count += 1
        progress.screen_item(_idx, _total, finding.full_name, to_tier2)
        log.debug("tier1 screen", extra={"context": {
            "repo": finding.full_name, "score": finding.score,
            "advance_to_tier2": to_tier2, "good_owner": good_owner,
            "method": finding.detection_method.value}})
        db.upsert_finding(finding, run_id)
    progress.screen_end(screened_count)

    confirmed = 0
    failed_clones: list[dict] = []  # repos we could not Tier-2 scan, with reasons
    if do_tier2:
        screened = [f for f in candidates.values()
                    if f.score >= scan_min_score or f.status is RepoFindingStatus.SCREENED]
        progress.phase("Analyze (Tier-2)", "clone + static scan, never executed")
        progress.tier2_start(len(screened))
        # Tier-2 STATICALLY analyzes each clone (never executes it). Scratch goes
        # to config.WORK_DIR when set, to keep large/ephemeral clones off a
        # near-full system drive; dir=None uses system temp (correct for CI/Linux).
        # Force-removed in finally so git's read-only pack files don't leave husks.
        workdir = tempfile.mkdtemp(dir=config.WORK_DIR)
        anchor_default: dict[str, str] = {}
        # OSM-flagged packages: a repo declaring one as a dependency installs
        # known malware (the fake-interview / crypto-task lure delivery vector).
        mal_packages = db.malicious_dependency_names()
        _t2_total = len(screened)
        try:
            for _t2_idx, finding in enumerate(screened, start=1):
                progress.tier2_item(_t2_idx, _t2_total, finding.full_name)
                # Well-known-legit org (microsoft, freebsd, ...) is never scanned or
                # confirmed, even at a high Tier-1 score, because a huge legit
                # codebase inevitably trips a rule (the microsoft/vscode env-read FP,
                # 2026-07-07). This is the definitive gate: the screened list can
                # include a high-score candidate regardless of the Tier-1 decision.
                if finding.full_name.split("/", 1)[0].casefold() in config.KNOWN_GOOD_OWNERS:
                    finding.status = RepoFindingStatus.REJECTED
                    finding.reasoning = (finding.reasoning or "") + \
                        " | well-known-legit owner; never scanned/confirmed"
                    db.upsert_finding(finding, run_id)
                    _decide(finding, "REJECTED", "well-known-legit owner (KNOWN_GOOD_OWNERS)")
                    continue
                # Offensive-security / research tool (README-flagged at Tier-1): its
                # attack code is its stated purpose, not malice delivered to victims.
                # Keep it a research breadcrumb, never confirmed/published -- extends
                # the red-team-tool protection to EVERY discovery method (the
                # karmaz95/crimson package_ref FP, 2026-07-07).
                if "security-tool" in finding.signals:
                    finding.status = RepoFindingStatus.SCREENED
                    finding.reasoning = (finding.reasoning or "") + \
                        " | security-research/offensive tool (README); breadcrumb, not confirmed"
                    db.upsert_finding(finding, run_id)
                    redteam_breadcrumbs += 1
                    _decide(finding, "SCREENED",
                            "security-research/offensive tool (README markers)")
                    continue
                kwargs = {"clone": clone} if clone else {}
                kwargs["malicious_packages"] = mal_packages
                restrict = None
                confirm_cats = None
                # P1: red-team forks confirm only on weaponization (added install
                # hooks / exfil / obfuscation), never the tool's own code; and an
                # unmodified mirror is dropped outright.
                if finding.detection_method is DetectionMethod.REDTEAM_LINEAGE:
                    confirm_cats = WEAPONIZATION_CATEGORIES
                    proceed, restrict, compared = _intent_gate(client, finding, anchor_default)
                    if not proceed:
                        finding.status = RepoFindingStatus.REJECTED
                        finding.reasoning = (finding.reasoning or "") + \
                            " | unmodified fork of red-team tool (no intent change)"
                        db.upsert_finding(finding, run_id)
                        rejected_mirrors += 1
                        _decide(finding, "REJECTED",
                                "unmodified fork of red-team tool (no intent delta)")
                        continue
                    if not compared:
                        # No diffable upstream (a name_match, or a fork we could not
                        # compare): there is no intent DELTA to judge, and the
                        # tool's own offensive purpose is never grounds to flag it.
                        # Keep it a research breadcrumb, not a confirmed finding.
                        finding.status = RepoFindingStatus.SCREENED
                        finding.reasoning = (finding.reasoning or "") + \
                            " | red-team tooling; no diffable intent delta -> breadcrumb"
                        db.upsert_finding(finding, run_id)
                        redteam_breadcrumbs += 1
                        _decide(finding, "SCREENED", "red-team tooling; no diffable intent delta")
                        continue
                else:
                    # A red-team tool surfaced by a NON-lineage pivot (owner /
                    # signature / IOC) is a research breadcrumb, not a finding. We
                    # have no upstream to diff, so we cannot prove weaponization was
                    # ADDED; the tool's own offensive code (reverse shells, cred
                    # dumping, obfuscation) is its purpose, not malice. Keep it
                    # screened so legitimate red-team tooling is never pinned to the
                    # registry. A genuinely weaponized fork still confirms via the
                    # lineage path above (which diffs against the upstream tool).
                    tool = matches_known_tool(finding.full_name, all_terms)
                    if tool:
                        finding.status = RepoFindingStatus.SCREENED
                        finding.reasoning = (finding.reasoning or "") + \
                            f" | matches pinned red-team tool '{tool}'; breadcrumb, not confirmed"
                        db.upsert_finding(finding, run_id)
                        redteam_breadcrumbs += 1
                        _decide(finding, "SCREENED", f"matches pinned red-team tool '{tool}'")
                        continue
                # Safety net: a scanner bug on ONE repo (e.g. a malformed manifest)
                # must never abort the whole run -- treat it as an unscannable clone
                # and move on (a full 2h pipeline died this way on 2026-07-07).
                try:
                    result = scan_candidate(
                        finding.full_name, workdir, restrict_paths=restrict,
                        confirm_categories=confirm_cats, **kwargs)
                except Exception as exc:  # noqa: BLE001
                    result = None
                    log.warning("scan_candidate crashed; skipping repo",
                                extra={"context": {"repo": finding.full_name, "err": str(exc)}})
                    _decide(finding, "SCAN_ERROR", f"scanner raised: {type(exc).__name__}")
                if result is None:  # clone failed (404/taken down) or exceeded bounds
                    failed_clones.append({"repo": finding.full_name,
                                          "reason": "clone_failed_or_bounds"})
                    _decide(finding, "CLONE_FAILED", "404/taken-down or exceeded size bounds")
                elif not result.confirmed:
                    # Scanned but did not meet the confirmation bar: a near-miss. This
                    # is the false-NEGATIVE / recall-gap signal -- what static signal it
                    # DID trip, so an operator can see which rules almost fired.
                    _decide(finding, "NOT_CONFIRMED",
                            f"scanned; static score {result.bash_score} below confirmation bar",
                            top_signals=sorted({f"{bf.category}:{bf.rule}"
                                                for bf in result.bash_findings})[:8])
                if result and result.confirmed:
                    finding.status = RepoFindingStatus.CONFIRMED
                    finding.score += result.bash_score
                    finding.signals = sorted(set(finding.signals) | set(result.signal_summary()))
                    finding.reasoning = (finding.reasoning or "") + \
                        f" | Tier-2 confirmed (bash score {result.bash_score})"
                    finding.code_hash = result.code_hash
                    finding.raw_payload["code_hash"] = result.code_hash
                    # Confidence tier (auto|review) -- gates gold + submit downstream.
                    finding.raw_payload["confidence"] = result.confidence
                    # The exact scanned commit -> permanent /blob/<sha>/ evidence links.
                    if result.commit_sha:
                        finding.raw_payload["commit_sha"] = result.commit_sha
                    # Provenance for the gold message (doc 02 6): file:line + rule
                    # per bash finding. The CONFIRMING findings come first so a
                    # noisy repo (1000s of weak hits) never buries the real signal.
                    _confirming = {id(bf) for bf in result.confirming_findings}
                    ordered = result.confirming_findings + [
                        bf for bf in result.bash_findings if id(bf) not in _confirming]
                    finding.raw_payload["bash_findings"] = [
                        {"file": bf.file, "line": bf.line, "category": bf.category,
                         "rule": bf.rule, "snippet": bf.snippet[:280]}
                        for bf in ordered[:20]
                    ]
                    finding.raw_payload["scanners"] = result.scanners
                    db.upsert_finding(finding, run_id)
                    confirmed += 1
                    confirmed_by_method[finding.detection_method.value] += 1
                    progress.confirmed(finding.full_name, finding.score)
                    _decide(finding, f"CONFIRMED[{result.confidence}]",
                            f"Tier-2 static confirm (bash score {result.bash_score})",
                            method=finding.detection_method.value, score=finding.score,
                            confirming=[f"{bf.category}:{bf.rule}"
                                        for bf in result.confirming_findings][:6])
                    # Compounding loop: mine this confirmed repo's IOCs into the
                    # search corpus so future hunts find more like it.
                    li = result.learned_iocs
                    for wh in li.webhooks:
                        db.record_learned_ioc(wh, "webhook", finding.full_name, run_id)
                    for tg in li.telegram:
                        db.record_learned_ioc(tg, "telegram", finding.full_name, run_id)
                    for dom in li.domains:
                        db.record_learned_ioc(dom, "domain", finding.full_name, run_id)
                    # Mine reusable code signatures so the next hunt finds this
                    # campaign's sibling repos (the novel-discovery loop).
                    for sig in result.learned_signatures:
                        db.record_learned_ioc(sig, "code_sig", finding.full_name, run_id)
        finally:
            _force_rmtree(workdir)
        progress.tier2_end(confirmed)

    delivered = 0
    osm_live = {r.casefold() for r in (osm_live_known or set())}
    if gold and notifier is not None:
        progress.phase("Deliver", "posting confirmed clusters to the review feed")
        # Gold is AUTO-tier only: a lone broad-signal (review) finding never pings
        # Discord. Plus the live re-check so we never report a repo OSM already has.
        def _is_auto(r) -> bool:
            try:
                return (json.loads(r["raw_payload"] or "{}").get("confidence") or
                        "review") == "auto"
            except Exception:  # noqa: BLE001
                return False
        rows = [r for r in db.undelivered_gold()
                if r["full_name"].casefold() not in osm_live and _is_auto(r)]
        # ONE report per connected cluster (campaign), never duplicated per-repo.
        for cluster in cluster_findings(rows):
            names = [r["full_name"] for r in cluster]
            # CLAIM the cluster (atomic) BEFORE posting, so a crash or a concurrent
            # run can never repost it; RELEASE it only if the post fails so it
            # retries next run. At-most-once: prefer a missed ping over a double one.
            db.set_gold_delivered(names, True)
            if notifier(cluster):
                delivered += len(names)
            else:
                db.set_gold_delivered(names, False)
        progress.note(f"delivered {delivered} confirmed finding(s) to the review feed")

    counts = {
        "candidates": len(candidates),
        "candidates_by_method": dict(by_method),
        "screened": screened_count,  # passed Tier-1 (cumulative, pre-Tier-2)
        "confirmed": confirmed,
        "confirmed_by_method": dict(confirmed_by_method),
        "rejected_mirrors": rejected_mirrors,  # unmodified red-team forks dropped
        "redteam_breadcrumbs": redteam_breadcrumbs,  # red-team tooling kept as lead
        "clones_failed": len(failed_clones),   # could not Tier-2 scan (continued)
        "gold_delivered": delivered,
    }
    db.finish_run(run_id, datetime.now(UTC), RunStatus.COMPLETED, counts)
    summary = {"run_id": run_id, "counts": counts, "failed_clones": failed_clones}
    log.info("hunt finished", extra={"context": {"run_id": run_id, "counts": counts}})
    return summary


def _default_readme(full_name: str) -> str:
    """Best-effort fetch of a repo README (for the security-tool screen)."""
    import requests
    for name in ("README.md", "README", "readme.md"):
        try:
            r = requests.get(
                f"https://raw.githubusercontent.com/{full_name}/HEAD/{name}", timeout=15)
            if r.status_code == 200:
                return r.text
        except Exception:  # noqa: BLE001
            pass
    return ""


def revalidate_findings(db, *, clone=scan_candidate, readme_fetch=_default_readme,
                        limit: int | None = None, run_id: str = "revalidate") -> dict:
    """Re-scan already-confirmed, unsubmitted findings under the CURRENT rules and
    reconcile the DB with them.

    A finding is DEMOTED to ``rejected`` when it no longer confirms (a fixed false
    positive) or its repo now reads as a security tool; otherwise its stored
    ``confidence`` tier is refreshed so gold/submit gating reflects today's rules.
    Never touches submitted rows or OSM-sourced repos. ``clone`` is the scanner
    (injectable; defaults to ``scan_candidate``) so it is unit-testable offline.
    """
    from .osm_submit import _ensure_submit_columns
    _ensure_submit_columns(db)  # submitted_osm / osm_threat_id are runtime columns
    rows = db.conn.execute(
        "SELECT full_name, raw_payload FROM repo_findings WHERE status='confirmed' "
        "AND submitted_osm=0 AND detection_method NOT IN ('osm_repository','redteam_lineage') "
        "ORDER BY full_name").fetchall()
    if limit:
        rows = rows[:limit]
    import shutil
    workdir = tempfile.mkdtemp(dir=config.WORK_DIR)
    out: dict = {"demoted": [], "retiered": [], "kept": []}
    try:
        for row in rows:
            fn = row["full_name"]
            sec = is_security_tool(readme_fetch(fn))
            result = clone(fn, workdir)
            confirmed = bool(result and result.confirmed)
            if sec or not confirmed:
                reason = "security-tool" if sec else "no-longer-confirms"
                note = f" | revalidated ({run_id}): demoted ({reason})"
                db.conn.execute(
                    "UPDATE repo_findings SET status='rejected', "
                    "reasoning=COALESCE(reasoning,'')||? WHERE full_name=?", (note, fn))
                out["demoted"].append((fn, reason))
            else:
                payload = json.loads(row["raw_payload"] or "{}")
                if payload.get("confidence") != result.confidence:
                    payload["confidence"] = result.confidence
                    db.conn.execute("UPDATE repo_findings SET raw_payload=? WHERE full_name=?",
                                    (json.dumps(payload), fn))
                    out["retiered"].append((fn, result.confidence))
                else:
                    out["kept"].append((fn, result.confidence))
        db.conn.commit()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return out
