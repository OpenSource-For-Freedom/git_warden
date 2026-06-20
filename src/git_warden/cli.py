"""Command-line entry point: ``git-warden ingest``."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import config
from .db import Database
from .feeds import default_artifact_feeds, default_feeds
from .feeds.rss import CisaAdvisoriesFeed, GoogleNewsFeed
from .logging_setup import configure_logging
from .models import SeedActor
from .pipeline import run_ingestion
from .seeds import load_seeds


def _cmd_ingest(args: argparse.Namespace) -> int:
    configure_logging(json_output=not args.pretty_logs)
    config.ensure_dirs()

    from .notify import post_discord
    from .orchestration import load_playbook

    seeds = load_seeds(args.seeds)
    db = Database.open(args.db)
    try:
        summary = run_ingestion(
            db,
            default_feeds(),
            seeds,
            artifact_feeds=default_artifact_feeds(),
            run_id=args.run_id,
            min_sources=args.min_sources,
            write_artifacts=not args.no_artifacts,
            playbook=load_playbook(),
            on_alert=lambda m: post_discord(m),
        )
    finally:
        db.close()

    json.dump(summary, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def _cmd_probe(args: argparse.Namespace) -> int:
    """Hit ONE live feed and show what comes back.

    The incremental "do the returns look sane?" check -- run this against the
    network before trusting the full pipeline, so we can pivot cheaply.
    """
    configure_logging(json_output=False)
    if args.feed == "osm":
        return _probe_osm(args)
    if args.feed == "github":
        return _probe_github(args)

    feed = GoogleNewsFeed() if args.feed == "google" else CisaAdvisoriesFeed()
    seed = SeedActor(name=args.term)
    observations = feed.collect("probe", [seed])

    print(f"feed={feed.source.value} term={args.term!r} -> {len(observations)} observation(s)\n")
    for obs in observations[: args.limit]:
        title = obs.raw_payload.get("title", "")
        print(f"- [{obs.observed_at:%Y-%m-%d}] {title}")
        print(f"    actor_key={obs.actor_key}  url={obs.url}")
    if len(observations) > args.limit:
        print(f"\n... {len(observations) - args.limit} more (use --limit to show)")
    return 0


def _probe_osm(args: argparse.Namespace) -> int:
    """Raw OSM /query-latest fetch + dump for one ecosystem.

    Sends GW_OSM_API_KEY as ``Authorization: Bearer`` (per OSM docs) and the
    required ``ecosystem`` query parameter. A sanity check against live data.
    """
    import requests  # local import: only the OSM probe needs it directly

    url = args.url or config.osm_endpoint("query-latest")
    if not config.OSM_API_KEY:
        print("warning: GW_OSM_API_KEY is empty; the request will likely 401.")

    headers = {"User-Agent": config.USER_AGENT, "Accept": "application/json"}
    if config.OSM_API_KEY:
        headers["Authorization"] = f"Bearer {config.OSM_API_KEY}"

    print(f"GET {url}?ecosystem={args.ecosystem}  (auth: Bearer)")
    resp = requests.get(
        url, params={"ecosystem": args.ecosystem}, headers=headers, timeout=config.HTTP_TIMEOUT
    )
    print(f"HTTP {resp.status_code}  content-type={resp.headers.get('content-type')}"
          f"  bytes={len(resp.content)}\n")

    try:
        data = resp.json()
    except ValueError:
        print("body is not JSON; first 2000 chars:\n")
        print(resp.text[:2000])
        return 0

    if isinstance(data, dict):
        print(f"JSON object with keys: {list(data.keys())}")
        threats = data.get("threats") or data.get("results") or data.get("data")
        if isinstance(threats, list):
            shown = min(args.limit, len(threats))
            print(f"threats: {len(threats)} item(s). First {shown} shown:\n")
            print(json.dumps(threats[: args.limit], indent=2)[:4000])
        else:
            print(json.dumps(data, indent=2)[:4000])
    else:
        print(json.dumps(data, indent=2)[:4000])
    return 0


def _probe_github(args: argparse.Namespace) -> int:
    """Validate GitHub access + show real returns the scanner will work with.

    With --repo owner/name: fetch metadata + README. Otherwise: search repos for
    --term. Always prints the rate-limit headroom.
    """
    from .github import GitHubClient

    if not config.GITHUB_TOKEN:
        print("warning: GW_GITHUB_TOKEN not set -> unauthenticated (60/hr, no GraphQL).")
    client = GitHubClient()

    rate = client.rate_limit()
    print(f"rate limit: {rate.remaining}/{rate.limit} remaining\n")

    if args.repo:
        owner, _, name = args.repo.partition("/")
        repo = client.get_repo(owner, name)
        if not repo:
            print(f"repo {args.repo!r} not found (or private).")
            return 0
        print(f"{repo['full_name']}  stars={repo.get('stargazers_count')}  "
              f"pushed={repo.get('pushed_at')}")
        print(f"  description: {repo.get('description')}")
        readme = client.get_readme(owner, name)
        if readme:
            print(f"\n  README ({len(readme)} chars), first 400:\n")
            print(readme[:400])
        else:
            print("  (no README)")
        return 0

    items = client.search_repositories(args.term, per_page=args.limit)
    print(f"search {args.term!r} -> {len(items)} repo(s):")
    for item in items:
        print(f"- {item['full_name']}  stars={item.get('stargazers_count')}  "
              f"{item.get('html_url')}")
        print(f"    {item.get('description')}")
    return 0


def _cmd_lineage(args: argparse.Namespace) -> int:
    """Find repurposed clones/forks of the pinned red-team tools."""
    configure_logging(json_output=False)
    from .github import GitHubClient
    from .redteam import known_good_repos, load_redteam_tools
    from .scanning import find_lineage_candidates, score_repo

    tools = load_redteam_tools()
    known_good = known_good_repos(tools)
    all_terms = {term for t in tools for term in t.match_terms}
    if args.tool:
        tools = [t for t in tools if t.name.casefold() == args.tool.casefold()]
        if not tools:
            print(f"no pinned tool named {args.tool!r}.")
            return 2

    if not config.GITHUB_TOKEN:
        print("warning: GW_GITHUB_TOKEN not set -> unauthenticated (60/hr).\n")
    client = GitHubClient()

    for tool in tools:
        candidates = find_lineage_candidates(client, tool, known_good=known_good)
        candidates.sort(key=lambda c: (-len(c.signals), -c.stars))

        if not args.screen:
            print(f"\n=== {tool.name}: {len(candidates)} lineage candidate(s) ===")
            for cand in candidates[: args.limit]:
                print(f"- {cand.full_name}  [{cand.relation}]  stars={cand.stars}  "
                      f"signals={','.join(cand.signals) or '-'}")
                print(f"    {cand.html_url}  pushed={cand.pushed_at}")
            continue

        # Tier-1 screen the top candidates: fetch README, score name+README.
        scored = []
        for cand in candidates[: args.screen]:
            owner, _, name = cand.full_name.partition("/")
            try:
                readme = client.get_readme(owner, name)
            except Exception:  # noqa: BLE001 -- a single README fetch failing is non-fatal
                readme = None
            result = score_repo(
                name=cand.full_name,
                full_name=cand.full_name,
                description=cand.description,
                readme=readme,
                known_terms=all_terms,
                renamed_fork=(cand.relation == "fork" and "renamed" in cand.signals),
            )
            scored.append(result)
        scored.sort(key=lambda r: -r.score)

        promoted = [r for r in scored if r.tier2]
        print(f"\n=== {tool.name}: screened {len(scored)}, {len(promoted)} -> Tier-2 ===")
        for res in scored:
            mark = "CLONE" if res.tier2 else "skip "
            print(f"[{mark}] score={res.score}  {res.full_name}")
            print(f"        signals: {', '.join(res.signal_names) or '-'}")
    return 0


def _cmd_screen_artifacts(args: argparse.Namespace) -> int:
    """Tier-1 screen the OSM repo scan-list against GitHub (README + metadata).

    These OSM 'repositories' artifacts ARE malicious GitHub repos; this confirms
    them live and scores the README signals (obfuscation/exfil/remote-exec) that
    forks don't exercise.
    """
    configure_logging(json_output=False)
    from .github import GitHubClient
    from .redteam import load_redteam_tools
    from .refs import split_repo_ref
    from .scanning import score_repo

    if not config.GITHUB_TOKEN:
        print("warning: GW_GITHUB_TOKEN not set -> unauthenticated (60/hr).\n")
    db = Database.open(args.db)
    rows = db.list_artifacts(artifact_type="repo", limit=args.limit * 3)
    terms = {term for tool in load_redteam_tools() for term in tool.match_terms}
    client = GitHubClient()

    results, removed, screened = [], 0, 0
    for row in rows:
        ref = json.loads(row["raw_payload"]).get("resource_identifier") or row["name"]
        parsed = split_repo_ref(ref)
        if not parsed:
            continue
        owner, name = parsed
        repo = client.get_repo(owner, name)
        if repo is None:
            removed += 1  # 404: likely already taken down -- itself a signal
            continue
        readme = None
        try:
            readme = client.get_readme(owner, name)
        except Exception:  # noqa: BLE001
            pass
        results.append(
            score_repo(
                name=f"{owner}/{name}", full_name=f"{owner}/{name}",
                description=repo.get("description"), readme=readme, known_terms=terms,
            )
        )
        screened += 1
        if screened >= args.limit:
            break
    db.close()

    results.sort(key=lambda r: -r.score)
    print(f"\nscreened {screened} live OSM repos ({removed} returned 404/removed):")
    for res in results:
        mark = "CLONE" if res.tier2 else "skip "
        print(f"[{mark}] score={res.score}  {res.full_name}")
        print(f"        signals: {', '.join(res.signal_names) or '-'}")
    return 0


def _cmd_iocs(args: argparse.Namespace) -> int:
    """Aggregate the searchable IOC pivot set from ingested OSM data.

    These IOCs (exfil webhooks, C2 domains, hashes) are mirrored into GitHub
    code search to discover MORE malicious repos sharing the same infrastructure.
    """
    configure_logging(json_output=False)
    from .scanning.ioc import IocSet, extract_iocs

    db = Database.open(args.db)
    rows = db.list_artifacts()
    agg = IocSet()
    for row in rows:
        payload = json.loads(row["raw_payload"])
        text = "\n".join(
            [payload.get("payload_description") or "", payload.get("threat_description") or ""]
        )
        agg.merge(extract_iocs(text))
    db.close()

    print(f"IOC pivot set from {len(rows)} OSM artifacts:")
    print(f"  discord webhooks: {len(agg.webhooks)}")
    print(f"  telegram bots:    {len(agg.telegram)}")
    print(f"  exfil/C2 domains: {len(agg.domains)}")
    print(f"  file hashes:      {len(agg.hashes)}")
    print(f"\ntop exfil/C2 domains (mirror these into GitHub code search), limit {args.limit}:")
    for domain, count in agg.domains.most_common(args.limit):
        print(f"  {count:3}  {domain}")
    return 0


def _cmd_discover(args: argparse.Namespace) -> int:
    """Mirror OSM IOCs into GitHub code search to find NEW malicious repos."""
    configure_logging(json_output=False)
    import re

    from .github import GitHubClient
    from .redteam import known_good_repos, load_redteam_tools
    from .refs import repo_full_name
    from .scanning.discovery import classify_hit, search_iocs
    from .scanning.ioc import IocSet, extract_iocs, is_attacker_host

    if not config.GITHUB_TOKEN:
        print("error: GW_GITHUB_TOKEN required for GitHub code search. Add it to .env.")
        return 2

    db = Database.open(args.db)
    rows = db.list_artifacts()
    agg = IocSet()
    known = {r for r in known_good_repos(load_redteam_tools())}
    for row in rows:
        payload = json.loads(row["raw_payload"])
        text = "\n".join(
            [payload.get("payload_description") or "", payload.get("threat_description") or ""]
        )
        agg.merge(extract_iocs(text))
        full = repo_full_name(payload.get("resource_identifier") or row["name"])
        if full:
            known.add(full.casefold())  # already-known OSM repo -> report only NEW ones
    db.close()

    # Distinctive pivots only: attacker-owned-looking domains (ephemeral hosts /
    # suspicious TLDs) and deduped Discord webhook ids. Corporate/cloud domains
    # never match is_attacker_host, so they are not searched.
    ids = []
    for webhook in agg.webhooks:
        m = re.search(r"webhooks/(\d+)", webhook)
        if m:
            ids.append(m.group(1))
    domains = [d for d, _ in agg.domains.most_common(50) if is_attacker_host(d)]
    # Attacker domains are the strongest pivot -- search them first.
    terms = list(dict.fromkeys(domains + ids))[: args.max_iocs]

    print(f"mirroring {len(terms)} OSM IOCs into GitHub code search "
          f"(pace {args.pace}s)...\n  {terms}\n")
    client = GitHubClient()
    hits = search_iocs(client, terms, known=known, per_term=args.per_ioc, pace_seconds=args.pace)

    suspicious = [h for h in hits if classify_hit(h) == "suspicious"]
    defensive = [h for h in hits if classify_hit(h) == "defensive"]
    suspicious.sort(key=lambda h: -len(h.matched_iocs))

    print(f"\n-> {len(suspicious)} suspicious candidate repo(s) "
          f"(filtered {len(defensive)} defensive IOC-catalog repos):")
    for hit in suspicious:
        print(f"- {hit.full_name}  matched={hit.matched_iocs}  files={hit.paths[:3]}")
        print(f"    {hit.html_url}")
    return 0


def _cmd_hunt(args: argparse.Namespace) -> int:
    """Run the full hunt: discover -> Tier-1 -> registry -> Tier-2 -> Discord gold."""
    configure_logging(json_output=not args.pretty_logs)
    config.ensure_dirs()
    from datetime import UTC, datetime

    from .github import GitHubClient
    from .hunt import hunt
    from .notify import format_finding, post_discord
    from .redteam import load_redteam_tools

    if not config.GITHUB_TOKEN:
        print("warning: GW_GITHUB_TOKEN not set -> code search disabled, rate limited.")

    db = Database.open(args.db)
    run_id = args.run_id or f"hunt-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    try:
        summary = hunt(
            db, GitHubClient(), load_redteam_tools(),
            run_id=run_id,
            do_ioc=not args.no_ioc,
            do_lineage=not args.no_lineage,
            do_actor=not args.no_actor,
            do_enrich=not args.no_enrich,
            do_osm=not args.no_osm,
            do_tier2=args.scan,
            max_iocs=args.max_iocs,
            max_packages=args.max_packages,
            max_osm=args.max_osm,
            search_pace=args.pace,
            limit=args.limit,
            gold=args.gold,
            notifier=lambda row: post_discord(format_finding(row)),
        )
    finally:
        db.close()
    json.dump(summary, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def _cmd_review(args: argparse.Namespace) -> int:
    """Analyst validation of confirmed findings (human-in-the-loop, PRD 3)."""
    configure_logging(json_output=False)
    from .enums import RepoFindingStatus

    db = Database.open(args.db)
    try:
        if args.approve:
            n = db.set_finding_status(args.approve, RepoFindingStatus.VALIDATED.value)
            print(f"validated {args.approve}" if n else f"no finding {args.approve!r}")
        elif args.reject:
            n = db.set_finding_status(args.reject, RepoFindingStatus.REJECTED.value)
            print(f"rejected {args.reject}" if n else f"no finding {args.reject!r}")
        else:
            rows = db.findings_by_status("confirmed")
            print(f"{len(rows)} confirmed finding(s) pending validation:")
            for r in rows:
                print(f"- {r['full_name']}  ({r['detection_method']})  score={r['score']}")
    finally:
        db.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="git-warden", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    ingest = sub.add_parser("ingest", help="Run the ingestion pipeline over the seed actors.")
    ingest.add_argument("--db", type=Path, default=config.DB_PATH, help="SQLite path.")
    ingest.add_argument(
        "--seeds", type=Path, default=config.SEED_ACTORS_PATH, help="Seed-actor JSON file."
    )
    ingest.add_argument("--run-id", default=None, help="Override the generated run id.")
    ingest.add_argument(
        "--min-sources",
        type=int,
        default=config.MIN_CORROBORATING_SOURCES,
        help="Independent feeds required to promote an actor.",
    )
    ingest.add_argument("--no-artifacts", action="store_true", help="Skip CSV/JSON artifacts.")
    ingest.add_argument(
        "--pretty-logs", action="store_true", help="Human-readable logs instead of JSON."
    )
    ingest.set_defaults(func=_cmd_ingest)

    probe = sub.add_parser("probe", help="Fetch one live feed and print raw returns.")
    probe.add_argument("--feed", choices=["google", "cisa", "osm", "github"], default="google")
    probe.add_argument("--term", default="Lazarus Group", help="Actor/query/search term.")
    probe.add_argument("--limit", type=int, default=10, help="Max items to print.")
    probe.add_argument("--url", default=None, help="OSM endpoint override (else configured base).")
    probe.add_argument(
        "--ecosystem", default="npm", help="OSM ecosystem (e.g. npm, pypi, repositories)."
    )
    probe.add_argument("--repo", default=None, help="GitHub owner/name to fetch (else search).")
    probe.set_defaults(func=_cmd_probe)

    lineage = sub.add_parser(
        "lineage", help="Find repurposed clones/forks of pinned red-team tools."
    )
    lineage.add_argument("--tool", default=None, help="Pinned tool name (default: all).")
    lineage.add_argument("--limit", type=int, default=15, help="Max candidates per tool to print.")
    lineage.add_argument(
        "--screen", type=int, default=0, metavar="N",
        help="Tier-1 screen the top N candidates (fetch README + score name/README).",
    )
    lineage.set_defaults(func=_cmd_lineage)

    screen = sub.add_parser(
        "screen-artifacts", help="Tier-1 screen the OSM repo scan-list against GitHub."
    )
    screen.add_argument("--db", type=Path, default=config.DB_PATH, help="SQLite path.")
    screen.add_argument("--limit", type=int, default=10, help="Repos to screen (rate-limited).")
    screen.set_defaults(func=_cmd_screen_artifacts)

    review = sub.add_parser("review", help="Analyst validate confirmed findings (approve/reject).")
    review.add_argument("--db", type=Path, default=config.DB_PATH, help="SQLite path.")
    review.add_argument("--approve", metavar="OWNER/REPO", help="Mark a finding validated.")
    review.add_argument("--reject", metavar="OWNER/REPO", help="Mark a finding rejected.")
    review.set_defaults(func=_cmd_review)

    iocs = sub.add_parser("iocs", help="Aggregate the searchable IOC pivot set from OSM data.")
    iocs.add_argument("--db", type=Path, default=config.DB_PATH, help="SQLite path.")
    iocs.add_argument("--limit", type=int, default=20, help="Top domains to show.")
    iocs.set_defaults(func=_cmd_iocs)

    discover = sub.add_parser(
        "discover", help="Mirror OSM IOCs into GitHub code search to find new malicious repos."
    )
    discover.add_argument("--db", type=Path, default=config.DB_PATH, help="SQLite path.")
    discover.add_argument("--max-iocs", type=int, default=8, help="IOC terms to search.")
    discover.add_argument("--per-ioc", type=int, default=15, help="Results per IOC.")
    discover.add_argument("--pace", type=float, default=7.0, help="Seconds between searches.")
    discover.set_defaults(func=_cmd_discover)

    hunt_p = sub.add_parser(
        "hunt", help="Full hunt: discover -> Tier-1 -> registry -> Tier-2 -> Discord gold."
    )
    hunt_p.add_argument("--db", type=Path, default=config.DB_PATH, help="SQLite path.")
    hunt_p.add_argument("--run-id", default=None, help="Override the generated run id.")
    hunt_p.add_argument("--no-ioc", action="store_true", help="Skip IOC code-search discovery.")
    hunt_p.add_argument("--no-lineage", action="store_true", help="Skip lineage discovery.")
    hunt_p.add_argument("--no-actor", action="store_true", help="Skip actor-account discovery.")
    hunt_p.add_argument("--no-enrich", action="store_true",
                        help="Skip OSM enrichment (owner/package pivots).")
    hunt_p.add_argument("--no-osm", action="store_true",
                        help="Skip direct Tier-2 validation of OSM-labeled malicious repos.")
    hunt_p.add_argument("--scan", action="store_true", help="Run Tier-2 clone+scan.")
    hunt_p.add_argument("--gold", action="store_true", help="Deliver confirmed to Discord.")
    hunt_p.add_argument("--max-iocs", type=int, default=8, help="IOC terms to search.")
    hunt_p.add_argument("--max-packages", type=int, default=8,
                        help="Malicious package names to code-search (package pivot).")
    hunt_p.add_argument("--max-osm", type=int, default=60,
                        help="OSM-labeled repos to clone+validate in Tier-2.")
    hunt_p.add_argument("--pace", type=float, default=7.0,
                        help="Seconds between code searches. Code search allows ~10/min, so "
                             "keep this >=6; the client also backs off on a rate-limit response.")
    hunt_p.add_argument("--limit", type=int, default=0,
                        help="Cap candidates processed (0 = no cap). Bounds a run.")
    hunt_p.add_argument("--pretty-logs", action="store_true", help="Human-readable logs.")
    hunt_p.set_defaults(func=_cmd_hunt)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except Exception:  # noqa: BLE001 -- top-level guard prints a clean error
        logging.getLogger("git_warden.cli").exception("ingestion failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
