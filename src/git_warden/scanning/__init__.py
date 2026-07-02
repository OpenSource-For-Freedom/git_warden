"""Week-2 scanning: red-team clone/lineage detection and (later) Tier-1/2 scans."""

from .actor_search import AccountRepo, find_actor_account_repos
from .bash_scanner import BashFinding, scan_repo, score_findings
from .content_scanner import scan_content
from .discovery import (
    RepoHit,
    build_search_terms,
    classify_hit,
    is_defensive_repo,
    search_iocs,
)
from .enrichment import OwnerRepo, find_owner_repos
from .ioc import IocSet, extract_iocs, is_attacker_host
from .lineage import LineageCandidate, find_lineage_candidates
from .manifest_scanner import scan_manifests
from .newsdiscovery import NewsHit, search_google_news, search_hackernews
from .screening import ScreeningResult, matches_known_tool, score_repo
from .tier2 import Tier2Result, analyze_repo, scan_candidate

__all__ = [
    "LineageCandidate",
    "find_lineage_candidates",
    "ScreeningResult",
    "score_repo",
    "matches_known_tool",
    "IocSet",
    "extract_iocs",
    "is_attacker_host",
    "RepoHit",
    "search_iocs",
    "classify_hit",
    "is_defensive_repo",
    "build_search_terms",
    "OwnerRepo",
    "find_owner_repos",
    "BashFinding",
    "scan_repo",
    "score_findings",
    "scan_manifests",
    "scan_content",
    "Tier2Result",
    "analyze_repo",
    "scan_candidate",
    "AccountRepo",
    "find_actor_account_repos",
    "NewsHit",
    "search_hackernews",
    "search_google_news",
]
