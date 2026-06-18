"""Week-2 scanning: red-team clone/lineage detection and (later) Tier-1/2 scans."""

from .bash_scanner import BashFinding, scan_repo, score_findings
from .discovery import RepoHit, build_search_terms, classify_hit, search_iocs
from .ioc import IocSet, extract_iocs, is_attacker_host
from .lineage import LineageCandidate, find_lineage_candidates
from .screening import ScreeningResult, score_repo
from .tier2 import Tier2Result, analyze_repo, scan_candidate

__all__ = [
    "LineageCandidate",
    "find_lineage_candidates",
    "ScreeningResult",
    "score_repo",
    "IocSet",
    "extract_iocs",
    "is_attacker_host",
    "RepoHit",
    "search_iocs",
    "classify_hit",
    "build_search_terms",
    "BashFinding",
    "scan_repo",
    "score_findings",
    "Tier2Result",
    "analyze_repo",
    "scan_candidate",
]
