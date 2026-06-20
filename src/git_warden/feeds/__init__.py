"""Feed adapters: threat-intel sources normalized to SourceObservation."""

from ..config import OSM_API_KEY
from .base import ArtifactFeed, Feed
from .http import HttpClient, RequestsHttpClient
from .mitre import MitreAttackFeed, parse_attack_groups
from .osm import OsmFeed, parse_query_latest
from .rss import CisaAdvisoriesFeed, GoogleNewsFeed, parse_feed

__all__ = [
    "Feed",
    "ArtifactFeed",
    "HttpClient",
    "RequestsHttpClient",
    "GoogleNewsFeed",
    "CisaAdvisoriesFeed",
    "MitreAttackFeed",
    "OsmFeed",
    "parse_feed",
    "parse_attack_groups",
    "parse_query_latest",
]


def default_feeds() -> list[Feed]:
    """The actor feeds run during ingestion.

    Google News supplies current activity; MITRE ATT&CK supplies authoritative
    actor attribution; together they satisfy the two-source promotion rule.
    CISA stays in the mix as a supplementary source.
    """
    return [GoogleNewsFeed(), MitreAttackFeed(), CisaAdvisoriesFeed()]


def default_artifact_feeds() -> list[ArtifactFeed]:
    """Indicator feeds populating the malicious-artifact scan list.

    OSM is included only when a token is configured, so local/CI runs without
    the key simply skip it rather than failing.
    """
    return [OsmFeed()] if OSM_API_KEY else []
