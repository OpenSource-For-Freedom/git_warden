"""Controlled vocabularies for the ingestion data contract.

These enums are the shared language between the ingestion layer (Week 1) and
the downstream scanning layers (Week 2+). Values are stored as their string
form in SQLite, so renaming a value is a schema migration, not a refactor.
"""

from __future__ import annotations

from enum import StrEnum


class FeedSource(StrEnum):
    """Independent threat-intelligence feeds (PRD section 10).

    "Independent" matters: multi-source corroboration counts *distinct* feeds,
    so each real, separately-operated source gets exactly one value here.
    """

    GOOGLE_RSS = "google_rss"
    OSINT = "osint"
    NVD = "nvd"
    OPEN_SOURCE_MALWARE = "open_source_malware"
    FBI_CISA = "fbi_cisa"
    MITRE_ATTACK = "mitre_attack"
    GITHUB = "github"


class ActorCategory(StrEnum):
    """Threat-actor categories from PRD section 7.1."""

    APT = "apt"
    NATION_STATE = "nation_state"
    FEDERATED_AFFILIATED = "federated_affiliated"
    HACKTIVIST = "hacktivist"
    CARTEL_AFFILIATED = "cartel_affiliated"
    UNKNOWN = "unknown"


class ActorStatus(StrEnum):
    """Lifecycle of a threat actor through the validator (PRD section 11).

    The validator is the strictest component: an actor is only ``PROMOTED``
    once at least two independent feeds corroborate it. A single feed leaves it
    ``QUARANTINED`` for manual review, never auto-ingested as confirmed.
    """

    CANDIDATE = "candidate"  # newly observed, not yet evaluated
    QUARANTINED = "quarantined"  # single-source; awaits manual review
    PROMOTED = "promoted"  # >= 2 independent feeds corroborate
    REJECTED = "rejected"  # recognized false positive (retained, not deleted)


class IdentifierType(StrEnum):
    """Kinds of actor identifier that seed downstream platform searches."""

    USERNAME = "username"
    ORGANIZATION = "organization"
    EMAIL = "email"
    ALIAS = "alias"
    PACKAGE = "package"
    DOMAIN = "domain"
    HASH = "hash"


class Platform(StrEnum):
    """Hosting platforms an identifier may belong to."""

    GITHUB = "github"
    GITLAB = "gitlab"
    GITEA = "gitea"
    GENERIC = "generic"  # not platform-specific (e.g. an email or domain)


class RunStatus(StrEnum):
    """State of an ingestion run."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ArtifactType(StrEnum):
    """A labeled malicious artifact is either a package or a repository."""

    PACKAGE = "package"
    REPO = "repo"


class RepoFindingStatus(StrEnum):
    """Lifecycle of a malicious-GitHub-repo finding (the product).

    ``candidate`` -> discovered (lineage/IOC/actor), not yet scanned.
    ``screened`` -> passed Tier-1 (name/README), queued for Tier-2.
    ``confirmed`` -> Tier-2 evidence; gold-eligible for Discord.
    ``rejected`` -> recognized false positive (retained, not deleted).
    """

    CANDIDATE = "candidate"
    SCREENED = "screened"
    CONFIRMED = "confirmed"  # Tier-2 evidence; delivered to Discord for validation
    VALIDATED = "validated"  # analyst-approved (PRD section 3) -> broader distribution
    REJECTED = "rejected"


class DetectionMethod(StrEnum):
    """How a candidate repo was discovered (provenance breadcrumb)."""

    IOC_SEARCH = "ioc_search"  # matched an OSM IOC in GitHub code search
    REDTEAM_LINEAGE = "redteam_lineage"  # clone/fork of a pinned red-team tool
    ACTOR_ACCOUNT = "actor_account"  # under a promoted threat-actor account
    OSM_REPOSITORY = "osm_repository"  # OSM-flagged repository artifact
    MALICIOUS_OWNER = "malicious_owner"  # other repo by a known-malicious-repo owner
    PACKAGE_REF = "package_ref"  # references a known-malicious package
    PACKAGE_SOURCE = "package_source"  # GitHub source repo of a known-malicious package
    SIGNATURE_MATCH = "signature_match"  # shares a confirmed malware code signature
    NEWS_MENTION = "news_mention"  # named in a Hacker News / Google News writeup


class ArtifactStatus(StrEnum):
    """Lifecycle of a malicious artifact (mirrors the actor lifecycle).

    OSM provides community-verified artifacts, so they enter as ``LABELED``;
    a reviewer may confirm or reject them, and rejection is sticky.
    """

    LABELED = "labeled"  # ingested from a labeling source (e.g. OSM)
    CONFIRMED = "confirmed"  # analyst-confirmed
    REJECTED = "rejected"  # recognized false positive (retained, not deleted)
