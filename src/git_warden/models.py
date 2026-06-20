"""Pydantic data contract for the ingestion layer.

Every feed adapter, regardless of source, must normalize its raw response into
these models before anything touches the database. Pydantic is the enforcement
point (PRD section 9: "Schema enforcement and normalization across sources").

Two layers of data:

* :class:`SourceObservation`; the raw breadcrumb. One record per claim a
  single feed makes in a single run. These are *retained forever*, including
  recognized false positives, so audits can confirm good data was never
  silently discarded (PRD section 11, "Retain everything").

* :class:`ThreatActor` (+ :class:`ActorIdentifier`, :class:`Campaign`); the
  normalized, deduplicated entity that observations roll up into. An actor is
  only trusted once independent feeds corroborate it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from .enums import (
    ActorCategory,
    ActorStatus,
    ArtifactStatus,
    ArtifactType,
    DetectionMethod,
    FeedSource,
    IdentifierType,
    Platform,
    RepoFindingStatus,
    RunStatus,
)


def _normalize_name(value: str) -> str:
    """Canonicalize a name/handle for dedup: trim, collapse space, casefold.

    Casefolding (not just lower()) so actor names that differ only by case or
    unicode case quirks collapse to one entity. Display casing is not preserved
    here by design; this value is the dedup key, not the label.
    """
    return " ".join(value.split()).casefold()


class ActorIdentifier(BaseModel):
    """A concrete handle that seeds downstream platform searches.

    Usernames, orgs, packages, domains; the things the GitHub/GitLab/Gitea
    scanning layers actually query on.
    """

    model_config = ConfigDict(frozen=True)

    identifier_type: IdentifierType
    value: str = Field(min_length=1)
    platform: Platform = Platform.GENERIC

    @field_validator("value")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("identifier value cannot be blank")
        return v


class Campaign(BaseModel):
    """A real-world campaign that links an actor to victims/sectors.

    These are the breadcrumbs from PRD section 10; power grid, hospitals,
    banks, schools, financial institutions, government targets.
    """

    name: str = Field(min_length=1)
    targets: list[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class SourceObservation(BaseModel):
    """One claim from one feed about one actor, captured during one run.

    This is the audit-grade raw layer. It is never mutated after insert and
    never deleted; the validator reads observations to decide promotion but does
    not rewrite them.
    """

    run_id: str
    source: FeedSource
    observed_at: datetime
    actor_name: str = Field(min_length=1)
    source_record_id: str | None = None
    url: HttpUrl | None = None
    category: ActorCategory = ActorCategory.UNKNOWN
    identifiers: list[ActorIdentifier] = Field(default_factory=list)
    campaigns: list[Campaign] = Field(default_factory=list)
    # The original feed payload, retained verbatim for audit / re-parsing.
    raw_payload: dict[str, Any] = Field(default_factory=dict)

    @property
    def actor_key(self) -> str:
        """Normalized dedup key linking this observation to a ThreatActor."""
        return _normalize_name(self.actor_name)


class ThreatActor(BaseModel):
    """Normalized, deduplicated actor; the entity downstream layers act on.

    ``corroborating_sources`` is the set of *distinct* feeds that have observed
    this actor; its size drives the promotion decision. Storing the set (rather
    than just a count) lets the validator stay idempotent across re-runs.
    """

    actor_key: str
    canonical_name: str
    category: ActorCategory = ActorCategory.UNKNOWN
    status: ActorStatus = ActorStatus.CANDIDATE
    corroborating_sources: set[FeedSource] = Field(default_factory=set)
    identifiers: list[ActorIdentifier] = Field(default_factory=list)
    campaigns: list[Campaign] = Field(default_factory=list)
    first_seen_run: str | None = None
    last_seen_run: str | None = None
    notes: str | None = None

    @field_validator("actor_key")
    @classmethod
    def _key_is_normalized(cls, v: str) -> str:
        norm = _normalize_name(v)
        if v != norm:
            raise ValueError("actor_key must already be normalized")
        return v

    @property
    def corroboration_count(self) -> int:
        return len(self.corroborating_sources)


class SeedActor(BaseModel):
    """A known threat actor that seeds feed queries (PRD section 7.1).

    Loaded from the version-controlled seed list. ``query_terms`` expands to the
    canonical name plus any aliases so a feed search catches all of them; every
    resulting observation is attributed back to this seed's :attr:`actor_key`.
    """

    name: str = Field(min_length=1)
    category: ActorCategory = ActorCategory.UNKNOWN
    aliases: list[str] = Field(default_factory=list)
    identifiers: list[ActorIdentifier] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()

    @property
    def actor_key(self) -> str:
        return _normalize_name(self.name)

    def query_terms(self) -> list[str]:
        """Canonical name plus aliases, de-duplicated, blanks dropped."""
        seen: set[str] = set()
        terms: list[str] = []
        for term in [self.name, *self.aliases]:
            t = term.strip()
            if t and t.casefold() not in seen:
                seen.add(t.casefold())
                terms.append(t)
        return terms


class MaliciousArtifact(BaseModel):
    """A known-malicious package or repository (PRD section 10, OSM).

    This is the bridge between ingestion and the Week-2 GitHub scanning layer:
    OSM populates it with already-labeled artifacts, and the scanner pulls its
    search list from it. ``actor_key`` links the artifact to a threat actor when
    the source attributes one; it stays ``None`` for unattributed indicators.

    ``ecosystem`` is intentionally a free string (npm, pypi, github, ...) until
    we see OSM's real vocabulary; the adapter can normalize it later.
    """

    artifact_type: ArtifactType
    name: str = Field(min_length=1)
    ecosystem: str = "unknown"
    source: FeedSource
    url: HttpUrl | None = None
    actor_key: str | None = None
    status: ArtifactStatus = ArtifactStatus.LABELED
    first_seen_run: str | None = None
    last_seen_run: str | None = None
    raw_payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name", "ecosystem")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class RedTeamTool(BaseModel):
    """A legitimate red-team tool in the known-good registry (doc 02 section 5).

    These are the *originals*. The scanner pins them, then treats clones/forks
    that share their lineage but differ in ownership or intent as candidates.
    ``org`` captures the organization-to-repository mapping (a parent project
    name often differs from its repo names). A name-only entry (empty ``repos``)
    is watched by name/alias; e.g. commercial tools with no official repo.
    """

    name: str = Field(min_length=1)
    org: str | None = None
    repos: list[str] = Field(default_factory=list)  # canonical "owner/name" anchors
    homepage: str | None = None
    aliases: list[str] = Field(default_factory=list)
    notes: str | None = None

    @field_validator("name")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()

    @property
    def match_terms(self) -> list[str]:
        """Name + aliases, for repo-name/README content matching."""
        terms, seen = [], set()
        for term in [self.name, *self.aliases]:
            t = term.strip()
            if t and t.casefold() not in seen:
                seen.add(t.casefold())
                terms.append(t)
        return terms


class RepoFinding(BaseModel):
    """A malicious (or candidate) GitHub repository; the program's product.

    The unified registry record (PRD section 1; doc 02 section 6). Carries the
    repo, why it's flagged, its attribution, and the provenance breadcrumbs that
    surfaced it. Confirmed findings are what reach the Discord gold feed.
    """

    full_name: str = Field(min_length=1)  # owner/repo (the dedup key)
    platform: Platform = Platform.GITHUB  # github | gitlab | gitea
    url: HttpUrl | None = None
    detection_method: DetectionMethod
    status: RepoFindingStatus = RepoFindingStatus.CANDIDATE
    score: int = 0
    code_hash: str | None = None  # whole-repo fingerprint -> cross-platform dedup
    actor_key: str | None = None  # attribution, when known
    reasoning: str | None = None  # plain-language why-flagged
    signals: list[str] = Field(default_factory=list)  # detection signals fired
    matched_iocs: list[str] = Field(default_factory=list)  # provenance breadcrumbs
    first_seen_run: str | None = None
    last_seen_run: str | None = None
    raw_payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("full_name")
    @classmethod
    def _normalize_full_name(cls, v: str) -> str:
        return v.strip().strip("/").casefold()


class RunSummary(BaseModel):
    """Per-run audit record (PRD section 13.1, "Full Transparency").

    Counts are kept loosely typed so each step can record whatever it tracked
    without a schema change every time a new metric is added.
    """

    run_id: str
    status: RunStatus = RunStatus.RUNNING
    started_at: datetime
    finished_at: datetime | None = None
    config_snapshot: dict[str, Any] = Field(default_factory=dict)
    counts: dict[str, int] = Field(default_factory=dict)
    notes: str | None = None
