"""MITRE ATT&CK Groups adapter; authoritative actor-registry corroboration.

Unlike the RSS feeds, this is a slow-moving *truth-set*: the enterprise ATT&CK
bundle (~53 MB) lists known intrusion sets with their aliases. It answers "is
this a recognized, named threat actor?"; an independent signal from news
activity, so an actor seen in both can be promoted (PRD section 11).

The bundle is downloaded once and cached; it is only re-fetched when the cache
exceeds ``MITRE_CACHE_MAX_AGE_DAYS``. ``parse_attack_groups`` is pure so it can
be tested against a small fixture bundle.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..config import CACHE_DIR, MITRE_ATTACK_URL, MITRE_CACHE_MAX_AGE_DAYS
from ..enums import FeedSource, IdentifierType, Platform
from ..models import ActorIdentifier, SeedActor, SourceObservation
from .base import Feed

log = logging.getLogger(__name__)


@dataclass
class AttackGroup:
    """One MITRE ATT&CK intrusion-set (threat group)."""

    name: str
    aliases: list[str]
    url: str | None
    description: str = ""

    def terms(self) -> set[str]:
        """Casefolded name + aliases for exact-token matching against seeds."""
        return {t.casefold() for t in [self.name, *self.aliases] if t and t.strip()}


def parse_attack_groups(bundle: dict) -> list[AttackGroup]:
    """Extract active intrusion-set groups from an ATT&CK STIX bundle."""
    groups: list[AttackGroup] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        url = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                url = ref.get("url")
                break
        groups.append(
            AttackGroup(
                name=obj.get("name", ""),
                aliases=list(obj.get("aliases", []) or []),
                url=url,
                description=obj.get("description", ""),
            )
        )
    return groups


def _now() -> datetime:
    return datetime.now(UTC)


class MitreAttackFeed(Feed):
    """Match seed actors against the cached MITRE ATT&CK group registry."""

    source = FeedSource.MITRE_ATTACK

    def __init__(
        self,
        http=None,
        url: str = MITRE_ATTACK_URL,
        cache_path: Path | None = None,
        max_age_days: int = MITRE_CACHE_MAX_AGE_DAYS,
    ) -> None:
        super().__init__(http)
        self.url = url
        self.cache_path = cache_path or (CACHE_DIR / "mitre_enterprise_attack.json")
        self.max_age_days = max_age_days

    def _cache_fresh(self) -> bool:
        if not self.cache_path.exists():
            return False
        mtime = datetime.fromtimestamp(self.cache_path.stat().st_mtime, tz=UTC)
        return (_now() - mtime) < timedelta(days=self.max_age_days)

    def _load_bundle(self) -> dict:
        if self._cache_fresh():
            log.info("mitre: using cache", extra={"context": {"path": str(self.cache_path)}})
            return json.loads(self.cache_path.read_text(encoding="utf-8"))

        log.info("mitre: downloading bundle", extra={"context": {"url": self.url}})
        text = self.http.get_text(self.url)
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(text, encoding="utf-8")
        except OSError as exc:  # caching is best-effort; a failure must not abort the run
            log.warning("mitre: cache write failed", extra={"context": {"err": str(exc)}})
        return json.loads(text)

    def collect(self, run_id: str, seeds: list[SeedActor]) -> list[SourceObservation]:
        groups = parse_attack_groups(self._load_bundle())
        observations: list[SourceObservation] = []
        for seed in seeds:
            seed_terms = {t.casefold() for t in seed.query_terms()}
            for group in groups:
                if seed_terms & group.terms():
                    observations.append(self._observation(run_id, seed, group))
                    break  # one corroborating observation per seed from this source
        return observations

    def _observation(self, run_id: str, seed: SeedActor, group: AttackGroup) -> SourceObservation:
        # Enrich with ATT&CK aliases (minus the seed's own name) as ALIAS identifiers.
        aliases = [
            ActorIdentifier(
                identifier_type=IdentifierType.ALIAS, value=alias, platform=Platform.GENERIC
            )
            for alias in group.aliases
            if alias.strip() and alias.casefold() != seed.name.casefold()
        ]
        return SourceObservation(
            run_id=run_id,
            source=self.source,
            observed_at=_now(),
            actor_name=seed.name,
            category=seed.category,
            source_record_id=group.url or group.name,
            url=group.url,
            identifiers=aliases,
            raw_payload={
                "mitre_name": group.name,
                "aliases": group.aliases,
                "url": group.url,
            },
        )
