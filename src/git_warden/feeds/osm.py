"""OpenSourceMalware (OSM) adapter -- labeled malicious packages/repos.

OSM is an *indicator* source (PRD section 10): records key on an artifact, not a
threat actor. We ingest the free ``GET /query-latest`` endpoint -- using it as
designed keeps us within OSM's ToS.

``query-latest`` takes a required ``ecosystem`` query parameter, so we poll each
package ecosystem plus ``repositories``. The live response envelope is
``{count, threats: [...]}`` (no top-level ecosystem), where each threat looks
like::

    {id, report_type, registry, resource_identifier, package_name,
     severity_level, status, tags, threat_description, payload_description,
     verified_by, first_seen, ...}

Artifact type is derived from each record's ``report_type`` (``package`` ->
PACKAGE, ``repositories`` -> REPO); other report types (domain, ip, ...) are
skipped -- they are IOCs, not packages/repos. The whole record is retained in
``raw_payload``, which carries the IOC-rich ``payload_description`` for Week-2
and the Discord gold output. Note: query-latest carries no package-author/
publisher field, so actor correlation isn't possible from this endpoint.

``parse_query_latest`` is pure so it can be tested against a fixture response.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ..config import OSM_API_KEY, osm_endpoint
from ..enums import ArtifactType, FeedSource
from ..models import MaliciousArtifact
from ..refs import repo_full_name
from .base import ArtifactFeed

log = logging.getLogger(__name__)

# Ecosystems OSM supports for query-latest. We poll the package registries plus
# "repositories"; "domains" is excluded -- it is an IOC type, not a package/repo.
PACKAGE_ECOSYSTEMS = (
    "npm",
    "pypi",
    "crates",
    "nuget",
    "maven",
    "go",
    "packagist",
    "rubygems",
    "vscode",
    "openvsx",
)
REPOSITORY_ECOSYSTEM = "repositories"
DEFAULT_ECOSYSTEMS = (*PACKAGE_ECOSYSTEMS, REPOSITORY_ECOSYSTEM)

# Per-record report_type -> artifact type. Other report types (domain, ip,
# wallet, container, ...) are IOCs, not packages/repos, and are skipped.
_TYPE_BY_REPORT = {
    "package": ArtifactType.PACKAGE,
    "repositories": ArtifactType.REPO,
    "repository": ArtifactType.REPO,
    "repo": ArtifactType.REPO,
}


def _threats(payload: Any) -> list[dict]:
    """Pull the threat list out of the {count, threats} envelope (or a wrapper)."""
    if isinstance(payload, dict):
        for key in ("threats", "results", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [t for t in value if isinstance(t, dict)]
    if isinstance(payload, list):  # defensive: bare array
        return [t for t in payload if isinstance(t, dict)]
    return []


def parse_query_latest(payload: Any) -> list[MaliciousArtifact]:
    """Parse one /query-latest response into package/repo artifacts.

    Type comes from each record's ``report_type`` (the live envelope has no
    top-level ecosystem). ``ecosystem`` is taken from the record's ``registry``.
    """
    artifacts: list[MaliciousArtifact] = []
    skipped = 0
    for threat in _threats(payload):
        artifact_type = _TYPE_BY_REPORT.get(str(threat.get("report_type", "")).lower())
        if artifact_type is None:
            skipped += 1
            continue

        ref = threat.get("resource_identifier") or threat.get("package_name")
        if artifact_type is ArtifactType.REPO:
            # Repos: canonical name is owner/repo parsed from the URL; the raw
            # resource_identifier is often a full https://github.com/... link.
            name = repo_full_name(ref) or threat.get("package_name")
            ecosystem = "github" if ref and "github.com" in str(ref).lower() else "repositories"
            url = ref if isinstance(ref, str) and ref.startswith("http") else None
        else:
            name = threat.get("package_name") or ref
            ecosystem = str(threat.get("registry") or "unknown")
            url = None

        if not name:
            skipped += 1
            continue
        artifacts.append(
            MaliciousArtifact(
                artifact_type=artifact_type,
                name=str(name),
                ecosystem=ecosystem,
                source=FeedSource.OPEN_SOURCE_MALWARE,
                url=url,
                actor_key=None,  # query-latest carries no actor/publisher field
                raw_payload=threat,
            )
        )
    if skipped:
        log.info(
            "osm: skipped non-package/repo or unnamed reports",
            extra={"context": {"skipped": skipped, "kept": len(artifacts)}},
        )
    return artifacts


class OsmFeed(ArtifactFeed):
    """Poll OSM's query-latest across ecosystems for malicious artifacts."""

    source = FeedSource.OPEN_SOURCE_MALWARE

    def __init__(self, http=None, token: str | None = None, ecosystems=DEFAULT_ECOSYSTEMS) -> None:
        super().__init__(http)
        self.token = token or OSM_API_KEY
        self.ecosystems = tuple(ecosystems)

    def current_repo_index(self) -> dict[str, dict]:
        """Live OSM ``repositories`` feed as {full_name.casefold(): intel}.

        Used to re-check an OSM-repo lead at hunt time so a stale/delisted lead
        from a prior ingest is dropped before we attribute it to OSM. NOTE: the
        free API only exposes ``query-latest`` (a recent-window firehose, not a
        per-repo lookup), so "present here" means "in OSM's current window".
        Returns an empty dict on any failure (caller treats as 'cannot verify').
        """
        if not self.token:
            return {}
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        try:
            text = self.http.get_text(
                osm_endpoint("query-latest"),
                params={"ecosystem": REPOSITORY_ECOSYSTEM}, headers=headers,
            )
            artifacts = parse_query_latest(json.loads(text))
        except Exception as exc:  # noqa: BLE001 -- verification is best-effort
            log.warning("osm: live repo re-check failed",
                        extra={"context": {"err": str(exc)}})
            return {}
        index: dict[str, dict] = {}
        for art in artifacts:
            payload = art.raw_payload or {}
            index[art.name.casefold()] = {
                "source": "open_source_malware",
                "severity": payload.get("severity_level"),
                "tags": payload.get("tags") or [],
                "threat": payload.get("threat_description")
                or payload.get("payload_description"),
            }
        return index

    def collect_artifacts(self, run_id: str) -> list[MaliciousArtifact]:  # noqa: ARG002
        if not self.token:
            raise RuntimeError("OSM token missing: set GW_OSM_API_KEY")
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        url = osm_endpoint("query-latest")

        artifacts: list[MaliciousArtifact] = []
        for ecosystem in self.ecosystems:
            try:
                text = self.http.get_text(url, params={"ecosystem": ecosystem}, headers=headers)
                artifacts.extend(parse_query_latest(json.loads(text)))
            except Exception as exc:  # one ecosystem failing must not lose the rest
                log.warning(
                    "osm: ecosystem fetch failed",
                    extra={"context": {"ecosystem": ecosystem, "err": str(exc)}},
                )
        return artifacts
