"""OSV.dev malicious-packages feed; bulk known-bad npm/PyPI packages.

The OpenSSF ``malicious-packages`` project is the largest open corpus of
confirmed-malicious open-source packages (tens of thousands of npm/PyPI
advisories). OSV.dev republishes it keyed on an *artifact* rather than a threat
actor, so it slots into the same indicator lane as OSM (:class:`OsmFeed`) and
directly seeds the Week-2 GitHub scanning layer.

Rather than hit OSV's per-package REST API tens of thousands of times, we pull
OSV's per-ecosystem *export* zip -- ``{ecosystem}/all.zip`` -- once per
ecosystem. Each zip is a flat archive of one JSON document per advisory. The
export mixes every advisory class (CVE-, GHSA-, PYSEC-, ...); the malicious
packages live under the ``MAL-`` id namespace, so we keep only ``MAL-*`` records
and drop the rest (those are ordinary vulnerabilities, not malware).

The exports are large, so this feed is opt-in (see ``default_artifact_feeds``)
and bounded to ``max_records`` artifacts per run to keep ingest quick. It is
keyless. Downloads and per-record parsing are defensive: a failed ecosystem
download or a malformed record is logged and skipped, never fatal.
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
from collections.abc import Iterator
from typing import Any

from ..enums import ArtifactType, FeedSource
from ..models import MaliciousArtifact
from .base import ArtifactFeed
from .http import HttpClient

log = logging.getLogger(__name__)

# OSV's per-ecosystem export bucket. Each object is a zip of one JSON advisory
# per member; public and keyless.
_EXPORT_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"

# OSV ecosystem name -> our free-string ecosystem label (matches OSM's vocab).
# OSV spells PyPI "PyPI"; we normalize to lowercase "pypi" for a single vocab.
_ECOSYSTEM_MAP = {"npm": "npm", "PyPI": "pypi"}


def _iter_mal_records(zip_bytes: bytes) -> Iterator[dict[str, Any]]:
    """Yield the ``MAL-*`` records from one OSV per-ecosystem export zip.

    Everything else (CVE-, GHSA-, PYSEC-, unreadable members) is skipped: only
    the ``MAL-`` id namespace is the malicious-packages corpus. A member that is
    not valid JSON is logged and skipped rather than aborting the whole export.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except Exception as exc:  # noqa: BLE001 - a corrupt download must not crash the feed
        log.warning("osv: unreadable export zip", extra={"context": {"err": str(exc)}})
        return
    with archive:
        for member in archive.namelist():
            if not member.endswith(".json"):
                continue
            try:
                record = json.loads(archive.read(member))
            except Exception as exc:  # noqa: BLE001 - one bad member must not lose the rest
                log.warning(
                    "osv: unreadable zip member",
                    extra={"context": {"member": member, "err": str(exc)}},
                )
                continue
            if isinstance(record, dict) and str(record.get("id", "")).startswith("MAL-"):
                yield record


def _artifact_from_record(record: dict[str, Any]) -> MaliciousArtifact | None:
    """Build a PACKAGE artifact from one ``MAL-`` OSV record, or None if unusable.

    Package name and ecosystem come from ``affected[0].package``; a record that
    names no package is not actionable for the scanner and is dropped.
    """
    affected = record.get("affected") or []
    if not affected:
        return None
    package = affected[0].get("package") or {}  # AttributeError if affected[0] isn't a dict
    name = package.get("name")
    if not name:
        return None
    osv_ecosystem = str(package.get("ecosystem") or "")
    ecosystem = _ECOSYSTEM_MAP.get(osv_ecosystem, osv_ecosystem.lower() or "unknown")
    return MaliciousArtifact(
        artifact_type=ArtifactType.PACKAGE,
        name=str(name),
        ecosystem=ecosystem,
        source=FeedSource.OPEN_SOURCE_MALWARE,
        raw_payload=record,  # full OSV record retained for audit / re-parsing
    )


class OsvMaliciousFeed(ArtifactFeed):
    """Pull OSV's per-ecosystem export zips for OpenSSF malicious packages."""

    source = FeedSource.OPEN_SOURCE_MALWARE

    def __init__(
        self,
        http: HttpClient | None = None,
        ecosystems: tuple[str, ...] = ("npm", "PyPI"),
        max_records: int = 200,
    ) -> None:
        super().__init__(http)
        self.ecosystems = tuple(ecosystems)
        self.max_records = max_records

    def collect_artifacts(self, run_id: str) -> list[MaliciousArtifact]:  # noqa: ARG002
        artifacts: list[MaliciousArtifact] = []
        for ecosystem in self.ecosystems:
            if len(artifacts) >= self.max_records:  # bound is per run, across ecosystems
                break
            url = _EXPORT_URL.format(ecosystem=ecosystem)
            try:
                data = self.http.get_bytes(url)
            except Exception as exc:  # one ecosystem failing must not lose the rest
                log.warning(
                    "osv: ecosystem download failed",
                    extra={"context": {"ecosystem": ecosystem, "err": str(exc)}},
                )
                continue
            for record in _iter_mal_records(data):
                if len(artifacts) >= self.max_records:
                    break
                try:
                    artifact = _artifact_from_record(record)
                except Exception as exc:  # noqa: BLE001 - a malformed record must not crash
                    log.warning(
                        "osv: malformed record skipped",
                        extra={"context": {"id": record.get("id"), "err": str(exc)}},
                    )
                    continue
                if artifact is not None:
                    artifacts.append(artifact)
        return artifacts
