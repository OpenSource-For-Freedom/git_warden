"""Offline tests for the OSV malicious-packages adapter (in-memory zip, no network)."""

from __future__ import annotations

import io
import json
import zipfile

from git_warden.enums import ArtifactType, FeedSource
from git_warden.feeds.osv import OsvMaliciousFeed

# A real OSV export is a flat zip of one JSON advisory per member. The corpus
# mixes advisory classes; only the "MAL-" id namespace is a malicious package.
MAL_NPM_RECORD = {
    "id": "MAL-2024-0001",
    "summary": "Malicious code in evil-pkg (npm)",
    "affected": [{"package": {"name": "evil-pkg", "ecosystem": "npm"}}],
}
MAL_PYPI_RECORD = {
    "id": "MAL-2024-0002",
    "affected": [{"package": {"name": "evil-dist", "ecosystem": "PyPI"}}],
}
# A regular vulnerability (not "MAL-") -> must be skipped, it is not malware.
CVE_RECORD = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "affected": [{"package": {"name": "innocent-lib", "ecosystem": "npm"}}],
}
# A "MAL-" record whose affected[0] isn't a dict -> must be skipped without error.
MALFORMED_RECORD = {"id": "MAL-2024-9999", "affected": ["not-a-package-object"]}


class FakeBytesHttpClient:
    """Returns canned zip bytes for get_bytes; records calls for assertions.

    Optionally raises to simulate a failed ecosystem download.
    """

    def __init__(self, content: bytes, *, error: Exception | None = None) -> None:
        self.content = content
        self.error = error
        self.calls: list[str] = []

    def get_bytes(self, url: str, *, params=None, headers=None) -> bytes:
        self.calls.append(url)
        if self.error is not None:
            raise self.error
        return self.content


def _make_zip(records: dict[str, dict]) -> bytes:
    """Pack {member_name: record} into an in-memory OSV-style export zip."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for member, record in records.items():
            archive.writestr(member, json.dumps(record))
    return buf.getvalue()


def test_keeps_only_mal_records():
    zip_bytes = _make_zip(
        {
            "MAL-2024-0001.json": MAL_NPM_RECORD,
            "GHSA-xxxx-yyyy-zzzz.json": CVE_RECORD,  # skipped: not MAL-
            "MAL-2024-9999.json": MALFORMED_RECORD,  # skipped: malformed, no crash
        }
    )
    http = FakeBytesHttpClient(zip_bytes)
    feed = OsvMaliciousFeed(http=http, ecosystems=("npm",))

    artifacts = feed.collect_artifacts("run-1")

    # Only the well-formed MAL- npm package survives.
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.artifact_type is ArtifactType.PACKAGE
    assert art.name == "evil-pkg"
    assert art.ecosystem == "npm"
    assert art.source is FeedSource.OPEN_SOURCE_MALWARE
    # Full OSV record retained for audit / re-parsing.
    assert art.raw_payload["id"] == "MAL-2024-0001"


def test_pypi_ecosystem_normalized():
    # OSV spells it "PyPI"; we normalize to lowercase "pypi".
    zip_bytes = _make_zip({"MAL-2024-0002.json": MAL_PYPI_RECORD})
    feed = OsvMaliciousFeed(http=FakeBytesHttpClient(zip_bytes), ecosystems=("PyPI",))

    artifacts = feed.collect_artifacts("run-1")

    assert len(artifacts) == 1
    assert artifacts[0].ecosystem == "pypi"
    assert artifacts[0].name == "evil-dist"


def test_max_records_bounds_the_count():
    records = {
        f"MAL-2024-{i:04d}.json": {
            "id": f"MAL-2024-{i:04d}",
            "affected": [{"package": {"name": f"evil-{i}", "ecosystem": "npm"}}],
        }
        for i in range(5)
    }
    feed = OsvMaliciousFeed(
        http=FakeBytesHttpClient(_make_zip(records)), ecosystems=("npm",), max_records=2
    )

    artifacts = feed.collect_artifacts("run-1")

    assert len(artifacts) == 2  # bounded per run so ingest stays quick


def test_failed_download_is_skipped_not_fatal():
    http = FakeBytesHttpClient(b"", error=RuntimeError("503 from bucket"))
    feed = OsvMaliciousFeed(http=http, ecosystems=("npm", "PyPI"))

    artifacts = feed.collect_artifacts("run-1")

    # Both ecosystems attempted; both fail defensively -> empty, no exception.
    assert artifacts == []
    assert len(http.calls) == 2
