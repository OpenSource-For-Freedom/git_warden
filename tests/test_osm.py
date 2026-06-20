"""Offline tests for the OSM adapter, matching the documented query-latest shape."""

from __future__ import annotations

import json

import pytest
from conftest import FakeHttpClient, make_fake_artifact_feed, utcnow

from git_warden.db import Database
from git_warden.enums import ArtifactType, FeedSource
from git_warden.feeds.osm import OsmFeed, parse_query_latest
from git_warden.pipeline import run_ingestion

# Live envelope: {count, threats: [...]}; no top-level ecosystem. Type comes
# from each record's report_type; ecosystem from registry. Mirrors real data.
NPM_RESPONSE = {
    "count": 2,
    "threats": [
        {
            "id": "uuid-1",
            "report_type": "package",
            "registry": "npm",
            "resource_identifier": "npm/@scope/evil-pkg",
            "package_name": "@scope/evil-pkg",
            "severity_level": "critical",
            "status": "verified",
            "threat_description": "Data exfiltration",
            "tags": ["infostealer", "install-script"],
            "verified_by": "6mile",
        },
        {
            "id": "uuid-2",
            "report_type": "package",
            "registry": "npm",
            "resource_identifier": "npm/sneaky-lib",
            "package_name": "sneaky-lib",
            "severity_level": "high",
            "tags": ["backdoor"],
        },
    ],
}

REPOS_RESPONSE = {
    "count": 1,
    "threats": [
        {
            "id": "uuid-3",
            "report_type": "repositories",
            "registry": "",
            "resource_identifier": "https://github.com/evil-org/evil-repo",
            "package_name": "evil-repo",
        }
    ],
}

DOMAINS_RESPONSE = {
    "count": 1,
    "threats": [
        {"id": "uuid-4", "report_type": "domain", "registry": "dns", "package_name": "evil.com"}
    ],
}


def test_parse_npm_packages():
    artifacts = parse_query_latest(NPM_RESPONSE)
    assert len(artifacts) == 2
    assert all(a.artifact_type is ArtifactType.PACKAGE for a in artifacts)
    assert all(a.source is FeedSource.OPEN_SOURCE_MALWARE for a in artifacts)
    assert artifacts[0].name == "@scope/evil-pkg"
    assert artifacts[0].ecosystem == "npm"  # from the record's registry
    # Full record retained, incl. the IOC-rich description fields and tags.
    assert artifacts[0].raw_payload["threat_description"] == "Data exfiltration"
    assert "infostealer" in artifacts[0].raw_payload["tags"]


def test_parse_repositories_maps_to_repo():
    artifacts = parse_query_latest(REPOS_RESPONSE)
    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.artifact_type is ArtifactType.REPO
    # Canonical owner/repo parsed from the resource_identifier URL.
    assert art.name == "evil-org/evil-repo"
    assert art.ecosystem == "github"
    assert str(art.url) == "https://github.com/evil-org/evil-repo"


def test_parse_domains_skipped():
    # domains are IOCs, not packages/repos -> not ingested into the scan list.
    assert parse_query_latest(DOMAINS_RESPONSE) == []


def test_osm_feed_polls_each_ecosystem():
    http = FakeHttpClient(json.dumps(NPM_RESPONSE))
    feed = OsmFeed(http=http, token="osm_test", ecosystems=("npm", "pypi"))
    artifacts = feed.collect_artifacts("run-1")
    # Two ecosystems polled (fake returns the npm body for both) -> 2 calls, 4 artifacts.
    assert len(http.calls) == 2
    assert len(artifacts) == 4


def test_osm_feed_requires_token(monkeypatch):
    # Force no ambient token (a local .env may otherwise supply one).
    monkeypatch.setattr("git_warden.feeds.osm.OSM_API_KEY", None)
    feed = OsmFeed(http=FakeHttpClient("{}"), token=None, ecosystems=("npm",))
    with pytest.raises(RuntimeError, match="token"):
        feed.collect_artifacts("run-1")


def test_pipeline_ingests_artifacts(tmp_path):
    db = Database.open(tmp_path / "osm.sqlite")
    artifacts = parse_query_latest(NPM_RESPONSE) + parse_query_latest(REPOS_RESPONSE)
    osm = make_fake_artifact_feed(FeedSource.OPEN_SOURCE_MALWARE, artifacts)

    summary = run_ingestion(
        db, feeds=[], seeds=[], artifact_feeds=[osm], run_id="run-1", now=utcnow()
    )

    assert summary["counts"]["artifacts"] == 3
    rows = db.conn.execute("SELECT COUNT(*) AS n FROM malicious_artifacts").fetchone()
    assert rows["n"] == 3
    db.close()