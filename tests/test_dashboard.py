"""Tests for the telemetry dashboard: pure queries + a FastAPI smoke test."""

from __future__ import annotations

from conftest import utcnow

from git_warden.dashboard import queries
from git_warden.db import Database
from git_warden.enums import ArtifactType, DetectionMethod, FeedSource, RepoFindingStatus
from git_warden.models import MaliciousArtifact, RepoFinding


def _seed(tmp_path):
    db = Database.open(tmp_path / "d.sqlite")
    db.start_run("r1", utcnow())
    # OSM knows this one -> validation, not novel
    db.upsert_artifact(MaliciousArtifact(
        artifact_type=ArtifactType.REPO, name="known/lure", ecosystem="github",
        source=FeedSource.OPEN_SOURCE_MALWARE,
        raw_payload={"resource_identifier": "https://github.com/known/lure",
                     "severity_level": "high", "tags": ["dprk"]}), "r1")
    db.upsert_finding(RepoFinding(
        full_name="known/lure", detection_method=DetectionMethod.OSM_REPOSITORY,
        status=RepoFindingStatus.CONFIRMED, score=8,
        raw_payload={"bash_findings": [
            {"file": "postcss.config.js", "line": 1, "category": "obfuscation",
             "rule": "eval-decoded"}], "osm": {"severity": "high", "tags": ["dprk"]}}), "r1")
    # novel campaign siblings via signature_match, sharing a signature
    for nm in ("evil/a", "evil/b"):
        db.upsert_finding(RepoFinding(
            full_name=nm, detection_method=DetectionMethod.SIGNATURE_MATCH,
            status=RepoFindingStatus.CONFIRMED, score=4, matched_iocs=["STUBSIG"],
            raw_payload={"bash_findings": [
                {"file": "postcss.config.mjs", "line": 1, "category": "obfuscation",
                 "rule": "eval-decoded"}]}), "r1")
    db.upsert_finding(RepoFinding(
        full_name="legit/app", detection_method=DetectionMethod.IOC_SEARCH,
        status=RepoFindingStatus.REJECTED, score=2), "r1")
    return db


def test_summary_counts_novel_vs_osm_known(tmp_path):
    db = _seed(tmp_path)
    s = queries.summary(db)
    assert s["confirmed"] == 3
    assert s["novel"] == 2            # evil/a, evil/b (known/lure is OSM-known)
    assert s["osm_known_confirmed"] == 1
    assert s["rejected"] == 1
    assert s["by_method"]["signature_match"] == 2
    db.close()


def test_campaign_clusters_group_by_signature_and_owner(tmp_path):
    db = _seed(tmp_path)
    c = queries.campaign_clusters(db)
    assert set(c["by_signature"]["STUBSIG"]) == {"evil/a", "evil/b"}
    assert set(c["by_owner"]["evil"]) == {"evil/a", "evil/b"}  # repeat owner
    db.close()


def test_finding_detail_and_telemetry(tmp_path):
    db = _seed(tmp_path)
    d = queries.finding_detail(db, "evil/a")
    assert d["novel"] is True
    assert d["flags"][0]["rule"] == "eval-decoded"
    assert queries.finding_detail(db, "nope/nope") is None
    flags = queries.flag_telemetry(db)
    assert any(f["flag"] == "obfuscation/eval-decoded" for f in flags)
    sy = queries.signature_yield(db)
    assert sy and sy[0]["repos"] == 2
    db.close()


def test_graph_nodes_and_edges(tmp_path):
    db = _seed(tmp_path)
    g = queries.graph(db)
    ids = {n["id"] for n in g["nodes"]}
    assert {"repo:evil/a", "owner:evil", "sig:STUBSIG"} <= ids
    repo = next(n for n in g["nodes"] if n["id"] == "repo:evil/a")
    assert repo["novel"] is True and repo["type"] == "repo"
    kinds = {(e["s"], e["t"], e["kind"]) for e in g["edges"]}
    assert ("owner:evil", "repo:evil/a", "owns") in kinds
    assert ("sig:STUBSIG", "repo:evil/a", "signature") in kinds
    db.close()


def test_bad_owners_query_endpoint_and_summary_split(tmp_path):
    db = Database.open(tmp_path / "bo.sqlite")
    db.start_run("r1", utcnow())
    # evidence-confirmed repo -> brands its owner "bad"
    db.upsert_finding(RepoFinding(
        full_name="badguy/proven", detection_method=DetectionMethod.SIGNATURE_MATCH,
        status=RepoFindingStatus.CONFIRMED, score=8,
        raw_payload={"bash_findings": [
            {"file": "x.js", "line": 1, "category": "obfuscation", "rule": "eval-decoded"}]}), "r1")
    # owner-association repo, no evidence of its own -> Bad Owners, never the wall
    db.upsert_finding(RepoFinding(
        full_name="badguy/just-owned", detection_method=DetectionMethod.MALICIOUS_OWNER,
        status=RepoFindingStatus.CONFIRMED, score=6), "r1")

    bo = queries.bad_owners(db)
    assert [b["full_name"] for b in bo] == ["badguy/just-owned"]
    assert bo[0]["provenance"] == ["badguy/proven"]
    s = queries.summary(db)
    assert s["published"] == 1 and s["bad_owners"] == 1     # evidence-only vs association
    db.close()

    from fastapi.testclient import TestClient

    from git_warden.dashboard.app import create_app
    client = TestClient(create_app(tmp_path / "bo.sqlite"))
    assert client.get("/api/bad-owners").json()[0]["full_name"] == "badguy/just-owned"


def test_fastapi_endpoints_smoke(tmp_path):
    _seed(tmp_path).close()
    from fastapi.testclient import TestClient

    from git_warden.dashboard.app import create_app
    client = TestClient(create_app(tmp_path / "d.sqlite"))
    assert client.get("/api/summary").json()["confirmed"] == 3
    assert client.get("/api/campaigns").json()["by_signature"]["STUBSIG"]
    assert client.get("/api/graph").json()["nodes"]
    assert client.get("/api/finding/evil/a").json()["novel"] is True
    assert client.get("/api/finding/nope/nope").status_code == 404
    assert client.get("/").status_code == 200  # serves the dashboard HTML
