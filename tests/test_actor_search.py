"""Tests for actor-account discovery (doc 02 section 2.1)."""

from __future__ import annotations

from conftest import utcnow

from git_warden.db import Database
from git_warden.enums import ActorCategory, DetectionMethod, IdentifierType, Platform
from git_warden.hunt import hunt
from git_warden.models import ActorIdentifier, RedTeamTool
from git_warden.scanning.actor_search import find_actor_account_repos


def _repo(full_name):
    return {
        "full_name": full_name,
        "owner": {"login": full_name.split("/")[0]},
        "html_url": f"https://github.com/{full_name}",
    }


class FakeClient:
    def __init__(self, repos_by_login):
        self.repos_by_login = repos_by_login

    def list_user_repos(self, login, per_page=100):
        return self.repos_by_login.get(login, [])

    # hunt also calls these in other stages; stub empty.
    def list_forks(self, owner, name, per_page=100, sort="newest"):
        return []

    def search_repositories(self, query, per_page=10):
        return []

    def search_code(self, query, per_page=20):
        return []

    def get_readme(self, owner, name):
        return None


def test_find_actor_account_repos_attributes_and_dedups():
    client = FakeClient({"evilcorp": [_repo("evilcorp/dropper"), _repo("evilcorp/loader")]})
    repos = find_actor_account_repos(client, [("apt-x", "evilcorp")], known={"evilcorp/loader"})
    names = {r.full_name for r in repos}
    assert names == {"evilcorp/dropper"}  # known excluded
    assert repos[0].actor_key == "apt-x"


def test_hunt_actor_account_stage_creates_attributed_findings(tmp_path):
    db = Database.open(tmp_path / "a.sqlite")
    db.start_run("seed", utcnow())
    db.ensure_actor("apt-x", "APT-X", ActorCategory.APT.value, "seed")
    db.set_actor_status("apt-x", "promoted")  # eval #3: only promoted actors seed
    db.add_identifier("apt-x", ActorIdentifier(
        identifier_type=IdentifierType.ORGANIZATION, value="evilcorp", platform=Platform.GITHUB))

    client = FakeClient({"evilcorp": [_repo("evilcorp/dropper")]})
    hunt(db, client, [RedTeamTool(name="Sliver", repos=["BishopFox/sliver"])],
         run_id="hunt-1", now=utcnow(), do_ioc=False, do_lineage=False, do_actor=True)

    row = db.conn.execute(
        "SELECT detection_method, actor_key FROM repo_findings WHERE full_name = ?",
        ("evilcorp/dropper",),
    ).fetchone()
    assert row["detection_method"] == DetectionMethod.ACTOR_ACCOUNT.value
    assert row["actor_key"] == "apt-x"
    db.close()
