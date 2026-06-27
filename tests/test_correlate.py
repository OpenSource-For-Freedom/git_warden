"""Tests for campaign correlation + threat-actor attribution by shared payload."""

from __future__ import annotations

import json

from conftest import utcnow

from git_warden.correlate import payload_key, propagate_campaign_attribution
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
    assert res == {"campaigns": 1, "attributed": 2}            # b/src and c/src
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
    assert propagate_campaign_attribution(db, "r1") == {"campaigns": 0, "attributed": 0}
    db.close()
