"""Tests for the doc-05 orchestration executor (playbooks + self-healing)."""

from __future__ import annotations

import pytest

from git_warden.orchestration import (
    ManualInterventionRequired,
    RunHealth,
    load_playbook,
    resilient_call,
)
from git_warden.orchestration.playbook import Backoff


def test_load_playbook_from_shipped_config():
    pb = load_playbook()
    names = {ec.name for ec in pb.error_classes}
    assert {"network", "rate_limit", "auth_failure"} <= names
    assert pb.thresholds  # thresholds present from settings.yaml


def test_classify_by_message():
    pb = load_playbook()
    assert pb.classify("HTTP 429 rate limit exceeded").name == "rate_limit"
    assert pb.classify("401 Bad credentials").name == "auth_failure"
    assert pb.classify("Connection timeout after 30s").name == "network"
    assert pb.classify("totally unexpected") is None


def test_backoff_delay_curve():
    bo = Backoff(base_seconds=5, factor=2, max_retries=4)
    assert bo.delay(1) == 5
    assert bo.delay(2) == 10
    assert bo.delay(3) == 20


def _playbook():
    return load_playbook()


def test_success_returns_immediately():
    calls = []
    out = resilient_call(
        lambda: calls.append(1) or "ok", playbook=_playbook(), sleeper=lambda s: None
    )
    assert out == "ok"
    assert len(calls) == 1


def test_transient_network_then_success_retries():
    state = {"n": 0}

    def flaky():
        state["n"] += 1
        if state["n"] < 3:
            raise TimeoutError("connection timeout")
        return "recovered"

    health = RunHealth()
    out = resilient_call(flaky, playbook=_playbook(), health=health, sleeper=lambda s: None)
    assert out == "recovered"
    assert state["n"] == 3
    assert health.errors["network"] == 2


def test_auth_failure_flags_manual_and_alerts():
    alerts = []

    def boom():
        raise PermissionError("401 bad credentials")

    with pytest.raises(ManualInterventionRequired):
        resilient_call(boom, playbook=_playbook(), sleeper=lambda s: None,
                       on_alert=alerts.append, label="github")
    assert any("manual intervention" in a for a in alerts)


def test_not_found_is_skipped():
    def gone():
        raise FileNotFoundError("404 not found")

    out = resilient_call(gone, playbook=_playbook(), sleeper=lambda s: None)
    assert out is None  # skip_and_log


def test_retries_exhausted_reraises():
    def always():
        raise TimeoutError("connection timeout")

    health = RunHealth()
    with pytest.raises(TimeoutError):
        resilient_call(always, playbook=_playbook(), health=health, sleeper=lambda s: None)
    # network max_retries is 4 -> attempts 1..5, last raises.
    assert health.errors["network"] == 5


def test_threshold_breach_alerts_once():
    pb = load_playbook()
    health = RunHealth()
    # Drive 'network' to its threshold via repeated failures across calls.
    alerts = []
    limit = pb.thresholds.get("feed_errors", 3)
    # Use a class mapped to a threshold key: thresholds use feed_errors etc.,
    # which won't match 'network'; assert RunHealth threshold logic directly.
    health.errors["feed_errors"] = limit
    breached = health.newly_breached(pb.thresholds)
    assert "feed_errors" in breached
    assert health.newly_breached(pb.thresholds) == []  # reported once
    _ = alerts
