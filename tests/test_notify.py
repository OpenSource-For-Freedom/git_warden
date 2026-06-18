"""Tests for Discord gold output formatting and posting."""

from __future__ import annotations

import json

from git_warden.notify import format_finding, post_discord


def _row(**kw):
    base = {
        "full_name": "evil/repo", "platform": "github",
        "url": "https://github.com/evil/repo",
        "detection_method": "ioc_search", "score": 9, "actor_key": "lazarus group",
        "reasoning": "exfil to attacker host", "signals": json.dumps(["bash:reverse_shell"]),
        "matched_iocs": json.dumps(["flipboxstudio.info"]),
        "raw_payload": json.dumps({
            "bash_findings": [
                {"file": "setup.sh", "line": 3, "category": "reverse_shell",
                 "rule": "dev-tcp-redirect"}
            ],
            "scanners": {"semgrep": "skipped (not installed)"},
        }),
    }
    base.update(kw)
    return base


def test_format_finding_includes_key_fields():
    msg = format_finding(_row())
    assert "evil/repo" in msg
    assert "flipboxstudio.info" in msg
    assert "lazarus group" in msg
    assert "reverse_shell" in msg          # detection provenance from bash rule
    assert "setup.sh:3" in msg             # IOC with explicit file path (doc 02 6)


def test_post_discord_noop_without_webhook(monkeypatch):
    # Force no ambient webhook (a local .env may otherwise supply one).
    monkeypatch.setattr("git_warden.notify.DISCORD_WEBHOOK", "")
    assert post_discord("hi", webhook=None) is False


def test_post_discord_posts_when_webhook_set():
    sent = {}

    class FakeResp:
        status = 204
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_opener(req, timeout=20):
        sent["url"] = req.full_url
        sent["body"] = req.data
        return FakeResp()

    ok = post_discord("hello", webhook="https://discord.test/webhook", opener=fake_opener)
    assert ok
    assert sent["url"] == "https://discord.test/webhook"
    assert b"hello" in sent["body"]


def test_post_discord_disables_mentions():
    sent = {}

    class FakeResp:
        status = 204
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_opener(req, timeout=20):
        sent["body"] = req.data
        return FakeResp()

    post_discord("hi", webhook="https://discord.test/wh", opener=fake_opener)
    body = json.loads(sent["body"])
    assert body["allowed_mentions"] == {"parse": []}


def test_format_finding_sanitizes_malicious_filename():
    # Attacker-controlled filename trying to break out + ping @everyone.
    row = _row(raw_payload=json.dumps({
        "bash_findings": [{"file": "x`@everyone http://evil",
                           "line": 1, "category": "exfiltration", "rule": "x"}],
        "scanners": {},
    }))
    msg = format_finding(row)
    assert "`@everyone" not in msg      # code-span breakout neutralized
    assert "@everyone" not in msg       # raw mention broken with zero-width char
