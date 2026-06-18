"""Tests for Discord gold output formatting and posting."""

from __future__ import annotations

import json

from git_warden.notify import format_finding, post_discord


def _row(**kw):
    base = {
        "full_name": "evil/repo", "url": "https://github.com/evil/repo",
        "detection_method": "ioc_search", "score": 9, "actor_key": "lazarus group",
        "reasoning": "exfil to attacker host", "signals": json.dumps(["bash:reverse_shell"]),
        "matched_iocs": json.dumps(["flipboxstudio.info"]),
    }
    base.update(kw)
    return base


def test_format_finding_includes_key_fields():
    msg = format_finding(_row())
    assert "evil/repo" in msg
    assert "flipboxstudio.info" in msg
    assert "lazarus group" in msg
    assert "reverse_shell" in msg


def test_post_discord_noop_without_webhook():
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
