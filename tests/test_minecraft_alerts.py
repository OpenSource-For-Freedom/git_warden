"""Minecraft stealer alerts go to their own Discord webhook, once each."""

from __future__ import annotations

import json

from git_warden.db import Database
from git_warden.notify import is_minecraft, notify_cluster, send_minecraft_alerts

MC = {"confidence": "auto", "bash_findings": [
    {"file": "Mod.java", "line": 3, "category": "credential_access",
     "rule": "mc-session-token", "snippet": "mc.getSession().getToken()"},
    {"file": "Mod.java", "line": 4, "category": "network_exfil",
     "rule": "discord-webhook", "snippet": "discord.com/api/webhooks/1/x"}]}
OTHER = {"confidence": "auto", "bash_findings": [
    {"file": ".vscode/tasks.json", "line": 0, "category": "install_hook",
     "rule": "vscode-autorun", "snippet": "curl x | bash"}]}


def _db(tmp_path):
    db = Database.open(tmp_path / "x.sqlite")
    for name, payload, score in (("evil/ratmod", MC, 9), ("lure/app", OTHER, 8),
                                 ("evil/review-only", {**MC, "confidence": "review"}, 5)):
        db.conn.execute(
            "INSERT INTO repo_findings (full_name, url, detection_method, status, score, "
            "raw_payload) VALUES (?,?,?,?,?,?)",
            (name, f"https://github.com/{name}", "signature_match", "confirmed", score,
             json.dumps(payload)))
    db.conn.commit()
    return db


def test_minecraft_alerts_go_to_their_own_webhook_once(tmp_path):
    db = _db(tmp_path)
    posts: list[tuple[str, dict]] = []

    def post(embeds, webhook):
        posts.append((webhook, embeds[0]))
        return True

    ledger = tmp_path / "evidence" / "minecraft_alerts.json"
    first = send_minecraft_alerts(db, ledger, webhook="https://mc.hook", post=post)
    assert first == {"sent": 1, "pending": 0}
    assert posts[0][0] == "https://mc.hook"
    assert posts[0][1]["title"] == "evil/ratmod"
    assert "Minecraft" in posts[0][1]["author"]["name"]
    # Recorded: a later run never re-alerts, and REVIEW findings never alert.
    assert json.loads(ledger.read_text()) == ["evil/ratmod"]
    again = send_minecraft_alerts(db, ledger, webhook="https://mc.hook", post=post)
    assert again["sent"] == 0 and len(posts) == 1
    db.close()


def test_failed_post_is_retried_next_run(tmp_path):
    db = _db(tmp_path)
    ledger = tmp_path / "ledger.json"
    send_minecraft_alerts(db, ledger, webhook="https://mc.hook", post=lambda **k: False)
    assert json.loads(ledger.read_text()) == []
    db.close()


def test_no_minecraft_webhook_sends_nothing(tmp_path):
    db = _db(tmp_path)
    called = []
    result = send_minecraft_alerts(db, tmp_path / "l.json", webhook="",
                                   post=lambda **k: called.append(k) or True)
    assert result["sent"] == 0 and called == []
    db.close()


def test_main_feed_skips_minecraft_rows(tmp_path, monkeypatch):
    db = _db(tmp_path)
    rows = {r["full_name"]: r for r in db.conn.execute("SELECT * FROM repo_findings")}
    sent: list[list] = []
    monkeypatch.setattr("git_warden.notify.post_discord",
                        lambda embeds: sent.append(embeds) or True)
    assert is_minecraft(rows["evil/ratmod"]) and not is_minecraft(rows["lure/app"])
    assert notify_cluster([rows["evil/ratmod"]]) is True and sent == []  # MC channel
    notify_cluster([rows["evil/ratmod"], rows["lure/app"]])
    assert sent[0][0]["title"] == "lure/app"
    db.close()


def test_evidence_tags_minecraft_family(tmp_path):
    import csv

    from git_warden.evidence import export
    db = _db(tmp_path)
    export(db, tmp_path / "evidence")
    with (tmp_path / "evidence" / "findings.csv").open(newline="") as fh:
        fam = {r["id"]: r["family"] for r in csv.DictReader(fh)}
    assert fam["evil/ratmod"] == "minecraft" and fam["lure/app"] == ""
    db.close()
