"""Discord gold output -- confirmed findings only (PRD section 13.2, doc 02 sec 6).

Only validated, confirmed malicious repos reach Discord, each as a human-readable
message a reviewer can act on without leaving it: repository, reasoning,
indicators/attribution, and detection provenance. Health/threshold alerts use
the same transport. Run artifacts (the full record) live elsewhere.
"""

from __future__ import annotations

import json
import logging
import urllib.request

from .config import DISCORD_WEBHOOK

log = logging.getLogger(__name__)


def format_finding(row) -> str:
    """Render a repo_findings row as a Discord-ready gold message."""
    signals = ", ".join(json.loads(row["signals"] or "[]")) or "n/a"
    iocs = ", ".join(json.loads(row["matched_iocs"] or "[]")) or "n/a"
    lines = [
        "**🛡️ Git Warden — confirmed malicious repository**",
        f"**Repository:** `{row['full_name']}`  {row['url'] or ''}",
        f"**Why:** {row['reasoning'] or 'see signals'}",
        f"**Detection:** {row['detection_method']} (score {row['score']})",
        f"**Signals:** {signals}",
        f"**Provenance (IOCs):** {iocs}",
        f"**Attribution:** {row['actor_key'] or 'unattributed'}",
    ]
    return "\n".join(lines)


def post_discord(
    content: str, *, webhook: str | None = None, opener=urllib.request.urlopen
) -> bool:
    """POST a message to the Discord webhook. Returns True on success.

    No-op (returns False) when no webhook is configured, so dry runs are safe.
    """
    webhook = webhook or DISCORD_WEBHOOK
    if not webhook:
        log.info("discord: no webhook configured; skipping")
        return False
    payload = json.dumps({"content": content[:1900]}).encode("utf-8")
    req = urllib.request.Request(
        webhook, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with opener(req, timeout=20) as resp:
            return 200 <= getattr(resp, "status", 200) < 300
    except Exception as exc:  # noqa: BLE001 -- alerting failure must not crash a run
        log.warning("discord post failed", extra={"context": {"err": str(exc)}})
        return False
