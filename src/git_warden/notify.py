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

from .config import DISCORD_WEBHOOK, USER_AGENT

log = logging.getLogger(__name__)


def format_finding(row) -> str:
    """Render a repo_findings row as a Discord-ready gold message (doc 02 6).

    Includes IOCs with explicit file paths and which scanner(s)/rule(s) fired, so
    a reviewer can act without leaving the message.
    """
    iocs = ", ".join(json.loads(row["matched_iocs"] or "[]")) or "n/a"
    payload = json.loads(row["raw_payload"] or "{}")
    bash = payload.get("bash_findings") or []
    scanners = payload.get("scanners") or {}

    # IOCs with explicit file paths: the per-file bash findings.
    ioc_lines = [f"  - `{b['file']}:{b['line']}` {b['category']}/{b['rule']}" for b in bash[:8]]
    if len(bash) > 8:
        ioc_lines.append(f"  - … {len(bash) - 8} more")

    # Detection provenance: which scanner(s)/rule(s) fired.
    rules = sorted({f"bash:{b['rule']}" for b in bash})
    scanner_fired = [n for n, s in scanners.items() if s == "flagged"]
    provenance = ", ".join(rules + scanner_fired) or "see signals"

    lines = [
        "**🛡️ Git Warden — confirmed malicious repository**",
        f"**Repository:** `{row['full_name']}` ({row['platform']})  {row['url'] or ''}",
        f"**Why:** {row['reasoning'] or 'see signals'}",
        f"**Detection provenance:** {provenance} (score {row['score']})",
        "**Indicators of compromise (file paths):**",
        *(ioc_lines or ["  - n/a"]),
        f"**Provenance (matched IOCs):** {iocs}",
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
        webhook,
        data=payload,
        # Discord rejects the default urllib User-Agent with 403 -- set our own.
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with opener(req, timeout=20) as resp:
            return 200 <= getattr(resp, "status", 200) < 300
    except Exception as exc:  # noqa: BLE001 -- alerting failure must not crash a run
        log.warning("discord post failed", extra={"context": {"err": str(exc)}})
        return False
