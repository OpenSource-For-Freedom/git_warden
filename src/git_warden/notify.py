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


def _safe(value) -> str:
    """Neutralize attacker-controlled (repo-derived) text for a Discord message.

    File paths/IOCs come from cloned untrusted repos and could contain backticks
    (code-span breakout), '@' (mentions), or newlines (spoofing). Strip/escape
    them so a crafted filename can't ping @everyone or inject links/markdown.
    """
    text = str(value if value is not None else "").replace("\n", " ").replace("\r", " ")
    # Neutralize the high-risk vectors: backtick (code-span breakout) and '@'
    # (mentions). allowed_mentions:[] in post_discord is the hard guarantee.
    return text.replace("`", "'").replace("@", "@​")


def format_finding(row) -> str:
    """Render a repo_findings row as a Discord-ready gold message (doc 02 6).

    Includes IOCs with explicit file paths and which scanner(s)/rule(s) fired, so
    a reviewer can act without leaving the message.
    """
    iocs = ", ".join(_safe(i) for i in json.loads(row["matched_iocs"] or "[]")) or "n/a"
    payload = json.loads(row["raw_payload"] or "{}")
    bash = payload.get("bash_findings") or []
    scanners = payload.get("scanners") or {}

    # IOCs with explicit file paths: the per-file bash findings (paths sanitized).
    ioc_lines = [
        f"  - `{_safe(b['file'])}:{b['line']}` {_safe(b['category'])}/{_safe(b['rule'])}"
        for b in bash[:8]
    ]
    if len(bash) > 8:
        ioc_lines.append(f"  - … {len(bash) - 8} more")

    # Detection provenance: which scanner(s)/rule(s) fired.
    rules = sorted({f"static:{_safe(b['rule'])}" for b in bash})
    scanner_fired = [_safe(n) for n, s in scanners.items() if s == "flagged"]
    provenance = ", ".join(rules + scanner_fired) or "see signals"

    # Lead-source intel: which feed pointed us here (OSM), with its own labeling.
    # The CONFIRMATION above is ours (static detection); this records the lead so
    # the message never reads "unattributed" when we actually have provenance.
    osm = payload.get("osm") or {}
    intel_line = None
    if osm:
        tags = ", ".join(_safe(t) for t in (osm.get("tags") or [])) or "none"
        sev = _safe(osm.get("severity") or "n/a")
        intel_line = f"OpenSourceMalware (severity {sev}; tags: {tags})"

    # Label by detection class (P3): a weaponized red-team fork reads differently
    # from a malicious supply-chain repo, so reviewers triage correctly.
    label = {
        "redteam_lineage": "⚠️ Git Warden — weaponized red-team tool fork",
        "ioc_search": "🛡️ Git Warden — malicious repository (IOC match)",
        "osm_repository": "🛡️ Git Warden — malicious repository (OSM)",
        "actor_account": "🛡️ Git Warden — threat-actor repository",
    }.get(row["detection_method"], "🛡️ Git Warden — confirmed malicious repository")

    lines = [
        f"**{label}**",
        f"**Repository:** `{_safe(row['full_name'])}` ({row['platform']})  "
        f"{_safe(row['url'] or '')}",
        f"**Why:** {_safe(row['reasoning'] or 'see signals')}",
        f"**Detection provenance:** {provenance} (score {row['score']})",
        "**Indicators of compromise (file paths):**",
        *(ioc_lines or ["  - n/a"]),
        f"**Matched IOCs:** {iocs}",
        *( [f"**Lead source (intel):** {intel_line}"] if intel_line else [] ),
        f"**Attribution:** {_safe(row['actor_key'] or 'unattributed')}",
        "_Pending analyst validation — `git-warden review --approve/--reject`_",
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
    payload = json.dumps(
        # allowed_mentions parse:[] means no @everyone/@here/role ping can ever
        # fire, even if some markup slips through sanitization (defense in depth).
        {"content": content[:1900], "allowed_mentions": {"parse": []}}
    ).encode("utf-8")
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
