"""Discord gold output; confirmed findings only (PRD section 13.2, doc 02 sec 6).

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


# Status -> embed accent colour (Discord integer RGB).
_EMBED_COLOR = {
    "confirmed": 0xE74C3C, "validated": 0xC0392B,
    "screened": 0x8A9BB0, "rejected": 0x4A5568,
}


def _owner(full_name: str) -> str:
    return full_name.split("/", 1)[0]


def cluster_findings(rows: list) -> list[list]:
    """Group findings into connected clusters (union-find).

    Two repos are connected if they share an OWNER, a matched signature/IOC, or a
    code-hash; i.e. they are part of the same campaign. Returns a list of
    clusters (each a list of rows); a lone finding is a cluster of one.
    """
    parent = {r["full_name"]: r["full_name"] for r in rows}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    buckets: dict = {}
    for r in rows:
        keys = [("owner", _owner(r["full_name"]))]
        keys += [("ioc", v) for v in json.loads(r["matched_iocs"] or "[]")]
        if r["code_hash"]:
            keys.append(("hash", r["code_hash"]))
        for k in keys:
            buckets.setdefault(k, []).append(r["full_name"])
    for members in buckets.values():
        for m in members[1:]:
            parent[find(members[0])] = find(m)

    groups: dict = {}
    rowby = {r["full_name"]: r for r in rows}
    for fn in parent:
        groups.setdefault(find(fn), []).append(rowby[fn])
    return sorted(groups.values(), key=len, reverse=True)


def _connection_label(rows: list) -> str:
    if len({_owner(r["full_name"]) for r in rows}) == 1:
        return f"same account ({_owner(rows[0]['full_name'])})"
    sigs = set()
    for r in rows:
        sigs |= set(json.loads(r["matched_iocs"] or "[]"))
    if sigs:
        return "shared malware signature"
    return "shared code-hash"


def finding_embed(row) -> dict:
    """The standardized Discord embed for a single finding (cluster of one)."""
    return cluster_embed([row])


def cluster_embed(rows: list) -> dict:
    """THE standardized Discord report (doc 02 6); one embed for one finding OR
    one connected campaign cluster.

    A consistent card: clickable repo title, the GitHub repo image, colour by
    status, and fields for provenance (detection, lead source, attribution) and
    indicators. When >1 repo is connected it adds a "Connected repos" field naming
    the cluster and how they link; so a campaign is presented as ONE card, never
    duplicated across messages.
    """
    primary = max(rows, key=lambda r: r["score"])
    full = primary["full_name"]
    owner, name = (full.split("/", 1) + [""])[:2]
    payload = json.loads(primary["raw_payload"] or "{}")
    bash = payload.get("bash_findings") or []
    osm = payload.get("osm") or {}
    method = _safe(primary["detection_method"])
    novel = method != "osm_repository"

    rules = sorted({f"static:{_safe(b['rule'])}" for b in bash}) or ["see signals"]
    ioc_lines = "\n".join(
        f"`{_safe(b['file'])}:{b['line']}` {_safe(b['category'])}/{_safe(b['rule'])}"
        for b in bash[:6]) or "n/a"

    fields = []
    connected = len(rows) > 1
    if connected:
        listing = "\n".join(f"`{_safe(r['full_name'])}`" for r in rows[:15])
        if len(rows) > 15:
            listing += f"\n…+{len(rows) - 15} more"
        fields.append({"name": f"🔗 Connected repos ({len(rows)}) — {_connection_label(rows)}",
                       "value": listing[:1024], "inline": False})
    fields += [
        {"name": "Detection", "value": ", ".join(rules)[:1024], "inline": True},
        {"name": "Method · score", "value": f"{method} · {primary['score']}", "inline": True},
        {"name": "Class", "value": "🆕 novel" if novel else "OSM-validated", "inline": True},
        {"name": f"Indicators — {_safe(name)} (file:line → rule)",
         "value": ioc_lines[:1024], "inline": False},
    ]
    if osm:
        tags = _safe(", ".join(osm.get("tags") or []))
        lead = f"OpenSourceMalware · sev {_safe(osm.get('severity'))} · {tags}"
        fields.append({"name": "Lead source", "value": lead[:1024], "inline": False})
    fields.append({"name": "Attribution",
                   "value": _safe(primary["actor_key"] or "unattributed"), "inline": False})

    title = full if not connected else f"{full}  +{len(rows) - 1} connected"
    author = ("🛡️ Git Warden — confirmed malicious campaign" if connected
              else "🛡️ Git Warden — confirmed malicious repository")
    return {
        "author": {"name": author},
        "title": _safe(title)[:256],
        "url": primary["url"] or f"https://github.com/{full}",
        "color": _EMBED_COLOR.get(primary["status"], 0xE74C3C),
        "description": _safe(primary["reasoning"] or "")[:600],
        "fields": fields,
        "image": {"url": f"https://opengraph.githubassets.com/1/{owner}/{name}"},
        "footer": {"text": "Pending analyst validation"},
    }


def post_discord(
    content: str = "", *, embeds: list | None = None,
    webhook: str | None = None, opener=urllib.request.urlopen,
) -> bool:
    """POST a message (content and/or up to 10 embeds) to the Discord webhook.

    No-op (returns False) when no webhook is configured, so dry runs are safe.
    """
    webhook = webhook or DISCORD_WEBHOOK
    if not webhook:
        log.info("discord: no webhook configured; skipping")
        return False
    # allowed_mentions parse:[] means no @everyone/@here/role ping can ever fire,
    # even if some markup slips through sanitization (defense in depth).
    body: dict = {"allowed_mentions": {"parse": []}}
    if content:
        body["content"] = content[:1900]
    if embeds:
        body["embeds"] = embeds[:10]
    payload = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        webhook,
        data=payload,
        # Discord rejects the default urllib User-Agent with 403; set our own.
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    try:
        with opener(req, timeout=20) as resp:
            return 200 <= getattr(resp, "status", 200) < 300
    except Exception as exc:  # noqa: BLE001
        log.warning("discord post failed", extra={"context": {"err": str(exc)}})
        return False
