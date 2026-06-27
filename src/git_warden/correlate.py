"""Campaign correlation + threat-actor attribution by shared injected payload.

Repos that inject the IDENTICAL ``eval(atob(...))`` payload are one campaign run
by one actor, even across different owner accounts and different signature labels.
This module fingerprints that payload and PROPAGATES any one member's threat-actor
attribution (e.g. an OSM-tagged repo -> DPRK) across the whole shared-payload
cluster, so the attribution lands in the DATA (the wall, OSM reports, dashboard),
not merely a view.
"""

from __future__ import annotations

import hashlib
import json
import re

from .db import Database

_ATOB = re.compile(r"atob\(\s*['\"]([A-Za-z0-9+/=\-]{16,})")


# Fingerprint the SHARED DEOBFUSCATOR STUB, not the whole blob. Across this
# campaign the first ~120 base64 chars (the loader: ``global['!']='11';var
# _$_1e42=(function(l,e){...``) are byte-identical, while the tail diverges because
# each repo embeds a different C2/payload after the same loader. A short prefix
# groups the campaign; the full blob would split it into one-repo "campaigns".
_STUB_CHARS = 96


def payload_key(raw_payload: str | None) -> str | None:
    """Stable fingerprint of a repo's injected ``eval(atob(...))`` loader stub, or None.

    Junk characters (``-``) malware sprinkles into the base64 to defeat parsers are
    stripped before hashing, and only the shared loader prefix is hashed, so every
    repo in one campaign fingerprints the same even though their tails differ.
    """
    bash = (json.loads(raw_payload or "{}") or {}).get("bash_findings") or []
    for b in bash:
        m = _ATOB.search(b.get("snippet") or "")
        if m:
            blob = re.sub(r"[^A-Za-z0-9+/]", "", m.group(1))
            if len(blob) >= _STUB_CHARS:
                return hashlib.sha1(blob[:_STUB_CHARS].encode()).hexdigest()[:10]
    return None


def propagate_campaign_attribution(db: Database, run_id: str) -> dict[str, int]:
    """Attribute every repo in a shared-payload campaign to the campaign's actor.

    Groups confirmed/validated findings by payload fingerprint; for each campaign
    (>= 2 repos) that already has ANY attributed member (e.g. an OSM repo tagged
    DPRK), registers that actor (so the actor_key FK is valid) and stamps it onto
    the UNattributed members. Sticky across runs: upsert_finding COALESCEs the
    existing actor_key, so a propagated attribution is never overwritten.

    Only spreads an attribution that already exists on a member sharing the exact
    malware payload, so it can never invent an attribution. Returns counts.
    """
    rows = db.conn.execute(
        "SELECT full_name, actor_key, raw_payload FROM repo_findings "
        "WHERE status IN ('confirmed', 'validated')"
    ).fetchall()
    by_payload: dict[str, list] = {}
    for r in rows:
        pk = payload_key(r["raw_payload"])
        if pk:
            by_payload.setdefault(pk, []).append(r)

    campaigns = attributed = 0
    for members in by_payload.values():
        if len(members) < 2:
            continue
        actor = next((m["actor_key"] for m in members if m["actor_key"]), None)
        if not actor:
            continue
        campaigns += 1
        # Register the actor so the actor_key FK is valid for the repos we stamp.
        db.ensure_actor(actor, actor, "campaign-attribution", run_id)
        for m in members:
            if not m["actor_key"]:
                db.set_attribution(m["full_name"], actor)
                attributed += 1
    return {"campaigns": campaigns, "attributed": attributed}
