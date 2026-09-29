"""Campaign correlation + threat-actor attribution.

Two fingerprints group confirmed repos into campaigns across owner accounts:

* ``payload``: the IDENTICAL ``eval(atob(...))`` loader stub. Strong enough to
  PROPAGATE one member's threat-actor attribution (e.g. an OSM-tagged repo ->
  DPRK) across the whole cluster, so it lands in the DATA (the wall, OSM
  reports, dashboard), not merely a view.
* ``dropper``: the delivery vector plus the dropper URL path with the host and
  values removed (``vscode-folderopen:settings/{os}?flag=``). The folderOpen
  ``tasks.json`` lures rotate a throwaway C2 host per repo, so host clustering
  splits them into one-repo "campaigns"; the path shape survives rotation.
  Used to CORRELATE (campaign ids, run summaries, dashboard) but never to spread
  attribution, since a path shape is weaker evidence than a shared payload.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

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


# Per-OS path segments the droppers vary between tasks (settings/linux,
# settings/mac, settings/windows): folded so one lure's three commands share a key.
_OS_SEGMENT = re.compile(
    r"(?<=/)(?:linux|mac|macos|osx|darwin|windows|win|win32|win64)(?=[/?])", re.I)
_VECTOR_OF_RULE = {"vscode-autorun": "vscode-folderopen"}
_MIN_CLUSTER = 2


def _dropper_shapes(flags: list[dict]) -> set[str]:
    """Host-free dropper URL shapes (``settings/{os}?flag=``) in a finding's evidence."""
    from .scanning.manifest_scanner import is_reputable_install_host
    from .scanning.signatures import _DROPPER_URL, _FETCH_CONTEXT

    out: set[str] = set()
    for f in flags:
        snippet = f.get("snippet") or ""
        # A folderOpen autorun already proved the command is a dropper; any other
        # rule must show the fetch-to-shell / eval-fetch context on the line itself.
        if f.get("rule") not in _VECTOR_OF_RULE and not _FETCH_CONTEXT.search(snippet):
            continue
        for m in _DROPPER_URL.finditer(snippet):
            host = re.match(r"https?://([^/\s'\"]+)", m.group(0))
            if host and is_reputable_install_host(host.group(1)):
                continue
            out.add(_OS_SEGMENT.sub("{os}", m.group("path").lstrip("/").lower()))
    return out


def dropper_key(raw_payload: str | None) -> str | None:
    """Rotation-resistant dropper fingerprint (vector + host-free URL shape), or None."""
    flags = (json.loads(raw_payload or "{}") or {}).get("bash_findings") or []
    shapes = _dropper_shapes(flags)
    if not shapes:
        return None
    vector = next((_VECTOR_OF_RULE[f.get("rule")] for f in flags
                   if f.get("rule") in _VECTOR_OF_RULE), "fetch-to-shell")
    return f"{vector}:{min(shapes)}"


def campaign_key(raw_payload: str | None) -> str | None:
    """A repo's campaign fingerprint: the shared loader stub first, else the dropper."""
    pk = payload_key(raw_payload)
    if pk:
        return f"payload:{pk}"
    dk = dropper_key(raw_payload)
    return f"dropper:{dk}" if dk else None


def campaign_id(key: str) -> str:
    """Short stable id for a campaign fingerprint (same key -> same id every run)."""
    return "GW-C-" + hashlib.sha1(key.encode()).hexdigest()[:8]


@dataclass
class Campaign:
    """Confirmed repos sharing one campaign fingerprint."""

    key: str
    members: list[str] = field(default_factory=list)
    owners: set[str] = field(default_factory=set)
    c2_hosts: set[str] = field(default_factory=set)
    actors: set[str] = field(default_factory=set)
    snippet: str = ""

    @property
    def id(self) -> str:
        return campaign_id(self.key)

    @property
    def kind(self) -> str:
        return self.key.split(":", 1)[0]

    @property
    def fingerprint(self) -> str:
        return self.key.split(":", 1)[1]


def campaign_index(
    db: Database, *, statuses: tuple[str, ...] = ("confirmed", "validated"),
    min_size: int = _MIN_CLUSTER,
) -> dict[str, Campaign]:
    """Map each clustered repo (``full_name``) to its :class:`Campaign`.

    Only fingerprints shared by at least ``min_size`` repos form a campaign, so a
    lone repo maps to nothing. Owners, C2 hosts and attributed actors are the
    union across members.
    """
    from .dprk import c2_hosts_from_flags

    ph = ",".join("?" for _ in statuses)
    camps: dict[str, Campaign] = {}
    for r in db.conn.execute(
        "SELECT full_name, actor_key, raw_payload FROM repo_findings "
        f"WHERE status IN ({ph}) ORDER BY full_name", statuses
    ):
        key = campaign_key(r["raw_payload"])
        if not key:
            continue
        c = camps.setdefault(key, Campaign(key))
        c.members.append(r["full_name"])
        c.owners.add(r["full_name"].split("/", 1)[0])
        if r["actor_key"]:
            c.actors.add(r["actor_key"])
        flags = (json.loads(r["raw_payload"] or "{}") or {}).get("bash_findings") or []
        c.c2_hosts.update(c2_hosts_from_flags(flags))
        if not c.snippet:
            c.snippet = next((f.get("snippet") or "" for f in flags
                              if f.get("snippet")), "")
    return {m: c for c in camps.values() if len(c.members) >= min_size
            for m in c.members}


def campaigns(db: Database, **kw) -> list[Campaign]:
    """Distinct campaigns, largest first."""
    uniq = {c.key: c for c in campaign_index(db, **kw).values()}
    return sorted(uniq.values(), key=lambda c: (-len(c.members), c.key))


def propagate_campaign_attribution(db: Database, run_id: str) -> dict[str, int]:
    """Attribute every repo in a shared-payload campaign to the campaign's actor.

    Groups confirmed/validated findings by payload fingerprint; for each campaign
    (>= 2 repos) that already has ANY attributed member (e.g. an OSM repo tagged
    DPRK), registers that actor (so the actor_key FK is valid) and stamps it onto
    the UNattributed members. Sticky across runs: upsert_finding COALESCEs the
    existing actor_key, so a propagated attribution is never overwritten.

    Only spreads an attribution that already exists on a member sharing the exact
    malware payload, so it can never invent an attribution. Dropper-shape clusters
    are counted (``clusters``) but never receive propagated attribution. Every
    clustered repo is recorded in ``campaign_members``. Returns counts.
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

    n_campaigns = attributed = 0
    for members in by_payload.values():
        if len(members) < 2:
            continue
        actor = next((m["actor_key"] for m in members if m["actor_key"]), None)
        if not actor:
            continue
        n_campaigns += 1
        # Register the actor so the actor_key FK is valid for the repos we stamp.
        db.ensure_actor(actor, actor, "campaign-attribution", run_id)
        for m in members:
            if not m["actor_key"]:
                db.set_attribution(m["full_name"], actor)
                attributed += 1
    clustered = campaign_index(db)
    db.record_campaign_members(
        [(c.id, c.key, name) for name, c in clustered.items()], run_id)
    return {"campaigns": n_campaigns, "attributed": attributed,
            "clusters": len({c.key for c in clustered.values()})}
