"""Pure correlation queries over the registry for the telemetry dashboard.

Every function takes a :class:`~git_warden.db.Database` and returns plain
JSON-able data; no web framework; so the correlation logic is fully
unit-testable. The FastAPI layer (:mod:`.app`) just serializes these.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from ..correlate import payload_key as _payload_key
from ..db import Database


def _owner(full_name: str) -> str:
    return full_name.split("/", 1)[0]


# The rule that CONFIRMED a repo mapped to a plain-language ATTACK VECTOR, so the
# dashboard says "VS Code folder-open dropper" instead of showing a raw blob.
# Ordered by confirmation strength; the first confirming rule found on a finding
# names its vector.
_VECTOR_BY_RULE = {
    "vscode-autorun": ("VS Code folder-open auto-run",
                       "A .vscode/tasks.json runOn:folderOpen task silently fetch-and-executes "
                       "a remote payload the moment the repo is opened in the editor."),
    "eval-decoded": ("Obfuscated eval(atob) loader",
                     "A base64 blob injected into a build config is decoded and executed at "
                     "load time (verified: it hijacks require/module and unpacks a second stage)."),
    "base64-decode-exec": ("Base64 decode-and-execute",
                           "Shell decodes a base64 blob and pipes it straight to a shell."),
    "py-decode-exec": ("Python decode-and-execute",
                       "Python exec/eval of a base64/marshal/zlib-decoded payload."),
    "npm-preinstall": ("npm install hook (preinstall)",
                       "Runs a fetch/decode-and-execute on npm install."),
    "npm-install": ("npm install hook", "Runs a fetch/decode-and-execute on npm install."),
    "npm-postinstall": ("npm install hook (postinstall)",
                        "Runs a fetch/decode-and-execute on npm install."),
    "npm-prepare": ("npm install hook (prepare)",
                    "Runs a fetch/decode-and-execute on npm install."),
    "npm-preuninstall": ("npm install hook (preuninstall)",
                         "Runs a fetch/decode-and-execute on npm uninstall."),
    "py-setup-exec": ("setup.py fetch-and-run",
                      "setup.py downloads-and-executes a payload at build time."),
    "env-dump": ("Environment / credential exfiltration",
                 "Serializes the whole process environment (secrets, tokens) to send it out."),
    "secret-exfil": ("Secret-file exfiltration",
                     "curl/wget uploads a private key or credentials file."),
    "shadow-read": ("Password-hash theft", "Reads/exfiltrates /etc/shadow."),
    "nc-exec": ("Reverse shell (netcat)", "nc -e spawns a shell back to the attacker."),
    "bash-i-socket": ("Reverse shell (bash /dev/tcp)",
                      "Interactive bash redirected over a raw TCP socket."),
    "osm-listed": ("Known-malicious dependency",
                   "Declares a version-pinned known-malicious package."),
}
_HOST_RE = re.compile(r"https?://(?:[^/@\s]*@)?([A-Za-z0-9.\-]+)")
# Reputable hosts that legitimately appear in a confirmed repo's build/install
# lines (installer CDNs, package registries, the platform's own APIs) and are NOT
# the attacker C2. `curl -fsSL https://deb.nodesource.com/setup_22.x | bash` is a
# standard Node install, not a dropper -- filtered so the C2 list stays clean.
_NOT_C2 = (
    "github.com", "githubusercontent.com", "npmjs.org", "npmjs.com", "pypi.org",
    "python.org", "nodejs.org", "microsoft.com", "vscode.dev", "google.com",
    "nodesource.com", "rustup.rs", "bun.sh", "get.docker.com", "download.docker.com",
    "apt.llvm.org", "packages.microsoft.com", "download.pytorch.org", "dl.google.com",
    "deb.debian.org", "archive.ubuntu.com", "files.pythonhosted.org", "python-poetry.org",
    "get.helm.sh", "cloudflare.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
)
# Findings whose snippet may carry the attacker C2: the confirming rule itself, or
# a fetch/exfil signal. Avoids pulling a legit host from an unrelated line.
_C2_CATEGORIES = ("download_exec", "network_exfil", "exfiltration")


def _classify_vector(flags: list[dict]) -> tuple[str | None, str | None, str | None, str | None]:
    """(vector, description, confirming rule, evidence file) from a finding's flags."""
    for b in flags:
        v = _VECTOR_BY_RULE.get(b.get("rule"))
        if v:
            return v[0], v[1], f"{b.get('category')}/{b.get('rule')}", b.get("file")
    return None, None, None, None


def _extract_c2(flags: list[dict]) -> list[str]:
    """Distinct attacker C2/payload hosts from a finding's CONFIRMING / fetch /
    exfil evidence (not every snippet), reputable installers filtered out."""
    hosts: list[str] = []
    seen: set[str] = set()
    for b in flags:
        if b.get("rule") not in _VECTOR_BY_RULE and b.get("category") not in _C2_CATEGORIES:
            continue
        for h in _HOST_RE.findall(b.get("snippet") or ""):
            host = h.rstrip(".").lower()
            # require a real TLD-ish last label (2+ alpha) so a snippet cut mid-URL
            # (`...260120.v`) is dropped, not shown as its own host.
            if host in seen or not re.search(r"\.[a-z]{2,}$", host):
                continue
            if any(host == n or host.endswith("." + n) for n in _NOT_C2):
                continue
            seen.add(host)
            hosts.append(host)
    # Drop truncated prefixes: a 280-char snippet can cut a repeated URL, yielding
    # `x.vercel` alongside `x.vercel.app`. Keep only the fullest form of each host.
    return [h for h in hosts if not any(o != h and o.startswith(h + ".") for o in hosts)]


def summary(db: Database) -> dict[str, Any]:
    """Headline counts: runs, finding statuses, novel vs OSM-known, gold."""
    c = db.conn
    status_counts = {
        r["status"]: r["n"]
        for r in c.execute("SELECT status, count(*) n FROM repo_findings GROUP BY status")
    }
    known = db.osm_known_repos()
    confirmed = [
        r["full_name"] for r in c.execute(
            "SELECT full_name FROM repo_findings WHERE status = 'confirmed'")
    ]
    novel = sum(1 for f in confirmed if f.casefold() not in known)
    return {
        "runs": c.execute("SELECT count(*) FROM runs").fetchone()[0],
        "confirmed": status_counts.get("confirmed", 0),
        "validated": status_counts.get("validated", 0),
        "rejected": status_counts.get("rejected", 0),
        "screened": status_counts.get("screened", 0),
        "candidate": status_counts.get("candidate", 0),
        "novel": novel,
        "osm_known_confirmed": len(confirmed) - novel,
        "gold_delivered": c.execute(
            "SELECT count(*) FROM repo_findings WHERE delivered_gold = 1").fetchone()[0],
        # The split the wall enforces: evidence-only published vs owner-association.
        "published": len(db.published_findings()),
        "bad_owners": len(db.bad_owner_findings()),
        "by_method": {
            r["detection_method"]: r["n"] for r in c.execute(
                "SELECT detection_method, count(*) n FROM repo_findings "
                "WHERE status = 'confirmed' GROUP BY detection_method")
        },
    }


def findings(db: Database, status: str | None = None) -> list[dict[str, Any]]:
    """Finding rows for the table, newest/high-score first; novel flag attached."""
    known = db.osm_known_repos()
    sql = ("SELECT full_name, detection_method, status, score, delivered_gold, "
           "actor_key, raw_payload FROM repo_findings")
    params: tuple = ()
    if status:
        sql += " WHERE status = ?"
        params = (status,)
    sql += " ORDER BY (status='confirmed') DESC, score DESC, full_name"
    out = []
    for r in db.conn.execute(sql, params):
        try:
            conf = json.loads(r["raw_payload"] or "{}").get("confidence")
        except Exception:  # noqa: BLE001
            conf = None
        out.append({
            "full_name": r["full_name"],
            "owner": _owner(r["full_name"]),
            "method": r["detection_method"],
            "status": r["status"],
            "score": r["score"],
            "gold": bool(r["delivered_gold"]),
            "attribution": r["actor_key"],
            "novel": r["full_name"].casefold() not in known,
            # AUTO = submit-eligible high-confidence capture; review = human queue.
            "confidence": conf if r["status"] == "confirmed" else None,
        })
    return out


def finding_detail(db: Database, full_name: str) -> dict[str, Any] | None:
    """One finding's full evidence: flags (file:line/rule), payload, provenance."""
    r = db.conn.execute(
        "SELECT * FROM repo_findings WHERE full_name = ?", (full_name.strip().casefold(),)
    ).fetchone()
    if r is None:
        return None
    payload = json.loads(r["raw_payload"] or "{}")
    flags = payload.get("bash_findings") or []
    vector, vector_desc, confirm_rule, evidence_file = _classify_vector(flags)
    # Country-level attribution for the right-panel detail. The DPRK infra set
    # EXCLUDES this repo so it never self-corroborates off its own C2.
    from ..actors import attribute as _attribute
    from ..containers import docker_findings, is_container_threat
    a = _attribute(flags, r["actor_key"], db.dprk_infra_hosts(exclude=r["full_name"]))
    return {
        "full_name": r["full_name"],
        "url": r["url"],
        "method": r["detection_method"],
        "status": r["status"],
        "score": r["score"],
        "reasoning": r["reasoning"],
        "attribution": r["actor_key"],
        "attribution_detail": {
            "origin": a.origin,
            "tier": a.tier,
            "label": a.label,
            "attributed": a.attributed,
            "actor": a.actor,
            "campaign": a.campaign,
            "signals": a.signals,
            "reasons": a.reasons,
            "c2": a.c2,
            "tags": a.tags,
        },
        # What the malware DOES + where + who it calls -- the human-readable core.
        "vector": vector,
        "vector_desc": vector_desc,
        "confirm_rule": confirm_rule,
        "evidence_file": evidence_file,
        "c2_hosts": _extract_c2(flags),
        "signals": json.loads(r["signals"] or "[]"),
        "matched_iocs": json.loads(r["matched_iocs"] or "[]"),
        "flags": flags,
        "scanners": payload.get("scanners") or {},
        "osm": payload.get("osm"),
        "code_hash": r["code_hash"],
        "gold": bool(r["delivered_gold"]),
        "novel": r["full_name"].casefold() not in db.osm_known_repos(),
        # Container threat: malicious behaviour in the Docker build recipe, stored
        # and shown separately (benign installer/healthcheck idioms never qualify).
        "container_threat": is_container_threat(flags),
        "docker_evidence": [
            {"file": b.get("file"), "line": b.get("line"),
             "category": b.get("category"), "rule": b.get("rule"),
             "snippet": (b.get("snippet") or "")[:200]}
            for b in docker_findings(flags)
        ],
    }


def attack_vectors(db: Database) -> list[dict[str, Any]]:
    """Confirmed findings grouped by ATTACK VECTOR (how the payload executes)."""
    by_vector: dict[str, dict[str, Any]] = {}
    for r in db.conn.execute(
        "SELECT full_name, raw_payload FROM repo_findings WHERE status = 'confirmed'"
    ):
        flags = (json.loads(r["raw_payload"] or "{}") or {}).get("bash_findings") or []
        vector, desc, _, _ = _classify_vector(flags)
        if not vector:
            vector, desc = ("other", "Confirmed on a static signature not yet vector-classified.")
        b = by_vector.setdefault(vector, {"vector": vector, "desc": desc, "repos": []})
        b["repos"].append(r["full_name"])
    out = [{"vector": v["vector"], "desc": v["desc"], "count": len(v["repos"]),
            "sample": v["repos"][:6]} for v in by_vector.values()]
    out.sort(key=lambda x: -x["count"])
    return out


def c2_infrastructure(db: Database) -> list[dict[str, Any]]:
    """Distinct attacker C2/payload hosts across confirmed findings, with the
    repos that call each -- the campaign's infrastructure map."""
    by_host: dict[str, set[str]] = {}
    for r in db.conn.execute(
        "SELECT full_name, raw_payload FROM repo_findings WHERE status = 'confirmed'"
    ):
        flags = (json.loads(r["raw_payload"] or "{}") or {}).get("bash_findings") or []
        for host in _extract_c2(flags):
            by_host.setdefault(host, set()).add(r["full_name"])
    out = [{"host": h, "repo_count": len(reps), "sample": sorted(reps)[:6]}
           for h, reps in by_host.items()]
    out.sort(key=lambda x: -x["repo_count"])
    return out


def bad_owners(db: Database) -> list[dict[str, Any]]:
    """Owner-association repos (no own evidence) with owner provenance.

    The dashboard mirror of the README's Bad Owners section: these never reach the
    wall (no per-repo evidence) and surface only because the owner ships malware
    elsewhere; each row carries the owner's evidence-confirmed repos as provenance.
    """
    return db.bad_owner_findings()


def campaign_clusters(db: Database) -> dict[str, Any]:
    """Correlate repos into campaigns by shared signature / owner / code-hash."""
    c = db.conn
    by_signature: dict[str, list[str]] = {}
    for r in c.execute("SELECT full_name, matched_iocs FROM repo_findings "
                       "WHERE detection_method = 'signature_match'"):
        for sig in json.loads(r["matched_iocs"] or "[]"):
            by_signature.setdefault(sig[:40], []).append(r["full_name"])

    by_owner: dict[str, list[str]] = {}
    for r in c.execute("SELECT full_name FROM repo_findings WHERE status = 'confirmed'"):
        by_owner.setdefault(_owner(r["full_name"]), []).append(r["full_name"])
    by_owner = {o: reps for o, reps in by_owner.items() if len(reps) > 1}

    by_code_hash: dict[str, list[str]] = {}
    for r in c.execute("SELECT full_name, code_hash FROM repo_findings "
                       "WHERE status = 'confirmed' AND code_hash IS NOT NULL AND code_hash != ''"):
        by_code_hash.setdefault(r["code_hash"][:16], []).append(r["full_name"])
    by_code_hash = {h: reps for h, reps in by_code_hash.items() if len(reps) > 1}

    return {"by_signature": by_signature, "by_owner": by_owner, "by_code_hash": by_code_hash}


def flag_telemetry(db: Database) -> list[dict[str, Any]]:
    """Frequency of each flag (category/rule) across confirmed findings' code."""
    cnt: Counter = Counter()
    for r in db.conn.execute("SELECT raw_payload FROM repo_findings "
                            "WHERE status IN ('confirmed', 'validated')"):
        for bf in (json.loads(r["raw_payload"] or "{}").get("bash_findings") or []):
            cnt[f"{bf['category']}/{bf['rule']}"] += 1
    return [{"flag": k, "count": v} for k, v in cnt.most_common(25)]


def signature_yield(db: Database) -> list[dict[str, Any]]:
    """How many distinct repos each malware signature surfaced (the loop's ROI)."""
    by_sig: dict[str, set] = {}
    for r in db.conn.execute("SELECT full_name, matched_iocs FROM repo_findings "
                            "WHERE detection_method = 'signature_match'"):
        for sig in json.loads(r["matched_iocs"] or "[]"):
            by_sig.setdefault(sig, set()).add(r["full_name"])
    return [
        {"signature": s[:48], "repos": len(reps)}
        for s, reps in sorted(by_sig.items(), key=lambda kv: -len(kv[1]))
    ]


# Graph scope widens the funnel shown: confirmed only (the product), confirmed +
# the actively-suspected candidates, or everything that was scanned (+ screened).
_GRAPH_SCOPES = {
    "confirmed": ("confirmed",),
    "active": ("confirmed", "candidate"),
    "all": ("confirmed", "candidate", "screened"),
}


def graph(db: Database, scope: str = "confirmed") -> dict[str, Any]:
    """Force-graph correlating repos with their OWNERS, SIGNATURES, and ACTORS.

    Nodes: repo (novel/method/score/status), owner, signature, actor. Edges:
    owner-owns-repo, signature-matched-repo, actor-attributed-repo, repo-repo
    (shared code-hash = same core). ``scope`` widens the funnel beyond confirmed:
    'confirmed' (default) -> 'active' (+candidate) -> 'all' (+screened), so the
    owner/signature/actor clusters of the full capture surface become visible.
    """
    from ..actors import attribute
    from ..containers import is_container_threat
    from ..dprk import c2_hosts_from_flags, campaign_vectors, is_dprk_actor_key

    c = db.conn
    statuses = _GRAPH_SCOPES.get(scope, _GRAPH_SCOPES["confirmed"])
    known = db.osm_known_repos()
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add(node_id: str, ntype: str, label: str, **kw) -> None:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": ntype, "label": label, **kw}

    ph = ",".join("?" for _ in statuses)
    rows = c.execute(
        "SELECT full_name, detection_method, matched_iocs, code_hash, score, status, "
        f"actor_key, raw_payload FROM repo_findings WHERE status IN ({ph})", statuses
    ).fetchall()
    # DISCOVERED PRODUCT: drop only osm_repository (pure re-validation of OSM's own
    # list). Everything WE surfaced stays -- signature/owner/ioc/lineage/news/actor/
    # package -- INCLUDING repos we discovered and later submitted (now in OSM). This
    # is the growing visual DB of our contributions, not OSM's catalogue echoed back.
    rows = [r for r in rows if r["detection_method"] != "osm_repository"]

    # Self-sourced DPRK infra for node attribution: a C2 host used by >= 2 discovered
    # campaign repos is corroborating infrastructure (a lone host is not, and this
    # also keeps a repo from self-corroborating on its own unique host).
    flags_by: dict[str, list] = {}
    host_repos: dict[str, set[str]] = {}
    for r in rows:
        flags = (json.loads(r["raw_payload"] or "{}") or {}).get("bash_findings") or []
        flags_by[r["full_name"]] = flags
        if is_dprk_actor_key(r["actor_key"]) or campaign_vectors(flags):
            for h in c2_hosts_from_flags(flags):
                host_repos.setdefault(h, set()).add(r["full_name"])
    shared_infra = {h for h, reps in host_repos.items() if len(reps) >= 2}

    by_hash: dict[str, list[str]] = {}
    camp_members: dict[str, list[str]] = {}   # payload fingerprint -> repos
    camp_actors: dict[str, set[str]] = {}     # payload fingerprint -> attributed origins
    for r in rows:
        repo, owner = r["full_name"], _owner(r["full_name"])
        flags = flags_by[repo]
        # Country-level attribution shown ON the node, so the visual DB carries
        # attribution (any country) even for repos with no stored actor_key.
        a = attribute(flags, r["actor_key"], shared_infra)
        add(f"repo:{repo}", "repo", repo.split("/", 1)[-1],
            repo=repo, novel=repo.casefold() not in known,
            method=r["detection_method"], score=r["score"], status=r["status"],
            origin=a.origin, tier=a.tier, actor=a.actor, attribution=a.label,
            container=is_container_threat(flags))
        add(f"owner:{owner}", "owner", owner)
        edges.append({"s": f"owner:{owner}", "t": f"repo:{repo}", "kind": "owns"})
        for sig in json.loads(r["matched_iocs"] or "[]"):
            add(f"sig:{sig[:40]}", "signature", sig[:18] + "…")
            edges.append({"s": f"sig:{sig[:40]}", "t": f"repo:{repo}", "kind": "signature"})
        # One hub per ORIGIN COUNTRY (only when attributed at probable+), so the
        # visual DB clusters by nation and adding a country needs no graph change.
        if a.attributed and a.origin:
            add(f"actor:{a.origin}", "actor", a.origin)
            edges.append({"s": f"actor:{a.origin}", "t": f"repo:{repo}", "kind": "actor"})
        if r["code_hash"]:
            by_hash.setdefault(r["code_hash"], []).append(repo)
        pk = _payload_key(r["raw_payload"])
        if pk:
            camp_members.setdefault(pk, []).append(repo)
            if a.attributed and a.origin:
                camp_actors.setdefault(pk, set()).add(a.origin)
    for reps in by_hash.values():
        for a, b in zip(reps, reps[1:], strict=False):
            edges.append({"s": f"repo:{a}", "t": f"repo:{b}", "kind": "codehash"})
    # Payload campaigns: repos sharing one eval(atob) payload are one campaign by
    # the same actor (across owners + signature labels). Wire any actor seen on a
    # member to the WHOLE campaign, so one OSM attribution (corex -> DPRK) lights up
    # every repo in the cluster.
    for pk, members in camp_members.items():
        if len(members) < 2:
            continue
        cid = f"camp:{pk}"
        add(cid, "campaign", f"payload {pk[:6]}", repos=len(members))
        for m in members:
            edges.append({"s": cid, "t": f"repo:{m}", "kind": "campaign"})
        for actor in camp_actors.get(pk, ()):
            add(f"actor:{actor}", "actor", actor)
            edges.append({"s": f"actor:{actor}", "t": cid, "kind": "attributed"})
    repo_n = sum(1 for n in nodes.values() if n["type"] == "repo")
    return {"nodes": list(nodes.values()), "edges": edges, "scope": scope, "repos": repo_n}


def funnel(db: Database) -> dict[str, int]:
    """Discovery-pipeline counts across the WHOLE DB (candidate -> screened ->
    confirmed -> rejected): the full capture volume behind the confirmed graph."""
    counts = {r["status"]: r["n"] for r in db.conn.execute(
        "SELECT status, count(*) n FROM repo_findings GROUP BY status")}
    return {k: counts.get(k, 0) for k in ("candidate", "screened", "confirmed", "rejected")}


def actor_contributions(db: Database) -> list[dict[str, Any]]:
    """Confirmed findings grouped by attributed threat actor.

    The highest-value breadcrumb: a repo tied to a KNOWN group (DPRK, APT28,
    Lazarus Group, ...), not just "malware, source/method unknown". Joins
    ``threat_actors`` for the registry status (promoted/quarantined/candidate)
    so the panel distinguishes a corroborated actor from a one-off free-text
    attribution; ``actor_key`` is the SAME normalized key the /api/graph actor
    nodes use, so a panel entry and its graph node always agree.
    """
    rows = db.conn.execute(
        "SELECT rf.full_name, rf.detection_method, rf.actor_key, "
        "COALESCE(ta.canonical_name, rf.actor_key) AS label, "
        "COALESCE(ta.status, 'unregistered') AS actor_status "
        "FROM repo_findings rf LEFT JOIN threat_actors ta ON ta.actor_key = rf.actor_key "
        "WHERE rf.status = 'confirmed' AND rf.actor_key IS NOT NULL AND rf.actor_key != ''"
    ).fetchall()
    by_actor: dict[str, dict[str, Any]] = {}
    for r in rows:
        bucket = by_actor.setdefault(r["actor_key"], {
            "actor_key": r["actor_key"], "label": r["label"],
            "actor_status": r["actor_status"], "repos": [], "methods": Counter(),
        })
        bucket["repos"].append(r["full_name"])
        bucket["methods"][r["detection_method"]] += 1
    out = []
    for bucket in by_actor.values():
        bucket["methods"] = dict(bucket["methods"])
        bucket["repo_count"] = len(bucket["repos"])
        out.append(bucket)
    out.sort(key=lambda b: -b["repo_count"])
    return out


def source_yield(db: Database) -> list[dict[str, Any]]:
    """Per discovery method: confirmed / rejected / screened / candidate counts +
    PRECISION (confirmed / (confirmed+rejected)).

    The signal that drove tonight's whole investigation: which breadcrumb source
    actually finds malware vs. produces noise. package_ref confirming 0 while
    rejecting 22 (0% precision) is the story a table makes obvious. ``precision``
    is None when a method has no adjudicated (confirmed|rejected) findings yet.
    """
    per_method: dict[str, dict[str, int]] = {}
    for r in db.conn.execute(
        "SELECT detection_method, status, count(*) n FROM repo_findings "
        "GROUP BY detection_method, status"
    ):
        m = per_method.setdefault(r["detection_method"],
                                  {"confirmed": 0, "rejected": 0, "screened": 0, "candidate": 0})
        if r["status"] in m:
            m[r["status"]] += r["n"]
    out = []
    for method, counts in per_method.items():
        adjudicated = counts["confirmed"] + counts["rejected"]
        out.append({
            "method": method, **counts,
            "adjudicated": adjudicated,
            "precision": (counts["confirmed"] / adjudicated) if adjudicated else None,
        })
    # Worst precision first among methods that HAVE produced findings to judge --
    # the noisy sources are what a reviewer needs to see and tune.
    out.sort(key=lambda x: (x["precision"] if x["precision"] is not None else 1.0,
                            -x["rejected"]))
    return out


def rejected_findings(db: Database, limit: int = 20) -> list[dict[str, Any]]:
    """Recent rejected findings: the false-positive counterpart to the wall.

    Given how many FPs this tool can surface, the rejected list is as important
    as the confirmed one -- it shows what was correctly kept OFF the wall (and,
    read over time, whether a detection rule is still misfiring).
    """
    out = []
    for r in db.conn.execute(
        "SELECT full_name, detection_method, score, reasoning FROM repo_findings "
        "WHERE status = 'rejected' ORDER BY last_seen_run DESC, score DESC LIMIT ?",
        (limit,)
    ):
        out.append({
            "full_name": r["full_name"], "method": r["detection_method"],
            "score": r["score"], "reasoning": r["reasoning"],
        })
    return out


def recent_runs(db: Database, limit: int = 8) -> dict[str, Any]:
    """Recent ingest/hunt runs, newest first, for the live activity feed.

    A run is ``live`` while status is 'running' (finish_run stamps finished_at and
    a terminal status). The dashboard pulses when any run is live and shows each
    run's confirmed count so new inclusions are visible the moment they land.
    """
    runs = []
    for r in db.conn.execute(
        "SELECT run_id, status, started_at, finished_at, counts FROM runs "
        "ORDER BY started_at DESC LIMIT ?", (limit,)
    ):
        counts = json.loads(r["counts"] or "{}")
        runs.append({
            "run_id": r["run_id"],
            "status": r["status"],
            "started_at": r["started_at"],
            "finished_at": r["finished_at"],
            "live": r["status"] == "running" and not r["finished_at"],
            "confirmed": counts.get("confirmed", 0),
            "candidates": counts.get("candidates", 0),
            "gold_delivered": counts.get("gold_delivered", 0),
        })
    return {"runs": runs, "live": any(x["live"] for x in runs)}


def runs_timeline(db: Database) -> list[dict[str, Any]]:
    """Per-run confirmed/candidate counts, oldest first (telemetry over time)."""
    out = []
    for r in db.conn.execute("SELECT run_id, status, counts FROM runs ORDER BY started_at"):
        counts = json.loads(r["counts"] or "{}")
        out.append({
            "run_id": r["run_id"],
            "status": r["status"],
            "candidates": counts.get("candidates", 0),
            "confirmed": counts.get("confirmed", 0),
            "gold_delivered": counts.get("gold_delivered", 0),
        })
    return out
