"""Pure correlation queries over the registry for the telemetry dashboard.

Every function takes a :class:`~git_warden.db.Database` and returns plain
JSON-able data -- no web framework -- so the correlation logic is fully
unit-testable. The FastAPI layer (:mod:`.app`) just serializes these.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from ..db import Database


def _owner(full_name: str) -> str:
    return full_name.split("/", 1)[0]


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
        "by_method": {
            r["detection_method"]: r["n"] for r in c.execute(
                "SELECT detection_method, count(*) n FROM repo_findings "
                "WHERE status = 'confirmed' GROUP BY detection_method")
        },
    }


def findings(db: Database, status: str | None = None) -> list[dict[str, Any]]:
    """Finding rows for the table, newest/high-score first; novel flag attached."""
    known = db.osm_known_repos()
    sql = ("SELECT full_name, detection_method, status, score, delivered_gold, actor_key "
           "FROM repo_findings")
    params: tuple = ()
    if status:
        sql += " WHERE status = ?"
        params = (status,)
    sql += " ORDER BY (status='confirmed') DESC, score DESC, full_name"
    out = []
    for r in db.conn.execute(sql, params):
        out.append({
            "full_name": r["full_name"],
            "owner": _owner(r["full_name"]),
            "method": r["detection_method"],
            "status": r["status"],
            "score": r["score"],
            "gold": bool(r["delivered_gold"]),
            "attribution": r["actor_key"],
            "novel": r["full_name"].casefold() not in known,
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
    return {
        "full_name": r["full_name"],
        "url": r["url"],
        "method": r["detection_method"],
        "status": r["status"],
        "score": r["score"],
        "reasoning": r["reasoning"],
        "attribution": r["actor_key"],
        "signals": json.loads(r["signals"] or "[]"),
        "matched_iocs": json.loads(r["matched_iocs"] or "[]"),
        "flags": payload.get("bash_findings") or [],
        "scanners": payload.get("scanners") or {},
        "osm": payload.get("osm"),
        "code_hash": r["code_hash"],
        "gold": bool(r["delivered_gold"]),
        "novel": r["full_name"].casefold() not in db.osm_known_repos(),
    }


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


def graph(db: Database) -> dict[str, Any]:
    """Force-graph nodes/edges correlating confirmed repos, owners, signatures.

    Nodes: repo (novel/method/score), owner, signature. Edges: owner-owns-repo,
    signature-matched-repo, repo-repo (shared code-hash = same core).
    """
    c = db.conn
    known = db.osm_known_repos()
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add(node_id: str, ntype: str, label: str, **kw) -> None:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": ntype, "label": label, **kw}

    by_hash: dict[str, list[str]] = {}
    for r in c.execute("SELECT full_name, detection_method, matched_iocs, code_hash, score "
                       "FROM repo_findings WHERE status = 'confirmed'"):
        repo, owner = r["full_name"], _owner(r["full_name"])
        add(f"repo:{repo}", "repo", repo.split("/", 1)[-1],
            repo=repo, novel=repo.casefold() not in known,
            method=r["detection_method"], score=r["score"])
        add(f"owner:{owner}", "owner", owner)
        edges.append({"s": f"owner:{owner}", "t": f"repo:{repo}", "kind": "owns"})
        for sig in json.loads(r["matched_iocs"] or "[]"):
            add(f"sig:{sig[:40]}", "signature", sig[:18] + "…")
            edges.append({"s": f"sig:{sig[:40]}", "t": f"repo:{repo}", "kind": "signature"})
        if r["code_hash"]:
            by_hash.setdefault(r["code_hash"], []).append(repo)
    for reps in by_hash.values():
        for a, b in zip(reps, reps[1:], strict=False):
            edges.append({"s": f"repo:{a}", "t": f"repo:{b}", "kind": "codehash"})
    return {"nodes": list(nodes.values()), "edges": edges}


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
