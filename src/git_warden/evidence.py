"""The committed ``evidence/`` store: every finding, one editable CSV.

``evidence/findings.csv`` lists every confirmed repository and VS Code
extension with the full column set. Each run refreshes the generated columns
and keeps two hand-edited columns untouched:

* ``reviewer_decision``: ``reject`` keeps an extension out of the OSM preview
  (anything else, or blank, has no effect);
* ``notes``: free text.

Rows already in the CSV are never dropped, so the file survives a lost data
cache. Each row points at ``evidence/<kind>/<id>.json``: the full static
evidence (file, line, rule, snippet for every finding) and the exact OSM report
body. ``evidence/osm_extension_ledger.json`` records submitted extensions.
"""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from . import config
from .db import Database

EVIDENCE_DIR = config.PROJECT_ROOT / "evidence"
CSV_NAME = "findings.csv"
LEDGER_NAME = "osm_extension_ledger.json"
EDITABLE = ("reviewer_decision", "notes")
COLUMNS = [
    "key", "kind", "id", "url", "registry", "owner", "status", "confidence", "score",
    "detection_method", "attribution", "campaign_id", "rules", "evidence_locations",
    "c2_hosts", "iocs", "matched_signatures", "reasons", "osm_status", "osm_threat_id",
    "first_seen", "last_seen", "evidence_file", *EDITABLE,
]
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")
_MAX_CELL = 2000


def _safe_name(text: str) -> str:
    return _SAFE.sub("_", text).strip("._")[:150] or "unnamed"


def _cell(value) -> str:
    text = "" if value is None else str(value)
    return text.replace("\r", " ").replace("\n", " | ")[:_MAX_CELL]


def _rules(findings: list[dict]) -> str:
    seen: list[str] = []
    for f in findings:
        r = f"{f.get('category') or 'other'}/{f.get('rule')}"
        if f.get("rule") and r not in seen:
            seen.append(r)
    return "; ".join(seen)


def _locations(findings: list[dict], cap: int = 30) -> str:
    out: list[str] = []
    for f in findings:
        loc = f"{f.get('file')}:{f.get('line')}"
        if f.get("file") and loc not in out:
            out.append(loc)
    return "; ".join(out[:cap]) + (f"; +{len(out) - cap} more" if len(out) > cap else "")


def read_csv(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    with path.open(newline="", encoding="utf-8") as fh:
        return {r["key"]: r for r in csv.DictReader(fh) if r.get("key")}


def rejected_keys(evidence_dir: Path = EVIDENCE_DIR) -> set[str]:
    """Keys a reviewer marked ``reject`` in the CSV."""
    return {k.casefold() for k, r in read_csv(evidence_dir / CSV_NAME).items()
            if (r.get("reviewer_decision") or "").strip().casefold() == "reject"}


def ledger_path(evidence_dir: Path = EVIDENCE_DIR) -> Path:
    return evidence_dir / LEDGER_NAME


def _repo_rows(db: Database, campaigns: dict) -> list[tuple[dict, dict]]:
    from .dprk import c2_hosts_from_flags
    from .osm_submit import _verified_iocs, build_report, campaign_context

    out = []
    for row in db.conn.execute(
            "SELECT * FROM repo_findings WHERE status IN ('confirmed', 'validated') "
            "ORDER BY full_name"):
        payload = json.loads(row["raw_payload"] or "{}") or {}
        findings = payload.get("bash_findings") or []
        keys = row.keys()
        submitted = "submitted_osm" in keys and bool(row["submitted_osm"])
        camp = campaigns.get(row["full_name"])
        key = f"repository:{row['full_name']}".casefold()
        rec = {
            "key": key, "kind": "repository", "id": row["full_name"],
            "url": row["url"] or f"https://github.com/{row['full_name']}",
            "registry": "github", "owner": row["full_name"].split("/", 1)[0],
            "status": row["status"], "confidence": payload.get("confidence") or "",
            "score": row["score"], "detection_method": row["detection_method"],
            "attribution": row["actor_key"] or "",
            "campaign_id": camp.id if camp else "",
            "rules": _rules(findings), "evidence_locations": _locations(findings),
            "c2_hosts": "; ".join(c2_hosts_from_flags(findings)),
            "iocs": _verified_iocs(row).replace("\n", "; "),
            "matched_signatures": "; ".join(json.loads(row["matched_iocs"] or "[]")),
            "reasons": (row["reasoning"] or "")[:500],
            "osm_status": "submitted" if submitted else "not_submitted",
            "osm_threat_id": (row["osm_threat_id"] if "osm_threat_id" in keys else "") or "",
            "first_seen": row["first_seen_run"] or "", "last_seen": row["last_seen_run"] or "",
            "evidence_file": f"repositories/{_safe_name(row['full_name'])}.json",
        }
        detail = {"finding": rec, "evidence": findings,
                  "commit_sha": payload.get("commit_sha"),
                  "osm_report": build_report(
                      row, campaign_ctx=campaign_context(db, row, index=campaigns))}
        out.append((rec, detail))
    return out


def _extension_rows(db: Database, ledger: dict[str, dict]) -> list[tuple[dict, dict]]:
    from .dprk import c2_hosts_from_flags
    from .extensions.osm import OSM_REGISTRY, _iocs

    out = []
    for row in db.extensions("confirmed"):
        payload = json.loads(row["raw_payload"] or "{}") or {}
        findings = payload.get("confirming_findings") or []
        ext_id = f"{row['namespace']}.{row['name']}"
        sub = ledger.get(row["ext_key"].casefold())
        rec = {
            "key": row["ext_key"].casefold(), "kind": "vscode-extension", "id": ext_id,
            "url": row["url"] or "", "registry": OSM_REGISTRY.get(row["registry"],
                                                                  row["registry"]),
            "owner": row["namespace"], "status": row["status"],
            "confidence": row["confidence"], "score": row["score"],
            "detection_method": "extension_hunt", "attribution": "", "campaign_id": "",
            "rules": _rules(findings), "evidence_locations": _locations(findings),
            "c2_hosts": "; ".join(c2_hosts_from_flags(findings)),
            "iocs": _iocs(findings).replace("\n", "; "), "matched_signatures": "",
            "reasons": "; ".join(json.loads(row["reasons"] or "[]")),
            "osm_status": "submitted" if sub else "not_submitted",
            "osm_threat_id": (sub or {}).get("threat_id", ""),
            "first_seen": row["first_seen_run"] or "", "last_seen": row["last_seen_run"] or "",
            "evidence_file": f"extensions/{_safe_name(row['ext_key'])}.json",
        }
        detail = {"finding": rec, "version": row["version"], "evidence": findings,
                  "extension": payload.get("extension") or {}}
        out.append((rec, detail))
    return out


def export(db: Database, evidence_dir: Path = EVIDENCE_DIR,
           preview: list[dict] | None = None) -> dict:
    """Refresh ``evidence/``. Returns counts. ``preview`` adds OSM preview bodies
    (``[{"key", "report"}]``) to extension evidence files and marks them
    ``awaiting_approval``."""
    from .correlate import campaign_index
    from .extensions.osm import _ledger_load

    evidence_dir.mkdir(parents=True, exist_ok=True)
    csv_path = evidence_dir / CSV_NAME
    existing = read_csv(csv_path)
    ledger = _ledger_load(ledger_path(evidence_dir))
    previews = {p["key"].casefold(): p["report"] for p in (preview or [])}

    rows = _repo_rows(db, campaign_index(db)) + _extension_rows(db, ledger)
    merged = dict(existing)
    for rec, detail in rows:
        if rec["key"] in previews and rec["osm_status"] == "not_submitted":
            rec["osm_status"] = "awaiting_approval"
            detail["osm_report"] = previews[rec["key"]]
        old = existing.get(rec["key"], {})
        for col in EDITABLE:
            rec[col] = old.get(col, "")
        merged[rec["key"]] = {c: _cell(rec.get(c)) for c in COLUMNS}
        target = evidence_dir / rec["evidence_file"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(detail, indent=2, ensure_ascii=False, default=str)
                          + "\n", encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for key in sorted(merged, key=lambda k: (merged[k].get("kind", ""), k)):
            writer.writerow({c: merged[key].get(c, "") for c in COLUMNS})
    return {"rows": len(merged), "refreshed": len(rows),
            "kept_from_previous": len(set(existing) - {r["key"] for r, _ in rows})}
