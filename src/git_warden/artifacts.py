"""Per-run artifacts for full transparency (PRD section 13.1).

Every run emits a CSV of all observed actors (including quarantined and rejected
ones, so audits confirm nothing good was silently dropped) and a JSON summary of
the run. These are inspection/audit outputs; distinct from the gold Discord
feed, which carries only confirmed findings.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pandas as pd

from .config import ARTIFACTS_DIR
from .db import Database

log = logging.getLogger(__name__)

# Full column set for the per-run findings CSV (everything an analyst needs to
# triage without opening the DB). Stable even when a run finds nothing.
_FINDINGS_COLUMNS = [
    "full_name",
    "owner",
    "platform",
    "status",
    "detection_method",
    "score",
    "novel",          # not already reported by OSM (our own contribution)
    "delivered_gold",  # 1 once sent to Discord
    "attribution",
    "url",
    "code_hash",
    "top_indicator",   # first file:line -> category/rule that fired
    "signals",
    "matched_iocs",
    "reasoning",
    "first_seen_run",
    "last_seen_run",
]

# README registry table is regenerated in place between these markers.
_README_START = "<!-- git-warden:registry:start -->"
_README_END = "<!-- git-warden:registry:end -->"
# The public wall shows only the most dangerous handful; the FULL confirmed list
# ships as the run's CSV artifact and to the Discord feed.
_README_MAX_ROWS = 10


def write_run_artifacts(
    db: Database,
    run_id: str,
    artifacts_dir: Path = ARTIFACTS_DIR,
) -> dict[str, Path]:
    """Write the actor CSV and run-summary JSON. Returns the paths written."""
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    actor_rows = [dict(r) for r in db.actors_for_run(run_id)]
    csv_path = artifacts_dir / f"{run_id}_actors.csv"
    # Stable columns even when a run produced no actors.
    columns = [
        "actor_key",
        "canonical_name",
        "category",
        "status",
        "source_count",
        "first_seen_run",
        "last_seen_run",
    ]
    pd.DataFrame(actor_rows, columns=columns).to_csv(csv_path, index=False)

    run_row = db.get_run(run_id)
    status_breakdown: dict[str, int] = {}
    for row in actor_rows:
        status_breakdown[row["status"]] = status_breakdown.get(row["status"], 0) + 1

    summary = {
        "run_id": run_id,
        "status": run_row["status"] if run_row else None,
        "started_at": run_row["started_at"] if run_row else None,
        "finished_at": run_row["finished_at"] if run_row else None,
        "counts": json.loads(run_row["counts"]) if run_row else {},
        "observations_by_source": db.observation_counts_by_source(run_id),
        "actors_by_status": status_breakdown,
        "actor_total": len(actor_rows),
    }
    json_path = artifacts_dir / f"{run_id}_summary.json"
    json_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")

    log.info(
        "wrote run artifacts",
        extra={"context": {"csv": str(csv_path), "summary": str(json_path)}},
    )
    return {"csv": csv_path, "summary": json_path}


def _top_indicator(raw_payload: str) -> str:
    """First file:line -> category/rule from a finding's static-scan payload."""
    bash = (json.loads(raw_payload or "{}") or {}).get("bash_findings") or []
    if not bash:
        return ""
    b = bash[0]
    return f"{b.get('file', '')}:{b.get('line', '')} {b.get('category', '')}/{b.get('rule', '')}"


def _finding_row(row) -> dict:
    """Flatten a repo_findings row into the CSV column set."""
    full = row["full_name"]
    return {
        "full_name": full,
        "owner": full.split("/", 1)[0],
        "platform": row["platform"],
        "status": row["status"],
        "detection_method": row["detection_method"],
        "score": row["score"],
        "novel": row["detection_method"] != "osm_repository",
        "delivered_gold": row["delivered_gold"],
        "attribution": row["actor_key"] or "",
        "url": row["url"] or f"https://github.com/{full}",
        "code_hash": (row["code_hash"] or "")[:16],
        "top_indicator": _top_indicator(row["raw_payload"]),
        "signals": " | ".join(json.loads(row["signals"] or "[]")),
        "matched_iocs": " | ".join(json.loads(row["matched_iocs"] or "[]")),
        "reasoning": (row["reasoning"] or "").replace("\n", " ")[:500],
        "first_seen_run": row["first_seen_run"],
        "last_seen_run": row["last_seen_run"],
    }


def write_findings_csv(
    db: Database,
    run_id: str,
    artifacts_dir: Path = ARTIFACTS_DIR,
) -> Path:
    """Write a CSV of every repo this run touched, with the full column set.

    Full transparency (PRD 13.1): newly discovered AND re-seen repos across all
    statuses (candidate, screened, confirmed, rejected). Columns are stable even
    when the run found nothing, so the artifact always exists.
    """
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    rows = [_finding_row(r) for r in db.findings_for_run(run_id)]
    csv_path = artifacts_dir / f"{run_id}_findings.csv"
    pd.DataFrame(rows, columns=_FINDINGS_COLUMNS).to_csv(csv_path, index=False)
    log.info(
        "wrote findings CSV",
        extra={"context": {"csv": str(csv_path), "rows": len(rows)}},
    )
    return csv_path


def _md_cell(value) -> str:
    """Sanitize a value for a single Markdown table cell (no row/col breakout)."""
    text = str(value if value is not None else "").replace("\n", " ").replace("\r", " ")
    return text.replace("|", "\\|").replace("`", "'")


def render_registry_table(rows: list) -> str:
    """Render confirmed malicious repos as a Markdown table (highest score first)."""
    header = (
        "| Repository | Detection | Score | Attribution | First seen | Why |\n"
        "|------------|-----------|-------|-------------|------------|-----|"
    )
    if not rows:
        return header + "\n| _none yet_ |  |  |  |  |  |"
    lines = [header]
    for r in rows:
        full = r["full_name"]
        repo = f"[`{_md_cell(full)}`](https://github.com/{_md_cell(full)})"
        why = _md_cell((r["reasoning"] or "")[:140])
        lines.append(
            f"| {repo} | {_md_cell(r['detection_method'])} | {r['score']} | "
            f"{_md_cell(r['actor_key'] or 'unattributed')} | "
            f"{_md_cell(r['first_seen_run'] or '')} | {why} |"
        )
    return "\n".join(lines)


def update_readme_registry_table(
    db: Database,
    readme_path: Path = Path("README.md"),
) -> bool:
    """Regenerate the Wall of Shame table in README between the markers.

    Returns True if the file content changed. Rendered from the run's DB each
    run: every repo Git Warden confirmed malicious by static analysis. A CI run
    confirms findings into its own DB, then renders + pushes the README, so the
    public wall reflects the latest run. ``gw review --reject owner/repo`` drops
    a false positive. The full per-run audit (all candidates) is in the run
    artifacts CSV.
    """
    if not readme_path.exists():
        log.warning("README not found; skipping registry table", extra={
            "context": {"path": str(readme_path)}})
        return False
    rows = db.published_findings()
    total = len(rows)
    # Public wall = the most dangerous handful (top score first). The full list is
    # not dumped here; it ships as the CSV artifact and to the Discord feed.
    top = sorted(rows, key=lambda r: r["score"] or 0, reverse=True)[:_README_MAX_ROWS]
    table = render_registry_table(top)
    if total > len(top):
        caption = (
            f"_Top {len(top)} of {total} repositories confirmed malicious by static "
            f"analysis this run, ranked by severity. The full list ships as the run's "
            f"CSV artifact and to the Discord feed; every row's evidence (file, line, "
            f"rule) is in that CSV. Dispute: open an issue and we will re-review._"
        )
    else:
        caption = (
            f"_{total} repositories confirmed malicious by static analysis, regenerated "
            f"each run. Every row's evidence (file, line, rule) is in the run artifacts "
            f"CSV. Dispute: open an issue and we will re-review._"
        )
    block = (
        f"{_README_START}\n"
        f"{caption}\n\n"
        f"{table}\n"
        f"{_README_END}"
    )
    original = readme_path.read_text(encoding="utf-8")
    if _README_START in original and _README_END in original:
        head, _, rest = original.partition(_README_START)
        _, _, tail = rest.partition(_README_END)
        updated = head + block + tail
    else:
        sep = "" if original.endswith("\n") else "\n"
        updated = (
            f"{original}{sep}\n## Wall of Shame\n\n"
            f"Auto-generated from the registry. The full per-run audit "
            f"(all candidates) is in the run artifacts.\n\n{block}\n"
        )
    if updated == original:
        return False
    readme_path.write_text(updated, encoding="utf-8")
    log.info("updated README registry table",
             extra={"context": {"rows": len(top), "total": total}})
    return True
