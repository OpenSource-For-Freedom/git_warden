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

from .config import ARTIFACTS_DIR, WALL_OF_SHAME_PATH
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


def _wall_entry(row) -> dict:
    """Build a committed Wall-of-Shame record from a validated finding row."""
    return {
        "full_name": row["full_name"],
        "detection_method": row["detection_method"],
        "score": row["score"],
        "attribution": row["actor_key"] or "unattributed",
        "first_seen_run": row["first_seen_run"] or "",
        "reasoning": (row["reasoning"] or "").replace("\n", " ")[:300],
        "evidence": _top_indicator(row["raw_payload"]),
    }


def load_wall(path: Path = WALL_OF_SHAME_PATH) -> list[dict]:
    """Read the committed analyst-approved Wall of Shame (or [] if absent)."""
    p = Path(path)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8") or "[]")
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        log.warning("wall_of_shame.json unreadable; treating as empty")
        return []


def save_wall(entries: list[dict], path: Path = WALL_OF_SHAME_PATH) -> None:
    ordered = sorted(entries, key=lambda e: (-int(e.get("score", 0) or 0),
                                             e.get("full_name", "")))
    Path(path).write_text(json.dumps(ordered, indent=2) + "\n", encoding="utf-8")


def add_to_wall(row, path: Path = WALL_OF_SHAME_PATH) -> list[dict]:
    """Add (or refresh) one validated finding on the committed Wall of Shame."""
    entry = _wall_entry(row)
    key = entry["full_name"].casefold()
    entries = [e for e in load_wall(path) if (e.get("full_name") or "").casefold() != key]
    entries.append(entry)
    save_wall(entries, path)
    return entries


def remove_from_wall(full_name: str, path: Path = WALL_OF_SHAME_PATH) -> bool:
    """Drop a finding from the Wall of Shame (analyst reject). True if removed."""
    key = full_name.strip().strip("/").casefold()
    entries = load_wall(path)
    kept = [e for e in entries if (e.get("full_name") or "").casefold() != key]
    if len(kept) == len(entries):
        return False
    save_wall(kept, path)
    return True


def render_registry_table(entries: list) -> str:
    """Render the Wall of Shame records as a Markdown table (highest score first)."""
    header = (
        "| Repository | Detection | Score | Attribution | First seen | Why |\n"
        "|------------|-----------|-------|-------------|------------|-----|"
    )
    if not entries:
        return header + "\n| _none yet_ |  |  |  |  |  |"
    lines = [header]
    for e in entries:
        full = e["full_name"]
        repo = f"[`{_md_cell(full)}`](https://github.com/{_md_cell(full)})"
        why = _md_cell((e.get("reasoning") or "")[:140])
        lines.append(
            f"| {repo} | {_md_cell(e.get('detection_method'))} | {e.get('score')} | "
            f"{_md_cell(e.get('attribution') or 'unattributed')} | "
            f"{_md_cell(e.get('first_seen_run') or '')} | {why} |"
        )
    return "\n".join(lines)


def update_readme_registry_table(
    readme_path: Path = Path("README.md"),
    wall_path: Path = WALL_OF_SHAME_PATH,
) -> bool:
    """Regenerate the Wall of Shame table in README between the markers.

    Returns True if the file content changed. The table is rendered from the
    COMMITTED wall_of_shame.json (the analyst-approved set), never from the
    gitignored DB, so a CI run renders exactly what was approved and committed,
    rather than wiping the wall from an empty CI database. Findings reach the
    file only via ``gw review --approve``; a public list is an accusation, so a
    human approves each repo. Cumulative.
    """
    if not readme_path.exists():
        log.warning("README not found; skipping registry table", extra={
            "context": {"path": str(readme_path)}})
        return False
    entries = load_wall(wall_path)
    table = render_registry_table(entries)
    block = (
        f"{_README_START}\n"
        f"_{len(entries)} analyst-validated malicious repositories. Maintained by "
        f"`gw review --approve`; only findings a human approved appear here. Each "
        f"row's evidence (file, line, rule) is in the run artifacts._\n\n"
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
            f"Auto-generated from the approved registry. The full per-run audit "
            f"(all candidates) is in the run artifacts.\n\n{block}\n"
        )
    if updated == original:
        return False
    readme_path.write_text(updated, encoding="utf-8")
    log.info("updated README registry table", extra={"context": {"rows": len(entries)}})
    return True
