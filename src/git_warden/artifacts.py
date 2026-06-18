"""Per-run artifacts for full transparency (PRD section 13.1).

Every run emits a CSV of all observed actors (including quarantined and rejected
ones, so audits confirm nothing good was silently dropped) and a JSON summary of
the run. These are inspection/audit outputs -- distinct from the gold Discord
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
