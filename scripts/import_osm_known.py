"""Import OSM's published PolinRider victim lists as a skip list.

    python scripts/import_osm_known.py PolinRider/polinrider-compromised-repos-july10.csv \
        PolinRider/polinrider-master-2026-04-11.csv

Writes evidence/osm_known_reports.csv: every repository OSM lists with a threat
ID. Those are already reported, so the submitter skips them instead of filing a
duplicate (osm_automation.evidence_skips). Rows are merged into the existing file
and never dropped. Source: github.com/OpenSourceMalware/PolinRider.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "evidence" / "osm_known_reports.csv"
COLUMNS = ["key", "threat_id", "source"]
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def _rows(path: Path):
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            norm = {k.strip().lower().replace(" ", "_"): (v or "").strip()
                    for k, v in row.items() if k}
            repo = norm.get("repository") or ""
            tid = norm.get("osm_threat_id") or ""
            if _REPO.match(repo) and _UUID.match(tid):
                yield f"repository:{repo}".casefold(), tid.lower()


def merge(sources: list[Path], out: Path = OUT, label: str = "osm-polinrider") -> dict:
    existing: dict[str, dict] = {}
    if out.exists():
        with out.open(newline="", encoding="utf-8") as fh:
            existing = {r["key"]: r for r in csv.DictReader(fh) if r.get("key")}
    added = 0
    for src in sources:
        for key, tid in _rows(src):
            if key not in existing:
                existing[key] = {"key": key, "threat_id": tid, "source": label}
                added += 1
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for key in sorted(existing):
            writer.writerow(existing[key])
    return {"rows": len(existing), "added": added}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("csv", nargs="+", type=Path)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)
    print(json.dumps(merge(args.csv, args.out)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
