"""Fail-closed unattended OSM submission for Git Warden.

This path is intentionally stricter than the interactive/local submit command.
Every repository is re-scanned in the hardened Tier-2 Docker sandbox, must still
confirm at AUTO confidence, must still be live at GitHub HEAD, and must pass an
authoritative OSM full-history pre-check twice: once before validation and again
immediately before POST. Any uncertainty blocks submission.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

import requests

from . import config
from . import intel_exchange as bus
from .db import Database
from .osm_submit import (
    build_report,
    campaign_context,
    gold_for_submission,
    mark_osm_submitted,
    repo_payload_live,
    submit_threat,
    unmark_osm_submitted,
)

POLICY_PATH = config.PROJECT_ROOT / "config" / "osm_automation.json"


class OSMPrecheckError(RuntimeError):
    """The authoritative novelty check could not prove the resource is novel."""


def _validate_policy(policy: dict) -> dict:
    """Refuse policy changes that weaken unattended-submission safety."""
    if policy.get("schema_version") != 1:
        raise RuntimeError("unsupported OSM automation policy schema")
    if policy.get("fail_closed") is not True:
        raise RuntimeError("OSM automation policy must remain fail-closed")
    if policy.get("required_confidence") != "auto":
        raise RuntimeError("Warden automation requires AUTO confidence")
    if policy.get("require_docker_sandbox") is not True:
        raise RuntimeError("Warden automation requires the Docker sandbox")
    if policy.get("require_positive_liveness") is not True:
        raise RuntimeError("Warden automation requires positive payload liveness")
    if policy.get("require_intrinsic_evidence") is not True:
        raise RuntimeError("Warden automation requires intrinsic evidence")
    if int(policy.get("osm_full_history_prechecks", 0)) < 2:
        raise RuntimeError("Warden automation requires at least two OSM pre-checks")
    if policy.get("require_shared_intel_dedup") is not True:
        raise RuntimeError("Warden automation requires shared-intel submission dedup")
    if policy.get("submit_domains") is not False:
        raise RuntimeError("unattended domain submission must remain disabled")
    limit = int(policy.get("max_submissions_per_run", 0))
    if not 1 <= limit <= 25:
        raise RuntimeError("Warden automation submission limit must be between 1 and 25")
    pace = float(policy.get("pace_seconds", 0))
    if pace < 6:
        raise RuntimeError("Warden automation pace must be at least 6 seconds")
    return policy


def load_policy(path: Path = POLICY_PATH) -> dict:
    import json

    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"cannot load OSM automation policy: {exc}") from exc
    if not isinstance(policy, dict):
        raise RuntimeError("OSM automation policy must be a JSON object")
    return _validate_policy(policy)


def _resource_key(resource: str) -> str:
    r = (resource or "").strip().casefold()
    marker = "github.com/"
    if marker in r:
        tail = r.split(marker, 1)[1].split("#", 1)[0].split("?", 1)[0].strip("/")
        parts = tail.split("/")
        if len(parts) >= 2:
            return "/".join(parts[:2])
    return r


def _search_full_history(term: str) -> list[dict]:
    token = config.OSM_API_KEY
    if not token:
        raise OSMPrecheckError("OSM API key is missing")
    try:
        response = requests.get(
            config.osm_endpoint("search"),
            params={"q": term},
            headers={
                "Authorization": f"Bearer {token}",
                "apikey": token,
                "Accept": "application/json",
            },
            timeout=config.HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise OSMPrecheckError(f"OSM full-history search failed for {term!r}: {exc}") from exc
    if response.status_code != 200:
        raise OSMPrecheckError(
            f"OSM full-history search returned HTTP {response.status_code} for {term!r}"
        )
    try:
        payload = response.json() if response.content else {}
    except ValueError as exc:
        raise OSMPrecheckError("OSM full-history search returned malformed JSON") from exc
    rows = payload.get("data") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise OSMPrecheckError("OSM full-history search returned an unexpected response shape")
    return [row for row in rows if isinstance(row, dict)]


def _existing_repo(full_name: str) -> dict | None:
    wanted = full_name.strip().strip("/").casefold()
    variants = (
        f"https://github.com/{wanted}",
        f"https://github.com/{wanted}/",
        f"github.com/{wanted}",
        f"github.com/{wanted}/",
    )
    for variant in variants:
        for row in _search_full_history(variant):
            resource = str(row.get("resource_identifier") or "")
            if _resource_key(resource) == wanted:
                return row
    return None


def _deep_validate(full_name: str) -> tuple[bool, str]:
    from .scanning.sandbox_runner import docker_available, scan_candidate_sandboxed

    if not docker_available():
        return False, "Docker sandbox unavailable"
    result = scan_candidate_sandboxed(full_name)
    if result is None:
        return False, "sandbox scan produced no result"
    if not result.confirmed:
        return False, "current Tier-2 scan no longer confirms malicious behavior"
    if result.confidence != "auto":
        return False, f"current Tier-2 confidence is {result.confidence!r}, not AUTO"
    if not result.confirming_findings and not result.package_spread:
        if not any(status == "flagged" for status in (result.scanners or {}).values()):
            return False, "current Tier-2 result has no confirming evidence"
    return True, f"current commit {result.commit_sha or 'HEAD'} confirmed AUTO"


def run(
    db: Database, *, limit: int | None = None, pace: float | None = None,
) -> int:
    policy = load_policy()
    limit = int(policy["max_submissions_per_run"]) if limit is None else limit
    pace = float(policy["pace_seconds"]) if pace is None else pace
    rows = gold_for_submission(db, limit=limit)
    if not rows:
        print("Warden OSM automation: no AUTO-tier novel candidates.")
        return 0

    sent = 0
    for row in rows:
        full_name = row["full_name"]
        resource = f"https://github.com/{full_name}"

        if bus.is_submitted("repository", resource):
            print(f"[skip] {full_name}: shared intelligence already marks it submitted")
            continue

        hit = _existing_repo(full_name)
        if hit:
            print(
                f"[skip] {full_name}: already in OSM "
                f"({hit.get('status')}, id {str(hit.get('id') or '')[:8]})"
            )
            bus.mark_submitted(
                "repository", resource, threat_id=str(hit.get("id") or "")
            )
            continue

        valid, reason = _deep_validate(full_name)
        if not valid:
            print(f"[skip] {full_name}: deep validation failed closed: {reason}")
            continue

        live = repo_payload_live(row)
        if live is not True:
            print(f"[skip] {full_name}: current payload liveness was not positively confirmed")
            continue

        # Close the race window: check OSM again immediately before the claim/POST.
        hit = _existing_repo(full_name)
        if hit:
            print(
                f"[skip] {full_name}: appeared in OSM during validation "
                f"({hit.get('status')}, id {str(hit.get('id') or '')[:8]})"
            )
            bus.mark_submitted(
                "repository", resource, threat_id=str(hit.get("id") or "")
            )
            continue
        if bus.is_submitted("repository", resource):
            print(f"[skip] {full_name}: shared intelligence changed during validation")
            continue

        report = build_report(
            row,
            dprk_infra=db.dprk_infra_hosts(exclude=full_name),
            campaign_ctx=campaign_context(db, row),
        )
        print(f"[validated] {full_name}: {reason}; OSM full history clear")

        mark_osm_submitted(db, full_name, None)
        try:
            response = submit_threat(report)
        except Exception:
            unmark_osm_submitted(db, full_name)
            raise

        threat_id = response.get("threat_id")
        mark_osm_submitted(db, full_name, threat_id)
        bus.mark_submitted("repository", resource, threat_id=threat_id)
        sent += 1
        print(f"[submitted] {full_name} -> {threat_id or 'OSM'}")
        if pace and row is not rows[-1]:
            time.sleep(pace)

    print(f"Warden OSM automation: submitted {sent} repository report(s).")
    return sent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=config.DB_PATH)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--pace", type=float, default=None)
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args(argv)

    if args.check_config:
        load_policy()
        print("Warden OSM automation policy: PASS")
        return 0

    db = Database.open(args.db)
    try:
        limit = None if args.limit is None else max(0, args.limit)
        pace = None if args.pace is None else max(0.0, args.pace)
        run(db, limit=limit, pace=pace)
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
