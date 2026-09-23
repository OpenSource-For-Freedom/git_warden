"""Fail-closed unattended OSM submission for Git Warden.

This path is intentionally stricter than the interactive/local submit command.
Every repository is re-scanned in the hardened Tier-2 Docker sandbox, must still
confirm at AUTO confidence, must still be live at GitHub HEAD, and must pass an
authoritative OSM full-history pre-check twice: once before validation and again
immediately before POST. Any uncertainty blocks submission.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import quote

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


class AutomationBlocked(RuntimeError):
    """The run cannot validate anything (no hunt data, no sandbox): fail loudly
    instead of reporting a misleading "nothing found"."""


# A candidate that failed validation is not re-scanned for this long, so repos
# whose payload was removed cannot pin the top of the queue forever. Transient
# failures (sandbox produced nothing, liveness check could not run) retry sooner.
RETRY_AFTER_SECONDS = 7 * 24 * 3600
TRANSIENT_RETRY_SECONDS = 24 * 3600


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


def _bus_submitted(full_name: str) -> bool:
    """Shared-intel dedup under ANY spelling either tool may have recorded
    (scheme or not, trailing slash, case)."""
    want = full_name.strip().strip("/").casefold()
    for target in bus.submitted_targets():
        kind, _, value = target.partition(":")
        if kind == "repository" and _resource_key(value) == want:
            return True
    return False


def _ensure_attempts_table(db) -> None:
    with db.transaction() as c:
        c.execute(
            "CREATE TABLE IF NOT EXISTS osm_automation_attempts ("
            "full_name TEXT PRIMARY KEY, retry_at REAL NOT NULL, reason TEXT)")


def _recently_failed(db, full_name: str, now: float) -> str | None:
    row = db.conn.execute(
        "SELECT retry_at, reason FROM osm_automation_attempts WHERE full_name = ?",
        (full_name,)).fetchone()
    if row and now < float(row["retry_at"]):
        return row["reason"] or "failed validation"
    return None


def _record_failure(db, full_name: str, reason: str, now: float, *,
                    transient: bool = False) -> None:
    wait = TRANSIENT_RETRY_SECONDS if transient else RETRY_AFTER_SECONDS
    with db.transaction() as c:
        c.execute(
            "INSERT OR REPLACE INTO osm_automation_attempts "
            "(full_name, retry_at, reason) VALUES (?, ?, ?)",
            (full_name, now + wait, reason))


def _clear_failure(db, full_name: str) -> None:
    with db.transaction() as c:
        c.execute("DELETE FROM osm_automation_attempts WHERE full_name = ?", (full_name,))


def _search_full_history(term: str) -> list[dict]:
    """Authoritative per-resource lookup via OSM's current check-malicious API."""
    token = config.OSM_API_KEY
    if not token:
        raise OSMPrecheckError("OSM API key is missing")
    try:
        response = requests.get(
            config.osm_endpoint("check-malicious"),
            params={
                "report_type": "repository",
                "resource_identifier": term,
            },
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            timeout=config.HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise OSMPrecheckError(
            f"OSM check-malicious request failed for {term!r}: {exc}"
        ) from exc
    if response.status_code in (401, 403):
        raise OSMPrecheckError(
            f"OSM rejected the API key (HTTP {response.status_code}) at "
            f"{config.osm_endpoint('check-malicious')}; verify OSM_KEY and the OSM base URL"
        )
    if response.status_code != 200:
        raise OSMPrecheckError(
            f"OSM check-malicious returned HTTP {response.status_code} for {term!r}"
        )
    try:
        payload = response.json() if response.content else {}
    except ValueError as exc:
        raise OSMPrecheckError("OSM check-malicious returned malformed JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("malicious"), bool):
        raise OSMPrecheckError("OSM check-malicious returned an unexpected response shape")
    if payload["malicious"] is False:
        return []

    details = payload.get("details")
    row = dict(details) if isinstance(details, dict) else {}
    row.setdefault("resource_identifier", str(payload.get("resource_identifier") or term))
    row.setdefault("report_type", str(payload.get("report_type") or "repository"))
    if payload.get("status") and not row.get("status"):
        row["status"] = payload["status"]
    return [row]


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


def _deep_validate(full_name: str):
    """Re-scan in the sandbox. Returns ``(ok, reason, Tier2Result | None)``."""
    from .scanning.sandbox_runner import docker_available, scan_candidate_sandboxed

    if not docker_available():
        return False, "Docker sandbox unavailable", None
    result = scan_candidate_sandboxed(full_name)
    if result is None:
        return False, "sandbox scan produced no result", None
    if not result.confirmed:
        return False, "current Tier-2 scan no longer confirms malicious behavior", result
    if result.confidence != "auto":
        return False, f"current Tier-2 confidence is {result.confidence!r}, not AUTO", result
    if not result.confirming_findings and not result.package_spread:
        if not any(status == "flagged" for status in (result.scanners or {}).values()):
            return False, "current Tier-2 result has no confirming evidence", result
    return True, f"current commit {result.commit_sha or 'HEAD'} confirmed AUTO", result


# --- Markdown run summary (GitHub step summary) ------------------------------
# Snippets, IOCs and report prose derive from attacker-controlled repo content,
# so they are only ever rendered inside fenced code blocks (never as live
# markdown/HTML/links). Repo-derived table cells are escaped.


def _fence(text: str, lang: str = "text") -> str:
    """A fenced block that attacker text cannot close early."""
    text = str(text or "").rstrip()
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    ticks = "`" * max(3, longest + 1)
    return f"{ticks}{lang}\n{text}\n{ticks}"


def _cell(text) -> str:
    """Escape a value for a markdown table cell / inline span."""
    text = re.sub(r"[\r\n]+", " ", str(text if text is not None else ""))
    return re.sub(r"([\\`*_\[\]<>|!#~])", r"\\\1", text)


def _code(text) -> str:
    """An inline code span (no escaping applies inside one, so drop backticks)."""
    text = re.sub(r"[\r\n`|]+", " ", str(text if text is not None else "")).strip()
    return f"`{text or ' '}`"


def validated_markdown(
    row, result, report: dict, *, status: str, threat_id: str | None = None,
) -> str:
    """One "Validated malicious repo" section for the run summary.

    ``status`` is ``not_reported`` (validate-only run: every gate passed and OSM
    has no record, nothing was POSTed), ``submitted`` or ``submit_failed``.
    """
    full_name = row["full_name"]
    url = f"https://github.com/{full_name}"
    sha = getattr(result, "commit_sha", "") or ""
    osm_line = {
        "not_reported": "**NOT YET REPORTED TO OSM** — full-history search found no "
                        "record (checked before and after validation); nothing was submitted",
        "submitted": f"Was not in OSM at validation; **submitted** as "
                     f"{_code(threat_id or 'unknown id')}",
        "submit_failed": "**NOT REPORTED TO OSM** — was not in OSM at validation, "
                         "but the submission POST failed; will retry next run",
    }[status]

    lines = [
        f"### Validated malicious repo: {_code(full_name)}",
        "",
        "| | |",
        "|---|---|",
        f"| Repository | {url} |",
        f"| OSM status | {osm_line} |",
        "| Shared intel (Warden/KNORR) | not marked submitted by either tool |",
        "| Tier-2 sandbox re-scan | confirmed, confidence **AUTO** |",
        f"| Scanned commit | {_code(sha or 'HEAD')} |",
        "| Payload live at HEAD | yes (re-fetched from raw.githubusercontent.com) |",
        f"| Severity | {_cell(report.get('severity_level'))} |",
        f"| Score | {_cell(row['score'])} |",
        f"| Detection method | {_cell(row['detection_method'])} |",
        f"| Tags | {_cell(', '.join(report.get('tags') or []))} |",
    ]
    flagged = sorted(n for n, s in (getattr(result, "scanners", None) or {}).items()
                     if s == "flagged")
    if flagged:
        lines.append(f"| Scanners flagged | {_cell(', '.join(flagged))} |")

    findings = list(getattr(result, "confirming_findings", None) or [])
    if findings:
        lines += ["", "**Confirming evidence (fresh sandbox scan)**", ""]
        for f in findings[:15]:
            where = f"{f.file}:{f.line}"
            if sha:
                link = f"{url}/blob/{quote(sha)}/{quote(str(f.file))}#L{int(f.line)}"
                where_md = f"[{_code(where)}]({link})"
            else:
                where_md = f"{_code(where)}"
            lines += [f"- {where_md} — {_cell(f.category)} / {_cell(f.rule)}",
                      "", _fence(f.snippet), ""]
        if len(findings) > 15:
            lines.append(f"- … {len(findings) - 15} more")
    iocs = report.get("verified_iocs")
    if iocs:
        lines += ["", "**IOCs**", "", _fence(iocs)]
    if report.get("threat_description"):
        lines += ["", "<details><summary>Threat description (as it would be "
                      "sent to OSM)</summary>", "", _fence(report["threat_description"]),
                  "", "</details>"]
    return "\n".join(lines) + "\n"


def run_summary_markdown(
    sections: list[str], skipped: list[tuple[str, str]], *, dry_run: bool,
    notes: list[str] | None = None,
) -> str:
    mode = ("validate-only — nothing was submitted to OSM" if dry_run
            else "submit — validated repos were POSTed to OSM")
    out = ["## Warden OSM automation", "", f"Mode: **{mode}**", "",
           f"Validated malicious repos: **{len(sections)}**", ""]
    out += [f"> {n}\n" for n in (notes or [])]
    if not sections:
        out += ["No repository passed every gate this run.", ""]
    out += sections
    if skipped:
        out += ["", "<details><summary>Skipped candidates "
                    f"({len(skipped)})</summary>", "",
                "| Repository | Reason |", "|---|---|"]
        out += [f"| {_code(name)} | {_cell(reason)} |" for name, reason in skipped]
        out += ["", "</details>"]
    return "\n".join(out) + "\n"


def _write_summary(path: Path | None, text: str) -> None:
    if path is None:
        return
    with Path(path).open("a", encoding="utf-8") as fh:
        fh.write(text)


def _effective_limits(policy: dict, limit: int | None, pace: float | None):
    """CLI/caller overrides may only TIGHTEN the policy, never loosen it."""
    cap = int(policy["max_submissions_per_run"])
    floor = float(policy["pace_seconds"])
    limit = cap if limit is None else min(max(1, int(limit)), cap)
    pace = floor if pace is None else max(float(pace), floor)
    return limit, pace


def run(
    db: Database, *, limit: int | None = None, pace: float | None = None,
    dry_run: bool = False, summary_path: Path | None = None,
    now: float | None = None, only: set[str] | None = None,
    validated_out: list[str] | None = None,
) -> tuple[int, int]:
    """Validate AUTO-tier candidates and (unless ``dry_run``) submit them.

    Returns ``(submitted, errors)``. ``limit`` caps the sandbox re-scans per run
    (the expensive step); cheap skips (already in OSM / shared intel / recently
    failed) do not consume it, so they cannot starve the queue. Every repo that
    passes all gates gets a "Validated malicious repo" section in the markdown
    summary appended to ``summary_path``. A ``dry_run`` never claims or POSTs.

    ``only`` restricts the run to those repos (the approval flow submits exactly
    what a human approved, never a newer candidate). Every repo that passes all
    gates is appended to ``validated_out``.

    Raises :class:`AutomationBlocked` when there is no hunt data or no sandbox,
    and :class:`OSMPrecheckError` when OSM cannot prove novelty (both after
    writing the summary).
    """
    policy = load_policy()
    limit, pace = _effective_limits(policy, limit, pace)
    now = time.time() if now is None else now
    sections: list[str] = []
    skipped: list[tuple[str, str]] = []
    notes: list[str] = []
    errors = 0
    sent = 0

    def skip(name: str, reason: str) -> None:
        print(f"[skip] {name}: {reason}")
        skipped.append((name, reason))

    try:
        total = db.conn.execute("SELECT COUNT(*) FROM repo_findings").fetchone()[0]
        if not total:
            raise AutomationBlocked(
                "no hunt data: repo_findings is empty (data cache not restored or "
                "evicted?) -- run The Warden hunt first")

        rows = gold_for_submission(db)  # all of them; `limit` caps sandbox scans
        if only is not None:
            rows = [r for r in rows if r["full_name"].casefold() in only]
        if not rows:
            print("Warden OSM automation: no AUTO-tier novel candidates.")
            notes.append(f"No AUTO-tier novel candidates among {total} findings.")
            return 0, 0

        from .scanning.sandbox_runner import docker_available
        if not docker_available():
            raise AutomationBlocked("Docker sandbox unavailable; cannot re-validate")

        _ensure_attempts_table(db)
        scans = 0
        for row in rows:
            full_name = row["full_name"]
            resource = f"https://github.com/{full_name}"

            if _bus_submitted(full_name):
                skip(full_name, "shared intelligence already marks it submitted")
                continue
            recent = _recently_failed(db, full_name, now)
            if recent:
                skip(full_name, f"cooling down after a failed validation: {recent}")
                continue
            if scans >= limit:
                notes.append(f"Scan limit ({limit}) reached; remaining candidates "
                             "wait for the next run.")
                break

            hit = _existing_repo(full_name)
            if hit:
                skip(full_name, f"already in OSM ({hit.get('status')}, "
                                f"id {str(hit.get('id') or '')[:8]})")
                bus.mark_submitted(
                    "repository", resource, threat_id=str(hit.get("id") or "")
                )
                continue

            scans += 1
            valid, reason, result = _deep_validate(full_name)
            if not valid:
                reason = f"deep validation failed closed: {reason}"
                _record_failure(db, full_name, reason, now, transient=result is None)
                skip(full_name, reason)
                continue

            live = repo_payload_live(row)
            if live is not True:
                reason = "current payload liveness was not positively confirmed"
                _record_failure(db, full_name, reason, now, transient=live is None)
                skip(full_name, reason)
                continue

            # Close the race window: check OSM again immediately before the claim/POST.
            hit = _existing_repo(full_name)
            if hit:
                skip(full_name, f"appeared in OSM during validation ({hit.get('status')}, "
                                f"id {str(hit.get('id') or '')[:8]})")
                bus.mark_submitted(
                    "repository", resource, threat_id=str(hit.get("id") or "")
                )
                continue
            if _bus_submitted(full_name):
                skip(full_name, "shared intelligence changed during validation")
                continue

            _clear_failure(db, full_name)
            report = build_report(
                row,
                dprk_infra=db.dprk_infra_hosts(exclude=full_name),
                campaign_ctx=campaign_context(db, row),
            )
            print(f"[validated] {full_name}: {reason}; OSM full history clear")
            if validated_out is not None:
                validated_out.append(full_name)

            if dry_run:
                sections.append(validated_markdown(row, result, report, status="not_reported"))
                print(f"[validated-only] {full_name}: not reported to OSM (validate-only run)")
                continue

            mark_osm_submitted(db, full_name, None)
            try:
                response = submit_threat(report)
            except Exception as exc:  # noqa: BLE001 - one bad POST must not stop the rest
                unmark_osm_submitted(db, full_name)
                sections.append(validated_markdown(row, result, report, status="submit_failed"))
                print(f"[error] {full_name}: OSM submission failed: {exc}")
                errors += 1
                continue

            threat_id = response.get("threat_id")
            mark_osm_submitted(db, full_name, threat_id)
            bus.mark_submitted("repository", resource, threat_id=threat_id)
            sections.append(validated_markdown(
                row, result, report, status="submitted", threat_id=threat_id))
            sent += 1
            print(f"[submitted] {full_name} -> {threat_id or 'OSM'}")
            time.sleep(pace)
    except (AutomationBlocked, OSMPrecheckError) as exc:
        notes.append(f"**Run blocked:** {exc}")
        raise
    finally:
        _write_summary(summary_path, run_summary_markdown(
            sections, skipped, dry_run=dry_run, notes=notes))

    if dry_run:
        print(f"Warden OSM automation: validated {len(sections)} repository report(s); "
              "none submitted (validate-only).")
    else:
        print(f"Warden OSM automation: submitted {sent} repository report(s), "
              f"{errors} failed.")
    return sent, errors


_REPO_NAME = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$")


def _read_only_file(path: Path) -> set[str]:
    """The approved repo list, normalized; anything malformed is dropped."""
    try:
        names = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot read approved repo list {path}: {exc}") from exc
    if not isinstance(names, list):
        raise SystemExit(f"approved repo list {path} must be a JSON array")
    out = {str(n).strip().strip("/").casefold() for n in names}
    return {n for n in out if _REPO_NAME.match(n)}


def _acquire_run_lock(path: Path):
    """Exclusive, non-blocking lock so overlapping cron runs cannot double-submit.
    Returns the open handle (keep it alive) or None if another run holds it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+")
    try:
        import fcntl
    except ImportError:  # Windows: rely on the scheduler not overlapping runs
        return handle
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    return handle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=config.DB_PATH)
    parser.add_argument("--limit", type=int, default=None,
                        help="Max sandbox re-scans this run (capped by the policy).")
    parser.add_argument("--pace", type=float, default=None,
                        help="Seconds between submissions (never below the policy).")
    parser.add_argument("--check-config", action="store_true")
    parser.add_argument(
        "--check-api", action="store_true",
        help="Read-only live OSM API contract check; never submits.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run every gate but never claim or POST; report validated repos only.")
    parser.add_argument(
        "--validated-json", type=Path, default=None,
        help="Write the repos that passed every gate to this JSON list.")
    parser.add_argument(
        "--only-file", type=Path, default=None,
        help="JSON list of owner/repo: restrict the run to exactly these repos "
             "(the ones a reviewer approved).")
    parser.add_argument(
        "--summary-md", type=Path,
        default=Path(os.environ["GITHUB_STEP_SUMMARY"])
        if os.environ.get("GITHUB_STEP_SUMMARY") else None,
        help="Append the markdown run summary here (default: $GITHUB_STEP_SUMMARY).")
    args = parser.parse_args(argv)

    if args.check_config:
        load_policy()
        print("Warden OSM automation policy: PASS")
        return 0

    if args.check_api:
        _search_full_history("https://github.com/torvalds/linux")
        print("Warden OSM API contract: PASS (GET /check-malicious)")
        return 0

    if not Path(args.db).exists():
        msg = (f"no hunt data: {args.db} does not exist (data cache not restored or "
               "evicted?) -- run The Warden hunt first")
        _write_summary(args.summary_md, run_summary_markdown(
            [], [], dry_run=args.dry_run, notes=[f"**Run blocked:** {msg}"]))
        print(f"Warden OSM automation BLOCKED: {msg}")
        return 2

    only = None
    if args.only_file is not None:
        only = _read_only_file(args.only_file)
        if not only:
            print("Warden OSM automation: approved list is empty; nothing to do.")
            return 0

    lock = _acquire_run_lock(Path(args.db).with_name("osm_automation.lock"))
    if lock is None:
        print("Warden OSM automation: another run holds the lock; exiting.")
        return 0
    try:
        db = Database.open(args.db)
        try:
            validated: list[str] = []
            _, errors = run(db, limit=args.limit, pace=args.pace, dry_run=args.dry_run,
                            summary_path=args.summary_md, only=only,
                            validated_out=validated)
            if args.validated_json is not None:
                args.validated_json.write_text(json.dumps(validated), encoding="utf-8")
        except (AutomationBlocked, OSMPrecheckError) as exc:
            print(f"Warden OSM automation BLOCKED: {exc}")
            return 2
        finally:
            db.close()
    finally:
        lock.close()
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
