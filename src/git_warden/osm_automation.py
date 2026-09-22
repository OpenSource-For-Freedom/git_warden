"""Fail-closed unattended OSM submission for Git Warden.

This path is intentionally stricter than the interactive/local submit command.
Every repository is re-scanned in the hardened Tier-2 Docker sandbox, must still
confirm at AUTO confidence, must still be live at GitHub HEAD, and must pass an
authoritative OSM full-history pre-check twice: once before validation and again
immediately before POST. Any uncertainty blocks submission.
"""

from __future__ import annotations

import argparse
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
) -> str:
    mode = ("validate-only — nothing was submitted to OSM" if dry_run
            else "submit — validated repos were POSTed to OSM")
    out = ["## Warden OSM automation", "", f"Mode: **{mode}**", "",
           f"Validated malicious repos: **{len(sections)}**", ""]
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


def run(
    db: Database, *, limit: int | None = None, pace: float | None = None,
    dry_run: bool = False, summary_path: Path | None = None,
) -> int:
    """Validate AUTO-tier candidates and (unless ``dry_run``) submit them.

    Every repo that passes all gates gets a "Validated malicious repo" section
    in the markdown summary appended to ``summary_path``. A ``dry_run`` never
    claims or POSTs, so each section records the repo as not yet reported.
    """
    policy = load_policy()
    limit = int(policy["max_submissions_per_run"]) if limit is None else limit
    pace = float(policy["pace_seconds"]) if pace is None else pace
    rows = gold_for_submission(db, limit=limit)
    sections: list[str] = []
    skipped: list[tuple[str, str]] = []

    def skip(name: str, reason: str) -> None:
        print(f"[skip] {name}: {reason}")
        skipped.append((name, reason))

    if not rows:
        print("Warden OSM automation: no AUTO-tier novel candidates.")
        _write_summary(summary_path, run_summary_markdown([], [], dry_run=dry_run))
        return 0

    sent = 0
    try:
        for row in rows:
            full_name = row["full_name"]
            resource = f"https://github.com/{full_name}"

            if bus.is_submitted("repository", resource):
                skip(full_name, "shared intelligence already marks it submitted")
                continue

            hit = _existing_repo(full_name)
            if hit:
                skip(full_name, f"already in OSM ({hit.get('status')}, "
                                f"id {str(hit.get('id') or '')[:8]})")
                bus.mark_submitted(
                    "repository", resource, threat_id=str(hit.get("id") or "")
                )
                continue

            valid, reason, result = _deep_validate(full_name)
            if not valid:
                skip(full_name, f"deep validation failed closed: {reason}")
                continue

            live = repo_payload_live(row)
            if live is not True:
                skip(full_name, "current payload liveness was not positively confirmed")
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
            if bus.is_submitted("repository", resource):
                skip(full_name, "shared intelligence changed during validation")
                continue

            report = build_report(
                row,
                dprk_infra=db.dprk_infra_hosts(exclude=full_name),
                campaign_ctx=campaign_context(db, row),
            )
            print(f"[validated] {full_name}: {reason}; OSM full history clear")

            if dry_run:
                sections.append(validated_markdown(row, result, report, status="not_reported"))
                print(f"[validated-only] {full_name}: not reported to OSM (validate-only run)")
                continue

            mark_osm_submitted(db, full_name, None)
            try:
                response = submit_threat(report)
            except Exception:
                unmark_osm_submitted(db, full_name)
                sections.append(validated_markdown(row, result, report, status="submit_failed"))
                raise

            threat_id = response.get("threat_id")
            mark_osm_submitted(db, full_name, threat_id)
            bus.mark_submitted("repository", resource, threat_id=threat_id)
            sections.append(validated_markdown(
                row, result, report, status="submitted", threat_id=threat_id))
            sent += 1
            print(f"[submitted] {full_name} -> {threat_id or 'OSM'}")
            if pace and row is not rows[-1]:
                time.sleep(pace)
    finally:
        _write_summary(summary_path, run_summary_markdown(sections, skipped, dry_run=dry_run))

    if dry_run:
        print(f"Warden OSM automation: validated {len(sections)} repository report(s); "
              "none submitted (validate-only).")
    else:
        print(f"Warden OSM automation: submitted {sent} repository report(s).")
    return sent


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=config.DB_PATH)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--pace", type=float, default=None)
    parser.add_argument("--check-config", action="store_true")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run every gate but never claim or POST; report validated repos only.")
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

    db = Database.open(args.db)
    try:
        limit = None if args.limit is None else max(0, args.limit)
        pace = None if args.pace is None else max(0.0, args.pace)
        run(db, limit=limit, pace=pace, dry_run=args.dry_run,
            summary_path=args.summary_md)
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
