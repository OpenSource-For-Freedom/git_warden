"""Approval-gated OSM submission for confirmed VS Code extensions.

First-round policy: nothing is sent without a person approving the exact batch.

1. Preview (``--dry-run``, runs with every hunt): each confirmed AUTO extension
   not already submitted is checked against OSM, and the exact report body that
   would be POSTed is written to the run summary and to ``--preview-json``. The
   ids that passed go to ``--validated-json``.
2. Submit (``--only-file``, runs only after the ``osm-extension-submission``
   environment is approved): restricted to the approved ids. Every extension is
   fetched again from its registry, re-scanned in the sandbox, must still
   confirm at AUTO, and must still be absent from OSM immediately before POST.

Any OSM lookup failure blocks the run (fail closed). Submitted extensions are
recorded in a ledger file and on the shared intelligence bus so they are never
offered twice.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path

import requests

from .. import config
from .. import intel_exchange as bus
from ..db import Database

# Registry names as OSM spells them (its feed polls "vscode" and "openvsx").
OSM_REGISTRY = {"vsmarketplace": "vscode", "openvsx": "openvsx"}
MAX_PER_RUN = 10          # first round: small batches a reviewer can read
PACE_SECONDS = 8.0
_EXT_ID = re.compile(r"^[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9._-]*$", re.I)
_KEY = re.compile(r"^(openvsx|vsmarketplace):[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9._-]*$")
_URL = re.compile(r"https?://[^\s'\"|)>`]+", re.I)


class OSMPrecheckError(RuntimeError):
    """OSM could not prove the extension is novel; nothing is sent."""


def _ledger_load(path: Path | None) -> dict[str, dict]:
    if path is None or not Path(path).exists():
        return {}
    try:
        rows = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {str(r.get("key", "")).casefold(): r for r in rows
            if isinstance(r, dict) and r.get("key")}


def _ledger_save(path: Path | None, ledger: dict[str, dict]) -> None:
    if path is None:
        return
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(sorted(ledger.values(), key=lambda r: r["key"]),
                                     indent=2) + "\n", encoding="utf-8")


def _bus_value(row) -> str:
    return f"{OSM_REGISTRY.get(row['registry'], row['registry'])}:{_ext_id(row)}".casefold()


def _ext_id(row) -> str:
    return f"{row['namespace']}.{row['name']}"


def already_submitted(row, ledger: dict[str, dict]) -> bool:
    return (row["ext_key"].casefold() in ledger
            or bus.is_submitted("package", _bus_value(row)))


def check_osm(ext_id: str, registry: str) -> bool:
    """True if OSM already reports this extension. Raises when it cannot tell."""
    token = config.OSM_API_KEY
    if not token:
        raise OSMPrecheckError("OSM API key is missing")
    try:
        response = requests.get(
            config.osm_endpoint("check-malicious"),
            params={"report_type": "package", "resource_identifier": ext_id,
                    "registry": OSM_REGISTRY.get(registry, registry)},
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            timeout=config.HTTP_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise OSMPrecheckError(f"OSM check-malicious failed for {ext_id!r}: {exc}") from exc
    if response.status_code != 200:
        raise OSMPrecheckError(
            f"OSM check-malicious returned HTTP {response.status_code} for {ext_id!r}")
    try:
        payload = response.json() if response.content else {}
    except ValueError as exc:
        raise OSMPrecheckError("OSM check-malicious returned malformed JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("malicious"), bool):
        raise OSMPrecheckError("OSM check-malicious returned an unexpected response shape")
    return payload["malicious"]


def _client_for(registry: str):
    if registry == "vsmarketplace":
        from .marketplace import MarketplaceClient
        return MarketplaceClient()
    from .openvsx import OpenVsxClient
    return OpenVsxClient()


def revalidate(row, *, client=None, scan=None) -> tuple[bool, str, dict | None, object]:
    """Fetch the extension again and re-scan it. ``(ok, reason, result, ext)``."""
    from ..scanning.sandbox_runner import docker_available, scan_extension_sandboxed

    if scan is None and not docker_available():
        return False, "Docker sandbox unavailable", None, None
    client = client or _client_for(row["registry"])
    scan = scan or scan_extension_sandboxed
    ext = client.extension(row["namespace"], row["name"])
    if ext is None or not ext.download_url:
        return False, "no longer published on the registry", None, None
    result = scan(ext.ext_id, ext.download_url)
    if result is None or result.get("fetch_failed"):
        return False, "current version could not be fetched for re-scan", result, ext
    if not result.get("confirmed"):
        return False, f"current version {ext.version} no longer confirms", result, ext
    if result.get("confidence") != "auto":
        return False, f"current confidence is {result.get('confidence')!r}, not AUTO", \
            result, ext
    if not result.get("confirming_findings"):
        return False, "current scan has no confirming evidence", result, ext
    return True, f"current version {ext.version} confirmed AUTO", result, ext


def _iocs(findings: list[dict]) -> str:
    from ..dprk import c2_hosts_from_flags

    lines: list[str] = []
    for h in c2_hosts_from_flags(findings):
        if h not in lines:
            lines.append(h)
    for f in findings:
        for u in _URL.findall(f.get("snippet") or ""):
            u = u.rstrip(".,;")
            if u not in lines:
                lines.append(u)
    return "\n".join(lines)


def _severity(findings: list[dict]) -> str:
    cats = {f.get("category") for f in findings}
    if cats & {"download_exec", "reverse_shell", "exfiltration", "network_exfil",
               "credential_harvest", "credential_access"}:
        return "critical"
    return "high"


def build_extension_report(row, result: dict, ext) -> dict:
    """The exact submit-threat-report body for one extension."""
    from ..osm_submit import (
        _BEHAVIOR,
        _BEHAVIOR_BY_RULE,
        OSM_CONTACT_EMAIL,
        OSM_CONTRIBUTOR,
        _no_dashes,
        _rule_summary,
    )

    ext_id = _ext_id(row)
    registry = OSM_REGISTRY.get(row["registry"], row["registry"])
    registry_name = ("the Visual Studio Marketplace" if row["registry"] == "vsmarketplace"
                     else "Open VSX")
    findings = result.get("confirming_findings") or []
    top = findings[0] if findings else {}
    info = result.get("extension") or {}
    behavior = _BEHAVIOR_BY_RULE.get(top.get("rule", "")) or _BEHAVIOR.get(
        top.get("category", ""), "The code performs actions that match malware.")
    where = top.get("file") or "the extension package"
    if top.get("line"):
        where += f" at line {top['line']}"
    try:
        reasons = json.loads(row["reasons"] or "[]")
    except ValueError:
        reasons = []
    activation = ", ".join(info.get("activation_events") or []) or "none declared"
    entry = ", ".join(info.get("entry_points") or []) or "none declared"
    signals = ", ".join(info.get("signals") or [])

    threat = [
        f"Git Warden confirmed the VS Code extension {ext_id} version {ext.version}, "
        f"published on {registry_name} by the publisher {row['namespace']}, as malicious "
        "by static analysis. The package was downloaded and unpacked inside an isolated "
        "sandbox and read, never executed.",
        f"The malicious code sits in {where} inside the package. {behavior}",
        f"The extension declares the activation events {activation} and the entry point "
        f"{entry}, so the code runs inside the editor of anyone who installs it.",
    ]
    if reasons:
        threat.append("It was selected for analysis because: " + "; ".join(reasons) + ".")
    if signals:
        threat.append(f"Additional extension signals: {signals}.")
    threat.append("No legitimate extension ships code like this. Removing it from the "
                  "registry and from installed editors is recommended.")

    rules = _rule_summary(findings)
    payload = (f"The malicious payload sits in {where}. {behavior}"
               + (f" Detection rules that fired in this package: {rules}." if rules else ""))

    tags = ["supply-chain", "vscode-extension", registry]
    if any("lookalike" in r for r in reasons):
        tags.append("impersonation")
    cat = top.get("category") or ""
    tags.append({"download_exec": "dropper", "obfuscation": "obfuscated-loader",
                 "credential_access": "credential-theft",
                 "exfiltration": "data-exfiltration"}.get(cat, "malware"))

    report = {
        "report_type": "package",
        "registry": registry,
        "package_name": ext_id,
        "resource_identifier": ext_id,
        "version_info": ext.version or row["version"] or "all",
        "threat_description": _no_dashes(" ".join(threat)),
        "payload_description": _no_dashes(payload),
        "publisher": row["namespace"],
        "severity_level": _severity(findings),
        "tags": list(dict.fromkeys(tags))[:10],
        "evidence_references": row["url"] or ext.url,
        "verified_iocs": _iocs(findings),
        "contributors": [OSM_CONTRIBUTOR] if OSM_CONTRIBUTOR else [],
    }
    if OSM_CONTACT_EMAIL:
        report["contact_email"] = OSM_CONTACT_EMAIL
    return report


def candidates(db: Database, ledger: dict[str, dict], only: set[str] | None = None):
    rows = [r for r in db.extensions("confirmed") if r["confidence"] == "auto"]
    rows = [r for r in rows if not already_submitted(r, ledger)]
    if only is not None:
        rows = [r for r in rows if r["ext_key"].casefold() in only]
    return sorted(rows, key=lambda r: (-int(r["score"] or 0), r["ext_key"]))


def _section(row, status: str, reason: str, report: dict | None, result: dict | None) -> str:
    from ..osm_automation import _cell, _code, _fence

    out = [f"### {_code(_ext_id(row))} ({_cell(row['registry'])})", "",
           f"**{status}**: {_cell(reason)}", ""]
    for f in ((result or {}).get("confirming_findings") or [])[:8]:
        out += [f"- {_code(str(f.get('file')) + ':' + str(f.get('line')))}: "
                f"{_cell(f.get('category'))} / {_cell(f.get('rule'))}", "",
                _fence(f.get("snippet") or ""), ""]
    if report is not None:
        out += ["<details><summary>Exact OSM report body</summary>", "",
                _fence(json.dumps(report, indent=2, ensure_ascii=False), "json"), "",
                "</details>", ""]
    return "\n".join(out)


def run(db: Database, *, dry_run: bool, ledger_path: Path | None = None,
        only: set[str] | None = None, limit: int = MAX_PER_RUN,
        pace: float = PACE_SECONDS, scan=None, client_for=None, check=None,
        post=None, sleep=time.sleep) -> dict:
    """Preview (dry_run) or submit the approved extensions. Returns a report dict."""
    from ..osm_submit import submit_threat

    check = check or check_osm
    post = post or submit_threat
    client_for = client_for or _client_for
    limit = max(1, min(int(limit), MAX_PER_RUN))
    pace = max(float(pace), PACE_SECONDS)
    ledger = _ledger_load(ledger_path)
    sections: list[str] = []
    validated: list[str] = []
    previews: list[dict] = []
    sent = errors = 0
    blocked = ""
    try:
        for row in candidates(db, ledger, only)[:limit]:
            ext_id = _ext_id(row)
            if not _EXT_ID.fullmatch(ext_id):
                continue
            if check(ext_id, row["registry"]):
                sections.append(_section(row, "Skipped", "already reported in OSM",
                                         None, None))
                continue
            ok, reason, result, ext = revalidate(
                row, client=client_for(row["registry"]), scan=scan)
            if not ok:
                sections.append(_section(row, "Not eligible", reason, None, result))
                continue
            report = build_extension_report(row, result, ext)
            if dry_run:
                validated.append(row["ext_key"])
                previews.append({"key": row["ext_key"], "report": report})
                sections.append(_section(row, "Awaiting approval",
                                         f"{reason}; not in OSM", report, result))
                continue
            if check(ext_id, row["registry"]):    # close the race right before POST
                sections.append(_section(row, "Skipped",
                                         "appeared in OSM during validation", None, None))
                continue
            try:
                response = post(report)
            except Exception as exc:  # noqa: BLE001 - one bad POST must not stop the rest
                errors += 1
                sections.append(_section(row, "Submit failed", str(exc)[:200], report,
                                         result))
                continue
            threat_id = str((response or {}).get("threat_id") or "")
            ledger[row["ext_key"].casefold()] = {
                "key": row["ext_key"], "threat_id": threat_id,
                "version": report["version_info"],
                "submitted_at": datetime.now(UTC).isoformat()}
            _ledger_save(ledger_path, ledger)
            bus.mark_submitted("package", _bus_value(row), threat_id=threat_id)
            sent += 1
            sections.append(_section(row, "Submitted", f"OSM threat id {threat_id or 'n/a'}",
                                     report, result))
            sleep(pace)
    except OSMPrecheckError as exc:
        blocked = str(exc)
    return {"dry_run": dry_run, "sent": sent, "errors": errors, "blocked": blocked,
            "validated": validated, "previews": previews, "sections": sections}


def summary_markdown(report: dict) -> str:
    mode = ("preview: nothing is sent until the osm-extension-submission environment "
            "is approved" if report["dry_run"] else "submit: approved extensions only")
    out = ["## VS Code extensions: OSM submission", "", f"Mode: {mode}", ""]
    if report["blocked"]:
        out += [f"> **Run blocked:** {report['blocked']}", ""]
    if report["dry_run"]:
        out += [f"Awaiting approval: **{len(report['validated'])}**", ""]
    else:
        out += [f"Submitted: **{report['sent']}** · errors: {report['errors']}", ""]
    if not report["sections"] and not report["blocked"]:
        out += ["No confirmed extension is waiting for OSM submission.", ""]
    out += report["sections"]
    return "\n".join(out) + "\n"


def _read_only_file(path: Path) -> set[str]:
    try:
        keys = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot read approved extension list {path}: {exc}") from exc
    if not isinstance(keys, list):
        raise SystemExit(f"approved extension list {path} must be a JSON array")
    return {str(k).casefold() for k in keys if _KEY.fullmatch(str(k).casefold())}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=config.DB_PATH)
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview only: validate and show report bodies, never POST.")
    parser.add_argument("--only-file", type=Path, default=None,
                        help="JSON list of approved extension keys (required to submit).")
    parser.add_argument("--validated-json", type=Path, default=None)
    parser.add_argument("--preview-json", type=Path, default=None)
    parser.add_argument("--ledger", type=Path, default=None,
                        help="Submitted-extension ledger (read, and appended on submit).")
    parser.add_argument("--limit", type=int, default=MAX_PER_RUN)
    parser.add_argument(
        "--summary-md", type=Path,
        default=Path(os.environ["GITHUB_STEP_SUMMARY"])
        if os.environ.get("GITHUB_STEP_SUMMARY") else None)
    args = parser.parse_args(argv)

    if not args.dry_run and args.only_file is None:
        print("Refusing to submit without an approved list (--only-file).")
        return 2
    if not Path(args.db).exists():
        print(f"no hunt data at {args.db}; nothing to do")
        return 0
    only = _read_only_file(args.only_file) if args.only_file else None
    if only is not None and not only:
        print("approved extension list is empty; nothing to do")
        return 0
    db = Database.open(args.db)
    try:
        report = run(db, dry_run=args.dry_run, ledger_path=args.ledger, only=only,
                     limit=args.limit)
    finally:
        db.close()
    if args.validated_json:
        args.validated_json.write_text(json.dumps(report["validated"]) + "\n",
                                       encoding="utf-8")
    if args.preview_json:
        args.preview_json.write_text(json.dumps(report["previews"], indent=2) + "\n",
                                     encoding="utf-8")
    if args.summary_md:
        with Path(args.summary_md).open("a", encoding="utf-8") as fh:
            fh.write(summary_markdown(report))
    print(json.dumps({k: report[k] for k in ("dry_run", "sent", "errors", "blocked",
                                              "validated")}))
    if report["blocked"]:
        return 3
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
