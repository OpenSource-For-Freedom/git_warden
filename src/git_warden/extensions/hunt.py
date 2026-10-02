"""VS Code extension hunt: Tier-1 metadata screen -> Tier-2 sandboxed scan.

Tier 1 (host, metadata only) collects candidates from Open VSX:
  * recently published extensions,
  * lookalikes of popular extensions (similar name or display name, different
    publisher), the impersonation pattern behind most malicious extensions,
  * other extensions from publishers OSM already reports as malicious,
and ranks them by cheap risk signals (few downloads, unverified publisher).

Tier 2 fetches and statically analyzes the top-ranked ``.vsix`` files inside the
hardened sandbox container with Warden's existing confirmation rules. Only those
rules can confirm; extension-specific signals (startup activation, a theme pack
that ships code, bundled binaries) are context for the analyst, never proof.
"""

from __future__ import annotations

import difflib
import json
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .. import config
from .. import intel_exchange as bus
from ..enums import RunStatus
from .openvsx import Extension, OpenVsxClient

log = logging.getLogger(__name__)

POPULAR_PATH = config.PROJECT_ROOT / "config" / "vscode_popular_extensions.json"
EXTENSION_ECOSYSTEMS = {"vscode", "openvsx", "vscode-extension", "open-vsx"}
_FEW_DOWNLOADS = 50


def load_popular(path: Path = POPULAR_PATH) -> list[dict]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return [d for d in data if isinstance(d, dict) and "." in str(d.get("id", ""))]


def _similar(a: str, b: str) -> float:
    a, b = a.casefold().strip(), b.casefold().strip()
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def lookalike_of(ext: Extension, popular: list[dict],
                 genuine: set[str] | None = None) -> str | None:
    """The popular extension id this one imitates, or None.

    Same display name or near-identical extension name under a DIFFERENT
    publisher. A genuine extension (any id on the popular list, e.g. the official
    prettier.prettier-vscode next to esbenp.prettier-vscode) is never a lookalike.
    """
    genuine = genuine if genuine is not None else {p["id"].casefold() for p in popular}
    if ext.ext_id.casefold() in genuine:
        return None
    for pop in popular:
        pop_id = pop["id"].casefold()
        pop_name = pop_id.split(".", 1)[1]
        if (_similar(ext.name, pop_name) >= 0.85
                or _similar(ext.display_name, pop.get("display", "")) >= 0.9):
            return pop["id"]
    return None


def _add(pool: dict[str, Extension], ext: Extension, reason: str, points: int) -> None:
    cur = pool.setdefault(ext.key, ext)
    if reason not in cur.reasons:
        cur.reasons.append(reason)
        cur.score += points


def osm_extension_publishers(db) -> dict[str, str]:
    """Publisher namespace -> one OSM-reported extension id from that publisher."""
    out: dict[str, str] = {}
    for row in db.conn.execute(
            "SELECT name, ecosystem FROM malicious_artifacts WHERE artifact_type = 'package'"):
        if str(row["ecosystem"] or "").casefold() not in EXTENSION_ECOSYSTEMS:
            continue
        name = str(row["name"] or "").strip()
        if "." in name:
            out.setdefault(name.split(".", 1)[0].casefold(), name)
    return out


def collect_candidates(client: OpenVsxClient, db, *, recent: int = 100,
                       popular: list[dict] | None = None,
                       max_publishers: int = 15) -> list[Extension]:
    """Tier 1: gather and rank candidates from metadata alone."""
    popular = load_popular() if popular is None else popular
    pool: dict[str, Extension] = {}

    for ext in client.recent(recent):
        _add(pool, ext, "recently published", 1)

    genuine = {p["id"].casefold() for p in popular}
    for pop in popular:
        query = pop.get("display") or pop["id"].split(".", 1)[1]
        for ext in client.search(query, size=25):
            target = lookalike_of(ext, [pop], genuine)
            if target:
                _add(pool, ext, f"lookalike of {target}", 3)

    for ns, reported in list(osm_extension_publishers(db).items())[:max_publishers]:
        for name in client.namespace_extensions(ns):
            ext = client.extension(ns, name)
            if ext:
                _add(pool, ext, f"publisher has OSM-reported extension {reported}", 5)

    for ext in pool.values():
        if ext.download_count < _FEW_DOWNLOADS:
            ext.reasons.append(f"few downloads ({ext.download_count})")
            ext.score += 1
        if ext.verified is False:
            ext.reasons.append("unverified publisher")
            ext.score += 1
    return sorted(pool.values(), key=lambda e: (-e.score, e.key))


def _already_scanned(db, ext: Extension) -> bool:
    row = db.get_extension(ext.key)
    return bool(row and row["version"] == ext.version
                and row["status"] in ("confirmed", "not_confirmed"))


def _record_intel(ext: Extension, result: dict) -> None:
    from ..dprk import c2_hosts_from_flags

    flags = result.get("confirming_findings") or []
    hosts = c2_hosts_from_flags(flags)
    if hosts:
        bus.record_many("c2_host", hosts, artifact=ext.ext_id)
    sigs = result.get("learned_signatures") or []
    if sigs:
        bus.record_many("code_sig", sigs, artifact=ext.ext_id)


def run_extension_hunt(db, *, client: OpenVsxClient | None = None, limit: int = 15,
                       recent: int = 100, rescan: bool = False, scan=None,
                       run_id: str | None = None) -> dict:
    """Screen, scan the top ``limit`` candidates in the sandbox, and store results."""
    from ..scanning.sandbox_runner import scan_extension_sandboxed

    client = client or OpenVsxClient()
    scan = scan or scan_extension_sandboxed
    run_id = run_id or (f"ext-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
                        f"-{uuid.uuid4().hex[:6]}")
    db.start_run(run_id, datetime.now(UTC), {"kind": "extensions", "limit": limit})

    candidates = collect_candidates(client, db, recent=recent)
    counts = {"candidates": len(candidates), "scanned": 0, "confirmed": 0,
              "confirmed_auto": 0, "review": 0, "fetch_failed": 0, "skipped_known": 0,
              "errors": 0}
    confirmed: list[tuple[Extension, dict]] = []
    failures: list[tuple[Extension, str]] = []
    for ext in candidates:
        if counts["scanned"] >= limit:
            break
        if not rescan and _already_scanned(db, ext):
            counts["skipped_known"] += 1
            continue
        if not ext.download_url:
            full = client.extension(ext.namespace, ext.name)
            if not full or not full.download_url:
                continue
            ext.download_url, ext.version = full.download_url, full.version or ext.version
        counts["scanned"] += 1
        result = scan(ext.ext_id, ext.download_url)
        if result is None:
            counts["errors"] += 1
            continue
        if result.get("fetch_failed"):
            counts["fetch_failed"] += 1
            reason = str(result.get("reason") or "unknown")[:200]
            failures.append((ext, reason))
            log.warning("extension fetch failed", extra={"context": {
                "ext": ext.ext_id, "url": ext.download_url, "reason": reason}})
            db.upsert_extension(ext, run_id, status="fetch_failed", payload=result)
            continue
        ok = bool(result.get("confirmed"))
        confidence = str(result.get("confidence") or "none")
        db.upsert_extension(ext, run_id, status="confirmed" if ok else "not_confirmed",
                            confidence=confidence, score=int(result.get("bash_score") or 0),
                            payload=result)
        log.info("extension decision", extra={"context": {
            "ext": ext.ext_id, "version": ext.version, "confirmed": ok,
            "confidence": confidence, "reasons": ext.reasons}})
        if ok:
            counts["confirmed"] += 1
            counts["confirmed_auto" if confidence == "auto" else "review"] += 1
            confirmed.append((ext, result))
            _record_intel(ext, result)

    db.finish_run(run_id, datetime.now(UTC), RunStatus.COMPLETED, counts)
    return {"run_id": run_id, "counts": counts,
            "confirmed": [{"extension": e.ext_id, "version": e.version, "url": e.url,
                           "confidence": r.get("confidence"), "reasons": e.reasons}
                          for e, r in confirmed],
            "fetch_failures": [{"extension": e.ext_id, "reason": why} for e, why in failures],
            "_details": confirmed}


def summary_markdown(report: dict) -> str:
    """Run summary: counts plus one evidence section per confirmed extension."""
    from ..osm_automation import _cell, _code, _fence

    c = report["counts"]
    out = ["## Warden VS Code extension hunt", "",
           f"Candidates screened: **{c['candidates']}** · scanned in sandbox: "
           f"**{c['scanned']}** · confirmed: **{c['confirmed']}** "
           f"({c['confirmed_auto']} auto, {c['review']} review) · "
           f"fetch failed: {c['fetch_failed']} · already scanned: {c['skipped_known']}", ""]
    if not report["_details"]:
        out += ["No extension confirmed malicious this run.", ""]
    for ext, result in report["_details"]:
        info = result.get("extension") or {}
        out += [f"### Confirmed malicious extension: {_code(ext.ext_id)}", "",
                "| | |", "|---|---|",
                f"| Registry page | {ext.url} |",
                f"| Version | {_code(ext.version or info.get('version'))} |",
                f"| Confidence | **{_cell(result.get('confidence'))}** |",
                f"| Downloads | {ext.download_count} |",
                f"| Why it was a candidate | {_cell('; '.join(ext.reasons))} |",
                f"| Activation events | {_cell(', '.join(info.get('activation_events') or []))} |",
                f"| Extension signals | {_cell(', '.join(info.get('signals') or []) or 'none')} |",
                "", "**Confirming evidence (sandbox static scan)**", ""]
        for f in (result.get("confirming_findings") or [])[:10]:
            out += [f"- {_code(str(f.get('file')) + ':' + str(f.get('line')))} — "
                    f"{_cell(f.get('category'))} / {_cell(f.get('rule'))}", "",
                    _fence(f.get("snippet") or ""), ""]
    fails = report.get("fetch_failures") or []
    if fails:
        out += ["", f"<details><summary>Fetch failures ({len(fails)})</summary>", "",
                "| Extension | Reason |", "|---|---|"]
        out += [f"| {_code(f['extension'])} | {_cell(f['reason'])} |" for f in fails]
        out += ["", "</details>"]
    return "\n".join(out) + "\n"
