"""In-container entrypoint for a sandboxed Tier-2 scan.

Runs INSIDE the hardened warden-sandbox container, never on the host. It clones the
target repository into the container's tmpfs (RAM, wiped on exit), runs the static
analysis, and prints the result as one JSON line on stdout. The malware bytes never
leave the container; only this JSON telemetry crosses back to the host, which is the
git_paca sandbox contract applied to warden's static scan.

Usage (inside the container): ``python -m git_warden.sandbox_entry <owner/name>``.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from .scanning.tier2 import analyze_repo, clone_repo


def _result_to_dict(result) -> dict:
    """Serialize a Tier2Result to the wire shape the host runner rebuilds from."""
    def bf(f):
        return {"file": f.file, "line": f.line, "category": f.category,
                "rule": f.rule, "snippet": f.snippet}
    li = result.learned_iocs
    return {
        "full_name": result.full_name,
        "code_hash": result.code_hash,
        "commit_sha": result.commit_sha,
        "bash_score": result.bash_score,
        "confirmed": result.confirmed,
        "confidence": result.confidence,
        "scanners": result.scanners,
        "bash_findings": [bf(f) for f in result.bash_findings],
        "confirming_findings": [bf(f) for f in result.confirming_findings],
        "learned_iocs": {
            "webhooks": sorted(getattr(li, "webhooks", set()) or set()),
            "telegram": sorted(getattr(li, "telegram", set()) or set()),
            "domains": sorted(getattr(li, "domains", set()) or set()),
        },
        "learned_signatures": list(result.learned_signatures),
        "package_spread": list(result.package_spread),
    }


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        print(json.dumps({"error": "no repo given"}))
        return 2
    full_name = argv[0]
    spread_intel = None
    # Optional package-spread intel: the host may bundle the incident manifest into
    # the image so the sandbox measures spread without reaching the host DB.
    try:
        from .config import COMPROMISED_MANIFEST_PATH
        from .scanning.lockfile_audit import load_compromised
        from .scanning.package_spread import build_intel
        if COMPROMISED_MANIFEST_PATH.exists():
            spread_intel = build_intel(None, load_compromised(COMPROMISED_MANIFEST_PATH))
    except Exception:  # noqa: BLE001 - spread is enrichment, never fatal
        spread_intel = None

    work = Path(tempfile.mkdtemp(dir="/work" if Path("/work").exists() else None))
    dest = work / full_name.replace("/", "__")
    cloned = clone_repo(full_name, dest, runner=subprocess.run)
    if cloned is None:
        print(json.dumps({"full_name": full_name, "clone_failed": True}))
        return 0
    result = analyze_repo(cloned, full_name, runner=subprocess.run, spread_intel=spread_intel)
    try:
        from .scanning.tier2 import _read_head_sha
        result.commit_sha = _read_head_sha(cloned, runner=subprocess.run)
    except Exception:  # noqa: BLE001
        pass
    print(json.dumps(_result_to_dict(result)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
