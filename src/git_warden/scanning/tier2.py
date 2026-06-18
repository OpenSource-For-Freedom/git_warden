"""Tier-2: clone a candidate repo and run deep analysis (doc 02 section 3.2).

Clones a high-scoring candidate, fingerprints it by code hash for cross-repo
dedup (doc 02 section 4), runs our custom bash scanner (doc 03), and invokes the
established OSS scanners -- GuardDog, Semgrep, YARA -- when their binaries are
present, skipping gracefully when they are not. The program does not reinvent
those engines (doc 02 section 3.2); it orchestrates them.

The clone step is injectable so the analysis is unit-testable on a fixture
directory with no network or git.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .bash_scanner import BashFinding, scan_repo, score_findings
from .ioc import IocSet, extract_repo_iocs

log = logging.getLogger(__name__)

# OSS scanners orchestrated in Tier-2. Each entry: how to invoke it on a path.
# semgrep runs with --json so we flag only on actual results, not error codes
# or chatter (eval finding #5).
_EXTERNAL_SCANNERS = {
    "semgrep": lambda root: ["semgrep", "--json", "--quiet", "--config", "auto", str(root)],
    "yara": None,  # needs a compiled ruleset path; wired when rules are provisioned
    "guarddog": None,  # package-ecosystem oriented; applied to package candidates
}

CONFIRM_THRESHOLD = 5
# A bash-only confirmation needs at least one high-signal category, so a lone
# enumeration/network-scan hit can't reach gold (eval finding #15).
_STRONG_BASH_CATEGORIES = frozenset({
    "reverse_shell", "download_exec", "exfiltration", "obfuscation",
    "persistence", "credential_harvest", "process_injection",
})
# full_name is untrusted intel -> strict allowlist before any clone/path use
# (eval finding #16).
_VALID_FULL_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
# Bound an untrusted clone so a path/zip bomb can't exhaust the host (#9).
_CLONE_MAX_BYTES = 500_000_000
_CLONE_MAX_FILES = 50_000
_HASH_MAX_FILE_BYTES = 5_000_000


@dataclass
class Tier2Result:
    full_name: str
    code_hash: str
    bash_findings: list[BashFinding] = field(default_factory=list)
    bash_score: int = 0
    scanners: dict[str, str] = field(default_factory=dict)  # name -> status/summary
    confirmed: bool = False
    learned_iocs: IocSet = field(default_factory=IocSet)  # IOCs mined from the code

    def signal_summary(self) -> list[str]:
        cats = sorted({f.category for f in self.bash_findings})
        return [f"bash:{c}" for c in cats] + [
            f"{name}:{status}" for name, status in self.scanners.items() if status == "flagged"
        ]


def repo_code_hash(root: Path) -> str:
    """Stable whole-repo fingerprint over file contents (for clone dedup)."""
    root = Path(root)
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts):
        rel = str(path.relative_to(root)).replace("\\", "/")
        try:
            # Bound per-file read so one giant blob can't exhaust memory (#9).
            if path.stat().st_size > _HASH_MAX_FILE_BYTES:
                digest.update(rel.encode("utf-8"))
                digest.update(f"oversize:{path.stat().st_size}".encode())
                continue
            data = path.read_bytes()
        except OSError:
            continue
        digest.update(rel.encode("utf-8"))
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()


def _within_bounds(root: Path) -> bool:
    """False if a cloned tree exceeds the file-count or total-byte caps (#9)."""
    files = 0
    total = 0
    for path in Path(root).rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        files += 1
        try:
            total += path.stat().st_size
        except OSError:
            continue
        if files > _CLONE_MAX_FILES or total > _CLONE_MAX_BYTES:
            return False
    return True


def clone_repo(
    full_name: str, dest: Path, *, runner=subprocess.run, timeout: int = 120
) -> Path | None:
    """Shallow-clone a public repo. Returns the path, or None on failure.

    Validates the untrusted ``full_name`` against a strict allowlist and passes
    ``--`` before the URL so a crafted value cannot become a path traversal or a
    git flag (eval finding #16). A failed/partial clone is cleaned up.
    """
    if not _VALID_FULL_NAME.match(full_name) or ".." in full_name:
        log.warning("clone rejected: invalid full_name", extra={"context": {"repo": full_name}})
        return None
    url = f"https://github.com/{full_name}.git"
    try:
        result = runner(
            ["git", "clone", "--depth", "1", "--quiet", "--", url, str(dest)],
            capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("clone failed", extra={"context": {"repo": full_name, "err": str(exc)}})
        shutil.rmtree(dest, ignore_errors=True)
        return None
    if result.returncode != 0:
        log.warning("clone non-zero", extra={"context": {"repo": full_name}})
        shutil.rmtree(dest, ignore_errors=True)
        return None
    return dest


def _run_external(name: str, root: Path, runner) -> str:
    """Run one OSS scanner if installed; return a status string.

    'flagged' must mean a real detection, never an error/chatter (eval #5). For
    semgrep we parse --json and flag only when the ``results`` array is non-empty;
    its error exit codes map to 'error' and do NOT contribute to confirmation.
    """
    builder = _EXTERNAL_SCANNERS.get(name)
    if builder is None or shutil.which(name) is None:
        return "skipped (not installed)"
    try:
        result = runner(builder(root), capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"error: {exc}"

    if name == "semgrep":
        try:
            payload = json.loads(result.stdout or "{}")
        except ValueError:
            return f"error: unparseable output (exit {result.returncode})"
        if payload.get("errors") and not payload.get("results"):
            return "error"
        return "flagged" if payload.get("results") else "clean"

    # Generic fallback for scanners wired later (not used while others are None).
    return "flagged" if (result.returncode != 0 or result.stdout.strip()) else "clean"


def analyze_repo(
    root: Path,
    full_name: str,
    *,
    runner=subprocess.run,
    confirm_threshold: int = CONFIRM_THRESHOLD,
) -> Tier2Result:
    """Run Tier-2 analysis on an already-cloned repo directory."""
    bash_findings = scan_repo(root)
    bash_score = score_findings(bash_findings)
    scanners = {name: _run_external(name, root, runner) for name in _EXTERNAL_SCANNERS}
    # Bash-only confirmation requires a high-signal category, not just a score
    # reachable from weak recon hits (eval finding #15).
    strong_bash = any(f.category in _STRONG_BASH_CATEGORIES for f in bash_findings)
    bash_confirmed = bash_score >= confirm_threshold and strong_bash
    confirmed = bash_confirmed or "flagged" in scanners.values()
    # Learning loop: mine IOCs from the code only once the repo is confirmed
    # malicious, so the search corpus grows from trusted ground truth.
    learned = extract_repo_iocs(root) if confirmed else IocSet()
    return Tier2Result(
        full_name=full_name,
        code_hash=repo_code_hash(root),
        bash_findings=bash_findings,
        bash_score=bash_score,
        scanners=scanners,
        confirmed=confirmed,
        learned_iocs=learned,
    )


def scan_candidate(
    full_name: str,
    workdir: Path,
    *,
    clone=clone_repo,
    runner=subprocess.run,
    confirm_threshold: int = CONFIRM_THRESHOLD,
) -> Tier2Result | None:
    """Clone + analyze a candidate. Returns None if the clone fails or is too big."""
    dest = Path(workdir) / full_name.replace("/", "__")
    cloned = clone(full_name, dest, runner=runner)
    if cloned is None:
        return None
    # Reject an oversized/path-bomb tree before walking it (eval finding #9).
    if not _within_bounds(cloned):
        log.warning("clone exceeds size bounds; skipping", extra={"context": {"repo": full_name}})
        shutil.rmtree(cloned, ignore_errors=True)
        return None
    return analyze_repo(cloned, full_name, runner=runner, confirm_threshold=confirm_threshold)
