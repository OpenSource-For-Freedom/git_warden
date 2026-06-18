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
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .bash_scanner import BashFinding, scan_repo, score_findings

log = logging.getLogger(__name__)

# OSS scanners orchestrated in Tier-2. Each entry: how to invoke it on a path.
_EXTERNAL_SCANNERS = {
    "semgrep": lambda root: ["semgrep", "--quiet", "--config", "auto", str(root)],
    "yara": None,  # needs a compiled ruleset path; wired when rules are provisioned
    "guarddog": None,  # package-ecosystem oriented; applied to package candidates
}

CONFIRM_THRESHOLD = 5


@dataclass
class Tier2Result:
    full_name: str
    code_hash: str
    bash_findings: list[BashFinding] = field(default_factory=list)
    bash_score: int = 0
    scanners: dict[str, str] = field(default_factory=dict)  # name -> status/summary
    confirmed: bool = False

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
            data = path.read_bytes()
        except OSError:
            continue
        digest.update(rel.encode("utf-8"))
        digest.update(hashlib.sha256(data).digest())
    return digest.hexdigest()


def clone_repo(
    full_name: str, dest: Path, *, runner=subprocess.run, timeout: int = 120
) -> Path | None:
    """Shallow-clone a public repo. Returns the path, or None on failure."""
    url = f"https://github.com/{full_name}.git"
    try:
        result = runner(
            ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
            capture_output=True, text=True, timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("clone failed", extra={"context": {"repo": full_name, "err": str(exc)}})
        return None
    if result.returncode != 0:
        log.warning("clone non-zero", extra={"context": {"repo": full_name}})
        return None
    return dest


def _run_external(name: str, root: Path, runner) -> str:
    """Run one OSS scanner if installed; return a status string."""
    builder = _EXTERNAL_SCANNERS.get(name)
    if builder is None or shutil.which(name) is None:
        return "skipped (not installed)"
    try:
        result = runner(builder(root), capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"error: {exc}"
    # Convention: non-empty findings on stdout / non-zero -> flagged.
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
    confirmed = bash_score >= confirm_threshold or "flagged" in scanners.values()
    return Tier2Result(
        full_name=full_name,
        code_hash=repo_code_hash(root),
        bash_findings=bash_findings,
        bash_score=bash_score,
        scanners=scanners,
        confirmed=confirmed,
    )


def scan_candidate(
    full_name: str,
    workdir: Path,
    *,
    clone=clone_repo,
    runner=subprocess.run,
    confirm_threshold: int = CONFIRM_THRESHOLD,
) -> Tier2Result | None:
    """Clone + analyze a candidate. Returns None if the clone fails."""
    dest = Path(workdir) / full_name.replace("/", "__")
    if clone(full_name, dest, runner=runner) is None:
        return None
    return analyze_repo(dest, full_name, runner=runner, confirm_threshold=confirm_threshold)
