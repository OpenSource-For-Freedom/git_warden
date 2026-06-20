"""Tier-2: clone a candidate repo and run deep analysis (doc 02 section 3.2).

Clones a high-scoring candidate, fingerprints it by code hash for cross-repo
dedup (doc 02 section 4), runs our custom bash scanner (doc 03), and invokes the
established OSS scanners -- GuardDog, Semgrep, YARA -- when their binaries are
present, skipping gracefully when they are not. The program does not reinvent
those engines (doc 02 section 3.2); it orchestrates them.

The clone step is injectable so the analysis is unit-testable on a fixture
directory with no network or git.

INVARIANT -- STATIC ANALYSIS ONLY: targets are shallow-cloned and *read*. Their
code is NEVER executed: no pip/npm install, no setup.py, no lifecycle/postinstall
scripts, no Makefiles, no running the repo. Behavioral/"detonation" execution is
explicitly out of scope. Keep `git clone --depth 1`. Do not add anything here
that runs target code.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .bash_scanner import BashFinding, scan_repo
from .content_scanner import scan_content
from .ioc import IocSet, extract_repo_iocs
from .manifest_scanner import scan_manifests

log = logging.getLogger(__name__)

# OSS scanners orchestrated in Tier-2 (doc 02 3.2). We do not reinvent these.
_SCANNER_NAMES = ("semgrep", "guarddog", "yara")

CONFIRM_THRESHOLD = 5

# Weights across ALL static scanners (bash + manifest + content). Distinct
# (category, rule) pairs are summed; a high-signal category is required to
# confirm so weak recon alone can't reach gold (eval finding #15).
_CATEGORY_WEIGHTS = {
    # bash Layer-1
    "reverse_shell": 5, "download_exec": 4, "exfiltration": 4, "obfuscation": 4,
    "persistence": 3, "credential_harvest": 3, "process_injection": 3,
    "lateral_movement": 2, "network_scan": 2, "enumeration": 1,
    # manifest / content (supply-chain malware)
    "install_hook": 5, "network_exfil": 4, "code_execution": 3, "credential_access": 3,
}
# Git Warden hunts the FULL attack surface (doc 03): hidden network attacks,
# enumeration/recon, typosquatting, viral implants -- not just supply-chain
# payloads. Confirmation uses a two-part model so the whole surface is in scope
# WITHOUT the tiledesk false positives:
#
#   confirmed = a single unambiguous SIGNATURE  OR  a recon->ACTION attack chain
#
# A SIGNATURE is a single (category, rule) that is malicious on its own -- a
# reverse shell, curl|bash, eval(atob(...)), a webhook exfil, an install hook.
# The CHAIN catches subtler attacks: a recon/collection signal (enumeration,
# network scan, credential gathering) paired with an ACTION signal (exfil,
# download-exec, reverse shell, persistence, obfuscation, injection, lateral
# movement). What made the tiledesk repos benign was the absence of an ACTION
# phase -- they reference ``.env`` and run ``whoami`` in CI but never exfil,
# execute untrusted code, or persist. A real implant ACTS on what it gathers.
# Bare idioms (child_process, exec(), env-var *names*, ``.env`` *references*) are
# neither a signature nor an action, so they cannot confirm on their own.
_SIGNATURE_RULES = frozenset({
    # bash Layer-1 -- unambiguous offensive shell
    ("reverse_shell", "dev-tcp-redirect"), ("reverse_shell", "nc-exec"),
    ("reverse_shell", "bash-i-socket"), ("reverse_shell", "mkfifo-shell"),
    ("reverse_shell", "python-reverse"),
    ("download_exec", "curl-pipe-shell"), ("download_exec", "fetch-then-exec"),
    ("exfiltration", "discord-webhook"), ("exfiltration", "telegram-bot"),
    ("exfiltration", "archive-then-send"),
    ("obfuscation", "base64-decode-exec"), ("obfuscation", "eval-base64"),
    ("obfuscation", "hex-escapes"),
    ("persistence", "cron"), ("persistence", "rc-files"), ("persistence", "systemd"),
    ("persistence", "authorized-keys"), ("persistence", "rc-local"),
    ("credential_harvest", "ssh-keys"), ("credential_harvest", "cloud-creds"),
    ("credential_harvest", "shadow-passwd"),
    ("process_injection", "ld-preload"), ("process_injection", "ptrace-mem"),
    ("process_injection", "gdb-attach"),
    # content scanner -- decode-and-run / exfil signatures
    ("obfuscation", "eval-decoded"), ("obfuscation", "py-decode-exec"),
    ("obfuscation", "fromcharcode-blob"), ("obfuscation", "hex-blob"),
    ("network_exfil", "discord-webhook"), ("network_exfil", "telegram-bot"),
    ("network_exfil", "paste-exfil"),
    ("credential_access", "env-dump"),
    # manifest scanner -- a lifecycle hook is only emitted with a suspicious cmd
    ("install_hook", "npm-preinstall"), ("install_hook", "npm-install"),
    ("install_hook", "npm-postinstall"), ("install_hook", "npm-prepare"),
    ("install_hook", "npm-preuninstall"), ("install_hook", "py-setup-exec"),
})
# Recon/collection phase -- "casing the joint." Benign on its own (CI runs
# ``whoami``; apps read ``.env``); an attack signal only when paired with action.
_RECON_CATEGORIES = frozenset({
    "enumeration", "network_scan", "credential_harvest", "credential_access",
})
# Action/egress/control phase -- getting data out, running untrusted code,
# establishing control, or hiding. Pairing recon with any of these is the chain
# that distinguishes an implant from a build script.
_ACTION_CATEGORIES = frozenset({
    "exfiltration", "network_exfil", "download_exec", "reverse_shell",
    "install_hook", "persistence", "process_injection", "lateral_movement",
    "obfuscation",
})
# Idioms too common to drive a chain even though they sit in a recon/action
# category: a token-NAME reference, bare base64 decode, ``curl -d``, ifconfig.
# Recorded as findings (context/score) but cannot, on their own, satisfy a phase
# -- otherwise a legit app that decodes base64 and reads an env var would chain.
_WEAK_RULES = frozenset({
    ("credential_harvest", "env-token-grab"),  # references a token's NAME, not theft
    ("obfuscation", "atob"),                    # bare atob() -- ubiquitous in JS
    ("obfuscation", "base64-buffer"),           # bare Buffer.from(x,'base64')
    ("exfiltration", "curl-post-data"),         # curl -d -- common API call idiom
    ("enumeration", "net-recon"),               # ifconfig/netstat -- common diagnostics
})
# Intent-change categories for RED-TEAM lineage (P1, doc 02 5): a fork of an
# offensive tool legitimately *has* reverse shells / injection -- that is the
# tool's purpose, not evidence of weaponization. Only ADDED supply-chain
# mechanisms (install hooks, exfil to attacker infra, fresh obfuscation, fetch-
# and-run, credential theft) indicate the intent changed. So lineage confirms
# ONLY on these, never on the tool's own offensive code.
WEAPONIZATION_CATEGORIES = frozenset({
    "install_hook", "network_exfil", "obfuscation", "download_exec",
    "exfiltration", "credential_access", "credential_harvest",
})


def _score_static(findings: list[BashFinding]) -> int:
    """Weighted score over distinct (category, rule) pairs (spam-resistant)."""
    seen = {(f.category, f.rule) for f in findings}
    return sum(_CATEGORY_WEIGHTS.get(category, 1) for category, _ in seen)


def _guarddog_ecosystem(root: Path) -> str | None:
    """npm/pypi if the repo carries a matching manifest, else None."""
    if (Path(root) / "package.json").exists():
        return "npm"
    if (Path(root) / "setup.py").exists() or (Path(root) / "pyproject.toml").exists():
        return "pypi"
    return None
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
        return [f"static:{c}" for c in cats] + [
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


def _force_rmtree(path: Path) -> None:
    """Remove a tree even when git left read-only ``.git`` pack files.

    On Windows ``shutil.rmtree`` cannot unlink read-only files, so scratch husks
    (40k+ files) pile up. The handler clears the read-only bit and retries. No-op
    if the path is already gone. Cross-platform: ``onexc`` (Py3.12+) with an
    ``onerror`` fallback for 3.11.
    """
    path = Path(path)
    if not path.exists():
        return

    def _onexc(func, p, _exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_onexc)
    else:  # pragma: no cover -- onexc was added in 3.12; onerror is the 3.11 path
        shutil.rmtree(path, onerror=_onexc)


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
    """Shallow-clone a public repo for STATIC reading. Path, or None on failure.

    Static analysis only: the target is never executed -- ``--depth 1`` fetches
    a single commit to read, nothing more. Validates the untrusted ``full_name``
    against a strict allowlist and passes ``--`` before the URL so a crafted
    value cannot become a path traversal or a git flag (eval finding #16). A
    failed/partial clone is force-removed (handles git's read-only pack files).
    """
    if not _VALID_FULL_NAME.fullmatch(full_name) or ".." in full_name:
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
        _force_rmtree(dest)
        return None
    if result.returncode != 0:
        log.warning("clone non-zero", extra={"context": {"repo": full_name}})
        _force_rmtree(dest)
        return None
    return dest


def _run_external(name: str, root: Path, runner) -> str:
    """Run one OSS scanner if installed; return a status string.

    'flagged' must mean a real detection, never an error/chatter (eval #5).
    These scanners READ the repo statically; none executes target code.
    """
    if shutil.which(name) is None:
        return "skipped (not installed)"

    if name == "semgrep":
        try:
            result = runner(["semgrep", "--json", "--quiet", "--config", "auto", str(root)],
                            capture_output=True, text=True, timeout=300)
            payload = json.loads(result.stdout or "{}")
        except (OSError, subprocess.SubprocessError):
            return "error"
        except ValueError:
            return "error"
        if payload.get("errors") and not payload.get("results"):
            return "error"
        return "flagged" if payload.get("results") else "clean"

    if name == "guarddog":
        # GuardDog statically scans a package directory for malicious indicators
        # (install hooks, exfiltration, typosquatting) -- doc 02 3.2 / PRD. It
        # does not install or run the package.
        eco = _guarddog_ecosystem(root)
        if eco is None:
            return "skipped (no package manifest)"
        try:
            result = runner(["guarddog", eco, "scan", str(root), "--output-format", "json"],
                            capture_output=True, text=True, timeout=300)
            payload = json.loads(result.stdout or "{}")
        except (OSError, subprocess.SubprocessError):
            return "error"
        except ValueError:
            return "error"
        issues = payload.get("issues")
        results = payload.get("results") or payload.get("findings")
        return "flagged" if (issues or results) else "clean"

    return "skipped (no rules)"  # yara: rulesets provisioned later


def analyze_repo(
    root: Path,
    full_name: str,
    *,
    runner=subprocess.run,
    confirm_threshold: int = CONFIRM_THRESHOLD,
    restrict_paths: set[str] | None = None,
    confirm_categories: frozenset[str] | None = None,
) -> Tier2Result:
    """Run Tier-2 STATIC analysis on an already-cloned repo (never executes it).

    Combines the bash Layer-1 scanner, the install-hook/manifest scanner, and the
    JS/Python content scanner, plus the OSS scanners. Confirmation spans the full
    attack surface via a two-part gate (see module constants): a single
    unambiguous SIGNATURE, or a recon->ACTION chain. ``restrict_paths`` limits
    which files count toward confirmation (red-team lineage diverged files, P1);
    ``confirm_categories`` restricts which categories may count (lineage uses
    WEAPONIZATION_CATEGORIES so a fork only confirms on added malicious mechanisms,
    not the tool's own offensive code).
    """
    findings = scan_repo(root) + scan_manifests(root) + scan_content(root)
    if restrict_paths is not None:
        allowed = {p.replace("\\", "/") for p in restrict_paths}
        findings = [f for f in findings if f.file.replace("\\", "/") in allowed]

    score = _score_static(findings)
    scanners = {name: _run_external(name, root, runner) for name in _SCANNER_NAMES}
    # Two-part gate over the full attack surface: a single unambiguous SIGNATURE,
    # or a recon->ACTION chain (gathering paired with egress/control/evasion). For
    # red-team lineage, confirm_categories restricts which categories may count so
    # the tool's own offensive code never confirms -- only ADDED weaponization.
    def _ok(category: str) -> bool:
        return confirm_categories is None or category in confirm_categories

    def _phase(f: BashFinding, categories: frozenset[str]) -> bool:
        return (f.category in categories and (f.category, f.rule) not in _WEAK_RULES
                and _ok(f.category))
    signature = any((f.category, f.rule) in _SIGNATURE_RULES and _ok(f.category)
                    for f in findings)
    has_recon = any(_phase(f, _RECON_CATEGORIES) for f in findings)
    has_action = any(_phase(f, _ACTION_CATEGORIES) for f in findings)
    chain = has_recon and has_action
    static_confirmed = score >= confirm_threshold and (signature or chain)
    # Only a MALWARE-SPECIFIC scanner (GuardDog: install hooks/exfil/typosquat;
    # YARA: malware rulesets) may solely confirm. Semgrep runs `--config auto`, a
    # general SAST pass that flags ordinary code smells (e.g. child_process.exec)
    # in legitimate apps -- letting it confirm alone would re-introduce the
    # tiledesk false positives in CI (where it is installed). Its findings still
    # appear in provenance via signal_summary, just not as sole proof.
    oss_confirmed = any(scanners.get(n) == "flagged" for n in ("guarddog", "yara"))
    confirmed = static_confirmed or oss_confirmed
    # Learning loop: mine IOCs only once confirmed, from trusted ground truth.
    learned = extract_repo_iocs(root) if confirmed else IocSet()
    return Tier2Result(
        full_name=full_name,
        code_hash=repo_code_hash(root),
        bash_findings=findings,   # all static findings (bash + manifest + content)
        bash_score=score,
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
    restrict_paths: set[str] | None = None,
    confirm_categories: frozenset[str] | None = None,
) -> Tier2Result | None:
    """Clone + STATICALLY analyze a candidate. None if the clone fails/too big.

    Invariant: the target is only read; its code is NEVER executed. The clone is
    force-removed on every exit path (success, skip, or error) so scratch does
    not accumulate -- important on a near-full system drive.
    """
    dest = Path(workdir) / full_name.replace("/", "__")
    cloned = clone(full_name, dest, runner=runner)
    if cloned is None:
        return None
    try:
        # Reject an oversized/path-bomb tree before walking it (eval finding #9).
        if not _within_bounds(cloned):
            log.warning("clone exceeds size bounds; skipping",
                        extra={"context": {"repo": full_name}})
            return None
        return analyze_repo(cloned, full_name, runner=runner,
                            confirm_threshold=confirm_threshold, restrict_paths=restrict_paths,
                            confirm_categories=confirm_categories)
    finally:
        _force_rmtree(cloned)
