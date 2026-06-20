"""Static install-hook / manifest scanner (doc 03 sec 1; PRD GuardDog role).

Supply-chain malware's #1 vector is a package *lifecycle hook* that runs code on
install (``npm`` pre/postinstall, ``setup.py`` exec). This STATICALLY parses
manifests and flags hooks with suspicious commands -- it NEVER executes anything
(no install, no setup.py, no scripts). The referenced payload files themselves
are caught by the content scanner.

Findings reuse :class:`~git_warden.scanning.bash_scanner.BashFinding`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .bash_scanner import BashFinding, is_ignored_path

_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "preuninstall")

# Commands inside a lifecycle hook that indicate code execution / fetch-and-run.
_SUSPICIOUS_CMD = re.compile(
    r"\bcurl\b|\bwget\b|\beval\b|node\s+-e|python[0-9]?\s+-c|base64|\bsh\b|\bbash\b|"
    r"powershell|invoke-|child_process|atob|fromCharCode|/dev/tcp|https?://|\.sh\b",
    re.IGNORECASE,
)
# Code execution inside setup.py (static regex; we do not run it).
_PY_SETUP_EXEC = re.compile(
    r"\bos\.system\(|subprocess\.(?:Popen|call|run|check_output|check_call)|"
    r"\b__import__\(|\beval\(|\bexec\(|\bcompile\(|\bmarshal\.loads\(",
    re.IGNORECASE,
)
_MAX_BYTES = 1_000_000


# Python requirement lines: ``name==1.2.3`` / ``name>=1`` / bare ``name``.
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:[=<>!~;\[].*)?$")


def _declared_deps(name: str, text: str) -> set[str]:
    """Dependency names declared by a manifest (npm package.json / pip reqs)."""
    deps: set[str] = set()
    if name == "package.json":
        try:
            data = json.loads(text or "{}") or {}
        except ValueError:
            return deps
        for key in ("dependencies", "devDependencies", "optionalDependencies",
                    "peerDependencies"):
            section = data.get(key)
            if isinstance(section, dict):
                deps.update(section.keys())
    else:  # requirements*.txt
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            m = _REQ_LINE.match(line)
            if m:
                deps.add(m.group(1))
    return deps


def scan_manifests(root, malicious_packages=None) -> list[BashFinding]:
    """Flag malicious lifecycle hooks AND known-malicious DEPENDENCIES. Static.

    ``malicious_packages`` maps ecosystem ('npm'/'pypi') -> frozenset of OSM-flagged
    names. A repo that declares one as a dependency installs known malware on
    ``npm/pip install`` -- the delivery vector behind fake-interview / crypto-task
    lure repos, whose own code looks benign. Matching is ECOSYSTEM-SCOPED
    (package.json vs npm, requirements/pip vs pypi) so a legit npm package does not
    collide with a same-named typosquat on another registry. Tier-A confirmation.
    """
    malicious_packages = malicious_packages or {}
    npm_bad = malicious_packages.get("npm", frozenset())
    pypi_bad = malicious_packages.get("pypi", frozenset())
    root = Path(root)
    findings: list[BashFinding] = []
    for path in root.rglob("*"):
        if not path.is_file() or is_ignored_path(path):
            continue
        name = path.name.lower()
        is_reqs = name.startswith("requirements") and name.endswith(".txt")
        if name not in ("package.json", "setup.py") and not is_reqs:
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")

        bad = npm_bad if name == "package.json" else (pypi_bad if is_reqs else frozenset())
        if bad:
            manifest_kind = "package.json" if name == "package.json" else name
            for dep in _declared_deps(manifest_kind, text):
                if dep.lower() in bad:
                    findings.append(BashFinding(
                        rel, 0, "malicious_dependency", "osm-listed", dep[:120]))

        if name == "package.json":
            try:
                scripts = (json.loads(text or "{}") or {}).get("scripts") or {}
            except ValueError:
                continue
            for hook in _LIFECYCLE:
                cmd = scripts.get(hook)
                if cmd and _SUSPICIOUS_CMD.search(str(cmd)):
                    findings.append(
                        BashFinding(rel, 0, "install_hook", f"npm-{hook}", str(cmd)[:200])
                    )
        elif name == "setup.py":
            for match in _PY_SETUP_EXEC.finditer(text):
                line = text[: match.start()].count("\n") + 1
                findings.append(
                    BashFinding(rel, line, "install_hook", "py-setup-exec", match.group(0)[:120])
                )
    return findings
