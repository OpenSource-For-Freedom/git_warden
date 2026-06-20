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

from .bash_scanner import BashFinding

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


def scan_manifests(root) -> list[BashFinding]:
    """Flag malicious package lifecycle hooks. Static parse only."""
    root = Path(root)
    findings: list[BashFinding] = []
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        name = path.name.lower()
        if name not in ("package.json", "setup.py"):
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")

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
        else:  # setup.py
            for match in _PY_SETUP_EXEC.finditer(text):
                line = text[: match.start()].count("\n") + 1
                findings.append(
                    BashFinding(rel, line, "install_hook", "py-setup-exec", match.group(0)[:120])
                )
    return findings
