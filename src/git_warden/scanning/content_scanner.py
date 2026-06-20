"""Static content scanner for JS/Python/etc. malware (the non-bash payloads).

Real malicious repos hide payloads in source: ``eval(atob(...))`` /
``Buffer.from(x,'base64')`` decode-and-run, ``child_process`` spawning, and
exfiltration to Discord/Telegram webhooks. The bash Layer-1 scanner targets
shell; this targets the supply-chain languages so true malicious repos actually
confirm. STATIC regex over file contents only -- nothing is executed.

Findings reuse :class:`~git_warden.scanning.bash_scanner.BashFinding`.
"""

from __future__ import annotations

import re
from pathlib import Path

from .bash_scanner import BashFinding

_SOURCE_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".rb", ".php", ".go", ".ps1"}
_MAX_BYTES = 1_000_000

_RULES: dict[str, list[tuple[str, re.Pattern]]] = {
    "obfuscation": [
        ("eval-decoded", re.compile(
            r"\beval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent|unescape)", re.I)),
        ("base64-buffer", re.compile(r"Buffer\.from\([^)]*['\"]base64['\"]", re.I)),
        ("atob", re.compile(r"\batob\s*\(")),
        ("fromcharcode-blob", re.compile(r"String\.fromCharCode\((?:\s*\d+\s*,){6,}")),
        ("py-decode-exec", re.compile(
            r"(?:exec|eval)\s*\(\s*(?:base64|marshal|zlib|__import__)", re.I)),
        ("hex-blob", re.compile(r"(?:\\x[0-9a-fA-F]{2}){12,}")),
    ],
    "code_execution": [
        ("node-child-process",
         re.compile(r"require\(\s*['\"]child_process['\"]|child_process", re.I)),
        ("js-exec", re.compile(r"\b(?:execSync|spawnSync|spawn|exec)\s*\(", re.I)),
        ("py-system", re.compile(r"\bos\.system\(|subprocess\.(?:Popen|run|call)", re.I)),
        ("py-dyn", re.compile(r"\b__import__\s*\(|\bcompile\s*\(|\bmarshal\.loads\(", re.I)),
    ],
    "network_exfil": [
        ("discord-webhook", re.compile(r"discord(?:app)?\.com/api/webhooks/", re.I)),
        ("telegram-bot", re.compile(r"api\.telegram\.org/bot", re.I)),
        ("paste-exfil", re.compile(r"webhook\.site|requestcatcher\.com|pastebin\.com/api", re.I)),
    ],
    "credential_access": [
        ("env-dump", re.compile(
            r"JSON\.stringify\(\s*process\.env|os\.environ\b.*(?:post|send|requests)", re.I)),
        ("keyfiles", re.compile(r"\.ssh/id_|\.aws/credentials|\.npmrc|\.env\b", re.I)),
    ],
}


def scan_content(root) -> list[BashFinding]:
    """Scan source files for obfuscation / exec / exfil. Static only."""
    root = Path(root)
    findings: list[BashFinding] = []
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        if path.suffix.lower() not in _SOURCE_EXT:
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        for lineno, line in enumerate(text.splitlines(), 1):
            for category, rules in _RULES.items():
                for rule_name, pattern in rules:
                    if pattern.search(line):
                        findings.append(
                            BashFinding(rel, lineno, category, rule_name, line.strip()[:200])
                        )
    return findings
