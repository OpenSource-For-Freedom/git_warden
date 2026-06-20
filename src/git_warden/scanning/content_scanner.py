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

from .bash_scanner import BashFinding, is_ignored_path

_JS_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
_PY_EXT = {".py"}
_SOURCE_EXT = _JS_EXT | _PY_EXT | {".rb", ".php", ".go", ".ps1"}
_MAX_BYTES = 1_000_000

# Each rule carries the language family it applies to so a Python pattern can't
# match a JavaScript file (the tiledesk FP fired ``py-dyn`` -- ``compile(`` -- on
# ``index.js``). "any" rules are language-agnostic (webhook URLs, key paths).
# Rules tuple: (rule_name, lang, pattern). lang in {"js", "py", "any"}.
_RULES: dict[str, list[tuple[str, str, re.Pattern]]] = {
    "obfuscation": [
        ("eval-decoded", "js", re.compile(
            r"\beval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent|unescape)", re.I)),
        ("base64-buffer", "js", re.compile(r"Buffer\.from\([^)]*['\"]base64['\"]", re.I)),
        ("atob", "js", re.compile(r"\batob\s*\(")),
        ("fromcharcode-blob", "js", re.compile(r"String\.fromCharCode\((?:\s*\d+\s*,){6,}")),
        ("py-decode-exec", "py", re.compile(
            r"(?:exec|eval)\s*\(\s*(?:base64|marshal|zlib|__import__)", re.I)),
        ("hex-blob", "any", re.compile(r"(?:\\x[0-9a-fA-F]{2}){12,}")),
    ],
    "code_execution": [
        ("node-child-process", "js",
         re.compile(r"require\(\s*['\"]child_process['\"]|child_process", re.I)),
        ("js-exec", "js", re.compile(r"\b(?:execSync|spawnSync|spawn|exec)\s*\(", re.I)),
        ("py-system", "py", re.compile(r"\bos\.system\(|subprocess\.(?:Popen|run|call)", re.I)),
        ("py-dyn", "py", re.compile(r"\b__import__\s*\(|\bcompile\s*\(|\bmarshal\.loads\(", re.I)),
    ],
    "network_exfil": [
        ("discord-webhook", "any", re.compile(r"discord(?:app)?\.com/api/webhooks/", re.I)),
        ("telegram-bot", "any", re.compile(r"api\.telegram\.org/bot", re.I)),
        ("paste-exfil", "any",
         re.compile(r"webhook\.site|requestcatcher\.com|pastebin\.com/api", re.I)),
    ],
    "credential_access": [
        ("env-dump", "any", re.compile(
            r"JSON\.stringify\(\s*process\.env|os\.environ\b.*(?:post|send|requests)", re.I)),
        ("keyfiles", "any", re.compile(r"\.ssh/id_|\.aws/credentials|\.npmrc|\.env\b", re.I)),
    ],
}


def _lang_for(suffix: str) -> str:
    if suffix in _JS_EXT:
        return "js"
    if suffix in _PY_EXT:
        return "py"
    return "other"


def _is_minified(name: str) -> bool:
    """Minified/bundled files are generated artifacts and trip hex/blob rules."""
    return name.endswith((".min.js", ".min.mjs", ".min.cjs")) or ".bundle." in name


def scan_content(root) -> list[BashFinding]:
    """Scan first-party source files for obfuscation / exec / exfil. Static only."""
    root = Path(root)
    findings: list[BashFinding] = []
    for path in root.rglob("*"):
        if not path.is_file() or is_ignored_path(path):
            continue
        suffix = path.suffix.lower()
        if suffix not in _SOURCE_EXT or _is_minified(path.name.lower()):
            continue
        lang = _lang_for(suffix)
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")
        for lineno, line in enumerate(text.splitlines(), 1):
            for category, rules in _RULES.items():
                for rule_name, rule_lang, pattern in rules:
                    if rule_lang != "any" and rule_lang != lang:
                        continue
                    if pattern.search(line):
                        findings.append(
                            BashFinding(rel, lineno, category, rule_name, line.strip()[:200])
                        )
    return findings
