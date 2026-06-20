"""Custom bash malware scanner; Layer 1 (static/signature), doc 03.

No adequate free bash-specific scanner exists, so this is our own (doc 03 sec 1).
Layer 1 inspects code without executing it, across the full attack surface
(doc 03 sec 2): enumeration, persistence, lateral movement, exfiltration,
reverse shells, process injection, credential harvesting, network scanning, and
obfuscation/evasion. It recursively finds bash and bash-bearing files; shell
embedded in setup scripts, CI workflows, Dockerfiles (doc 03 sec 4); and emits
per-file, categorized findings (doc 03 sec 5).

Layer 2 (sandboxed behavioral execution, doc 03 sec 3.2) is deliberately out of
scope here; it is the heavy lift and lands later.

Pure functions over text/paths: fully unit-testable with no execution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Per-category severity weight (reverse shells / exfil / download-exec are the
# strongest signals; enumeration is common and weak on its own).
_WEIGHTS = {
    "reverse_shell": 5,
    "download_exec": 4,
    "exfiltration": 4,
    "obfuscation": 3,
    "persistence": 3,
    "credential_harvest": 3,
    "process_injection": 3,
    "lateral_movement": 2,
    "network_scan": 2,
    "enumeration": 1,
}

# Category -> (rule name, regex). Case-insensitive, matched per line.
_RULES: dict[str, list[tuple[str, re.Pattern]]] = {
    "reverse_shell": [
        ("dev-tcp-redirect", re.compile(r"/dev/tcp/|/dev/udp/", re.I)),
        ("nc-exec", re.compile(r"\bn(?:c|cat)\b[^\n]*\s-e\b", re.I)),
        ("bash-i-socket", re.compile(r"bash\s+-i\b[^\n]*(>&|2>&1)", re.I)),
        ("mkfifo-shell", re.compile(r"mkfifo[^\n]*\b(nc|ncat|sh|bash)\b", re.I)),
        ("python-reverse", re.compile(r"socket\.socket[^\n]*(connect|SOCK_STREAM)", re.I)),
    ],
    "download_exec": [
        ("curl-pipe-shell", re.compile(r"(curl|wget)\s[^\n|]*\|\s*(sh|bash|python|perl)", re.I)),
        ("fetch-then-exec",
         re.compile(r"(curl|wget)\s[^\n]*-o\s*\S+[^\n]*;\s*(sh|bash|chmod)", re.I)),
    ],
    "exfiltration": [
        ("discord-webhook", re.compile(r"discord(?:app)?\.com/api/webhooks/", re.I)),
        ("telegram-bot", re.compile(r"api\.telegram\.org/bot", re.I)),
        # curl/wget POSTING or UPLOADING a secret FILE is credential exfil (the
        # data is the tell, not the host): `curl -d @~/.ssh/id_rsa http://x`.
        ("secret-exfil", re.compile(
            r"\b(?:curl|wget)\b[^\n]*(?:-d|--data(?:-binary)?|-F|--form|-T|--upload-file)"
            r"[^\n]*(?:id_rsa|id_ed25519|\.ssh/|\.aws/credentials|/etc/shadow|/etc/passwd|"
            r"\.env\b|credentials?\.(?:json|ya?ml)|secrets?\.(?:json|ya?ml|txt))", re.I)),
        ("curl-post-data",
         re.compile(r"\bcurl\b.*(?:\s-[dFT]\b|--data\b|--upload-file\b)", re.I)),
        ("archive-then-send", re.compile(r"(tar|zip|gzip)\b[^\n]*\|\s*(curl|nc|wget)", re.I)),
    ],
    "persistence": [
        ("cron", re.compile(r"\bcrontab\b|/etc/cron|@reboot", re.I)),
        ("rc-files", re.compile(r">>\s*~?/?\.?(bashrc|bash_profile|profile|zshrc)\b", re.I)),
        ("systemd", re.compile(r"systemctl\s+enable|/etc/systemd/system/", re.I)),
        ("authorized-keys", re.compile(r"\.ssh/authorized_keys", re.I)),
        ("rc-local", re.compile(r"/etc/rc\.local|launchctl\s+load", re.I)),
    ],
    "credential_harvest": [
        ("ssh-keys", re.compile(r"id_rsa|id_ed25519|\.ssh/id_", re.I)),
        ("cloud-creds", re.compile(r"\.aws/credentials|\.config/gcloud|\.azure/", re.I)),
        # reads /etc/shadow (password hashes); /etc/passwd is benign/ubiquitous
        ("shadow-passwd", re.compile(r"/etc/shadow\b", re.I)),
        ("env-token-grab", re.compile(r"\b(AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN|API_KEY)\b", re.I)),
    ],
    "process_injection": [
        ("ld-preload", re.compile(r"\bLD_PRELOAD\b", re.I)),
        ("ptrace-mem", re.compile(r"/proc/\d+/mem|\bptrace\b", re.I)),
        ("gdb-attach", re.compile(r"gdb\s+-p\b", re.I)),
    ],
    "lateral_movement": [
        ("sshpass", re.compile(r"\bsshpass\b", re.I)),
        ("remote-exec", re.compile(r"\b(psexec|wmiexec|pscp)\b", re.I)),
    ],
    "network_scan": [
        ("scanner", re.compile(r"\b(nmap|masscan|zmap)\b", re.I)),
        ("port-sweep", re.compile(r"nc\s+-z\b", re.I)),
    ],
    "enumeration": [
        ("host-recon", re.compile(r"\b(uname\s+-a|whoami|hostname|id)\b", re.I)),
        ("net-recon", re.compile(r"\b(ifconfig|ip\s+addr|netstat|ss\s+-)\b", re.I)),
    ],
    "obfuscation": [
        ("base64-decode-exec", re.compile(r"base64\s+(-d|--decode)[^\n]*\|\s*(sh|bash)", re.I)),
        ("eval-base64", re.compile(r"eval\s[^\n]*base64", re.I)),
        ("hex-escapes", re.compile(r"(?:\\x[0-9a-fA-F]{2}){6,}")),
        ("ifs-obfuscation", re.compile(r"\$\{IFS\}")),
        ("eval-subshell", re.compile(r"eval\s+[\"']?\$\(")),
    ],
}

# Files that carry shell even without a .sh extension (doc 03 sec 4).
_BASH_BEARING_NAMES = {"dockerfile", "makefile", "setup.py", "package.json"}
_BASH_SUFFIXES = {".sh", ".bash", ".ksh", ".zsh"}
_EMBEDDED_SUFFIXES = {".yml", ".yaml"}  # CI workflows etc.
_SHEBANG = re.compile(r"^#!.*\b(ba|z|k)?sh\b")
_MAX_BYTES = 1_000_000

# Paths that are NOT the repo author's executable payload. Two kinds:
#   * Vendored/generated trees (THIRD-PARTY code); the tiledesk FP came from
#     `node_modules/bytes` and `node_modules/content-disposition`.
#   * Test / fixture / example trees, which legitimately contain attack strings
#     as data; the crewhaus FP came from a prompt-injection DETECTOR whose
#     `index.test.ts` cites `webhook.site` / telegram as test fixtures.
# Excluding both means only first-party, shipped code can confirm a finding.
# (Names are compared case-insensitively.)
_IGNORE_DIRS = frozenset({
    ".git", "node_modules", "bower_components", "vendor", "third_party",
    "third-party", "dist", "build", "out", ".next", ".nuxt", "target",
    ".venv", "venv", "virtualenv", "site-packages", "__pycache__", "pods",
    ".gradle", ".terraform", ".yarn",
    # non-payload: tests/fixtures/examples carry attack strings as DATA
    "test", "tests", "__tests__", "spec", "__spec__", "fixtures", "fixture",
    "__fixtures__", "mocks", "__mocks__", "e2e", "testdata", "examples", "example",
})
# Test-file name markers (a test file can live anywhere, e.g. `src/x.test.ts`).
_TEST_FILE_MARKERS = (".test.", ".spec.", ".stories.", ".fixture.", ".mock.")


def is_ignored_path(path: Path) -> bool:
    """True if a path is vendored/generated or a test/fixture (skip for scanning)."""
    parts = {p.lower() for p in path.parts}
    if _IGNORE_DIRS & parts:
        return True
    name = path.name.lower()
    return any(marker in name for marker in _TEST_FILE_MARKERS)


@dataclass
class BashFinding:
    file: str
    line: int
    category: str
    rule: str
    snippet: str


def is_bash_bearing(path: Path, first_line: str) -> bool:
    """Whether a file should be scanned for shell (doc 03 sec 4)."""
    name = path.name.lower()
    if path.suffix.lower() in _BASH_SUFFIXES or name in _BASH_BEARING_NAMES:
        return True
    if path.suffix.lower() in _EMBEDDED_SUFFIXES and "workflow" in str(path).lower():
        return True
    return bool(_SHEBANG.match(first_line))


def scan_text(text: str, file: str = "<text>") -> list[BashFinding]:
    """Run every rule against each line of text. Pure."""
    findings: list[BashFinding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for category, rules in _RULES.items():
            for rule_name, pattern in rules:
                if pattern.search(line):
                    findings.append(
                        BashFinding(file, lineno, category, rule_name, line.strip()[:200])
                    )
    return findings


def scan_repo(root: Path) -> list[BashFinding]:
    """Recursively scan a cloned repo's bash-bearing files."""
    root = Path(root)
    findings: list[BashFinding] = []
    for path in root.rglob("*"):
        if not path.is_file() or is_ignored_path(path):
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            with path.open("r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except OSError:
            continue
        first_line = content.split("\n", 1)[0] if content else ""
        if not is_bash_bearing(path, first_line):
            continue
        rel = str(path.relative_to(root))
        findings.extend(f.__class__(rel, f.line, f.category, f.rule, f.snippet)
                        for f in scan_text(content, rel))
    return findings


def score_findings(findings: list[BashFinding]) -> int:
    """Weighted score. Distinct (category, rule) pairs count once to limit spam."""
    seen = {(f.category, f.rule) for f in findings}
    return sum(_WEIGHTS.get(category, 1) for category, _ in seen)
