"""Static install-hook / manifest scanner (doc 03 sec 1; PRD GuardDog role).

Supply-chain malware's #1 vector is a package *lifecycle hook* that runs code on
install (``npm`` pre/postinstall, ``setup.py`` exec). This STATICALLY parses
manifests and flags hooks with suspicious commands; it NEVER executes anything
(no install, no setup.py, no scripts). The referenced payload files themselves
are caught by the content scanner.

Findings reuse :class:`~git_warden.scanning.bash_scanner.BashFinding`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .bash_scanner import (
    _INSTALL_HOST_RE,
    BashFinding,
    is_ignored_path,
    is_reputable_install_host,
)

_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "preuninstall")

# FETCH-AND-RUN or DECODE-AND-RUN inside a lifecycle hook. The 2026-07-02 audit
# found the old alternation (bare \bsh\b / \bbash\b / \.sh\b / https?:// / base64
# / powershell / invoke- / child_process) confirmed a repo MALICIOUS alone on
# ordinary tooling: `postinstall: bash ./scripts/install.sh`, `echo Docs:
# https://...`, `invoke-build`, a script named gen-base64-assets.js. install_hook
# is Tier-A confirm-alone, so the gate must be the ACTUAL supply-chain shape:
# download-and-execute, decode-and-execute, or inline code exec -- not merely
# "invokes a shell script".
_FETCH = r"(?:curl|wget|iwr|invoke-webrequest)"
_RUNSH = r"(?:sh|bash|zsh|python[0-9]?|perl|node|cmd|powershell|pwsh|iex)"
_SUSPICIOUS_CMD = re.compile(
    rf"{_FETCH}\b[^\n]*\|\s*{_RUNSH}\b"                                   # curl ... | sh
    rf"|{_FETCH}\b[^\n]*-o\b[^\n]*(?:;|&&)\s*(?:{_RUNSH}|chmod)\b"        # curl -o x; sh x
    r"|\bnode\s+(?:-e|--eval)\b|\bpython[0-9]?\s+-c\b|\bperl\s+-e\b|\bruby\s+-e\b"  # inline code
    r"|\beval\s*\(|\bnew\s+Function\s*\("                                 # JS eval / Function()
    # decode -> run
    r"|(?:base64\s+(?:-d|--decode)|\batob\s*\()[^\n]*(?:\|\s*" + _RUNSH + r"|\beval\b|\bexec\b)"
    r"|/dev/tcp/"                                                         # reverse shell
    r"|\b(?:iex|invoke-expression)\b",                                    # PS download-exec
    re.IGNORECASE,
)
# A lifecycle script that ONLY fetches from a reputable installer host is a normal
# toolchain bootstrap (Meteor, Rust, Node, Docker, Bun, ...), not a dropper -- so it
# must not confirm (the chris-visser/meteor-vue-admin `curl install.meteor.com | sh`
# and jose-compu/zk-vrf `rustup` preinstall FPs, 2026-07-07). An attacker preinstall
# fetching a non-installer host still fires. The host list itself lives in
# bash_scanner so every layer shares one copy.


def _only_reputable_install(cmd: str) -> bool:
    """True if a lifecycle command fetches ONLY from reputable installer hosts."""
    hosts = [h.lower().rstrip(".") for h in _INSTALL_HOST_RE.findall(cmd or "")]
    return bool(hosts) and all(is_reputable_install_host(h) for h in hosts)


# `node -e "<inline>"` in a lifecycle hook is only a dropper when the inline code
# actually fetches / decodes / spawns. A package-manager guard (read
# npm_config_user_agent, process.exit) or a local `require('./postinstall')` is
# benign and ubiquitous -- the frankhli843/gemmahermes PM-guard FP (2026-07-07).
_NODE_EVAL = re.compile(r"\bnode\s+(?:-e|--eval)\b", re.I)
_NODE_EVAL_DANGER = re.compile(
    r"child_process|\bexec(?:Sync)?\s*\(|\bspawn|\bfetch\s*\(|https?://|/dev/tcp/"
    r"|\batob\s*\(|Buffer\.from\([^)]*base64|\beval\s*\(|\bFunction\s*\(|require\s*\(\s*"
    r"['\"](?:child_process|node:child_process|https?|node:https?|net|dgram)",
    re.I)


def _is_benign_node_eval(cmd: str) -> bool:
    """True if the command's danger is ONLY a `node -e` whose inline code neither
    fetches, decodes, nor spawns (a PM guard / local require), so it must not confirm."""
    c = str(cmd or "")
    return bool(_NODE_EVAL.search(c)) and not _NODE_EVAL_DANGER.search(c)
# FETCH-AND-RUN inside setup.py (static regex; we do not run it). A bare
# exec()/subprocess in setup.py is NORMAL; legit packages compile extensions
# (subprocess -> cmake/nvcc), read their version (exec(open('_version.py'))), and
# shell out to `pip install --index-url https://...` (the audit's FP class).
# Malware DECODES or DOWNLOADS-AND-RUNS a payload, so we require that context:
# exec/eval of base64/marshal/zlib/fetched content, or a subprocess that PIPES a
# download to a shell (curl|wget ... | sh) -- NOT merely a URL in an argument.
_PY_SETUP_EXEC = re.compile(
    r"(?:exec|eval)\s*\(\s*(?:base64|bytes\.fromhex|codecs\.decode|marshal|zlib|"
    r"requests|urllib|urlopen|__import__\s*\(\s*['\"](?:urllib|requests))"
    r"|(?:os\.system|subprocess\.\w+)\s*\([^)]{0,200}?"
    r"(?:curl|wget)\b[^)]{0,80}?\|\s*(?:sh|bash)\b",
    re.IGNORECASE,
)
_MAX_BYTES = 1_000_000


# Python requirement lines: ``name==1.2.3`` / ``name>=1`` / bare ``name``. Group 2
# captures the raw version constraint (if any), not just the name.
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*([=<>!~;\[].*)?$")

# A declared specifier confirms a malicious-dependency match ONLY when it is an
# EXACT PIN of the compromised version. The 2026-07-02 audit caught the earlier
# _VERSION_STRIP approach stripping `^` off `^1.2.3` -> `1.2.3` and matching: a
# caret/tilde/`>=` RANGE floats to the latest PATCHED release, not the one
# historically-compromised version, so a range must NOT confirm (precision-first,
# PRD 5: miss a dependency match rather than flag every user of a popular package
# whose npm-default caret range has long since resolved past the bad release).
# Any range/wildcard/url/workspace marker => not an exact pin => no match.
_RANGE_MARKERS = ("^", "~", ">", "<", "*", "x", "||", " - ", "latest", "workspace:",
                  "file:", "link:", "git", "http", "npm:", " ")
_EXACT_PIN = re.compile(r"^=?=?\s*v?(\d[\w.\-+]*)$")


def _exact_pinned_version(spec: str | None) -> str:
    """The bare version IFF ``spec`` is an exact pin (1.2.3 / =1.2.3 / ==1.2.3),
    else "" for any range/wildcard/non-registry specifier."""
    s = (spec or "").strip()
    if not s:
        return ""
    low = s.lower()
    if any(m in low for m in _RANGE_MARKERS):
        return ""
    m = _EXACT_PIN.match(s)
    return m.group(1) if m else ""


def _declared_deps(name: str, text: str) -> dict[str, str]:
    """Dependency name -> its declared version specifier (npm package.json / pip
    reqs). An unpinned/absent specifier maps to ``""``."""
    deps: dict[str, str] = {}
    if name == "package.json":
        try:
            data = json.loads(text or "{}") or {}
        except ValueError:
            return deps
        for key in ("dependencies", "devDependencies", "optionalDependencies",
                    "peerDependencies"):
            section = data.get(key)
            if isinstance(section, dict):
                for dep, spec in section.items():
                    if isinstance(dep, str):
                        deps[dep] = spec if isinstance(spec, str) else ""
    else:  # requirements*.txt
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            m = _REQ_LINE.match(line)
            if m:
                deps[m.group(1)] = m.group(2) or ""
    return deps


def scan_manifests(root, malicious_packages=None) -> list[BashFinding]:
    """Flag malicious lifecycle hooks AND known-malicious DEPENDENCIES. Static.

    ``malicious_packages`` maps ecosystem ('npm'/'pypi') -> {name: frozenset of
    the EXACT version(s) OSM reported compromised}. A repo declaring one of those
    exact versions installs known malware on ``npm/pip install``; the delivery
    vector behind fake-interview / crypto-task lure repos, whose own code looks
    benign. Matching is ECOSYSTEM-SCOPED (package.json vs npm, requirements/pip vs
    pypi) so a legit npm package does not collide with a same-named typosquat on
    another registry, AND VERSION-SCOPED: many flagged names are legitimate,
    widely-used packages (PostHog, Mastra plugins) where an attacker compromised
    the maintainer account for ONE release (the Shai-Hulud worm); a name-only
    match confirmed mastra-ai/mastra, a 25k-star legitimate project, as malicious.
    Tier-A confirmation.
    """
    malicious_packages = malicious_packages or {}
    npm_bad = malicious_packages.get("npm", {})
    pypi_bad = malicious_packages.get("pypi", {})
    root = Path(root)
    findings: list[BashFinding] = []
    for path in root.rglob("*"):
        if not path.is_file() or is_ignored_path(path):
            continue
        name = path.name.lower()
        is_reqs = name.startswith("requirements") and name.endswith(".txt")
        if name not in ("package.json", "setup.py", "tasks.json") and not is_reqs:
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root)).replace("\\", "/")

        bad = npm_bad if name == "package.json" else (pypi_bad if is_reqs else {})
        if bad:
            manifest_kind = "package.json" if name == "package.json" else name
            for dep, spec in _declared_deps(manifest_kind, text).items():
                compromised = bad.get(dep.lower())
                if not compromised:
                    continue
                declared = _exact_pinned_version(spec)
                if declared and declared in compromised:
                    findings.append(BashFinding(
                        rel, 0, "malicious_dependency", "osm-listed",
                        f"{dep}@{declared} (OSM-compromised release)"[:120]))

        if name == "package.json":
            try:
                pkg = json.loads(text or "{}")
            except ValueError:
                continue
            scripts = pkg.get("scripts") if isinstance(pkg, dict) else None
            scripts = scripts if isinstance(scripts, dict) else {}
            for hook in _LIFECYCLE:
                cmd = scripts.get(hook)
                if (cmd and _SUSPICIOUS_CMD.search(str(cmd))
                        and not _only_reputable_install(str(cmd))
                        and not _is_benign_node_eval(str(cmd))):
                    findings.append(
                        BashFinding(rel, 0, "install_hook", f"npm-{hook}", str(cmd)[:200])
                    )
            # A VS Code tasks[] array can also be embedded in package.json (not
            # just .vscode/tasks.json); icecoldjay/bri hid its folder-open
            # auto-run there, so scan it the same way.
            findings.extend(_scan_vscode_tasks(text, rel))
        elif name == "setup.py":
            for match in _PY_SETUP_EXEC.finditer(text):
                line = text[: match.start()].count("\n") + 1
                findings.append(
                    BashFinding(rel, line, "install_hook", "py-setup-exec", match.group(0)[:120])
                )
        elif name == "tasks.json":
            # VS Code task that auto-runs on folder-open (the DPRK lure vector,
            # OSM-flagged on CoreX): opening the repo in VS Code silently executes
            # the command. Malicious when it carries a fetch-and-run / exec idiom.
            findings.extend(_scan_vscode_tasks(text, rel))
    return findings


def _task_command_blob(task: dict) -> str:
    """All command/arg text in a VS Code task, INCLUDING per-OS overrides.

    A task's command can live at the top level OR under ``osx`` / ``linux`` /
    ``windows`` blocks, which malware uses to ship a ``curl | sh`` for Unix and a
    ``curl | cmd`` for Windows in one task (icecoldjay/bri). Reading only the
    top-level ``command`` misses all of it, so collect every source.
    """
    parts: list[str] = []
    for src in (task, task.get("osx"), task.get("linux"), task.get("windows")):
        if not isinstance(src, dict):
            continue
        cmd = src.get("command")
        if isinstance(cmd, str):
            parts.append(cmd)
        elif isinstance(cmd, list):
            parts += [str(p) for p in cmd]
        parts += [str(a) for a in (src.get("args") or [])]
    return " ".join(parts)


def _scan_vscode_tasks(text: str, rel: str) -> list[BashFinding]:
    try:
        data = json.loads(text or "{}")
    except ValueError:
        return []
    # A tasks.json is normally an object; tolerate a top-level array / scalar / null
    # (a malformed or unusual file must not crash the whole scan -- it aborted a
    # full pipeline run on 2026-07-07).
    tasks = data.get("tasks") if isinstance(data, dict) else None
    tasks = tasks if isinstance(tasks, list) else []
    out: list[BashFinding] = []
    for task in tasks if isinstance(tasks, list) else []:
        if not isinstance(task, dict):
            continue
        run_on = ((task.get("runOptions") or {}).get("runOn") or "").lower()
        blob = _task_command_blob(task)
        # A folderOpen task that ONLY fetches from reputable registries (a venv+pip+
        # curl-maven-jar build bootstrap) is not a dropper; an attacker C2 fetch
        # (or a pure inline eval / reverse shell with no reputable host) still fires.
        if (run_on == "folderopen" and _SUSPICIOUS_CMD.search(blob)
                and not _only_reputable_install(blob)
                and not _is_benign_node_eval(blob)):
            out.append(BashFinding(rel, 0, "install_hook", "vscode-autorun", blob[:200]))
    return out
