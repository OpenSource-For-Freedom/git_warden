"""Static content scanner for JS/Python/etc. malware (the non-bash payloads).

Real malicious repos hide payloads in source: ``eval(atob(...))`` /
``Buffer.from(x,'base64')`` decode-and-run, ``child_process`` spawning, and
exfiltration to Discord/Telegram webhooks. The bash Layer-1 scanner targets
shell; this targets the supply-chain languages so true malicious repos actually
confirm. STATIC regex over file contents only; nothing is executed.

Findings reuse :class:`~git_warden.scanning.bash_scanner.BashFinding`.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path

from .bash_scanner import BashFinding, is_benign_construct, is_ignored_path

_JS_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
_PY_EXT = {".py"}
# Minecraft mods and server plugins (Forge/Fabric/Bukkit/Paper/Velocity) are JVM
# code, so session-token stealers, remote-jar loaders and plugin backdoors live in
# Java/Kotlin source that no other rule family reads.
_JVM_EXT = {".java", ".kt"}
_SOURCE_EXT = _JS_EXT | _PY_EXT | _JVM_EXT | {".rb", ".php", ".go", ".ps1"}
_MAX_BYTES = 1_000_000

# Each rule carries the language family it applies to so a Python pattern can't
# match a JavaScript file (the tiledesk FP fired ``py-dyn``; ``compile(``; on
# ``index.js``). "any" rules are language-agnostic (webhook URLs, key paths).
# Rules tuple: (rule_name, lang, pattern). lang in {"js", "py", "jvm", "any"}.
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
        # An in-memory class defined straight from a base64 literal/decoder is a
        # hidden stager: the bytecode never exists as a file a reviewer could read.
        # Mod/plugin loaders define classes from jar entries, never from base64.
        ("jvm-decode-defineclass", "jvm", re.compile(
            r"\bdefineClass\s*\([^\n]*(?:Base64|getDecoder|decodeBase64|parseBase64Binary)")),
    ],
    "code_execution": [
        ("node-child-process", "js",
         re.compile(r"require\(\s*['\"]child_process['\"]|child_process", re.I)),
        ("js-exec", "js", re.compile(r"\b(?:execSync|spawnSync|spawn|exec)\s*\(", re.I)),
        ("py-system", "py", re.compile(r"\bos\.system\(|subprocess\.(?:Popen|run|call)", re.I)),
        ("py-dyn", "py", re.compile(r"\b__import__\s*\(|\bcompile\s*\(|\bmarshal\.loads\(", re.I)),
        ("jvm-runtime-exec", "jvm",
         re.compile(r"Runtime\.getRuntime\(\)\s*\.\s*exec\s*\(|\bnew\s+ProcessBuilder\s*\(")),
    ],
    "download_exec": [
        # A mod/plugin that builds a class loader over a hard-coded remote URL runs
        # whatever jar that host serves (the fractureiser / Skyrage loader shape).
        # Library loaders do the same against Maven Central, so this is HOST-GATED in
        # Tier-2: it confirms only against an attacker host (public IP, paste site).
        ("jvm-remote-classload", "jvm",
         re.compile(r"\bnew\s+URLClassLoader\s*\([^\n]*https?://")),
    ],
    "network_exfil": [
        ("discord-webhook", "any", re.compile(r"discord(?:app)?\.com/api/webhooks/", re.I)),
        ("telegram-bot", "any", re.compile(r"api\.telegram\.org/bot", re.I)),
        ("paste-exfil", "any",
         re.compile(r"webhook\.site|requestcatcher\.com|pastebin\.com/api", re.I)),
    ],
    "credential_access": [
        # Requires the WHOLE process.env object (immediately closed by ``,``/``)``),
        # not a single named property: JSON.stringify(process.env) dumps every
        # secret in the environment, while JSON.stringify(process.env.NODE_ENV) is
        # webpack/bundler dead-code-elimination boilerplate present in nearly
        # every JS build (the mastra-ai/mastra FP, 2026-07-02) and carries no
        # secret at all.
        # word-boundaried \b...\b around post/send/requests (mem0ai/mem0 FP,
        # 2026-07-02): unbounded, this matched "POST" inside "POSTGRES_HOST" --
        # ordinary os.environ.get("POSTGRES_...") config code, not exfiltration.
        # Split by language: `process.env` is JS, `os.environ` is Python. The old
        # "any" rule matched Python PROSE inside a JS comment (a scanner describing
        # its own env-exfil rule -- the dnszlsk/muad-dib FP, 2026-07-07). Gating each
        # branch to its language stops the cross-language prose match.
        ("env-dump", "js", re.compile(r"JSON\.stringify\(\s*process\.env\s*[,)]", re.I)),
        ("env-dump", "py", re.compile(r"os\.environ\b.*\b(?:post|send|requests)\b", re.I)),
        # Actual secret-FILE access (private keys, cloud creds); a credential
        # theft signal. A bare ``.env`` reference is NOT here: every dotenv app
        # has one, and it manufactured the tiledesk false positives.
        ("keyfiles", "any", re.compile(r"\.ssh/id_|\.aws/credentials|\.config/gcloud", re.I)),
        # Minecraft session-token theft (the "ratter" stealers spread as cracked
        # clients, cheat mods and fake plugins). The access token logs in as the
        # victim's Microsoft/Mojang account. Covers the MCP/SRG name (func_148254_d
        # getToken, func_111286_b getSessionID), Yarn (getSession().getAccessToken())
        # and Mojang mappings (getUser().getAccessToken()). getAccessToken() is a
        # generic OAuth accessor, so that branch needs a Minecraft receiver
        # (Minecraft*.getX(), mc, minecraft, client) or a Spring/OAuth web app would
        # match. Account-switcher mods read the token too, so on its own this only
        # SCORES; it confirms in Tier-2 as steal-and-send, next to a webhook/bot
        # exfil channel in the same file.
        ("mc-session-token", "jvm", re.compile(
            r"\b(?:getSession|func_110432_I)\s*\(\s*\)\s*\.\s*"
            r"(?:getToken|getSessionID|func_148254_d|func_111286_b)\s*\("
            r"|(?:\bMinecraft\w*\s*\.\s*\w+\s*\(\s*\)|\bmc|\bminecraft|\bclient)\s*\.\s*"
            r"(?:getSession|getUser)\s*\(\s*\)\s*\.\s*getAccessToken\s*\(")),
        # Launcher account stores holding refresh/access tokens: the vanilla launcher,
        # Lunar, Feather and Essential. Language-agnostic because Python/JS stealers
        # sweep them as well. launcher_profiles.json is deliberately absent: every
        # Forge/Fabric installer legitimately writes it.
        ("mc-launcher-accounts", "any", re.compile(
            r"launcher_accounts(?:_microsoft_store)?\.json|"
            r"lunarclient[/\\]+settings[/\\]+game[/\\]+accounts\.json|"
            r"\.feather[/\\]+accounts\.json|essential[/\\]+microsoft_accounts\.json", re.I)),
    ],
}


# Decode-and-EXECUTE rules confirm a repo on their own, so we VERIFY the payload
# rather than trusting the syntax: decode the encoded literal and require concrete
# malicious indicators in the decoded content. A literal that decodes to benign
# text (e.g. eval(atob('aGVsbG8=')) -> "hello") is dropped; a dynamic loader
# (eval(atob(varName))) has no static payload but also no benign use, so it holds.
_DECODE_EXEC_RULES = {"eval-decoded", "py-decode-exec"}
# Capture EVERYTHING between the quotes: malware sprinkles junk (e.g. '-') into
# the blob to defeat naive base64 parsers, relying on Node's atob/Buffer to
# ignore it. We sanitize to standard base64 before decoding, mimicking that.
_ENCODED_LITERAL = re.compile(
    r"(?:atob|Buffer\.from|b64decode|base64\.b64decode)\s*\(\s*b?['\"]([^'\"]{16,})['\"]")
# A literal blob run through marshal/zlib/compile is a hidden COMPILED payload: it
# decodes to bytecode (no text indicators to match), and legitimate code never ships
# compiled bytecode hidden in a string constant. Confirm on the wrapper itself.
_COMPILED_WRAPPER = re.compile(r"marshal\.loads|zlib\.decompress|\bcompile\s*\(", re.I)
_NON_B64 = re.compile(r"[^A-Za-z0-9+/]")
_DECODED_INDICATORS: list[tuple[str, re.Pattern]] = [
    ("require/module hijack", re.compile(r"\brequire\b|\bmodule\b")),
    ("child_process/exec", re.compile(r"child_process|\bexec(?:Sync)?\s*\(|\bspawn", re.I)),
    ("env access", re.compile(r"process\.env|os\.environ", re.I)),
    ("network host", re.compile(r"https?://", re.I)),
    ("fetch/XHR", re.compile(r"\bfetch\s*\(|XMLHttpRequest|http\.request", re.I)),
    ("second-stage decode",
     re.compile(r"\beval\s*\(|\batob\s*\(|Function\s*\(|fromCharCode", re.I)),
    ("crypto/wallet theft", re.compile(r"wallet|mnemonic|private[_ ]?key|seed\s*phrase", re.I)),
]


def _verify_decode_exec(line: str) -> tuple[bool, str]:
    """Decide whether a decode-and-exec LINE is genuinely malicious.

    Returns (is_malicious, evidence_note). Decodes the encoded LITERAL argument
    and checks the decoded payload for malicious indicators; a dynamic loader
    (no static literal to decode) has no benign use and holds on its own.
    """
    m = _ENCODED_LITERAL.search(line)
    if not m:
        # No EMBEDDED literal blob: the decode target is a VARIABLE, f-string
        # placeholder, or expression (eval(base64_decode(VAR)); exec(b64decode(
        # '{encoded}'))). That is NOT malicious on its own -- it is how devops
        # scripts build a remote command (mycosoft-mas), how offensive tools
        # generate payloads (etherghost webshell manager), and how a scanner names
        # its own detection rules (dnszlsk/muad-dib). A real embedded stager
        # HARDCODES the encoded blob; the earlier "dynamic stager => confirm" rule
        # manufactured exactly these false positives (2026-07-07).
        return False, ""
    if _COMPILED_WRAPPER.search(line):
        return True, "embedded compiled/marshalled payload (hidden stager)"
    blob = _NON_B64.sub("", m.group(1))  # standard base64 only (drops junk + padding)
    try:
        decoded = base64.b64decode(blob + "=" * (-len(blob) % 4),
                                   validate=False).decode("utf-8", "ignore")
    except Exception:  # noqa: BLE001
        return False, ""  # cannot verify the payload -> do not confirm on this alone
    hits = [name for name, pat in _DECODED_INDICATORS if pat.search(decoded)]
    if hits:
        return True, "decoded payload -> " + ", ".join(hits[:4])
    return False, ""  # decodes to benign content -> not malware


def _lang_for(suffix: str) -> str:
    if suffix in _JS_EXT:
        return "js"
    if suffix in _PY_EXT:
        return "py"
    if suffix in _JVM_EXT:
        return "jvm"
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
                    if pattern.search(line) and not is_benign_construct(rule_name, line):
                        snippet = line.strip()[:200]
                        if rule_name in _DECODE_EXEC_RULES:
                            malicious, note = _verify_decode_exec(line)
                            if not malicious:
                                continue  # decodes to benign content -> not malware
                            snippet = f"{note} | {snippet}"[:200]
                        findings.append(BashFinding(rel, lineno, category, rule_name, snippet))
    return findings
