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
# Windows batch: PolinRider's propagation script (temp_auto_push.bat) is .bat.
_BAT_EXT = {".bat", ".cmd"}
_SOURCE_EXT = _JS_EXT | _PY_EXT | _JVM_EXT | _BAT_EXT | {".rb", ".php", ".go", ".ps1"}
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
        # Node spawning a fetch-to-shell: child_process.exec("curl http://x/a.sh |
        # bash") or the PowerShell "iwr ... | iex" equivalent. The bash scanner only
        # reads shell files, so this is how a malicious VS Code extension or npm
        # payload drops its second stage unseen. HOST-GATED in Tier-2 like
        # curl-pipe-shell: an installer from a reputable host never confirms.
        ("js-exec-fetch-shell", "js", re.compile(
            r"\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\([^\n]*"
            r"\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n]*"
            r"(?:\|\s*(?:ba|z|da)?sh\b|\|\s*iex\b|\|\s*powershell|\|\s*cmd\b"
            r"|Invoke-Expression)", re.I)),
    ],
    # PolinRider (DPRK; OSM, github.com/OpenSourceMalware/PolinRider): a shuffle-
    # cipher loader appended to JS config files. Each alternative is a fingerprint
    # with no legitimate use: the two variant markers, a variant global next to its
    # seed or decoder name (the OSM YARA rule's conditions, per line), the blockchain
    # dead-drop addresses its second stage reads, and its two XOR keys.
    "malware_signature": [
        ("polinrider-loader", "any", re.compile(
            r"rmcej%otb%|Cot%3t=shtP"
            r"|global\[['\"]!['\"]\][^\n]*(?:2857687|_\$_1e42)"
            r"|global\[['\"]_V['\"]\][^\n]*(?:1111436|\bMDy\b)"
            r"|global\[['\"]_V['\"]\]\s*=\s*['\"]8-(?:st)?\d+['\"]"
            r"|TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP|TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG"
            r"|0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e"
            r"|0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3"
            r"|2\[gWfGj;<:-93Z\^C|m6:tTh\^D\)cBz\?NM\]")),
        # GlassWorm / ForceMemo (Koi, Aikido, StepSecurity, Socket; IOC set from
        # afine-com/glassworm-hunter 2026-04-05): the invisible payload itself (a
        # long run of Unicode variation selectors, which no text needs more than
        # one of in a row), its decoder (codePointAt arithmetic on both selector
        # ranges feeding eval/Function), the Solana dead-drop wallets, the
        # ForceMemo Python marker variable, the loader AES key and the C2 IPs.
        ("invisible-unicode-payload", "any", re.compile(
            "[\ufe00-\ufe0f\U000e0100-\U000e01ef]{64,}")),
        ("glassworm-ioc", "any", re.compile(
            r"codePointAt[^\n]{0,300}0x(?:fe00|e0100)[^\n]{0,300}0x(?:fe00|e0100)"
            r"[^\n]{0,300}\b(?:eval|Function)\s*\("
            r"|\b(?:28PKnu7RzizxBzFPoLp69HLXp9bJL3JFtT2s5QzHsEA2"
            r"|BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC"
            r"|6YGcuyFRJKZtcaYCCFba9fScNUvPkGXodXE1mJiSzqDJ"
            r"|G2YxRa6wt1qePMwfJzdXZG62ej4qaTC7YURzuh2Lwd3t"
            r"|DSRUBTziADDHSik7WQvSMjvwCHFsbsThrbbjWMoJPUiW"
            r"|lzcdrtfxyqiplpd|wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz)\b"
            r"|(?<![\d.])(?:217\.69\.3\.218|199\.247\.10\.166|217\.69\.13\.229"
            r"|45\.76\.45\.151|45\.32\.151\.157|107\.191\.62\.170|140\.82\.52\.31"
            r"|199\.247\.13\.106|104\.238\.191\.54|108\.61\.208\.161|45\.32\.150\.251"
            r"|217\.69\.11\.60|70\.34\.242\.255|217\.69\.3\.152|45\.32\.150\.97"
            r"|217\.69\.11\.57|217\.69\.11\.99|217\.69\.0\.159|45\.76\.44\.240"
            r"|45\.150\.34\.158)(?![\d.])", re.I)),
        # Shai-Hulud (Sep 2025), Sha1-Hulud 2.0 (Nov 2025) and TeamPCP's Mini
        # Shai-Hulud (Apr-May 2026; copyleftdev/mini-shai-hulud-dragnet, IC3
        # FLASH-20260702-01): the worm's own banner strings, its exfil webhook,
        # rogue-runner name, payload file names inside a package hook, its C2
        # domains and IPs, and its scramble salt.
        ("shai-hulud-ioc", "any", re.compile(
            r"Sha1-Hulud: The Second Coming|A Mini Shai-Hulud has Appeared"
            r"|LongLiveTheResistanceAgainstMachines|Exiting as russian language detected!"
            r"|webhook\.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7|\bSHA1HULUD\b"
            r"|shai-hulud-workflow\.yml|\bctf-scramble-v2\b"
            r"|\b(?:audit\.checkmarx\.cx|api\.masscan\.cloud|git-tanstack\.com)\b"
            r"|(?<![\d.])(?:94\.154\.172\.43|83\.142\.209\.11|83\.142\.209\.194"
            r"|45\.148\.10\.212)(?![\d.])"
            r"|\bnode\s+(?:setup_bun|bun_environment)\.js\b")),
    ],
    # PolinRider's propagation script: rewinds the Windows clock to the last
    # commit's time, amends the commit with --no-verify and force-pushes, so the
    # injected payload looks like it was always there. Setting the system date to
    # a variable holding the last commit date has no legitimate use, and the file
    # proves past compromise even after the payload was cleaned up.
    "propagation": [
        ("git-history-forgery", "bat", re.compile(
            r"^\s*date\s+%LAST_COMMIT_DATE%|^\s*time\s+%LAST_COMMIT_TIME%", re.I)),
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
        # Crypto wallet theft: the on-disk stores of desktop wallets and the
        # browser-extension IDs of wallet add-ons (MetaMask, Phantom, Coinbase,
        # Binance, TronLink), whose local storage holds the encrypted vault.
        # Stealers sweep these lists; a wallet app names its own store, not a
        # list of rivals'. Like the Minecraft rules it only SCORES alone and
        # confirms in Tier-2 as steal-and-send, next to an exfil channel in the
        # same file. wallet.dat is deliberately absent: Bitcoin Core forks name it.
        ("wallet-theft", "any", re.compile(
            r"exodus[/\\]+exodus\.wallet|electrum[/\\]+wallets|"
            r"atomic[/\\]+Local Storage|ethereum[/\\]+keystore|coinomi[/\\]+wallets|"
            r"com\.liberty\.jaxx|nkbihfbeogaeaoehlefnkodbefgpgknn|"
            r"bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|"
            r"fhbohimaelbohpjbbldcngcnapndodjp|ibnejdfjmmkpcnlpebklmnkoeoihofec", re.I)),
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
    if suffix in _BAT_EXT:
        return "bat"
    return "other"


def _is_minified(name: str) -> bool:
    """Minified/bundled files are generated artifacts and trip hex/blob rules."""
    return name.endswith((".min.js", ".min.mjs", ".min.cjs")) or ".bundle." in name


# Minecraft anti-rat scanners and triage tools match the same token reads and
# launcher account paths they look for, next to webhook patterns, so steal-and-
# send would confirm them (moleclient/antirat JarScanner.java, cev-api/java-triage
# behaviors.py, 2026-10-02). Inside detector code these two rules are detection
# data. Scoped to the Minecraft rules only: renaming a stealer to Scanner.java
# only drops the Minecraft credential evidence, never the webhook or loader rules.
_MC_RULES = {"mc-session-token", "mc-launcher-accounts"}
# Rules that are detection DATA inside detector code (the wallet-store list is
# exactly what an anti-stealer scanner looks for, too).
_DETECTOR_DATA_RULES = _MC_RULES | {"wallet-theft", "polinrider-loader", "glassworm-ioc",
                                    "shai-hulud-ioc", "invisible-unicode-payload"}
_DETECTOR_DIRS = {"scan", "scanner", "scanners", "scanning", "detect", "detection", "detector",
                  "detectors", "triage", "analysis", "analyzer", "analyzers",
                  "heuristics", "antirat", "anti-rat", "antimalware", "antivirus"}
_DETECTOR_STEM = re.compile(
    r"scanner|scan$|detector|detection|detect$|triage|heuristic|behaviou?rs?$|"
    r"analy[sz]er|anti-?rat", re.I)


# A repository whose own name says it is a detector (baum1810/grabber-detector,
# moleclient/antirat, 2026-10-03): its whole tree is detection code, so the
# Minecraft credential rules are detection data anywhere in it.
_DETECTOR_REPO = re.compile(
    r"detect|scanner|anti-?rat|anti-?grabber|anti-?stealer|antimalware|antivirus|"
    r"triage|analy[sz]er|rat-?remover|grabber-?remover", re.I)


def _is_detector_path(rel: str) -> bool:
    parts = rel.lower().split("/")
    if _DETECTOR_DIRS & set(parts[:-1]):
        return True
    # Test fixtures that replay attacks (src/runtimeFixture/..., fixtures/).
    if any("fixture" in p for p in parts[:-1]):
        return True
    return bool(_DETECTOR_STEM.search(parts[-1].rsplit(".", 1)[0]))


def is_detector_repo(full_name: str | None) -> bool:
    """True if the repository's own name marks it as a detection tool."""
    return bool(full_name) and bool(_DETECTOR_REPO.search(full_name.split("/")[-1]))


# A web font starts with its format's magic bytes. PolinRider hid its loader in a
# fake .woff2 (public/fonts/fa-solid-400.woff2) that Node runs as JavaScript, so a
# "font" that is really script text is a payload, not an asset.
_FONT_EXT = {".woff", ".woff2", ".ttf", ".otf", ".eot"}
_FONT_MAGIC = (b"wOFF", b"wOF2", b"\x00\x01\x00\x00", b"OTTO", b"true", b"ttcf")
_SCRIPT_IN_FONT = re.compile(
    r"\brequire\s*\(|\bglobal\s*\[|\bmodule\.exports\b|\beval\s*\(|\bFunction\s*\(")


def _fake_font_finding(path: Path, rel: str) -> BashFinding | None:
    try:
        if path.stat().st_size > _MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if data[:4] in _FONT_MAGIC or (path.suffix.lower() == ".eot" and data[34:36] == b"LP"):
        return None
    text = data.decode("utf-8", errors="ignore")
    if text.lstrip().startswith("<"):
        return None  # an HTML error page or SVG saved under a font name, not a loader
    m = _SCRIPT_IN_FONT.search(text)
    if not m:
        return None
    line = text[: m.start()].count("\n") + 1
    snippet = text[max(0, m.start() - 40): m.start() + 120].replace("\n", " ").strip()
    return BashFinding(rel, line, "malware_signature", "fake-font-payload",
                       f"not a font: script text in a font file | {snippet}"[:200])


_CI_EXT = {".yml", ".yaml"}


def _scan_signatures_only(path: Path, root: Path, repo_name: str | None) -> list[BashFinding]:
    """Known-malware fingerprints in a CI workflow (Shai-Hulud plants its own)."""
    rel = str(path.relative_to(root)).replace("\\", "/")
    if is_detector_repo(repo_name) or _is_detector_path(rel):
        return []
    try:
        if path.stat().st_size > _MAX_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for rule_name, _lang, pattern in _RULES["malware_signature"]:
            if pattern.search(line):
                out.append(BashFinding(rel, lineno, "malware_signature", rule_name,
                                       line.strip()[:200]))
    return out


def scan_content(root, repo_name: str | None = None) -> list[BashFinding]:
    """Scan first-party source files for obfuscation / exec / exfil. Static only."""
    root = Path(root)
    findings: list[BashFinding] = []
    detector_repo = is_detector_repo(repo_name)
    for path in root.rglob("*"):
        if not path.is_file() or is_ignored_path(path):
            continue
        suffix = path.suffix.lower()
        if suffix in _FONT_EXT:
            rel = str(path.relative_to(root)).replace("\\", "/")
            fake = _fake_font_finding(path, rel)
            if fake:
                findings.append(fake)
            continue
        if suffix in _CI_EXT:
            if ".github" in path.parts or "workflows" in path.parts:
                findings.extend(_scan_signatures_only(path, root, repo_name))
            continue
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
        detector = detector_repo or _is_detector_path(rel)
        for lineno, line in enumerate(text.splitlines(), 1):
            for category, rules in _RULES.items():
                for rule_name, rule_lang, pattern in rules:
                    if rule_lang != "any" and rule_lang != lang:
                        continue
                    if detector and rule_name in _DETECTOR_DATA_RULES:
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
