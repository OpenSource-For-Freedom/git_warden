"""Report confirmed true positives back to OpenSourceMalware.

The WRITE side of the OSM integration. Safe to ship: it is dry-run by default,
uses YOUR own OSM API key (``GW_OSM_API_KEY``) and contributor identity
(``GW_OSM_CONTRIBUTOR``), checks OSM before every submission so it never
duplicates an existing report, and keeps a human in the loop. Self-contained --
it does its own HTTP and DB access.

Run it directly (or via ``make submit``):

    python -m git_warden.osm_submit               # dry run, prints the reports
    python -m git_warden.osm_submit --wizard       # interactive step-by-step
    python -m git_warden.osm_submit --reconcile    # our reports vs OSM (read-only)
    python -m git_warden.osm_submit --confirm      # actually POST to OSM

Reads use ``check-malicious``; writes POST to the live function
``submit-threat-report``. The public docs name the write endpoint
``submit-threat``, but that 404s in production (joint hunt, 2026-09-28: every
POST to ``/functions/v1/submit-threat`` returned 404). Only NOVEL confirmed findings are eligible
(:func:`gold_for_submission`): intrinsic-evidence finds OSM does not already
have. Each report carries its proof -- the detection method and the confirming
file:line + rule -- so reviewers can verify. Operator notes (cleanup, run-
specific ids) live in the gitignored ``osm_reports.md``, not here.
"""

from __future__ import annotations

import json
import os
import re

from .actors import attribute as attribute_actor
from .config import HTTP_TIMEOUT, OSM_API_KEY, osm_endpoint
from .containers import CONTAINER_TAGS, is_container_threat

# The contributor credited on every threat report you submit. Set GW_OSM_CONTRIBUTOR
# to YOUR OSM username/org so reports are attributed to you (blank = omit the field).
OSM_CONTRIBUTOR = os.environ.get("GW_OSM_CONTRIBUTOR", "")
# Optional contact email attached to OSM threat submissions (for follow-up).
OSM_CONTACT_EMAIL = os.environ.get("GW_OSM_CONTACT_EMAIL")
_RUN_TS = re.compile(r"(\d{8})T(\d{6})Z")


def _run_to_iso(run_id: str | None) -> str | None:
    """Turn a run id like ``hunt-20260620T131622Z`` into ``2026-06-20T13:16:22Z``."""
    m = _RUN_TS.search(run_id or "")
    if not m:
        return None
    d, t = m.group(1), m.group(2)
    return f"{d[0:4]}-{d[4:6]}-{d[6:8]}T{t[0:2]}:{t[2:4]}:{t[4:6]}Z"

# Severity from the WORST confirming signal, not the aggregate score: one reverse
# shell is critical even at a low score, while a pile of weak signals is not. This
# drives both OSM's severity_level and the submit queue's most-severe-first order.
# Tunable -- bump a category here to re-rank everything.
_CATEGORY_SEVERITY = {
    # critical: direct RCE / supply-chain delivery / immediate theft
    "reverse_shell": 4, "install_hook": 4, "download_exec": 4,
    "malicious_dependency": 4, "exfiltration": 4, "credential_harvest": 4,
    # high: loaders / injection / cred access / exfil channels / code exec
    "obfuscation": 3, "process_injection": 3, "credential_access": 3,
    "network_exfil": 3, "code_execution": 3,
    # a known malware family's own fingerprint (PolinRider loader, fake font)
    "malware_signature": 4,
    # PolinRider's commit-forging propagation script (payload may be cleaned up)
    "propagation": 3,
    # medium: persistence / lateral movement
    "persistence": 2, "lateral_movement": 2,
    # low: recon
    "enumeration": 1, "network_scan": 1,
}
_SEVERITY_LEVEL = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "low"}


def severity_rank(row) -> int:
    """0-4 danger rank = the worst detected category. Use to sort most-severe-first."""
    payload = json.loads(row["raw_payload"] or "{}") or {}
    bash = payload.get("bash_findings") or []
    return max((_CATEGORY_SEVERITY.get(b.get("category", ""), 0) for b in bash), default=0)


def severity_level(row) -> str:
    """OSM severity_level for a finding, from its worst signal."""
    return _SEVERITY_LEVEL[severity_rank(row)]


# Plain-language explanation of what each detected category actually does, so the
# report reads as a human writeup instead of a rule dump. Full sentences, no
# arrows and no dashes.
# Some rules inside a shared category trigger in completely different ways, so the
# category sentence alone would misdescribe them. A VS Code folderOpen task is an
# install_hook to the scanner, but nothing is installed and the generic wording
# ("installing the project is enough") would tell an OSM reviewer the wrong thing.
# A rule listed here overrides its category text.
_BEHAVIOR_BY_RULE = {
    "vscode-autorun": (
        "The code runs automatically from a Visual Studio Code task configured to "
        "trigger on folderOpen. Nothing has to be installed, built, or clicked. "
        "Opening the project folder in the editor is enough to run the attacker's "
        "command. The task fetches a remote script and pipes it straight into a "
        "shell, with a separate payload selected for macOS, Linux and Windows. It "
        "also carries a presentation block that sets reveal to never and echo to "
        "false and closes the panel afterwards, which hides the terminal so the "
        "victim never sees the command run. Suppressing output next to a fetch and "
        "pipe has no legitimate use and shows the intent is concealment."
    ),
    "mc-session-token": (
        "The code reads the Minecraft session access token from the running game "
        "client. That token logs in as the victim's Microsoft or Mojang account "
        "without a password. Stealer mods, cheat clients and fake plugins grab it "
        "and post it to a webhook or bot the attacker controls, which hands over "
        "the account."
    ),
    "mc-launcher-accounts": (
        "The code reads the saved account store of a Minecraft launcher (the "
        "vanilla launcher, Lunar Client, Feather Client or the Essential mod). "
        "Those files hold refresh and access tokens for the victim's Microsoft "
        "account, so copying them lets the attacker sign in as the victim."
    ),
}

_BEHAVIOR = {
    "obfuscation": (
        "The file hides part of its logic in a base64-encoded blob that the program "
        "decodes and executes at load time. This is deliberate obfuscation. It keeps the "
        "real behavior out of sight during a quick code review and past simple scanners. "
        "A legitimate project file has no reason to decode and run content this way."
    ),
    "reverse_shell": (
        "The code opens a reverse shell. The host that runs it dials back out to a server "
        "the attacker controls and hands over an interactive command prompt, giving the "
        "attacker direct, hands-on control of the machine."
    ),
    "install_hook": (
        "The code runs automatically from a package install hook, so installing the "
        "project is enough to execute the attacker's payload with no further action from "
        "the victim. This is the classic supply-chain delivery method."
    ),
    "download_exec": (
        "The code fetches a further script or binary from a remote location and runs it, "
        "pulling additional attacker-controlled code onto the machine after the first "
        "stage lands."
    ),
    "exfiltration": (
        "The code reads sensitive data from the machine and sends it to a remote endpoint "
        "the attacker controls."
    ),
    "credential_harvest": (
        "The code collects credentials such as SSH keys, cloud provider secrets, and "
        "saved tokens. These are the primary target of this kind of campaign."
    ),
    "credential_access": (
        "The code reaches into credential files such as private keys and cloud "
        "configuration to steal authentication material."
    ),
    "malicious_dependency": (
        "The project declares a dependency that is already catalogued as malware, so "
        "installing it pulls in known malicious code automatically."
    ),
    "process_injection": (
        "The code injects itself into another running process so it executes with more "
        "trust and is harder to spot."
    ),
    "network_exfil": (
        "The code sends collected data out through an external channel such as a chat "
        "webhook or bot that serves as a drop point for stolen information."
    ),
    "code_execution": (
        "The code assembles or fetches instructions at runtime and executes them, keeping "
        "its real behavior out of the plain source."
    ),
    "persistence": (
        "The code establishes persistence so the attacker's payload keeps running after "
        "the machine restarts."
    ),
}


# One line per detection rule for the report's payload bullets: what the code
# does and why that is malicious, short enough to scan. The long _BEHAVIOR text
# above stays for the extension reports.
_WHY_BY_RULE = {
    "vscode-autorun": "VS Code task with runOn: folderOpen; runs the moment the folder "
                      "is opened, no install or click needed",
    "mc-session-token": "reads the Minecraft session access token, which logs in as the "
                        "victim without a password",
    "mc-launcher-accounts": "reads Minecraft launcher account stores (Microsoft refresh "
                            "and access tokens)",
    "discord-webhook": "hardcoded Discord webhook, the drop point for stolen data",
    "telegram-bot": "hardcoded Telegram bot API, the drop point for stolen data",
    "paste-exfil": "posts data to a paste or request-capture service",
    "secret-exfil": "uploads a secret file (SSH key, cloud credentials, .env) with curl",
    "curl-post-data": "posts collected data to a remote host",
    "archive-then-send": "archives local files and sends them to a remote host",
    "curl-pipe-shell": "downloads a remote script and pipes it straight into a shell",
    "fetch-then-exec": "downloads a file and runs it",
    "js-exec-fetch-shell": "Node child_process runs a download piped into a shell",
    "jvm-remote-classload": "loads Java classes from a remote jar at runtime",
    "remote-exec": "runs a command fetched from a remote host",
    "eval-decoded": "decodes a hidden blob and executes it at load time (obfuscated loader)",
    "eval-base64": "decodes a base64 blob and executes it",
    "base64-decode-exec": "decodes a base64 blob and executes it",
    "py-decode-exec": "decodes a hidden blob and executes it with exec()",
    "fromcharcode-blob": "rebuilds code from character codes to hide it, then runs it",
    "jvm-decode-defineclass": "decodes a hidden Java class and defines it at runtime",
    "wallet-theft": "reads crypto wallet stores or wallet-extension vaults "
                    "(Exodus, Electrum, MetaMask and others)",
    "polinrider-loader": "PolinRider shuffle-cipher loader (OSM-documented DPRK "
                         "marker, dead-drop address or XOR key)",
    "fake-font-payload": "script code disguised as a font file and run with Node",
    "git-history-forgery": "PolinRider propagation script: rewinds the clock, amends "
                           "the last commit with --no-verify and force-pushes to hide "
                           "the injection",
    "campaign-package": "depends on an npm package published by the PolinRider operator",
    "keyfiles": "reads SSH private keys or cloud credential files",
    "ssh-keys": "reads SSH private keys",
    "cloud-creds": "reads cloud provider credentials",
    "env-dump": "serializes the whole environment (every secret in it)",
    "env-token-grab": "collects tokens from environment variables",
    "shadow-read": "reads /etc/shadow password hashes",
    "nc-exec": "netcat hands a shell to a remote host (reverse shell)",
    "bash-i-socket": "interactive bash bound to a network socket (reverse shell)",
    "mkfifo-shell": "named-pipe shell relayed over the network (reverse shell)",
    "python-reverse": "Python socket connects out and hands over a shell",
    "dev-tcp-redirect": "shell redirected over /dev/tcp to a remote host",
    "py-system": "runs shell commands through os.system",
    "cron": "installs a cron job so the payload survives a reboot",
    "systemd": "installs a systemd service so the payload survives a reboot",
    "rc-files": "edits shell startup files so the payload runs on every login",
    "rc-local": "edits rc.local so the payload runs at boot",
    "authorized-keys": "adds an attacker SSH key to authorized_keys",
    "ld-preload": "injects a library into every process through LD_PRELOAD",
}
_WHY_BY_CATEGORY = {
    "obfuscation": "hides code in an encoded blob that is decoded and run",
    "reverse_shell": "opens a reverse shell to an attacker host",
    "install_hook": "runs automatically from a package install hook",
    "download_exec": "downloads further code and runs it",
    "exfiltration": "sends local data to a remote endpoint",
    "network_exfil": "sends collected data out through an external channel",
    "credential_harvest": "collects credentials (SSH keys, cloud secrets, tokens)",
    "credential_access": "reads credential files",
    "malicious_dependency": "depends on a package already catalogued as malware",
    "process_injection": "injects code into another process",
    "code_execution": "builds or fetches code at runtime and executes it",
    "persistence": "sets up persistence across reboots",
}
_EXFIL_CHANNEL = {"discord-webhook": "a Discord webhook", "telegram-bot": "a Telegram bot",
                  "paste-exfil": "a paste service"}
_CRED_CATS = {"credential_access", "credential_harvest"}
_EXFIL_CATS = {"network_exfil", "exfiltration"}
_MC_RULES = {"mc-session-token", "mc-launcher-accounts"}
_WALLET_RE = re.compile(r"wallet|metamask|exodus|electrum|phantom|mnemonic|seed\s*phrase",
                        re.I)


def _loc(b: dict) -> str:
    return f"{b.get('file')}:{b['line']}" if b.get("line") else str(b.get("file") or "")


def _confirming(payload: dict) -> list[dict]:
    """The findings that confirmed the repo, without the incidental hits after them.

    Confirming findings are stored first. Newer findings record how many; for
    older ones, keep the hits in the top finding's file or from its rule (a
    steal-and-send pair always shares a file; a planted dropper shares a rule).
    """
    bash = payload.get("bash_findings") or []
    if not bash:
        return []
    n = payload.get("confirming_count")
    if isinstance(n, int) and n > 0:
        return bash[:n]
    top = bash[0]
    return [b for b in bash
            if b.get("file") == top.get("file") or b.get("rule") == top.get("rule")]


def _prose_hosts(bash: list[dict]) -> list[str]:
    """Attacker hosts worth naming in prose: no shared services (discord.com is the
    exfil channel, named on its own) and no snippet-truncated host names."""
    hosts = [h for h in _c2_hosts(bash) if not _is_shared_service(h)]
    return [h for h in hosts if not any(o != h and o.startswith(h) for o in hosts)]


def _threat_class(bash: list[dict]) -> str:
    """One phrase naming what the malware is, from every rule that fired."""
    rules = {b.get("rule") for b in bash}
    cats = {b.get("category") for b in bash}
    wallets = "wallet-theft" in rules or any(
        _WALLET_RE.search(b.get("snippet") or "") for b in bash)
    if "polinrider-loader" in rules or "fake-font-payload" in rules:
        kind = "PolinRider loader (DPRK backdoor/infostealer)"
    elif "vscode-autorun" in rules:
        kind = "VS Code autorun dropper"
    elif "git-history-forgery" in rules:
        kind = "PolinRider-compromised repository (commit-forging propagation script)"
    elif "campaign-package" in rules:
        kind = "Malicious npm dependency (PolinRider)"
    elif cats & _CRED_CATS and cats & _EXFIL_CATS:
        kind = "Infostealer and cryptostealer" if wallets else "Infostealer"
        if rules & _MC_RULES:
            kind += " targeting Minecraft accounts"
        return kind
    elif rules & _MC_RULES:
        kind = "Minecraft account stealer"
    elif "reverse_shell" in cats:
        kind = "Reverse shell backdoor"
    elif "install_hook" in cats:
        kind = "Install-hook dropper"
    elif "download_exec" in cats:
        kind = "Dropper"
    elif "obfuscation" in cats:
        kind = "Obfuscated loader"
    elif "malicious_dependency" in cats:
        kind = "Malicious dependency"
    else:
        kind = "Malware"
    if wallets:
        kind += " with crypto wallet theft"
    return kind


def _exfil_phrase(bash: list[dict]) -> str:
    """'exfiltrating to a Discord webhook (a2.py:27)', or ''."""
    for b in bash:
        channel = _EXFIL_CHANNEL.get(b.get("rule", ""))
        if channel:
            return f"exfiltrating to {channel} ({_loc(b)})"
    return ""


def _payload_bullets(bash: list[dict], cap: int = 8) -> list[str]:
    """One bullet per detection rule: first location, what it does, how many more."""
    order: list[str] = []
    hits: dict[str, list[dict]] = {}
    for b in bash:
        key = b.get("rule") or b.get("category") or "other"
        if key not in hits:
            order.append(key)
            hits[key] = []
        if not any(_loc(h) == _loc(b) for h in hits[key]):
            hits[key].append(b)
    lines = []
    for key in order[:cap]:
        first = hits[key][0]
        why = (_WHY_BY_RULE.get(first.get("rule", ""))
               or _WHY_BY_CATEGORY.get(first.get("category", ""), "matches malware behavior"))
        if first.get("rule") == "vscode-autorun" and re.search(
                r"reveal[^\n]{0,20}never|\"echo\"\s*:\s*false", first.get("snippet") or "", re.I):
            why += "; terminal hidden (reveal: never)"
        more = len(hits[key]) - 1
        lines.append(f"- {_loc(first)}: {why}" + (f" (+{more} more)" if more > 0 else ""))
    if len(order) > cap:
        lines.append(f"- plus {len(order) - cap} more detection rules")
    return lines


# --- campaign context (attack vector + attacker C2), derived from the evidence ---
_HOST_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)")
_NOT_C2 = ("github.com", "githubusercontent.com", "nodesource.com", "npmjs.org",
           "npmjs.com", "pypi.org", "nodejs.org", "rustup.rs", "docker.com",
           "python.org", "microsoft.com", "google.com", "jsdelivr.net", "unpkg.com")


def _c2_hosts(bash: list[dict]) -> list[str]:
    """Attacker C2/payload hosts from the confirming fetch/exfil evidence."""
    hosts: list[str] = []
    for b in bash:
        if b.get("rule") != "vscode-autorun" and b.get("category") not in (
                "download_exec", "network_exfil", "exfiltration"):
            continue
        for h in _HOST_RE.findall(b.get("snippet") or ""):
            host = h.rstrip(".").lower()
            if (host in hosts or not re.search(r"\.[a-z]{2,}$", host)
                    or any(host == n or host.endswith("." + n) for n in _NOT_C2)):
                continue
            hosts.append(host)
    return [h for h in hosts if not any(o != h and o.startswith(h + ".") for o in hosts)]


_URL_IOC_RE = re.compile(r"https?://[^\s'\"|)>]+", re.I)


def _verified_iocs(row) -> str:
    """Curated, machine-verifiable IOCs for the report's ``verified_iocs`` field --
    the attacker C2 host(s), the exact payload URL(s), the dropper command, and the
    dropper file path, one per line, so OSM indexes them as pivotable indicators
    rather than leaving them buried in prose."""
    payload = json.loads(row["raw_payload"] or "{}")
    bash = payload.get("bash_findings") or []
    lines: list[str] = []
    seen: set[str] = set()

    def add(x: str) -> None:
        x = (x or "").strip()
        if x and x.lower() not in seen:
            seen.add(x.lower())
            lines.append(x)

    for h in _c2_hosts(bash):
        add(h)                                    # C2 / payload host
    for b in bash:
        sn = b.get("snippet") or ""
        for u in _URL_IOC_RE.findall(sn):
            add(u.rstrip("|").strip())            # exact payload URL
        m = re.search(r"(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh)\b", sn, re.I)
        if m:
            add(m.group(0).strip())               # download-and-run command
    if bash and bash[0].get("file"):
        add(bash[0]["file"])                      # dropper file path
    # Drop truncation artifacts: a line that is a strict prefix of a longer one
    # (a snippet cut mid-URL leaves e.g. 'https://host.vercel.' before the full URL).
    return "\n".join(x for x in lines
                     if not any(y != x and y.startswith(x) for y in lines))


def _vectors(bash: list[dict]) -> list[str]:
    """Delivery-vector tags derived from the confirming rules."""
    rules = {b.get("rule") for b in bash}
    v = []
    if "vscode-autorun" in rules:
        v.append("vscode-folderopen-autorun")
    if {"eval-decoded", "base64-decode-exec", "py-decode-exec"} & rules:
        v.append("obfuscated-eval-atob-loader")
    if any((r or "").startswith("npm-") for r in rules):
        v.append("npm-install-hook")
    if "py-setup-exec" in rules:
        v.append("setup-py-fetch-and-run")
    if {"mc-session-token", "mc-launcher-accounts"} & rules:
        v.append("minecraft-account-stealer")
    if "polinrider-loader" in rules:
        v.append("polinrider-config-injection")
    if "git-history-forgery" in rules:
        v.append("polinrider-commit-forgery")
    if "fake-font-payload" in rules:
        v.append("fake-font-loader")
    if "campaign-package" in rules:
        v.append("polinrider-npm-package")
    return v


# The two vectors above are the signature tradecraft of the DPRK-attributed
# "Contagious Interview" campaign (fake-recruiter coding-task lures).
_CAMPAIGN_VECTORS = {"vscode-folderopen-autorun", "obfuscated-eval-atob-loader"}


def _campaign_sentence(vectors: list[str], c2: list[str]) -> str:
    """One line naming the matching campaign tradecraft, or "" when none matches."""
    polinrider = {"polinrider-config-injection", "polinrider-commit-forgery",
                  "polinrider-npm-package"}
    if polinrider & set(vectors):
        s = ("PolinRider (DPRK; Lazarus, Contagious Interview cluster), as documented "
             "by OpenSourceMalware.")
    elif "vscode-folderopen-autorun" in vectors:
        s = ("Matches PolinRider / Contagious Interview (DPRK): fake-recruiter coding "
             "tasks that run a downloader when opened in VS Code.")
    elif "obfuscated-eval-atob-loader" in vectors:
        s = ("The eval(atob(...)) loader hidden in a project file is Contagious Interview "
             "(DPRK-attributed) tradecraft.")
    else:
        return ""
    if c2:
        s += f" Payload host: {', '.join(c2)}."
    return s


_MAX_LISTED_HOSTS = 5


def campaign_context(db, row, index: dict | None = None) -> str:
    """One or two lines tying this repo to its Git Warden campaign.

    Uses the same fingerprints as the run summary and dashboard (``correlate``):
    a shared payload loader stub, or a dropper URL shape with host, OS segment
    and parameter values removed. Gives the campaign id, how many repos and
    accounts share it, the fingerprint and a few payload hosts. The member list
    stays in Git Warden's evidence store; listing it here buried the payload.
    "" when the repo is in no campaign.
    """
    from .correlate import campaign_index

    camp = (index if index is not None else campaign_index(db)).get(row["full_name"])
    if camp is None:
        return ""
    if not [m for m in camp.members if m != row["full_name"]]:
        return ""
    hosts = sorted(h for h in camp.c2_hosts if _reportable_domain(h))
    if camp.kind == "payload":
        shape = f"loader stub {camp.fingerprint}"
    else:
        shape = f"dropper URL shape {camp.fingerprint.split(':', 1)[-1]}"
    text = (f"Campaign {camp.id}: one of {len(camp.members)} confirmed repos across "
            f"{len(camp.owners)} accounts sharing the {shape}.")
    if hosts:
        shown = hosts[:_MAX_LISTED_HOSTS]
        text += (f" Payload served from {len(hosts)} distinct hosts, including "
                 f"{', '.join(shown)}.")
    return text


def _matched_signatures(row) -> list[str]:
    """The code-search signatures that surfaced this repo (provenance)."""
    try:
        raw = row["matched_iocs"]
    except (KeyError, IndexError):
        return []
    try:
        terms = json.loads(raw) if isinstance(raw, str) else list(raw or [])
    except ValueError:
        return []
    return [str(t) for t in terms if t][:5]


def _rule_summary(bash: list[dict]) -> str:
    """Every detection rule that fired, with how many files it fired in."""
    files: dict[str, set] = {}
    for b in bash:
        if b.get("rule"):
            key = f"{b.get('category') or 'other'}/{b['rule']}"
            files.setdefault(key, set()).add(b.get("file") or "")
    parts = [f"{k} ({len(v)} file{'s' if len(v) != 1 else ''})"
             for k, v in sorted(files.items(), key=lambda kv: (-len(kv[1]), kv[0]))]
    return ", ".join(parts)


def _threat_description(row, assessment=None, campaign_ctx: str = "") -> str:
    """A few short lines: what the malware is, where, how it runs, who is behind it."""
    payload = json.loads(row["raw_payload"] or "{}") or {}
    bash = _confirming(payload)
    top = bash[0] if bash else {}
    files = list(dict.fromkeys(b.get("file") for b in bash if b.get("file")))

    head = _threat_class(bash)
    exfil = _exfil_phrase(bash)
    if exfil:
        head += f", {exfil}"
    if files:
        head += f". Payload in {', '.join(files[:3])}" + (
            f" and {len(files) - 3} more files" if len(files) > 3 else "")
    lines = [head + "."]

    if top.get("rule") == "vscode-autorun":
        lines.append("Runs automatically when the folder is opened in VS Code "
                     "(hidden folderOpen task that fetches and runs a remote script).")
    snippet = top.get("snippet") or ""
    if "second-stage decode" in snippet:
        lines.append("The decoded blob rewrites the Node module loader and unpacks a "
                     "further hidden stage: a working multi-stage loader, not data.")
    same_rule = {b.get("file") for b in bash
                 if b.get("rule") == top.get("rule") and b.get("file")}
    if len(same_rule) > 1:
        lines.append(f"The same dropper is planted in {len(same_rule)} directories.")

    campaign = _campaign_sentence(_vectors(bash), _prose_hosts(bash))
    if campaign:
        lines.append(campaign)
    if campaign_ctx:
        lines.append(campaign_ctx)
    attribution = _attribution_paragraph(assessment)
    if attribution:
        lines.append(attribution)
    elif row["actor_key"]:
        lines.append(f"Open source intelligence links this activity to {row['actor_key']}.")
    signatures = _matched_signatures(row)
    if signatures:
        lines.append("Found by GitHub code search for a confirmed malware signature: "
                     + "; ".join(signatures) + ".")
    lines.append("Confirmed by static analysis; the code was read, never executed.")
    return "\n".join(lines)


def _tags(row, assessment=None) -> list[str]:
    """Campaign-descriptive public tags for the OSM report (NOT our internal rule
    names). Leads with the threat class + delivery vector, then the country-level
    attribution tags, which the engine already gated: an attributed origin's tags
    (e.g. ``dprk``, ``contagious-interview``) only at probable+; a lone tradecraft
    vector is ``dprk-consistent-tradecraft`` so we never over-attribute a copycat."""
    bash = json.loads(row["raw_payload"] or "{}").get("bash_findings") or []
    vectors = _vectors(bash)
    tags: list[str] = ["supply-chain", "github-repo"]
    if assessment is not None:
        tags += list(assessment.tags)     # tier/origin-appropriate, already gated
    if is_container_threat(bash):         # malicious Docker build recipe
        tags += list(CONTAINER_TAGS)
    tags += vectors
    # a plain threat-behavior tag from the worst confirming category
    cat = (bash[0].get("category") if bash else "") or ""
    tags.append({"install_hook": "dropper", "obfuscation": "obfuscated-loader",
                 "credential_access": "credential-theft", "exfiltration": "data-exfiltration",
                 "malicious_dependency": "malicious-dependency"}.get(cat, "malware"))
    out: list[str] = []
    for t in tags:
        if t and t not in out:
            out.append(t)
    return out[:10]


def _attribution_paragraph(assessment) -> str:
    """Honest, tier-aware attribution prose from the country-level assessment.

    Enumerates the signals so a reviewer can check each, and never asserts a
    country on a single evidence signal (operator policy: 2+ evidence, OR a
    specific named-group intel attribution)."""
    if assessment is None or assessment.tier == "unattributed":
        return ""
    who = assessment.actor or assessment.origin or "an unknown actor"
    if assessment.actor and assessment.origin and assessment.origin not in assessment.actor:
        who = f"{assessment.origin} {assessment.actor}"
    camp = (f" '{assessment.campaign}'"
            if assessment.campaign and assessment.tier != "possible"
            and assessment.campaign != assessment.actor else "")
    lead = {
        "confirmed": f"Attribution: we assess this repository as CONFIRMED {who}{camp} activity.",
        "probable": f"Attribution: we assess this repository as PROBABLE {who}{camp} activity.",
        "possible": (f"Attribution: the tradecraft is consistent with {assessment.origin}, "
                     f"but a single signal is a lead rather than an attribution, so we do "
                     f"not attribute it on this evidence alone."),
    }[assessment.tier]
    if assessment.reasons:
        lead += " Signals: " + "; ".join(
            r.strip().rstrip(".") for r in assessment.reasons) + "."
    return lead


def _evidence_refs(row, cap: int = 15) -> str:
    """ALL confirming file:line proof links, not just the first.

    OSM's evidence_references is a single string, so we pack every distinct
    confirming location (deduped by file+line, confirming findings first because
    hunt orders them that way) newline-joined, capped so one noisy repo can't
    produce a thousand-line field. Reviewers get every proof point, not one."""
    full = row["full_name"]
    payload = json.loads(row["raw_payload"] or "{}")
    bash = payload.get("bash_findings") or []
    # Pin to the exact scanned commit if we captured it: a /blob/<sha>/ link stays
    # valid forever, where /blob/HEAD/ rots the moment the file is removed. Falls
    # back to HEAD for older findings scanned before commit_sha was recorded.
    ref = payload.get("commit_sha") or "HEAD"
    refs: list[str] = []
    seen: set[tuple] = set()
    for b in bash:
        f = b.get("file")
        if not f:
            continue
        key = (f, b.get("line"))
        if key in seen:
            continue
        seen.add(key)
        anchor = f"#L{b['line']}" if b.get("line") else ""
        refs.append(f"https://github.com/{full}/blob/{ref}/{f}{anchor}")
        if len(refs) >= cap:
            break
    return "\n".join(refs) if refs else f"https://github.com/{full}"


def _payload_description(row) -> str:
    """Where the payload is, then one bullet per detection rule saying why it matters."""
    payload = json.loads(row["raw_payload"] or "{}") or {}
    bash = _confirming(payload)
    files = list(dict.fromkeys(b.get("file") for b in bash if b.get("file")))
    lines = [f"Malicious payload found in: {', '.join(files[:5]) or 'see evidence references'}"]
    lines += _payload_bullets(bash)
    hosts = _prose_hosts(bash)
    if hosts:
        lines.append(f"- Attacker hosts: {', '.join(hosts)}")
    return "\n".join(lines)


_EM_DASH = re.compile(r"\s*[\u2014\u2015]\s*|\s+[\u2013]\s+|\s+--\s+")


def _no_dashes(text: str) -> str:
    """Prose sent to OSM never carries em dashes (house style): ' a — b ' and a
    spaced en dash or double hyphen become ', '. Text pulled in from elsewhere
    (attribution reasons, actor names) is covered too. A bare en dash in a range
    becomes a hyphen. IOC fields are left byte-exact."""
    return _EM_DASH.sub(", ", text or "").replace("\u2013", "-")


def build_report(row, dprk_infra=None, campaign_ctx: str = "") -> dict:
    """Map a confirmed repo_findings row to an OSM submit-threat request body.

    ``row`` is a sqlite3.Row (or any mapping) with the repo_findings columns.
    Fills every field the OSM form / API accepts: report_type, resource_identifier
    (the repo URL), version_info, threat_description, payload_description,
    severity_level, tags, evidence_references, and an optional contact_email.

    ``dprk_infra`` is the self-sourced C2 set (this repo EXCLUDED) that drives the
    multi-signal DPRK assessment; the caller passes ``db.dprk_infra_hosts(exclude=
    full_name)``. Absent it (unit tests), attribution falls back to whatever single
    signals the evidence alone supports.
    """
    full = row["full_name"]
    owner = full.split("/", 1)[0]
    payload = json.loads(row["raw_payload"] or "{}") or {}
    bash = payload.get("bash_findings") or []
    assessment = attribute_actor(bash, row["actor_key"], dprk_infra or set())

    report = {
        "report_type": "repository",
        # OSM wants the full URL with scheme (per maintainer): https://github.com/...
        "resource_identifier": f"https://github.com/{full}",
        "version_info": "all",
        "threat_description": _no_dashes(
            _threat_description(row, assessment, campaign_ctx)),
        "payload_description": _no_dashes(_payload_description(row)),
        "publisher": owner,
        "severity_level": severity_level(row),
        "tags": _tags(row, assessment),
        # ALL confirming file:line proof, not just the first (see _evidence_refs).
        "evidence_references": _evidence_refs(row),
        # Curated IOCs (C2 host, payload URL, dropper command, path) so OSM indexes
        # them as pivotable indicators, not just prose.
        "verified_iocs": _verified_iocs(row),
        "contributors": [OSM_CONTRIBUTOR] if OSM_CONTRIBUTOR else [],
    }
    fs, ls = _run_to_iso(row["first_seen_run"]), _run_to_iso(row["last_seen_run"])
    if fs:
        report["first_seen"] = fs
    if ls:
        report["last_seen"] = ls
    if OSM_CONTACT_EMAIL:
        report["contact_email"] = OSM_CONTACT_EMAIL
    return report


def domain_reports_for(row, assessment, db=None) -> list[dict]:
    """report_type:'domain' IOC reports for each attacker C2/payload host of a repo.

    OSM accepts domain reports, so the C2 infrastructure we extract becomes
    pivotable IOCs cross-linked to the repo instead of dying in prose. Hosts come
    from the assessment (confirming/fetch/exfil evidence) plus any domains mined
    into learned_iocs for this repo. Attribution tags track the repo's tier."""
    full = row["full_name"]
    repo_url = f"https://github.com/{full}"
    hosts: list[str] = list(assessment.c2)
    if db is not None:
        for ioc in db.iocs_for_repo(full):
            if ioc["kind"] == "domain" and ioc["value"] not in hosts:
                hosts.append(ioc["value"])
    # Never accuse a URL shortener or a shared service of being C2. The redirect or
    # the multi-tenant API is not the attacker's infrastructure, and a domain report
    # against one asks OSM to blocklist it for every legitimate user.
    hosts = [h for h in hosts if _reportable_domain(h)]
    tags = ["c2", "supply-chain", "github-repo"] + list(assessment.tags)
    reports = []
    for h in hosts:
        reports.append({
            "report_type": "domain",
            "resource_identifier": h,
            "threat_description": (
                f"Command-and-control / payload-delivery host for the malicious "
                f"repository {repo_url}. The repository fetches or exfiltrates through "
                f"this host as part of its confirmed malicious behavior; the linked "
                f"repository report carries the file:line evidence."),
            "severity_level": "high",
            "tags": tags[:10],
            "evidence_references": repo_url,
            "contributors": [OSM_CONTRIBUTOR] if OSM_CONTRIBUTOR else [],
        })
    return reports


# Registrable URL-shortener domains: a short link is a redirect, not attacker C2
# infrastructure, so we never submit one as a malicious domain even if it is
# corroborated across repos (the weak single-repo `*.s.gy` / `*.short.gy` hosts
# from the 2026-07-06 FP audit).
_URL_SHORTENERS = (
    "s.gy", "short.gy", "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy",
    "cutt.ly", "is.gd", "ow.ly", "buff.ly", "lnkd.in", "shorturl.at", "t.ly",
)


def _is_shortener(host: str) -> bool:
    return any(host == s or host.endswith("." + s) for s in _URL_SHORTENERS)


# Shared services that malware abuses as a drop point. The host is NOT attacker
# infrastructure: api.telegram.org is Telegram's own bot API and serves millions of
# legitimate bots. The malicious artifact is the specific bot token or webhook path,
# never the domain, so reporting the domain would ask OSM to blocklist the service
# for everyone. Run #88 queued api.telegram.org as a C2 domain report.
#
# Matched EXACTLY (optionally with a www prefix) rather than by suffix, because a
# platform's attacker-controlled SUBDOMAIN is real infrastructure and must still be
# reportable. default-configuration.vercel.app is the live example: vercel.app is a
# service, that subdomain is the dropper host.
_SHARED_SERVICE_HOSTS = frozenset({
    "api.telegram.org", "telegram.org",
    "discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com",
    "hooks.slack.com", "slack.com",
    "github.com", "api.github.com", "raw.githubusercontent.com", "gist.github.com",
    "gitlab.com", "bitbucket.org",
    "pastebin.com", "webhook.site", "requestbin.com", "pipedream.net",
    "transfer.sh", "file.io", "0x0.st", "termbin.com",
    "t.me", "api.mailgun.net", "api.sendgrid.com",
})


def _is_shared_service(host: str) -> bool:
    """True if the host is a legitimate shared service rather than attacker infra."""
    h = (host or "").lower().rstrip(".")
    return h in _SHARED_SERVICE_HOSTS or h.removeprefix("www.") in _SHARED_SERVICE_HOSTS


def _reportable_domain(host: str) -> bool:
    """True if a host may be submitted to OSM as a malicious domain in its own right."""
    return bool(host) and not _is_shortener(host) and not _is_shared_service(host)


def corroborated_c2(db, min_repos: int = 2) -> list[dict]:
    """Attacker C2 hosts seen in >= ``min_repos`` confirmed repos, with each host's
    corroborating repos and best attribution.

    The corroboration gate is the false-positive guard: a host used by many
    confirmed repos is attacker infrastructure; a one-off (or a URL shortener) is
    not, so it is held back for manual review rather than submitted. Hosts come
    from every confirmed repo's fetch/exfil evidence plus its mined learned_iocs
    domains, so this covers ALREADY-SUBMITTED repos too (their infra was never
    reported as its own IOC)."""
    from .actors import attribute
    from .dprk import c2_hosts_from_flags

    infra = db.dprk_infra_hosts()
    host_repos: dict[str, set[str]] = {}
    host_attr: dict = {}
    for r in db.conn.execute(
        "SELECT full_name, actor_key, raw_payload FROM repo_findings "
        "WHERE status IN ('confirmed', 'validated')"
    ):
        flags = (json.loads(r["raw_payload"] or "{}") or {}).get("bash_findings") or []
        hosts = {h for h in c2_hosts_from_flags(flags) if _reportable_domain(h)}
        for ioc in db.iocs_for_repo(r["full_name"]):
            if ioc["kind"] == "domain" and _reportable_domain(ioc["value"]):
                hosts.add(ioc["value"])
        if not hosts:
            continue
        a = attribute(flags, r["actor_key"], infra)
        for h in hosts:
            host_repos.setdefault(h, set()).add(r["full_name"])
            # keep the strongest attribution seen carrying this host (for its tags)
            if h not in host_attr or (a.attributed and not host_attr[h].attributed):
                host_attr[h] = a
    host_repos = _merge_truncated_hosts(host_repos)
    out = [{"host": h, "repos": sorted(reps), "attr": host_attr.get(h)}
           for h, reps in host_repos.items() if len(reps) >= min_repos and host_attr.get(h)]
    out.sort(key=lambda d: -len(d["repos"]))
    return out


def _merge_truncated_hosts(host_repos: dict[str, set]) -> dict[str, set]:
    """Fold a truncation-artifact host into the full one it is a prefix of.

    A stored evidence snippet is capped, so a URL cut mid-domain leaves a partial
    host: ``vscode-production-setting.ve`` for ``vscode-production-setting.vercel.app``.
    Both would be reported as separate C2 domains, the short one invalid. A host that
    is a strict prefix of another AND is continued by a letter (cut mid-label, not a
    real subdomain boundary) is merged into the longer one so the count stays right.
    """
    hosts = list(host_repos)
    dropped: set[str] = set()
    for short in hosts:
        for long in hosts:
            if long is short or len(long) <= len(short):
                continue
            if long.startswith(short) and long[len(short)].isalpha():
                host_repos[long] |= host_repos[short]
                dropped.add(short)
                break
    return {h: r for h, r in host_repos.items() if h not in dropped}


def domain_ioc_report(host: str, repos: list[str], attr) -> dict:
    """An OSM report_type:'domain' report for a corroborated C2 host."""
    tags = ["c2", "supply-chain"] + list(getattr(attr, "tags", []))
    seen = ", ".join(f"https://github.com/{x}" for x in repos[:3])
    return {
        "report_type": "domain",
        "resource_identifier": host,
        "threat_description": (
            f"This host is command-and-control and payload-delivery infrastructure for "
            f"{len(repos)} confirmed malicious GitHub repositories, for example {seen}. "
            f"We extracted it from their confirmed fetch and exfiltration evidence. The "
            f"linked repository reports carry the file and line proof for each one."),
        "severity_level": "high",
        "tags": tags[:10],
        "evidence_references": "\n".join(f"https://github.com/{x}" for x in repos[:15]),
        "contributors": [OSM_CONTRIBUTOR] if OSM_CONTRIBUTOR else [],
    }


def submitted_findings_for_enrich(db) -> list:
    """Already-submitted repos (submitted_osm = 1) with their OWN evidence, whose
    reports predate the current enrichment and can be UPDATED (OSM upserts by
    resource_identifier). Never touches OSM-list re-validations or breadcrumbs."""
    _ensure_submit_columns(db)
    rows = db.conn.execute(
        "SELECT * FROM repo_findings WHERE submitted_osm = 1 "
        "AND status IN ('confirmed', 'validated') "
        "AND detection_method NOT IN ('osm_repository', 'redteam_lineage') "
        "ORDER BY score DESC, full_name"
    ).fetchall()
    return [r for r in rows if _has_intrinsic_evidence(r)]


def _ensure_domain_table(db) -> None:
    """Local at-most-once ledger for submitted C2 domains (gitignored, like the
    submit columns): so a domain seen across many repos is reported to OSM once."""
    db.conn.execute(
        "CREATE TABLE IF NOT EXISTS osm_submitted_domains ("
        "host TEXT PRIMARY KEY, first_repo TEXT, threat_id TEXT)")
    db.conn.commit()


def _domain_already_submitted(db, host: str) -> bool:
    _ensure_domain_table(db)
    return db.conn.execute(
        "SELECT 1 FROM osm_submitted_domains WHERE host = ?", (host,)).fetchone() is not None


def _mark_domain_submitted(db, host: str, repo: str, threat_id: str | None) -> None:
    _ensure_domain_table(db)
    with db.transaction() as c:
        c.execute(
            "INSERT OR REPLACE INTO osm_submitted_domains (host, first_repo, threat_id) "
            "VALUES (?, ?, ?)", (host, repo, threat_id))


def _osm_resource_key(resource: str, report_type: str | None = None) -> str:
    """Normalize an OSM resource_identifier to a comparison key: a repo URL to
    ``owner/repo``, everything else to the bare lowercased value."""
    r = (resource or "").strip().casefold()
    if "github.com" in r:
        m = re.search(r"github\.com/([^/]+/[^/#?]+)", r)
        if m:
            return m.group(1).rstrip("/")
    return r


def osm_current_reports(token: str | None = None, http=None) -> dict:
    """CHECK OSM FIRST. What OSM already reports right now, from the free
    ``query-latest`` endpoint, as ``{resource_key: {id, status, verified_by,
    report_type, resource}}``.

    This is the guard that must run before any submission so we never re-report a
    resource OSM already has (ours or another researcher's). IMPORTANT LIMIT:
    query-latest is a RECENT-WINDOW firehose, not a full history or a per-resource
    lookup (that is OSM Pro), so a resource absent here MAY still exist in OSM if it
    was reported long ago. Treat a hit as authoritative "already reported"; treat a
    miss as "unknown, not proven novel"."""
    import requests

    token = token or OSM_API_KEY
    if not token:
        return {}
    out: dict = {}
    # Poll repositories, the package registries, and the IOC ecosystems we submit to.
    ecosystems = ("repositories", "npm", "pypi", "vscode", "openvsx", "crates", "go",
                  "domains", "ip", "container", "url", "wallet")
    for eco in ecosystems:
        try:
            resp = requests.get(
                osm_endpoint("query-latest"), params={"ecosystem": eco},
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            data = resp.json() if resp.content else {}
        except Exception as exc:  # noqa: BLE001
            print(f"  [warn] OSM query-latest '{eco}' failed: {exc}")
            continue
        threats = (data.get("threats") or data.get("results") or data.get("data") or []
                   if isinstance(data, dict) else data if isinstance(data, list) else [])
        for t in threats:
            if not isinstance(t, dict):
                continue
            rid = t.get("resource_identifier") or t.get("package_name")
            if not rid:
                continue
            out[_osm_resource_key(str(rid), t.get("report_type"))] = {
                "id": t.get("id"), "status": t.get("status"),
                "verified_by": t.get("verified_by"), "report_type": t.get("report_type"),
                "resource": str(rid)}
    return out


def _repo_id_variants(full_name: str) -> list[str]:
    """Repository identifier spellings accepted by OSM check-malicious.

    The current API requires URL-form repository identifiers. A trailing slash is
    still a distinct historical spelling, so both URL forms are checked. The old
    scheme-less spellings are deliberately excluded because the live endpoint
    rejects them with HTTP 400.
    """
    o = full_name.strip().strip("/")
    return [f"https://github.com/{o}", f"https://github.com/{o}/"]


def osm_search(
    term: str, *, report_type: str | None = None,
    token: str | None = None, http=None,
) -> list[dict]:
    """Authoritative exact-resource lookup via OSM check-malicious.

    The current public API accepts report_type and resource_identifier
    and returns malicious: true|false. A positive response is normalized to
    the historical list-of-records shape used by the rest of Warden.
    """
    import requests

    token = token or OSM_API_KEY
    if not token:
        return []
    report_type = report_type or (
        "repository" if "github.com/" in term.casefold() else "domain"
    )
    try:
        resp = requests.get(
            osm_endpoint("check-malicious"),
            params={
                "report_type": report_type,
                "resource_identifier": term,
            },
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            timeout=HTTP_TIMEOUT,
        )
        if resp.status_code != 200:
            return []
        data = resp.json() if resp.content else {}
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(data, dict) or not isinstance(data.get("malicious"), bool):
        return []
    if data["malicious"] is False:
        return []

    details = data.get("details")
    row = dict(details) if isinstance(details, dict) else {}
    row.setdefault("resource_identifier", str(data.get("resource_identifier") or term))
    row.setdefault("report_type", str(data.get("report_type") or report_type))
    if data.get("status") and not row.get("status"):
        row["status"] = data["status"]
    return [row]


def osm_existing_repo(full_name: str, *, token: str | None = None, http=None) -> dict | None:
    """AUTHORITATIVE novelty gate for a repository: the pre-existing OSM record for
    ``full_name`` under ANY resource_identifier spelling, or ``None`` if truly novel.

    This queries OSM's full history (see :func:`osm_search`), so it catches the
    months-old and other-researcher reports that ``query-latest``'s recent window
    silently misses -- the exact gap that let us duplicate already-verified reports.
    """
    want = full_name.strip().strip("/").casefold()
    for variant in _repo_id_variants(full_name):
        for row in osm_search(variant, report_type="repository", token=token, http=http):
            rid = str(row.get("resource_identifier") or "")
            if _osm_resource_key(rid) == want:
                return row
    return None


def osm_existing_resource(term: str, *, token: str | None = None, http=None) -> dict | None:
    """Authoritative novelty gate for a non-repo resource (domain, IP, URL, wallet):
    the pre-existing OSM record whose resource_identifier exactly matches ``term``
    (case-insensitive), or ``None``. Backs the domain-IOC dedup the same way
    :func:`osm_existing_repo` backs repos."""
    want = term.strip().casefold()
    for row in osm_search(term, report_type="domain", token=token, http=http):
        rid = str(row.get("resource_identifier") or row.get("package_name") or "")
        if rid.strip().casefold() == want:
            return row
    return None


def _http_get(url: str, timeout: int = 20):
    """Minimal GET returning ``(status_code, text)``; injectable for tests."""
    import requests
    r = requests.get(url, timeout=timeout)
    return r.status_code, (r.text or "")


def repo_payload_live(row, *, fetch=_http_get) -> bool | None:
    """Re-fetch the confirming evidence at the repo's CURRENT HEAD and confirm the
    malicious payload is still there.

    OSM re-verifies against the live repository, so a payload removed since our scan
    is a guaranteed FALSE_POSITIVE. Returns ``True`` if the payload is still live,
    ``False`` if the file is gone (404) or the distinctive token has been removed,
    and ``None`` if the check could not run (no evidence / network error) so the
    caller can fail open rather than block a send on a transient hiccup.
    """
    payload = json.loads(row["raw_payload"] or "{}")
    bash = payload.get("bash_findings") or []
    if not bash:
        return None
    top = bash[0]  # hunt orders the confirming finding first
    fpath = top.get("file")
    if not fpath:
        return None
    from .dprk import c2_hosts_from_flags
    hosts = c2_hosts_from_flags(bash)
    snippet = (top.get("snippet") or "").strip()
    token = hosts[0] if hosts else (snippet.split() or [""])[0]
    url = f"https://raw.githubusercontent.com/{row['full_name']}/HEAD/{fpath}"
    try:
        code, text = fetch(url)
    except Exception:  # noqa: BLE001
        return None
    if code == 404:
        return False
    if code != 200:
        return None
    return True if not token else (token in text)


def audit(db, *, limit: int | None = None) -> int:
    """Read-only: report each submission's CURRENT standing in OSM.

    For every repo we marked submitted, ask OSM's authoritative resource check what it says
    now (verified / pending / false-positive / absent) and whether OSM's canonical
    id matches the one we stored (a mismatch means our report is a duplicate of
    another researcher's, or was superseded). Turns eyeballing the web dashboard
    into one command, and surfaces the duplicate/rejected reports to clean up.
    """
    rows = db.conn.execute(
        "SELECT full_name, osm_threat_id FROM repo_findings WHERE submitted_osm=1 "
        "ORDER BY full_name").fetchall()
    if limit:
        rows = rows[:limit]
    if not rows:
        print("No submissions marked in the local ledger yet (nothing to audit).")
        return 0
    print(f"Auditing {len(rows)} submission(s) against OSM full history "
          f"(check-malicious endpoint)...\n")
    from collections import Counter
    tally: Counter = Counter()
    dupes, gone = [], []
    for r in rows:
        hit = osm_existing_repo(r["full_name"])
        if not hit:
            tally["absent"] += 1
            gone.append(r["full_name"])
            print(f"  ABSENT          {r['full_name']}  (not found in OSM now)")
            continue
        status = (hit.get("status") or "unknown").lower()
        tally[status] += 1
        osm_id, ours = str(hit.get("id") or ""), str(r["osm_threat_id"] or "")
        dup = ours and osm_id and osm_id[:8] != ours[:8]
        flag = "  [DUP: canonical != ours]" if dup else ""
        if dup:
            dupes.append((r["full_name"], osm_id[:8], ours[:8]))
        print(f"  {status.upper():<15} {r['full_name']}  id={osm_id[:8]}{flag}")
    print("\n  Summary: " + ", ".join(f"{k}={v}" for k, v in sorted(tally.items())))
    if dupes:
        print(f"\n  {len(dupes)} report(s) whose OSM canonical id differs from ours "
              f"(likely duplicates to decline):")
        for name, osm_id, ours in dupes:
            print(f"    {name}  osm={osm_id}  ours={ours}")
    if tally.get("false_positive"):
        print(f"\n  {tally['false_positive']} marked FALSE_POSITIVE by OSM reviewers "
              f"(rejected).")
    return 0


def print_queue(db) -> int:
    """Read-only: the AUTO-tier submit queue -- novel, unsubmitted, high-confidence
    captures ready for a human go/no-go. This is the morning review view: every row
    here cleared the confidence tier, evidence gate, and local novelty check."""
    rows = gold_for_submission(db)  # AUTO + novel + unsubmitted + has-evidence
    if not rows:
        print("Submit queue is empty -- no novel AUTO-tier captures awaiting review.")
        return 0
    print(f"AUTO-tier submit queue: {len(rows)} novel capture(s) ready for review\n")
    print(f"  {'repo':44} {'sev':9} {'method':16} score")
    print("  " + "-" * 78)
    for r in rows:
        print(f"  {r['full_name']:44} {severity_level(r):9} "
              f"{r['detection_method']:16} {r['score']}")
    print("\n  Review, then submit with:  make submit ARGS=\"--confirm\"")
    print("  (each is re-checked against OSM full history + liveness before sending)")
    return 0


def _osm_repo_url(full_name: str) -> str:
    """The OSM website page for a repository report (where 'Update Report' lives)."""
    from urllib.parse import quote
    return "https://opensourcemalware.com/repository/" + quote(
        "https://github.com/" + full_name, safe="")


def _enrich_walkthrough(db, name: str, tid, ask, pause) -> None:
    """Print copy-paste-ready field values + where each goes in OSM's Update form."""
    r = db.get_finding(name)
    report = build_report(r, dprk_infra=db.dprk_infra_hosts(exclude=name),
                          campaign_ctx=campaign_context(db, r))
    flags = json.loads(r["raw_payload"] or "{}").get("bash_findings") or []
    from .dprk import c2_hosts_from_flags
    iocs = sorted({h for h in c2_hosts_from_flags(flags) if not _is_shortener(h)})
    print("\n" + "-" * 68)
    print(f"  ENRICH:  {name}")
    print(f"  report id: {tid}")
    print("\n  1) Open this page in your browser:")
    print(f"       {_osm_repo_url(name)}")
    print("  2) Click the 'Update Report' button (bottom-right of the report card).")
    print("  3) Fill in these fields (copy-paste each block):\n")
    print(f"     [ Severity Level ]   choose:  {report['severity_level']}")
    print("\n     [ Evidence References ]   paste (semicolon-separated, or one per line):")
    for line in report["evidence_references"].splitlines():
        print(f"         {line}")
    if iocs:
        print("\n     [ Verified IOCs ]   paste one per line "
              "(this is the box OSM reads indicators from):")
        for h in iocs:
            print(f"         {h}")
    else:
        print("\n     [ Verified IOCs ]   leave blank (this repo has no network C2 host).")
    print(f"\n     [ Tags ]   add each:  {', '.join(report['tags'])}")
    print("\n     [ Payload Description ]   replace the text with:")
    print(f"         {report['payload_description']}")
    print("\n  4) Click 'Update Report' to save.")
    pause("\n  Press Enter when this one is updated (or Ctrl+C to stop)...")


def wizard(db, args) -> int:
    """Interactive, step-by-step OSM submission for non-technical operators.

    Shows a plain-language 'SUBMIT OSM REPORT' walkthrough: checks OSM first so we
    never double-report, submits genuinely-new findings via the API on the user's
    OK, and for reports OSM already has, guides the user field-by-field through the
    website's 'Update Report' form (the API cannot update yet). TTY-gated: when not
    run in a real terminal it prints the whole walkthrough as text and never blocks
    on input."""
    import sys

    tty = sys.stdin.isatty()

    def ask(prompt: str, default: str = "") -> str:
        if not tty:
            print(f"{prompt}[non-interactive -> '{default or 'skip'}']")
            return default
        try:
            return input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return default

    def pause(msg: str) -> None:
        if tty:
            try:
                input(msg)
            except (EOFError, KeyboardInterrupt):
                pass
        else:
            print(msg + "  [non-interactive -> continuing]")

    bar = "=" * 68
    print(f"\n{bar}\n  SUBMIT OSM REPORT\n{bar}")
    print("This walks you through reporting Git Warden's confirmed findings to")
    print("OpenSourceMalware (OSM). Nothing is sent without your OK.\n")

    # Credentials
    if not OSM_API_KEY:
        print("You need an OSM API key (it starts with 'osm_').")
        print("  Where to find it: opensourcemalware.com -> sign in -> Settings -> API Tokens.")
        print("  Then add it to your .env file as  GW_OSM_API_KEY=osm_...  and re-run.")
        return 0
    print("OSM API key: found. Good.\n")

    # STEP 1 -- check OSM first
    print("STEP 1 of 4  ::  Checking what OSM already has, so we never double-report...")
    osm_now = osm_current_reports()
    print(f"  OSM currently lists {len(osm_now)} resource(s) in its recent window.\n")

    # STEP 2 -- reconcile
    print("STEP 2 of 4  ::  Your findings compared to OSM")
    b = reconcile(db, osm_now)["buckets"]
    candidate_rows = [r for r in gold_for_submission(db)
                      if r["full_name"].casefold() not in osm_now]
    # AUTHORITATIVE full-history gate (check-malicious endpoint) on top of the recent-window
    # filter: catches months-old / other-researcher reports query-latest can't see.
    print("  Cross-checking OSM full history (check-malicious endpoint)...")
    new_rows = []
    for r in candidate_rows:
        hit = osm_existing_repo(r["full_name"])
        if hit:
            print(f"  [skip] {r['full_name']}: already in OSM full history "
                  f"({hit.get('status')}, id {str(hit.get('id'))[:8]})")
        else:
            new_rows.append(r)
    print(f"  {len(new_rows):>3}  NEW malicious repo(s) not yet in OSM  (we can submit these)")
    print(f"  {len(b['verified_ours']):>3}  of your reports already verified in OSM  "
          f"(we can enrich these)")
    print(f"  {len(b['not_in_window']):>3}  older/other reports not in the recent window\n")

    # STEP 3 -- submit NEW via API
    if new_rows:
        print(f"STEP 3 of 4  ::  Submit {len(new_rows)} NEW report(s) via the API")
        go = ask(f"  Review and submit {len(new_rows)} new report(s) now? [y/N]: ", "n")
        if go.lower() == "y":
            for r in new_rows:
                report = build_report(r, dprk_infra=db.dprk_infra_hosts(exclude=r["full_name"]),
                                      campaign_ctx=campaign_context(db, r))
                print(f"\n  Repo: {r['full_name']}")
                print(f"    severity: {report['severity_level']} | "
                      f"tags: {', '.join(report['tags'])}")
                print(f"    evidence: {report['evidence_references'].splitlines()[0]}")
                if ask("    Submit THIS one to OSM? [y/N]: ", "n").lower() != "y":
                    print("    skipped.")
                    continue
                mark_osm_submitted(db, r["full_name"], None)
                try:
                    resp = submit_threat(report)
                    mark_osm_submitted(db, r["full_name"], resp.get("threat_id"))
                    print(f"    submitted -> {resp.get('threat_id')} ({resp.get('status')})")
                except Exception as exc:  # noqa: BLE001
                    unmark_osm_submitted(db, r["full_name"])
                    print(f"    FAILED (released, retry later): {exc}")
    else:
        print("STEP 3 of 4  ::  No new repos to submit (all your discoveries are "
              "already in OSM).")

    # STEP 4 -- enrich existing via the website's Update form
    enrichable = b["verified_ours"]
    print()
    if enrichable:
        print(f"STEP 4 of 4  ::  Enrich {len(enrichable)} existing report(s)")
        print("  OSM's API can create but not yet UPDATE reports, so for each one below")
        print("  you'll use the website's 'Update Report' button. I show you exactly what")
        print("  to paste and where. Do a few now, or all of them.")
        go = ask(f"  Walk through enriching (up to {len(enrichable)}) now? [y/N]: ", "n")
        if go.lower() == "y":
            limit = args.limit or len(enrichable)
            for name, tid in enrichable[:limit]:
                _enrich_walkthrough(db, name, tid, ask, pause)
    else:
        print("STEP 4 of 4  ::  Nothing to enrich right now.")

    print("\n" + bar)
    print("  Done. Thanks for contributing to OSM.")
    print(bar)
    return 0


def reconcile(db, osm_now: dict | None = None) -> dict:
    """Cross-check our locally-marked submissions against OSM's actual state.

    Classifies each ``submitted_osm=1`` repo by comparing our stored ``osm_threat_id``
    to what OSM reports for that resource now:

      * verified_ours   - OSM's canonical id equals ours and it is verified: a real
                          report of ours, enrichable in place by its threat_id.
      * verified_other  - OSM's canonical report has a DIFFERENT id (another
                          researcher's, or our submission is a duplicate of theirs).
      * pending         - present in OSM, still under review.
      * not_in_window   - absent from query-latest's recent window: either an older
                          verified report (still enrichable by stored id) or gone.
    """
    _ensure_submit_columns(db)   # osm_threat_id / submitted_osm are local runtime columns
    osm_now = osm_current_reports() if osm_now is None else osm_now
    rows = db.conn.execute(
        "SELECT full_name, osm_threat_id FROM repo_findings WHERE submitted_osm=1 "
        "ORDER BY full_name").fetchall()
    buckets: dict[str, list] = {"verified_ours": [], "verified_other": [],
                                "pending": [], "not_in_window": []}
    for r in rows:
        hit = osm_now.get(_osm_resource_key(r["full_name"]))
        stored = r["osm_threat_id"]
        if not hit:
            buckets["not_in_window"].append((r["full_name"], stored))
        elif str(hit.get("status")).lower() == "pending":
            buckets["pending"].append((r["full_name"], hit.get("id")))
        elif stored and hit.get("id") and str(hit["id"]) == str(stored):
            buckets["verified_ours"].append((r["full_name"], stored))
        else:
            buckets["verified_other"].append((r["full_name"], hit.get("id"), stored))
    return {"osm_window": len(osm_now), "total_submitted": len(rows), "buckets": buckets}


class _RequestsPoster:
    """Minimal POST client. The local build does its own HTTP so the tracked
    feeds.http client carries no write path."""

    def post_json(self, url: str, *, json: dict | None = None,
                  headers: dict[str, str] | None = None) -> dict:
        import requests

        resp = requests.post(url, json=json, headers=headers, timeout=HTTP_TIMEOUT)
        if resp.status_code >= 400:
            # Keep OSM's own error text: a bare "404 Not Found" hid which endpoint
            # or field was wrong.
            raise requests.HTTPError(
                f"{resp.status_code} from {url}: {(resp.text or '').strip()[:300]}",
                response=resp)
        return resp.json() if resp.content else {}


def submit_threat(report: dict, *, token: str | None = None, http=None) -> dict:
    """POST one report to OSM ``submit-threat-report``. Returns the parsed response.

    Raises if no token, or on an HTTP error (the caller logs and continues).
    """
    token = token or OSM_API_KEY
    if not token:
        raise RuntimeError("GW_OSM_API_KEY is not set; cannot submit to OSM.")
    http = http or _RequestsPoster()
    return http.post_json(
        osm_endpoint("submit-threat-report"),
        json=report,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )


# --- Local submit-tracking columns (kept out of the shared schema migration) ---
_SUBMIT_COLUMNS = {
    "submitted_osm": "INTEGER NOT NULL DEFAULT 0",  # 1 once reported to OSM
    "osm_threat_id": "TEXT",                        # OSM's returned report id
}


def _ensure_submit_columns(db) -> None:
    """Add the submit-tracking columns if they are not present yet.

    They live only in this local module (gitignored), so we migrate them at
    runtime instead of in the shared init_db migration.
    """
    have = {row[1] for row in db.conn.execute("PRAGMA table_info(repo_findings)")}
    missing = {k: v for k, v in _SUBMIT_COLUMNS.items() if k not in have}
    if not missing:
        return
    with db.transaction() as c:
        for name, decl in missing.items():
            c.execute(f"ALTER TABLE repo_findings ADD COLUMN {name} {decl}")


def _has_intrinsic_evidence(row) -> bool:
    """True if the finding carries its OWN static confirming evidence.

    A ``status='confirmed'`` repo passed Tier-2 on its own code, but we double-
    check here (defense in depth) that raw_payload actually holds bash_findings:
    only a repo with its own file:line proof is submittable to OSM.
    """
    payload = json.loads(row["raw_payload"] or "{}") or {}
    return bool(payload.get("bash_findings"))


def finding_confidence(row) -> str:
    """The confidence tier stored at scan time (``auto`` | ``review``).

    Defaults to ``review`` when absent, so a legacy finding scanned before tiering
    (or any un-tiered row) is NEVER treated as auto-submittable. Only ``auto`` --
    a delivery/exfil/dependency mechanism or a malware-scanner flag -- is eligible
    for gold delivery and one-click submission; ``review`` waits for a human.
    """
    try:
        return json.loads(row["raw_payload"] or "{}").get("confidence") or "review"
    except Exception:  # noqa: BLE001
        return "review"


def gold_for_submission(db, limit: int = 0, *, min_confidence: str = "auto") -> list:
    """Novel confirmed TRUE POSITIVES not yet reported to OSM.

    A repo is submittable when it was Tier-2 CONFIRMED on its OWN static evidence
    (file:line proof in bash_findings), is novel, and reached the ``auto``
    confidence tier -- a high-precision delivery/exfil/dependency mechanism, not a
    lone broad signal. The discovery METHOD does not gate this. We still exclude
    osm_repository (OSM already has it) and redteam_lineage (a research breadcrumb).
    ``submitted_osm`` gates out anything already sent. Pass ``min_confidence=
    "review"`` to include the human-review tier (never the default).
    """
    _ensure_submit_columns(db)
    known = db.osm_known_repos()
    rows = db.conn.execute(
        "SELECT * FROM repo_findings WHERE status IN ('confirmed', 'validated') "
        "AND submitted_osm = 0 "
        "AND detection_method NOT IN ('osm_repository', 'redteam_lineage') "
        "ORDER BY score DESC, full_name"
    ).fetchall()
    allow = {"auto"} if min_confidence == "auto" else {"auto", "review"}
    novel = [r for r in rows
             if r["full_name"].casefold() not in known and _has_intrinsic_evidence(r)
             and finding_confidence(r) in allow]
    return novel[:limit] if limit else novel


def mark_osm_submitted(db, full_name: str, threat_id: str | None) -> None:
    """Claim/record a finding as reported to OSM (submitted_osm = 1, store the id)."""
    _ensure_submit_columns(db)
    with db.transaction() as c:
        c.execute(
            "UPDATE repo_findings SET submitted_osm = 1, osm_threat_id = ? "
            "WHERE full_name = ?",
            (threat_id, full_name.strip().strip("/").casefold()),
        )


def unmark_osm_submitted(db, full_name: str) -> None:
    """Release a submission claim (submitted_osm = 0) so a finding whose POST failed
    is retried next run. Used by the claim-first submit loop."""
    _ensure_submit_columns(db)
    with db.transaction() as c:
        c.execute(
            "UPDATE repo_findings SET submitted_osm = 0 WHERE full_name = ?",
            (full_name.strip().strip("/").casefold(),),
        )


def main(argv: list[str] | None = None) -> int:
    """Local operator entry point: ``python -m git_warden.osm_submit [--confirm]``."""
    import argparse
    from pathlib import Path

    from . import config
    from .db import Database

    p = argparse.ArgumentParser(
        prog="python -m git_warden.osm_submit",
        description="Report novel confirmed true positives to OpenSourceMalware (LOCAL ONLY).")
    p.add_argument("--db", type=Path, default=config.DB_PATH, help="SQLite path.")
    p.add_argument("--confirm", action="store_true",
                   help="Actually POST to OSM (default is a dry run).")
    p.add_argument("--limit", type=int, default=0,
                   help="Cap submissions this run (0 = all eligible).")
    p.add_argument("--min-severity", choices=["critical", "high", "medium", "low"],
                   help="Only submit findings at or above this severity tier.")
    p.add_argument("--owners", default="",
                   help="Comma-separated owner allowlist: only submit repos under these "
                        "accounts (for controlled, reviewed batches).")
    p.add_argument("--repo", action="append", default=[],
                   help="Explicit repo (owner/name) to include; repeatable. Overrides "
                        "--owners/--min-severity ordering to send exactly this vetted set.")
    p.add_argument("--pace", type=float, default=8.0,
                   help="Seconds between submissions (OSM rate-limits; keep >=6).")
    p.add_argument("--no-domains", action="store_true",
                   help="Skip the corroborated C2 domain IOC reports.")
    p.add_argument("--min-corroboration", type=int, default=2,
                   help="Min confirmed repos a C2 host must appear in to be submitted "
                        "as a domain IOC (the false-positive guard; default 2).")
    p.add_argument("--enrich", action="store_true",
                   help="Enrich already-submitted reports (CURRENTLY BLOCKED: the API is "
                        "create-only, so re-POST would duplicate; needs the update-report "
                        "endpoint). Use --reconcile to see the enrichable set meanwhile.")
    p.add_argument("--reconcile", action="store_true",
                   help="Cross-check our submitted reports against OSM's live state and "
                        "print the exact enrichable set (verified / pending / gone). "
                        "Read-only; sends nothing.")
    p.add_argument("--wizard", action="store_true",
                   help="Interactive step-by-step 'SUBMIT OSM REPORT' walkthrough for "
                        "non-technical operators (checks OSM first, submits new, and "
                        "guides you field-by-field through enriching existing reports).")
    p.add_argument("--audit", action="store_true",
                   help="Report each of your submissions' CURRENT standing in OSM "
                        "(verified / pending / false-positive / absent) via the "
                        "authoritative resource check, and flag duplicates. Read-only.")
    p.add_argument("--no-liveness", action="store_true",
                   help="Skip the pre-send liveness recheck (by default each repo's "
                        "payload is re-fetched at HEAD before submitting, so a repo "
                        "whose payload was removed is not sent to fail OSM review).")
    p.add_argument("--queue", action="store_true",
                   help="Show the AUTO-tier submit queue: novel, unsubmitted, "
                        "high-confidence captures ready for review. Read-only.")
    args = p.parse_args(argv)

    floor = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    db = Database.open(args.db)
    try:
        if args.wizard:
            return wizard(db, args)
        if args.reconcile:
            print("Reconciling our submissions against OSM (query-latest)...")
            res = reconcile(db)
            b = res["buckets"]
            print(f"  OSM window: {res['osm_window']} resources; "
                  f"we marked {res['total_submitted']} submitted.\n")
            print(f"  verified, OURS (enrich in place by threat_id): {len(b['verified_ours'])}")
            print(f"  verified, another researcher's canonical:      {len(b['verified_other'])}")
            print(f"  pending in OSM:                                {len(b['pending'])}")
            print(f"  not in recent window (old-verified or gone):   {len(b['not_in_window'])}")
            enrich_now = len(b["verified_ours"])
            reachable = enrich_now + len(b["not_in_window"])
            print(f"\n  ENRICHABLE now (confirmed ours): {enrich_now}")
            print(f"  ENRICHABLE by stored id (incl. older-verified, some may be gone): "
                  f"up to {reachable}")
            if b["verified_other"]:
                print("\n  Heads-up, these show a DIFFERENT canonical id than ours "
                      "(another researcher's report, or our duplicate):")
                for name, osm_id, ours in b["verified_other"][:15]:
                    print(f"    {name}  osm={str(osm_id)[:8]}  ours={str(ours)[:8]}")
            return 0

        if args.audit:
            return audit(db, limit=args.limit or None)

        if args.queue:
            return print_queue(db)

        import time

        def _filters(rows):
            # MOST-SEVERE-FIRST (worst signal, score as tiebreaker), then
            # --min-severity/--repo/--owners, then --limit -- so a capped batch is
            # the top of the danger ranking. Applied to both new repos AND updates,
            # so `--repo owner/name` can target a single vetted submission.
            rows = sorted(rows, key=lambda r: (severity_rank(r), r["score"]), reverse=True)
            if args.min_severity:
                rows = [r for r in rows if severity_rank(r) >= floor[args.min_severity]]
            if args.repo:
                want = {x.strip().strip("/").casefold() for x in args.repo}
                rows = [r for r in rows if r["full_name"].casefold() in want]
            elif args.owners:
                allow = {o.strip().casefold() for o in args.owners.split(",") if o.strip()}
                rows = [r for r in rows if r["full_name"].split("/", 1)[0].casefold() in allow]
            return rows[: args.limit] if args.limit else rows

        # STEP 1: CHECK OSM FIRST. Never re-report a resource OSM already has
        # (ours or anyone's). This is the guard that was missing when we duplicated
        # two already-verified domain reports.
        print("Checking OSM for existing reports (query-latest)...")
        osm_now = osm_current_reports()
        print(f"  OSM currently reports {len(osm_now)} resource(s) in its recent window.")

        rows = _filters(gold_for_submission(db))                    # NEW repos
        skipped_repos = [r for r in rows if r["full_name"].casefold() in osm_now]
        rows = [r for r in rows if r["full_name"].casefold() not in osm_now]

        domains = ([] if args.no_domains else
                   [d for d in corroborated_c2(db, args.min_corroboration)
                    if not _domain_already_submitted(db, d["host"])])
        skipped_domains = [d for d in domains if d["host"].casefold() in osm_now]
        domains = [d for d in domains if d["host"].casefold() not in osm_now]

        for r in skipped_repos:
            key = r["full_name"].casefold()
            print(f"  [skip] {r['full_name']}: already in OSM ({osm_now[key]['status']})")
        for d in skipped_domains:
            print(f"  [skip] domain {d['host']}: already in OSM "
                  f"({osm_now[d['host'].casefold()]['status']})")

        # STEP 1b: AUTHORITATIVE full-history novelty gate. query-latest above is a
        # recent window and is BLIND to months-old / other-researcher reports -- that
        # blindness is what let us duplicate already-verified reports. The search
        # endpoint checks OSM's whole corpus by exact resource_identifier (all format
        # spellings), so a hit here is a real "already reported, do not re-submit".
        print("Cross-checking OSM full history (check-malicious endpoint, all id spellings)...")
        pre_existing = {}
        for r in list(rows):
            hit = osm_existing_repo(r["full_name"])
            if hit:
                pre_existing[r["full_name"]] = hit
        rows = [r for r in rows if r["full_name"] not in pre_existing]
        for name, hit in pre_existing.items():
            print(f"  [skip] {name}: ALREADY in OSM full history -- "
                  f"{hit.get('status')}, id {str(hit.get('id'))[:8]}, "
                  f"res {hit.get('resource_identifier')}  (NOT re-submitting)")

        pre_domains = {}
        for d in list(domains):
            hit = osm_existing_resource(d["host"])
            if hit:
                pre_domains[d["host"]] = hit
        domains = [d for d in domains if d["host"] not in pre_domains]
        # Cross-tool dedup: skip a C2 host knorr already submitted from a container.
        from . import intel_exchange as bus
        _bus_dom = {d["host"] for d in domains if bus.is_submitted("domain", d["host"])}
        for host in sorted(_bus_dom):
            print(f"  [skip] domain {host}: already submitted by knorr (shared bus)")
        domains = [d for d in domains if d["host"] not in _bus_dom]
        for host, hit in pre_domains.items():
            print(f"  [skip] domain {host}: ALREADY in OSM full history -- "
                  f"{hit.get('status')}, id {str(hit.get('id'))[:8]}  (NOT re-submitting)")

        # ENRICHMENT: re-POSTing to submit-threat CREATES A DUPLICATE (the
        # endpoint is create-only). A true update needs OSM's update-report route,
        # which is not wired yet, so refuse rather than duplicate.
        if args.enrich:
            print("\n  [blocked] --enrich re-POSTs to a create-only endpoint, which "
                  "DUPLICATES. Wire OSM's update-report API (update by threat_id) "
                  "first. Skipping enrichment this run.")

        if not rows and not domains:
            print("\nNothing new to submit (already in OSM, or nothing qualified).")
            return 0

        def _post_with_retry(report):
            """POST once with 429 backoff. Returns (resp|None, exc|None)."""
            last = None
            for attempt in range(4):
                try:
                    return submit_threat(report), None
                except Exception as exc:  # noqa: BLE001
                    last = exc
                    if "429" in str(exc) and attempt < 3:
                        wait = args.pace * (2 ** attempt)
                        print(f"  [rate-limited] backing off {wait:.0f}s")
                        time.sleep(wait)
                        continue
                    break
            return None, last

        sent = domains_sent = 0

        # --- 1) NEW repo reports (novel, not yet submitted) ------------------
        if rows:
            print(f"\n{len(rows)} NEW confirmed true positive(s), most severe first:")
            for i, r in enumerate(rows):
                report = build_report(r, dprk_infra=db.dprk_infra_hosts(exclude=r["full_name"]),
                                      campaign_ctx=campaign_context(db, r))
                if not args.confirm:
                    print(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
                    continue
                # Liveness recheck: OSM verifies against the live repo, so never send
                # one whose payload was removed since our scan (guaranteed rejection).
                if not args.no_liveness and repo_payload_live(r) is False:
                    print(f"  [skip] {r['full_name']}: payload no longer present at HEAD "
                          f"(would fail OSM live verification)")
                    continue
                if i:
                    time.sleep(args.pace)
                mark_osm_submitted(db, r["full_name"], None)  # claim-first (at-most-once)
                resp, exc = _post_with_retry(report)
                if resp is None:
                    unmark_osm_submitted(db, r["full_name"])  # release -> retry next run
                    print(f"  [FAIL] {r['full_name']}: {exc}")
                    continue
                try:
                    mark_osm_submitted(db, r["full_name"], resp.get("threat_id"))
                except Exception:  # noqa: BLE001
                    pass
                sent += 1
                bus.mark_submitted("repository", f"https://github.com/{r['full_name']}",
                                   threat_id=resp.get("threat_id"))
                print(f"  [OK]   {r['full_name']} -> {resp.get('threat_id')} "
                      f"({resp.get('status', 'submitted')})")

        # ENRICHMENT UPDATES are handled above (blocked): a real update needs OSM's
        # update-report route, not a re-POST. Not run here.

        # --- 2) Corroborated C2 domain IOC reports (corpus-wide, additive) --
        if domains:
            print(f"\n{len(domains)} corroborated C2 domain IOC(s) "
                  f"(seen in >= {args.min_corroboration} repos, shorteners excluded):")
            for d in domains:
                report = domain_ioc_report(d["host"], d["repos"], d["attr"])
                if not args.confirm:
                    print(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
                    continue
                time.sleep(args.pace)
                _mark_domain_submitted(db, d["host"], d["repos"][0], None)  # claim-first
                resp, exc = _post_with_retry(report)
                if resp is None:
                    print(f"  [FAIL] domain {d['host']}: {exc}")
                    continue
                domains_sent += 1
                bus.mark_submitted("domain", d["host"], threat_id=resp.get("threat_id"))
                try:
                    _mark_domain_submitted(db, d["host"], d["repos"][0], resp.get("threat_id"))
                except Exception:  # noqa: BLE001
                    pass
                print(f"  [OK]   domain {d['host']} ({len(d['repos'])} repos) "
                      f"-> {resp.get('threat_id')}")

        if args.confirm:
            print(f"\nOSM: {sent} new report(s), {domains_sent} C2 domain IOC(s) "
                  f"(pending community review). Enrichment updates need the update-report API.")
        else:
            total = len(rows) + len(domains)
            print(f"\nDry run: NOTHING sent. {total} report(s) above ({len(rows)} new repos, "
                  f"{len(domains)} C2 domain IOCs). Re-run with --confirm to submit.")
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
