"""The egress schema: no outbound channel, no malicious action.

A package or repository can look dodgy (an encoded blob, an environment dump,
a hook that runs a local script) and still do nothing to anyone. What turns
it into malware is a channel to the attacker. So every confirmation names
one, and is traced back from it:

* ``exfil``      data leaves: a webhook, bot or paste channel, a POST or
                 upload of collected data or secret files;
* ``c2``         the attacker gets control: a reverse shell or C2 framework;
* ``fetch-run``  code comes in from an attacker host and is executed: a
                 fetch-and-run hook or task, a remote class load, a decoded
                 stager whose payload reaches the network;
* ``family``     a fingerprint of a documented malware family (PolinRider,
                 GlassWorm, Shai-Hulud ...) or a dependency OSM lists as
                 malicious: the egress is documented for the family;
* ``none``       no outbound channel: suspicious ("telemetry"-style), never
                 confirmed or submitted.

Shared by git_warden, KNORR (its own gate maps onto the same channels) and
Huginn (vendored with the rest of the analyzer).
"""

from __future__ import annotations

import re

CHANNELS = ("exfil", "c2", "fetch-run", "family", "none")
_RANK = {c: i for i, c in enumerate(CHANNELS)}

_EXFIL_CATEGORIES = frozenset({"exfiltration", "network_exfil"})
_CREDENTIAL_CATEGORIES = frozenset({"credential_access", "credential_harvest"})
_FAMILY_CATEGORIES = frozenset({"malware_signature", "malicious_dependency", "propagation"})
# Network evidence inside a matched line (or a decode-and-exec note).
_NETWORK = re.compile(
    r"https?://|\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b"
    r"|\bfetch\s*\(|XMLHttpRequest|\bhttps?\.(?:get|request)\b|\brequests\.(?:get|post)\b"
    r"|\burllib\b|\bsocket\b|network host|fetch/XHR", re.I)
# A credential read on the same line as a send is exfil by itself
# (requests.post(url, json=dict(os.environ)), fetch(u, {body: JSON.stringify(process.env)})).
_SEND = re.compile(r"\b(?:send|post|upload|sendall)\s*\(", re.I)
# The sink in a source file: an outbound call to some address. Used when the
# confirming line itself is only the source (a credential read, a loader).
SINK = re.compile(
    r"\bfetch\s*\(\s*['\"`]?https?://|\bfetch\s*\(\s*\w+"
    r"|\baxios(?:\.\w+)?\s*\(|\bhttps?\.(?:get|request)\s*\(|XMLHttpRequest|navigator\.sendBeacon"
    r"|\brequests\.(?:post|get|put)\s*\(|\burllib\.request\.urlopen\s*\(|\bhttpx\.\w+\s*\("
    r"|\bsocket\.(?:connect|create_connection)\s*\(|\bnet\.(?:connect|createConnection)\s*\("
    r"|\b(?:curl|wget)\s[^\n]*https?://|\bInvoke-(?:WebRequest|RestMethod)\b"
    r"|\bHttpClient\b|\bURL\s*\(\s*\"https?://[^\"]+\"\s*\)\.openConnection", re.I)


def channel_of(finding) -> str | None:
    """The outbound channel one finding demonstrates, or None."""
    category = _get(finding, "category")
    snippet = _get(finding, "snippet")
    if category in _EXFIL_CATEGORIES:
        return "exfil"
    if category in _CREDENTIAL_CATEGORIES and (_SEND.search(snippet) or _NETWORK.search(snippet)):
        return "exfil"
    if category == "reverse_shell":
        return "c2"
    if category == "download_exec":
        return "fetch-run"
    if category in ("install_hook", "obfuscation", "code_execution") and _NETWORK.search(snippet):
        return "fetch-run"
    if category in _FAMILY_CATEGORIES:
        return "family"
    return None


def sink_channel(confirming) -> str:
    """The channel a same-file outbound call stands for, given what it sinks:
    a credential or secret source makes it exfil; a loader makes it fetch-run."""
    cats = {_get(f, "category") for f in confirming}
    return "exfil" if cats & (_CREDENTIAL_CATEGORIES | _EXFIL_CATEGORIES) else "fetch-run"


def classify(confirming, findings=(), *, scanner_flagged: bool = False):
    """(channel, the findings that show it) for one confirmed result.

    The confirming findings decide first. When they carry no channel (a
    review-tier loader, a lone env dump), a channel elsewhere in the SAME
    files counts too: the stealer reads in one line and posts in the next.
    A malware-specific scanner hit (YARA rules are family fingerprints)
    counts as ``family``.
    """
    best, shown = _best(confirming)
    if best == "none":
        files = {_get(f, "file") for f in confirming}
        best, shown = _best([f for f in findings if _get(f, "file") in files])
    if best == "none" and scanner_flagged:
        return "family", []
    return best, shown


def describe(channel: str, shown) -> str:
    """A plain sentence naming the channel and where it is."""
    where = ", ".join(dict.fromkeys(_loc(f) for f in shown[:3])) or "see evidence"
    return {
        "exfil": f"sends data out ({where})",
        "c2": f"opens a remote shell or C2 channel ({where})",
        "fetch-run": f"fetches code from a remote host and runs it ({where})",
        "family": f"carries a documented malware family's fingerprint ({where})",
    }.get(channel, "no outbound channel found")


def _best(findings):
    best, shown = "none", []
    for f in findings:
        ch = channel_of(f)
        if ch is None:
            continue
        if _RANK[ch] < _RANK[best]:
            best, shown = ch, [f]
        elif ch == best:
            shown.append(f)
    return best, shown


def _get(finding, key: str) -> str:
    value = finding.get(key) if isinstance(finding, dict) else getattr(finding, key, "")
    return str(value or "")


def _loc(finding) -> str:
    line = _get(finding, "line")
    return f"{_get(finding, 'file')}:{line}" if line and line != "0" else _get(finding, "file")
