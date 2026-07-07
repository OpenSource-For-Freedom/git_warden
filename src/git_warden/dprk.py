"""DPRK / Contagious-Interview attribution: multi-signal, evidence-based.

Attribution here is NOT a single tag echoed back from OSM. It is a confidence
tier derived from INDEPENDENT evidence signals we can point at, so a reviewer can
check each one:

  1. tradecraft_vector    -- the confirming rules ARE the Contagious-Interview
     delivery vectors: a VS Code ``folderOpen`` autorun task, or an obfuscated
     ``eval(atob(...))`` loader injected into a build config.
  2. c2_infra_overlap     -- the repo's payload host is one we already extracted
     from a prior DPRK-attributed / campaign repo (the self-sourced infra set).
  3. decoded_family       -- the decoded second stage matches the BeaverTail /
     InvisibleFerret loader fingerprint (module-loader hijack, child_process
     exec, credential paths) that the Tier-2 scanner verified by decoding.
  4. malicious_dependency -- the repo declares a known-malicious npm/pypi package
     used as the campaign's delivery dependency.

Operator policy (Tim): assert ``dprk`` ONLY with 2+ independent signals. A lone
tradecraft vector is reported as ``dprk-consistent-tradecraft``, never attributed
outright -- those vectors are increasingly copied by non-DPRK actors, and flat
over-attribution is what erodes OSM data quality. OSM's own ``dprk`` tag is kept
as corroboration but never counts toward the 2-signal bar: re-asserting OSM's own
claim back to OSM is not new evidence.

Pure and dependency-free (stdlib only) so both the OSM submit path and the
dashboard's finding detail import the SAME assessment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Confirming-rule -> campaign delivery vector. These two vectors are the signature
# tradecraft of the DPRK "Contagious Interview" fake-recruiter coding-task lures.
_VECTOR_RULES = {
    "vscode-autorun": "vscode-folderopen-autorun",
    "eval-decoded": "obfuscated-eval-atob-loader",
    "base64-decode-exec": "obfuscated-eval-atob-loader",
    "py-decode-exec": "obfuscated-eval-atob-loader",
}
CAMPAIGN_VECTORS = frozenset({"vscode-folderopen-autorun", "obfuscated-eval-atob-loader"})

# BeaverTail / InvisibleFerret decoded-stage fingerprints. These are checked ONLY
# against evidence the scanner produced by actually decoding the blob (the
# "second-stage decode" / "dynamic stager" verified markers), plus concrete loader
# indicators, so a benign example line never trips the family signal.
_DECODE_VERIFIED = ("second-stage decode", "dynamic stager")
_FAMILY_MARKERS = (
    "child_process", "module._load", "require('child_process')", "globalthis[",
    "global['_']", "pyshell", "process.env", "login data", "id_rsa",
)

# C2 extraction (kept in lockstep with dashboard.queries._extract_c2 semantics so
# the infra set and the displayed hosts agree).
_HOST_RE = re.compile(r"https?://(?:[^/@\s]*@)?([A-Za-z0-9.\-]+)")
_NOT_C2 = (
    "github.com", "githubusercontent.com", "npmjs.org", "npmjs.com", "pypi.org",
    "python.org", "nodejs.org", "microsoft.com", "vscode.dev", "google.com",
    "nodesource.com", "rustup.rs", "bun.sh", "get.docker.com", "download.docker.com",
    "apt.llvm.org", "packages.microsoft.com", "download.pytorch.org", "dl.google.com",
    "deb.debian.org", "archive.ubuntu.com", "files.pythonhosted.org", "python-poetry.org",
    "get.helm.sh", "cloudflare.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
)
_C2_CATEGORIES = ("download_exec", "network_exfil", "exfiltration")

# actor_key values (already normalized: trim/collapse/casefold) that mean DPRK.
_DPRK_ACTOR_KEYS = frozenset({
    "dprk (north korea)", "lazarus group", "kimsuky", "andariel", "bluenoroff",
})


def campaign_vectors(flags: list[dict]) -> list[str]:
    """Contagious-Interview delivery vectors present in a finding's flags."""
    out: list[str] = []
    for b in flags or []:
        v = _VECTOR_RULES.get(b.get("rule"))
        if v and v not in out:
            out.append(v)
    return out


def c2_hosts_from_flags(flags: list[dict]) -> list[str]:
    """Attacker C2/payload hosts from a finding's confirming / fetch / exfil
    evidence, reputable installers filtered out. Mirrors the dashboard extractor."""
    hosts: list[str] = []
    seen: set[str] = set()
    for b in flags or []:
        if b.get("rule") not in _VECTOR_RULES and b.get("category") not in _C2_CATEGORIES:
            continue
        for h in _HOST_RE.findall(b.get("snippet") or ""):
            host = h.rstrip(".").lower()
            if host in seen or not re.search(r"\.[a-z]{2,}$", host):
                continue
            if any(host == n or host.endswith("." + n) for n in _NOT_C2):
                continue
            seen.add(host)
            hosts.append(host)
    return [h for h in hosts if not any(o != h and o.startswith(h + ".") for o in hosts)]


def is_dprk_actor_key(actor_key: str | None) -> bool:
    """True if an actor_key denotes a DPRK-family actor (OSM/news corroboration)."""
    return bool(actor_key) and actor_key.strip().casefold() in _DPRK_ACTOR_KEYS


@dataclass(frozen=True)
class DprkAssessment:
    """A resolved DPRK attribution: tier + the independent signals behind it."""

    tier: str                              # confirmed | probable | possible | unattributed
    signals: list[str] = field(default_factory=list)   # machine names present
    reasons: list[str] = field(default_factory=list)   # human-readable, one per signal
    c2: list[str] = field(default_factory=list)        # attacker hosts (display + IOC reports)
    vectors: list[str] = field(default_factory=list)   # campaign delivery vectors matched
    osm_corroborated: bool = False         # OSM/news already named DPRK (context only)

    @property
    def attributed(self) -> bool:
        """True when we assert ``dprk`` (2+ independent signals): probable+."""
        return self.tier in ("confirmed", "probable")

    @property
    def label(self) -> str:
        return {
            "confirmed": "CONFIRMED DPRK (Contagious Interview)",
            "probable": "PROBABLE DPRK (Contagious Interview)",
            "possible": "POSSIBLE DPRK-consistent tradecraft",
            "unattributed": "Unattributed",
        }[self.tier]

    @property
    def tag(self) -> str | None:
        """The public campaign tag for the OSM report, gated by tier."""
        if self.attributed:
            return "dprk"
        if self.tier == "possible":
            return "dprk-consistent-tradecraft"
        return None


def assess(
    flags: list[dict],
    actor_key: str | None,
    dprk_infra: set[str] | frozenset[str] | None = None,
    *,
    c2_hosts: list[str] | None = None,
) -> DprkAssessment:
    """Assess DPRK attribution for one confirmed finding from its evidence.

    ``flags`` is the finding's ``raw_payload['bash_findings']``. ``dprk_infra`` is
    the self-sourced set of C2 hosts seen in prior DPRK/campaign repos; pass it
    with the CURRENT repo excluded so a repo never self-corroborates. ``c2_hosts``
    overrides the extractor (callers that already extracted them pass them in).
    """
    flags = flags or []
    infra = {h.lower() for h in (dprk_infra or set())}
    c2 = c2_hosts if c2_hosts is not None else c2_hosts_from_flags(flags)
    vectors = campaign_vectors(flags)

    signals: list[str] = []
    reasons: list[str] = []

    if vectors:
        signals.append("tradecraft_vector")
        reasons.append(
            "Delivery vector matches Contagious-Interview tradecraft: "
            + ", ".join(vectors) + ".")

    overlap = sorted(h for h in c2 if h in infra)
    if overlap:
        signals.append("c2_infra_overlap")
        reasons.append(
            "Payload host overlaps infrastructure seen in prior DPRK/campaign "
            "repos: " + ", ".join(overlap) + ".")

    snippets = " ".join((b.get("snippet") or "") for b in flags).lower()
    decoded_verified = any(m in snippets for m in _DECODE_VERIFIED)
    if decoded_verified and any(m in snippets for m in _FAMILY_MARKERS):
        signals.append("decoded_family")
        reasons.append(
            "Decoded second stage matches the BeaverTail/InvisibleFerret loader "
            "fingerprint (module-loader hijack / child_process exec / credential "
            "paths), verified by decoding the blob.")

    if any(b.get("category") == "malicious_dependency" for b in flags):
        signals.append("malicious_dependency")
        reasons.append(
            "Declares a known-malicious package used as the campaign's delivery "
            "dependency.")

    osm_corroborated = is_dprk_actor_key(actor_key)
    if osm_corroborated:
        reasons.append(
            f"Corroboration (not counted toward attribution): OSM/news already "
            f"names {actor_key}.")

    # Tier from the count of INDEPENDENT evidence signals (OSM tag excluded).
    n = len(signals)
    has_vector = "tradecraft_vector" in signals
    has_infra = "c2_infra_overlap" in signals
    has_decoded = "decoded_family" in signals
    if (has_decoded and (has_vector or has_infra)) or n >= 3:
        tier = "confirmed"
    elif n == 2:
        tier = "probable"
    elif n == 1:
        tier = "possible"
    else:
        tier = "unattributed"

    return DprkAssessment(
        tier=tier, signals=signals, reasons=reasons, c2=c2, vectors=vectors,
        osm_corroborated=osm_corroborated,
    )
