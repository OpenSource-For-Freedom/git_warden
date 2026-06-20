"""Extract searchable IOCs from OSM threat text; the discovery multiplier.

OSM is a proof-of-concept corpus: each report's ``payload_description`` names
the concrete infrastructure a malicious repo/package uses (Discord/Telegram
exfil webhooks, C2 domains, file hashes). We mine those IOCs and mirror them
into our own GitHub code search; a repo exfiltrating to the same webhook or
domain is very likely part of the same campaign that OSM has not fully mapped.

``extract_iocs`` is pure so it is unit-tested against fixture text.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

# Infrastructure/doc domains that show up in threat text but are not IOCs --
# excluded so they don't pollute the search pivot set.
BENIGN_DOMAINS = frozenset({
    "github.com",
    "raw.githubusercontent.com",
    "githubusercontent.com",
    "objects.githubusercontent.com",
    "schemas.openxmlformats.org",
    "react.dev",
    "lua.org",
    "www.lua.org",
    "momentjs.com",
    "npmjs.com",
    "www.npmjs.com",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "w3.org",
    "www.w3.org",
    # Common legitimate API/infra endpoints seen in threat text (not IOCs).
    "api.anthropic.com",
    "api.openai.com",
    "api.mainnet-beta.solana.com",
    "clang.llvm.org",
    "go.dev",
    "golang.org",
    "crates.io",
    # Generic exfil HOSTS (captured as webhooks/telegram already); useless as
    # domain search terms because they appear in millions of repos.
    "discord.com",
    "discordapp.com",
    "api.telegram.org",
    "telegram.org",
    "t.me",
    "pastebin.com",
    "webhook.site",
    # Legit infra/services malware references but that are not C2 (observed as
    # noise in live discovery). This denylist is maintained as we see more.
    "publicsuffix.org",
    "curl.se",
    "jsonkeeper.com",
    "www.jsonkeeper.com",
    "ggpolarbear.com",
    "clientbp.ggpolarbear.com",
    "sentry.io",
    # Legit AI/inference APIs on suspicious-looking TLDs (.xyz); referenced by
    # many benign ML repos (the hazyresearch/m2, evo-design/evo false positives).
    "api.together.xyz",
    "together.xyz",
    "together.ai",
})

_DISCORD = re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/[\w-]+")
_TELEGRAM = re.compile(r"api\.telegram\.org/bot[\w:.\-]+")
_DOMAIN = re.compile(r"https?://([a-z0-9.\-]+\.[a-z]{2,})", re.IGNORECASE)
_HASH = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)

# A domain is only treated as a C2/exfil IOC when it appears on a line about
# exfiltration/destination/callback; not every URL mentioned in a report.
_C2_CONTEXT = re.compile(
    r"exfil|destinat|\bc2\b|command.?and.?control|webhook|beacon|callback|"
    r"upload|network\s+request|posts?\s+to|sends?\s+(?:data|to)|connect",
    re.IGNORECASE,
)


@dataclass
class IocSet:
    """Counters of IOCs, so we can rank by how many reports reference each."""

    webhooks: Counter = field(default_factory=Counter)
    telegram: Counter = field(default_factory=Counter)
    domains: Counter = field(default_factory=Counter)
    hashes: Counter = field(default_factory=Counter)

    def merge(self, other: IocSet) -> None:
        self.webhooks.update(other.webhooks)
        self.telegram.update(other.telegram)
        self.domains.update(other.domains)
        self.hashes.update(other.hashes)

    def searchable(self) -> list[str]:
        """High-value strings worth a GitHub code search (webhooks + domains)."""
        return list(self.webhooks) + list(self.telegram) + list(self.domains)


# Disposable hosting where attackers stand up throwaway C2/exfil endpoints.
# NOTE: *.github.io / *.gitlab.io deliberately EXCLUDED (eval finding #10) --
# Pages domains host millions of benign sites and flooded discovery; they are
# not throwaway C2 like the entries below.
_EPHEMERAL_SUFFIXES = (
    ".onrender.com", ".workers.dev", ".rbmock.dev", ".repl.co", ".replit.dev",
    ".glitch.me", ".pages.dev", ".ngrok.io", ".ngrok-free.app", ".ngrok.app",
    ".trycloudflare.com", ".serveo.net", ".r2.dev", ".deno.dev", ".fly.dev",
    ".herokuapp.com", ".surge.sh",
)
# TLDs disproportionately used for malicious/throwaway domains.
_SUSPICIOUS_TLDS = (
    ".info", ".xyz", ".top", ".cc", ".gq", ".tk", ".ml", ".ga", ".cf", ".icu",
    ".click", ".shop", ".online", ".site", ".fun", ".lol", ".su", ".live",
    ".sbs", ".cfd", ".rest", ".buzz", ".monster",
)


def is_attacker_host(domain: str) -> bool:
    """True if a domain looks attacker-owned (ephemeral host or suspicious TLD).

    A pattern allowlist, not a denylist: corporate/cloud/CDN domains (azure.com,
    googleapis.com, ...) simply don't match, so they are never searched. Trades
    some recall (a plain attacker .com is missed) for high precision; the
    chosen no-noise stance; Tier-2 still catches what discovery misses.
    """
    d = domain.lower()
    return d.endswith(_EPHEMERAL_SUFFIXES) or d.endswith(_SUSPICIOUS_TLDS)


def extract_iocs(text: str | None) -> IocSet:
    """Parse one threat-description blob into an IocSet.

    Webhooks/telegram/hashes are unambiguous and extracted anywhere; domains are
    only taken from lines in an exfil/C2 context, so incidental URLs (docs, code
    references) don't pollute the search pivot set.
    """
    text = text or ""
    domains: Counter = Counter()
    for line in text.splitlines():
        if _C2_CONTEXT.search(line):
            for domain in _DOMAIN.findall(line):
                low = domain.lower()
                if low not in BENIGN_DOMAINS:
                    domains[low] += 1
    return IocSet(
        webhooks=Counter(_DISCORD.findall(text)),
        telegram=Counter(_TELEGRAM.findall(text)),
        domains=domains,
        hashes=Counter(h.lower() for h in _HASH.findall(text)),
    )


_CODE_MAX_BYTES = 1_000_000


def extract_code_iocs(text: str | None) -> IocSet:
    """Extract IOCs from source CODE (the learning loop, expand core search).

    Unlike :func:`extract_iocs` (tuned for OSM threat prose), code *is* the
    behavior, so domains are not C2-context-gated; instead only
    attacker-owned-looking domains are kept (high precision). Webhooks/telegram/
    hashes are taken anywhere.
    """
    text = text or ""
    domains = Counter(
        d.lower()
        for d in _DOMAIN.findall(text)
        if d.lower() not in BENIGN_DOMAINS and is_attacker_host(d.lower())
    )
    return IocSet(
        webhooks=Counter(_DISCORD.findall(text)),
        telegram=Counter(_TELEGRAM.findall(text)),
        domains=domains,
        hashes=Counter(),  # file hashes from prose; code-derived hashes are noisy
    )


def extract_repo_iocs(root) -> IocSet:
    """Walk a cloned repo's text files and aggregate code IOCs."""
    from pathlib import Path

    agg = IocSet()
    for path in Path(root).rglob("*"):
        if not path.is_file() or ".git" in path.parts:
            continue
        try:
            if path.stat().st_size > _CODE_MAX_BYTES:
                continue
            agg.merge(extract_code_iocs(path.read_text(encoding="utf-8", errors="ignore")))
        except OSError:
            continue
    return agg
