"""Tier-1 screening: score a repo on name + README, no cloning (doc 02 section 3.1).

Decides the *entrypoints* -- which repos are worth the cost of a Tier-2 clone +
scanner run. A repository name alone is a weak signal (doc 02 section 2.2: a
bland name is a hiding technique and "cannot, by itself, justify a flag"), so we
score the name and README *jointly* and require corroborating evidence before
promoting to Tier-2.

Note the distinction: promoting to Tier-2 means "worth investigating by cloning"
-- it is not a confirmed finding. Confirmation comes from the Tier-2 scanners.
So name-driven promotion is acceptable here; the strict bar applies to gold.

``score_repo`` is pure (name/description/readme in, result out) so thresholds
and signals can be tuned and tested offline.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Confusable/homoglyph map (doc 02 2.2): common Cyrillic/Greek lookalikes and a
# few leet substitutions folded to a Latin "skeleton" so a visually-identical
# tool-name impersonation is detected even at edit distance N.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ѕ": "s", "ј": "j", "һ": "h", "к": "k", "м": "m", "н": "h", "т": "t", "в": "b",
    "ո": "n", "ε": "e", "ο": "o", "α": "a", "ρ": "p", "ν": "v", "τ": "t", "ι": "i",
    "κ": "k", "μ": "m", "ѵ": "v",
    "0": "o", "1": "l", "3": "e", "5": "s",
})


def _skeleton(text: str) -> str:
    """NFKC-normalize, casefold, and fold confusables to a comparison skeleton."""
    return unicodedata.normalize("NFKC", text).casefold().translate(_CONFUSABLES)

# Signal weights. Promotion needs corroboration -- see DEFAULT_TIER2_THRESHOLD.
STRONG = 3
MEDIUM = 2
WEAK = 1
DEFAULT_TIER2_THRESHOLD = 4

# Overtly malicious tokens that, in a repo NAME, suggest intent. Deliberately
# tight: common red-team terms (c2, exploit, payload, beacon, rat) are excluded
# because legitimate tools use them -- they would add noise.
_NAME_TOKENS = (
    "malware",
    "stealer",
    "keylogger",
    "grabber",
    "backdoor",
    "trojan",
    "ransomware",
    "exfil",
    "weaponized",
    "weaponised",
)

# README heuristics (case-insensitive).
_EXFIL = re.compile(
    r"discord(app)?\.com/api/webhooks/|api\.telegram\.org/bot|webhook\.site|"
    r"requestcatcher\.com|pipedream\.net|pastebin\.com/raw|paste\.ee|"
    r"token\s*grabber|cookie\s*stealer|wallet\s*drainer|seed\s*phrase",
    re.IGNORECASE,
)
_REMOTE_EXEC = re.compile(
    r"curl\s+[^\n|]+\|\s*(sh|bash)|wget\s+[^\n|]+\|\s*(sh|bash)|"
    r"iex\s*\(|invoke-expression|-enc(odedcommand)?\b|frombase64string|"
    r"certutil\s+-urlcache",
    re.IGNORECASE,
)
_OBFUSCATION = re.compile(
    r"[A-Za-z0-9+/]{120,}={0,2}|(?:\\x[0-9a-fA-F]{2}){20,}|"
    r"\beval\s*\(|\bexec\s*\(|atob\s*\(|base64\s*-d|frombase64string",
    re.IGNORECASE,
)
_STEALER = re.compile(
    r"\b(stealer|keylogger|grabber|clipper|infostealer|credential\s*harvest)\b",
    re.IGNORECASE,
)


@dataclass
class ScreeningResult:
    full_name: str
    score: int
    signals: list[tuple[str, int]] = field(default_factory=list)
    tier2: bool = False

    @property
    def signal_names(self) -> list[str]:
        return [name for name, _ in self.signals]


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a or not b:
        return len(a) + len(b)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _short_name(name: str) -> str:
    return name.split("/", 1)[-1].casefold()


def _name_signals(
    short: str, description: str, known_terms, renamed_fork: bool
) -> list[tuple[str, int]]:
    signals: list[tuple[str, int]] = []

    # Compare on confusable-folded skeletons so homoglyph impersonations match.
    skel = _skeleton(short)
    # Carry both the raw casefold and the skeleton of each term, so the
    # homoglyph test compares raw-vs-raw, not raw-vs-skeleton (eval verify #4).
    term_info = [(t, t.casefold(), _skeleton(t)) for t in known_terms if t]

    # Homoglyph/confusable swap: skeletons match but the RAW names differ.
    homoglyph = next((t for t, traw, ts in term_info if ts and ts == skel and short != traw), None)
    wrapped = next((t for t, traw, ts in term_info if ts and ts in skel and ts != skel), None)
    near = None
    if not homoglyph and not wrapped:
        near = next(
            (t for t, traw, ts in term_info
             if ts and len(ts) >= 4 and 1 <= _levenshtein(skel, ts) <= 2),
            None,
        )

    if homoglyph:
        signals.append((f"homoglyph-of:{homoglyph}", STRONG))
    elif near:
        # Lookalike of a known tool (e.g. "shiver" ~ "sliver"): strong on its own.
        signals.append((f"typosquat-of:{near}", STRONG))
    elif wrapped and not renamed_fork:
        # A *non-fork* repo embedding a tool name is notable; for a fork it's
        # expected (it forked that tool), so we don't double-count it there.
        signals.append((f"wraps-known-tool:{wrapped}", MEDIUM))
    elif renamed_fork and not wrapped:
        # A fork renamed to drop the tool name entirely is hiding its lineage --
        # more suspicious than one that kept the name.
        signals.append(("lineage-obscured-rename", MEDIUM))

    haystack = f"{short} {description}".casefold()
    token = next((tok for tok in _NAME_TOKENS if tok in haystack), None)
    if token:
        signals.append((f"malicious-name-token:{token}", MEDIUM))
    return signals


def score_repo(
    *,
    name: str,
    full_name: str,
    description: str | None = None,
    readme: str | None = None,
    known_terms=(),
    renamed_fork: bool = False,
    tier2_threshold: int = DEFAULT_TIER2_THRESHOLD,
) -> ScreeningResult:
    """Score one repo's name + README. Higher score = more worth a Tier-2 clone."""
    short = _short_name(name or full_name)
    signals = _name_signals(short, description or "", tuple(known_terms), renamed_fork)

    if renamed_fork:
        signals.append(("renamed-fork-of-pinned", MEDIUM))

    text = readme or ""
    if _EXFIL.search(text):
        signals.append(("readme-exfil-indicator", STRONG))
    if _REMOTE_EXEC.search(text):
        signals.append(("readme-remote-exec", STRONG))
    if _OBFUSCATION.search(text):
        signals.append(("readme-obfuscation", MEDIUM))
    if _STEALER.search(text):
        signals.append(("readme-stealer-terms", MEDIUM))
    if len(text.strip()) < 50:
        signals.append(("minimal-readme", WEAK))

    score = sum(weight for _, weight in signals)
    return ScreeningResult(full_name=full_name, score=score, signals=signals,
                           tier2=score >= tier2_threshold)
