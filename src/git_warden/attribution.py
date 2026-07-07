"""Threat-actor attribution shared across feeds (PRD section 7.1 vocabulary).

Every source that can name a threat actor -- OSM's own tags, a Hacker News /
Google News writeup -- attributes using the SAME normalized ``actor_key``, so
a real actor (e.g. Lazarus Group) links to ONE canonical entity in
``threat_actors`` regardless of which breadcrumb found it. Earlier this baked
the source into the key itself ("DPRK (North Korea) (per OSM)"), which meant
the SAME actor named by two different sources registered as two separate,
disconnected "candidate" rows instead of one tracked entity -- the providence
("per OSM" / "per Hacker News") is display-only and belongs in ``reasoning``,
never in the identity key.

``Attribution.key`` uses the SAME normalization as :class:`~.models.SeedActor`
(``_normalize_name``: trim, collapse space, casefold) so a specific-group match
lands on the EXACT existing ``threat_actors`` row seeded from
seed_actors.json, rather than creating a parallel duplicate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .config import SEED_ACTORS_PATH
from .models import _normalize_name
from .seeds import load_seeds

# Generic nation/threat-class descriptors a source may use without naming a
# specific group (OSM's own tag vocabulary; "DPRK", "APT" as bare terms).
# These have no existing seed_actors.json entry to link to, so they register
# as their own stable (source-agnostic) candidate actor on first use.
_NATION_LABELS = {
    "dprk": "DPRK (North Korea)", "north korea": "DPRK (North Korea)",
    "lazarus": "Lazarus Group", "kimsuky": "Kimsuky", "apt": "APT",
    "russia": "Russia", "china": "China", "iran": "Iran",
}


@dataclass(frozen=True)
class Attribution:
    """A resolved actor attribution: the canonical registry key + display name."""

    key: str            # normalized, source-agnostic; links to threat_actors
    label: str           # human-readable canonical name for display


def attribution_for_tags(tags: list[str]) -> Attribution | None:
    """Map a source's own tag list (e.g. OSM's) to an Attribution, or None."""
    for tag in tags:
        label = _NATION_LABELS.get(str(tag).strip().lower())
        if label:
            return Attribution(key=_normalize_name(label), label=label)
    return None


def load_actor_terms(path=SEED_ACTORS_PATH) -> dict[str, str]:
    """{lowercased name/alias: canonical actor name} for every seed actor.

    The same vocabulary the ingest layer validates against (seed_actors.json:
    Lazarus Group, APT28, Kimsuky, ...), so a news writeup naming a group is
    attributed with the identical canonical name used elsewhere in the tool.
    """
    terms: dict[str, str] = {}
    for actor in load_seeds(path):
        for term in actor.query_terms():
            terms.setdefault(term.casefold(), actor.name)
    return terms


def match_actors_in_text(text: str, actor_terms: dict[str, str]) -> list[str]:
    """Canonical actor names (specific groups) mentioned in free text.

    Longer terms are checked first so "APT28" wins over a shorter substring
    that happens to also match; word-boundaried so "APT" alone never matches
    inside "APT28" and vice versa.
    """
    if not text:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for term in sorted(actor_terms, key=len, reverse=True):
        if re.search(rf"\b{re.escape(term)}\b", text, re.I):
            name = actor_terms[term]
            if name not in seen:
                seen.add(name)
                found.append(name)
    return found


def attribution_for_text(text: str, actor_terms: dict[str, str]) -> Attribution | None:
    """Best attribution for free text: a NAMED group beats a bare nation tag.

    Checks specific actors (Lazarus Group, APT28, Kimsuky, ...) first since
    that links to the real, already-tracked registry entity and is more
    actionable than a generic "DPRK"/"APT" mention; falls back to the
    nation-level vocabulary only if no specific group is named.
    """
    actors = match_actors_in_text(text, actor_terms)
    if actors:
        return Attribution(key=_normalize_name(actors[0]), label=actors[0])
    for term, label in _NATION_LABELS.items():
        if re.search(rf"\b{re.escape(term)}\b", text, re.I):
            return Attribution(key=_normalize_name(label), label=label)
    return None
