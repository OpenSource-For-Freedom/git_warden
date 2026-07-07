"""Multi-actor threat attribution: data-driven, evidence + intel signals.

Generalizes the DPRK-only engine (see :mod:`~git_warden.dprk`) into a registry
that maps the seeded threat actors (config/seed_actors.json) onto their **origin**
(North Korea / Russia / China / Iran / Cybercrime) and attributes a finding to a
country. Adding an actor is a DATA entry in ``ACTOR_ORIGIN`` -- the engine, the
dashboard hubs, and the OSM tags pick it up automatically.

Attribution discipline is uniform (Tim's DPRK policy, applied to every actor):

  * 2+ independent EVIDENCE signals (our own detectors: tradecraft vector, C2
    infra overlap, decoded malware family, malicious dependency) -> attributed.
  * a specific NAMED-GROUP intel attribution (OSM/news naming e.g. APT28, Lazarus
    Group, Kimsuky) -> attributed. A named group is a reviewed human call, not the
    generic-vector guess the copycat guard protects against.
  * a bare NATION tag ("russia", "dprk") with nothing else -> a lead (possible),
    never an assertion.

Today only North Korea carries evidence detectors (the Contagious-Interview
tradecraft in :mod:`~git_warden.dprk`); every other origin attributes from named
intel now and gains its own detectors as we add them -- drop a vector rule /
family marker into a campaign profile and the whole pipeline uses it.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import dprk

# --- actor -> origin ---------------------------------------------------------
# Canonical actor_key (normalized: trim/collapse/casefold, as attribution.py
# stores it) -> origin country/bloc. Mirrors config/seed_actors.json categories.
# ADD A COUNTRY: map its actors here; nothing else needs to change.
ACTOR_ORIGIN = {
    # North Korea (DPRK)
    "lazarus group": "North Korea", "tradertraitor": "North Korea",
    "famous chollima": "North Korea", "kimsuky": "North Korea",
    "dprk (north korea)": "North Korea",
    # Russia
    "apt28": "Russia", "apt29": "Russia", "sandworm team": "Russia",
    "turla": "Russia", "gamaredon group": "Russia", "russia": "Russia",
    # China
    "apt41": "China", "volt typhoon": "China", "china": "China",
    # Iran
    "muddywater": "Iran", "oilrig": "Iran", "charming kitten": "Iran",
    "iran": "Iran",
    # Financially-motivated / non-state
    "fin7": "Cybercrime", "scattered spider": "Cybercrime",
    "wizard spider": "Cybercrime", "shai-hulud": "Cybercrime",
}
# Bare nation/threat-class descriptors: real as a lead, but NOT a specific group,
# so they never attribute on their own (the copycat guard).
NATION_TERMS = frozenset({"dprk (north korea)", "russia", "china", "iran", "apt"})

# Per-origin OSM campaign tags emitted when we attribute at probable+.
_ORIGIN_TAGS = {
    "North Korea": ["dprk", "north-korea"],
    "Russia": ["russia"],
    "China": ["china"],
    "Iran": ["iran"],
    "Cybercrime": ["cybercrime"],
}


def _norm(actor_key: str | None) -> str:
    k = (actor_key or "").strip().casefold()
    # Tolerate legacy provenance suffixes ("DPRK (North Korea) (per OSM)") so an
    # older-format actor_key still maps to its origin.
    i = k.find(" (per ")
    return k[:i].strip() if i != -1 else k


def origin_for_actor(actor_key: str | None) -> str | None:
    """Origin country/bloc for a stored actor_key, or None if unmapped."""
    return ACTOR_ORIGIN.get(_norm(actor_key))


def is_named_group(actor_key: str | None) -> bool:
    """True if actor_key is a SPECIFIC group (APT28, Lazarus, ...), not a bare
    nation tag -- a specific named attribution counts toward attribution."""
    k = _norm(actor_key)
    return bool(k) and k in ACTOR_ORIGIN and k not in NATION_TERMS


@dataclass(frozen=True)
class Attribution:
    """A resolved, country-level attribution with the reasoning behind it."""

    origin: str | None                       # country/bloc, or None
    tier: str = "unattributed"               # confirmed|probable|possible|unattributed
    actor: str | None = None                 # specific group label, if named
    campaign: str | None = None              # human campaign name, if known
    signals: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    c2: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    @property
    def attributed(self) -> bool:
        return self.tier in ("confirmed", "probable")

    @property
    def label(self) -> str:
        if not self.origin:
            return "Unattributed"
        who = self.actor or self.origin
        return {
            "confirmed": f"CONFIRMED {who}",
            "probable": f"PROBABLE {who}",
            "possible": f"POSSIBLE {who}-consistent",
        }.get(self.tier, self.origin)


def attribute(flags: list[dict], actor_key: str | None,
              dprk_infra: set[str] | frozenset[str] | None = None) -> Attribution:
    """Attribute a confirmed finding to a country from evidence + intel.

    ``dprk_infra`` is the self-sourced North-Korea C2 set (this repo excluded).
    Evidence attribution is North-Korea-only today; every other origin attributes
    from a specific named-group intel tag until it grows its own detectors.
    """
    d = dprk.assess(flags, actor_key, dprk_infra)     # DPRK evidence assessment
    intel_origin = origin_for_actor(actor_key)
    named = is_named_group(actor_key)

    # 1) DPRK evidence clears the 2-signal bar -> attribute North Korea on evidence.
    if d.attributed:
        actor = actor_key if named and intel_origin == "North Korea" else None
        return Attribution(
            origin="North Korea", tier=d.tier, actor=actor,
            campaign="Contagious Interview", signals=list(d.signals),
            reasons=list(d.reasons), c2=list(d.c2),
            tags=["contagious-interview", "fake-recruiter"] + _ORIGIN_TAGS["North Korea"])

    # 2) A specific NAMED group from intel is itself an attribution (any country).
    if named:
        origin = intel_origin
        return Attribution(
            origin=origin, tier="probable", actor=actor_key,
            signals=["named_group_intel"],
            reasons=[f"OSM/news attributes this to the named threat group "
                     f"'{actor_key}' ({origin})."],
            c2=list(d.c2),
            tags=[actor_key.replace(" ", "-").casefold()] + _ORIGIN_TAGS.get(origin, []))

    # 3) One DPRK evidence signal -> DPRK-consistent lead (not asserted).
    if d.tier == "possible":
        return Attribution(
            origin="North Korea", tier="possible", campaign="Contagious Interview",
            signals=list(d.signals), reasons=list(d.reasons), c2=list(d.c2),
            tags=["dprk-consistent-tradecraft"])

    # 4) A bare nation tag with nothing else -> a country lead.
    if intel_origin:
        return Attribution(
            origin=intel_origin, tier="possible", signals=["nation_tag"],
            reasons=[f"Generic {intel_origin} nation tag from intel; no "
                     f"corroborating evidence yet."],
            c2=list(d.c2))

    return Attribution(origin=None, tier="unattributed", c2=list(d.c2))
