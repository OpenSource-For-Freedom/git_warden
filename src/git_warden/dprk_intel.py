"""Curated DPRK / Contagious-Interview intel for DIRECT attribution matching.

The self-sourced infra set (``Database.dprk_infra_hosts``) only knows hosts this
tool already confirmed, so a fresh campaign C2 attributes as nothing on first
contact. This module adds the other half: a small, curated set of known-bad
indicators matched DIRECTLY, so a known host, a host that fits the operator's
naming shape, or the operator's dropper URL path fingerprint lifts attribution
immediately.

Two design rules, both learned the hard way this month:

* Every indicator must have near-zero legitimate use. Host shapes require the
  campaign's own naming, never a bare PaaS domain. The path fingerprint requires
  the operator's OS-selector-plus-flag structure, not just any fetch.
* No owner-handle matching. The cluster's owners are compromised victims, so a
  handle rule would brand victims. Attribution is code and infrastructure only.

Pure and cached: the JSON is read and compiled once.
"""

from __future__ import annotations

import json
import logging
import re
from functools import lru_cache

from .config import DPRK_INTEL_PATH

log = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _intel() -> dict:
    try:
        data = json.loads(DPRK_INTEL_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.warning("DPRK intel file missing or invalid; direct matching disabled",
                    extra={"context": {"path": str(DPRK_INTEL_PATH)}})
        return {}
    return data if isinstance(data, dict) else {}


@lru_cache(maxsize=1)
def _host_patterns() -> list[re.Pattern]:
    return [re.compile(p, re.I) for p in _intel().get("known_c2_host_patterns", [])]


@lru_cache(maxsize=1)
def _path_patterns() -> list[re.Pattern]:
    return [re.compile(p, re.I) for p in _intel().get("dropper_path_patterns", [])]


@lru_cache(maxsize=1)
def known_hosts() -> frozenset[str]:
    """Exact known-DPRK C2 host names, lowercased."""
    return frozenset(h.lower().rstrip(".") for h in _intel().get("known_c2_hosts", []))


@lru_cache(maxsize=1)
def campaign_packages() -> frozenset[str]:
    """Known Contagious-Interview malicious package names, lowercased."""
    return frozenset(p.lower() for p in _intel().get("campaign_package_names", []))


def is_known_dprk_host(host: str) -> bool:
    """True if ``host`` is a curated DPRK C2, exactly or by the operator's naming shape."""
    h = (host or "").lower().rstrip(".")
    if not h:
        return False
    return h in known_hosts() or any(p.match(h) for p in _host_patterns())


def matches_dropper_path(text: str) -> bool:
    """True if ``text`` contains the operator's dropper URL path fingerprint.

    This is what survives host rotation: the ``/settings/<os>?flag=`` structure is
    the operator's, not the host's, so a brand-new host still matches on the path.
    """
    t = text or ""
    return any(p.search(t) for p in _path_patterns())


def is_campaign_package(name: str) -> bool:
    """True if ``name`` is a known campaign malicious package (exact, lowercased)."""
    return (name or "").lower() in campaign_packages()


def known_infra_hits(hosts) -> list[str]:
    """The subset of ``hosts`` that are curated known-DPRK infrastructure."""
    return sorted({h for h in hosts if is_known_dprk_host(h)})
