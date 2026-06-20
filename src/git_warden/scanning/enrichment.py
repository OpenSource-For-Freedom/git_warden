"""Threat-hunting enrichment: expand the GitHub search from OSM intelligence.

The hunt was finding almost only red-team forks because OSM's malicious-repo /
package intelligence was never turned into search criteria. This adds the
strongest pivot: enumerate every other public repo under an owner who already
shipped a known-malicious repo (a bad actor's account holds more bad repos).
Each becomes a candidate that still passes Tier-1/Tier-2 before it confirms.

(The package pivot -- code-searching malicious package names -- rides the
existing IOC code-search path in hunt; see Database.malicious_package_terms.)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass
class OwnerRepo:
    full_name: str
    owner: str
    html_url: str


def find_owner_repos(client, owners, *, known: set[str]) -> list[OwnerRepo]:
    """Other public repos under known-malicious-repo owners, excluding known ones."""
    found: dict[str, OwnerRepo] = {}
    for owner in owners:
        try:
            repos = client.list_user_repos(owner)
        except Exception as exc:  # one account failing must not lose the rest
            log.warning("owner pivot lookup failed",
                        extra={"context": {"owner": owner, "err": str(exc)}})
            continue
        for repo in repos:
            full = repo.get("full_name")
            if not full or full.casefold() in known:
                continue
            found[full.casefold()] = OwnerRepo(
                full_name=full,
                owner=(repo.get("owner") or {}).get("login", ""),
                html_url=repo.get("html_url", ""),
            )
    return list(found.values())
