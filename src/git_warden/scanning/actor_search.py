"""Actor-account discovery (doc 02 section 2.1).

Threat-actor usernames/organizations from the validated dataset seed the search:
every public repo under a known actor account is a candidate, attributed to that
actor. Handles are curated intelligence (seeded into the actor identifiers); this
module just enumerates and attributes -- it does not invent attributions.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass
class AccountRepo:
    full_name: str
    owner: str
    html_url: str
    actor_key: str


def find_actor_account_repos(
    client, actor_logins: list[tuple[str, str]], *, known: set[str]
) -> list[AccountRepo]:
    """Repos under each (actor_key, github_login), excluding already-known repos."""
    found: dict[str, AccountRepo] = {}
    for actor_key, login in actor_logins:
        try:
            repos = client.list_user_repos(login)
        except Exception as exc:  # one account failing must not lose the rest
            log.warning("actor-account lookup failed",
                        extra={"context": {"login": login, "err": str(exc)}})
            continue
        for repo in repos:
            full = repo.get("full_name")
            if not full or full.casefold() in known:
                continue
            found[full.casefold()] = AccountRepo(
                full_name=full,
                owner=(repo.get("owner") or {}).get("login", ""),
                html_url=repo.get("html_url", ""),
                actor_key=actor_key,
            )
    return list(found.values())
