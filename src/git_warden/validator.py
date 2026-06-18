"""Validation: promote, quarantine, or hold actors by corroboration.

The strictest component in the system (PRD section 11). Its only job is to
decide each actor's status from how many *independent* feeds corroborate it:

* ``>= MIN_CORROBORATING_SOURCES`` distinct feeds -> ``PROMOTED``
* exactly one feed                                -> ``QUARANTINED`` (manual review)
* a recognized false positive (``REJECTED``)      -> left untouched, never revived

It reads the append-only observation/corroboration data and writes only the
actor status, so it is safe to re-run over the same data.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

from .config import MIN_CORROBORATING_SOURCES
from .db import Database
from .enums import ActorStatus

log = logging.getLogger(__name__)


def validate_actors(
    db: Database,
    actor_keys: Iterable[str],
    min_sources: int = MIN_CORROBORATING_SOURCES,
) -> dict[str, ActorStatus]:
    """Recompute and persist status for each actor. Returns the decisions.

    A manual ``REJECTED`` verdict is sticky: the validator will not auto-promote
    a known false positive even if new feeds corroborate it. Re-rejecting is a
    human action.
    """
    results: dict[str, ActorStatus] = {}
    for actor_key in actor_keys:
        row = db.get_actor(actor_key)
        if row is None:
            log.warning("validate: actor not found", extra={"context": {"actor": actor_key}})
            continue

        if row["status"] == ActorStatus.REJECTED.value:
            results[actor_key] = ActorStatus.REJECTED
            continue

        count = db.corroborating_source_count(actor_key)
        status = ActorStatus.PROMOTED if count >= min_sources else ActorStatus.QUARANTINED
        db.set_actor_status(actor_key, status.value)
        results[actor_key] = status
        log.info(
            "validated actor",
            extra={"context": {"actor": actor_key, "sources": count, "status": status.value}},
        )
    return results
