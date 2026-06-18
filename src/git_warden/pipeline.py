"""Ingestion pipeline: feeds -> raw observations -> validation -> artifacts.

Orchestrates one ingestion run end to end. Per-feed failures are isolated and
logged rather than aborting the whole run -- an early nod to the resilience the
Phase-2 orchestration layer formalizes (doc 05).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from .artifacts import write_run_artifacts
from .config import MIN_CORROBORATING_SOURCES
from .db import Database
from .enums import ActorStatus, RunStatus
from .feeds.base import ArtifactFeed, Feed
from .models import SeedActor
from .validator import validate_actors

log = logging.getLogger(__name__)


def default_run_id(now: datetime) -> str:
    return f"run-{now.strftime('%Y%m%dT%H%M%SZ')}"


def run_ingestion(
    db: Database,
    feeds: list[Feed],
    seeds: list[SeedActor],
    *,
    artifact_feeds: list[ArtifactFeed] | None = None,
    run_id: str | None = None,
    now: datetime | None = None,
    min_sources: int = MIN_CORROBORATING_SOURCES,
    write_artifacts: bool = True,
) -> dict:
    """Execute one ingestion run and return its summary dict."""
    artifact_feeds = artifact_feeds or []
    now = now or datetime.now(UTC)
    run_id = run_id or default_run_id(now)

    all_sources = [f.source.value for f in feeds] + [f.source.value for f in artifact_feeds]
    db.start_run(
        run_id,
        now,
        config={"feeds": all_sources, "min_sources": min_sources},
    )
    log.info("ingestion run started", extra={"context": {"run_id": run_id}})

    touched: set[str] = set()
    observation_count = 0
    feed_errors: dict[str, str] = {}

    for feed in feeds:
        try:
            observations = feed.collect(run_id, seeds)
        except Exception as exc:  # isolate one feed's failure from the run
            feed_errors[feed.source.value] = str(exc)
            log.exception(
                "feed collection failed",
                extra={"context": {"feed": feed.source.value}},
            )
            continue

        for obs in observations:
            obs_id = db.record_observation(obs)
            observation_count += 1
            db.ensure_actor(obs.actor_key, obs.actor_name, obs.category.value, run_id)
            db.link_actor_source(obs.actor_key, obs.source.value, obs_id)
            for ident in obs.identifiers:
                db.add_identifier(obs.actor_key, ident)
            for campaign in obs.campaigns:
                db.add_campaign(obs.actor_key, campaign)
            touched.add(obs.actor_key)

    # Indicator feeds (OSM): populate the malicious-artifact scan list.
    artifact_count = 0
    for afeed in artifact_feeds:
        try:
            artifacts = afeed.collect_artifacts(run_id)
        except Exception as exc:  # isolate; an artifact-feed failure must not abort
            feed_errors[afeed.source.value] = str(exc)
            log.exception(
                "artifact feed collection failed",
                extra={"context": {"feed": afeed.source.value}},
            )
            continue
        for artifact in artifacts:
            db.upsert_artifact(artifact, run_id)
            artifact_count += 1

    decisions = validate_actors(db, touched, min_sources=min_sources)
    promoted = sum(1 for s in decisions.values() if s is ActorStatus.PROMOTED)
    quarantined = sum(1 for s in decisions.values() if s is ActorStatus.QUARANTINED)

    counts = {
        "observations": observation_count,
        "actors": len(touched),
        "artifacts": artifact_count,
        "promoted": promoted,
        "quarantined": quarantined,
        "feed_errors": len(feed_errors),
    }
    # A run is only FAILED if every feed errored; partial failures still complete.
    total_feeds = len(feeds) + len(artifact_feeds)
    all_failed = total_feeds > 0 and len(feed_errors) == total_feeds
    status = RunStatus.FAILED if all_failed else RunStatus.COMPLETED
    db.finish_run(run_id, datetime.now(UTC), status, counts)

    summary = {"run_id": run_id, "counts": counts, "feed_errors": feed_errors}
    if write_artifacts:
        paths = write_run_artifacts(db, run_id)
        summary["artifacts"] = {k: str(v) for k, v in paths.items()}

    log.info("ingestion run finished", extra={"context": summary})
    return summary
