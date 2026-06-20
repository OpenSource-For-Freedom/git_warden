"""End-to-end ingestion pipeline test with fake feeds (no network)."""

from __future__ import annotations

import json
from pathlib import Path

from conftest import make_fake_feed, utcnow

from git_warden.db import Database
from git_warden.enums import ActorCategory, FeedSource
from git_warden.pipeline import run_ingestion


def test_pipeline_promotes_corroborated_quarantines_single(tmp_path):
    db = Database.open(tmp_path / "p.sqlite")

    # "APT-X" is reported by two independent feeds; "Lonely" by only one.
    google = make_fake_feed(
        FeedSource.GOOGLE_RSS,
        [("APT-X", ActorCategory.APT.value), ("Lonely", ActorCategory.UNKNOWN.value)],
    )
    cisa = make_fake_feed(FeedSource.FBI_CISA, [("APT-X", ActorCategory.APT.value)])

    summary = run_ingestion(
        db,
        [google, cisa],
        seeds=[],
        run_id="run-1",
        now=utcnow(),
    )

    assert summary["counts"] == {
        "observations": 3,
        "actors": 2,
        "artifacts": 0,
        "promoted": 1,
        "quarantined": 1,
        "feed_errors": 0,
    }
    assert db.get_actor("apt-x")["status"] == "promoted"
    assert db.get_actor("lonely")["status"] == "quarantined"

    # Artifacts written and retain BOTH actors (audit transparency).
    artifacts = summary["artifacts"]
    summary_json = json.loads(Path(artifacts["summary"]).read_text(encoding="utf-8"))
    assert summary_json["actor_total"] == 2
    assert summary_json["actors_by_status"] == {"promoted": 1, "quarantined": 1}
    assert Path(artifacts["csv"]).exists()
    db.close()


def test_pipeline_isolates_a_failing_feed(tmp_path):
    db = Database.open(tmp_path / "p2.sqlite")

    good = make_fake_feed(FeedSource.GOOGLE_RSS, [("APT-X", ActorCategory.APT.value)])

    class BoomFeed(type(good)):
        def collect(self, run_id, seeds):
            raise RuntimeError("feed down")

    boom = BoomFeed()
    boom.source = FeedSource.FBI_CISA

    summary = run_ingestion(db, [good, boom], seeds=[], run_id="run-1", now=utcnow())

    # The good feed still ingested; the failure is recorded, run not aborted.
    assert summary["counts"]["observations"] == 1
    assert summary["counts"]["feed_errors"] == 1
    assert "fbi_cisa" in summary["feed_errors"]
    db.close()


def test_pipeline_with_playbook_still_isolates_unclassified_failure(tmp_path):
    # With the orchestration playbook, an unclassified feed error re-raises
    # immediately (no retry/sleep) and is isolated; run still completes.
    from git_warden.orchestration import load_playbook

    db = Database.open(tmp_path / "p3.sqlite")
    good = make_fake_feed(FeedSource.GOOGLE_RSS, [("APT-X", ActorCategory.APT.value)])

    class BoomFeed(type(good)):
        def collect(self, run_id, seeds):
            raise RuntimeError("feed down")

    boom = BoomFeed()
    boom.source = FeedSource.FBI_CISA

    summary = run_ingestion(
        db, [good, boom], seeds=[], run_id="run-1", now=utcnow(),
        playbook=load_playbook(),
    )
    assert summary["counts"]["observations"] == 1
    assert summary["counts"]["feed_errors"] == 1
    db.close()
