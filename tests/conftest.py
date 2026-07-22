"""Shared test helpers: offline HTTP + feed fakes (no network in tests)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from git_warden.enums import FeedSource
from git_warden.feeds.base import ArtifactFeed, Feed
from git_warden.models import MaliciousArtifact, SourceObservation


@pytest.fixture(autouse=True)
def _isolate_search_telemetry(tmp_path, monkeypatch):
    """Keep test searches out of the operator's live telemetry log.

    Every test that exercises ``search_code`` publishes a telemetry event, and
    six suites do. Without this the fake queries and simulated throttles land in
    data/search_telemetry.jsonl and show up on the dashboard as though a real
    hunt had been throttled nine times, which is exactly the sort of false
    signal an operator would act on.
    """
    from git_warden.github import telemetry

    monkeypatch.setattr(telemetry, "SEARCH_LOG", tmp_path / "search_telemetry.jsonl")


def utcnow() -> datetime:
    return datetime(2026, 6, 18, tzinfo=UTC)


class FakeHttpClient:
    """Returns canned text for any URL; records calls for assertions."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.calls: list[tuple[str, dict | None]] = []

    def get_text(self, url: str, *, params=None, headers=None) -> str:
        self.calls.append((url, params))
        return self.text


def make_fake_feed(source: FeedSource, actor_specs: list[tuple[str, str]]) -> Feed:
    """A feed that emits one observation per (actor_name, category) spec."""

    class _FakeFeed(Feed):
        def collect(self, run_id, seeds):  # noqa: ARG002
            return [
                SourceObservation(
                    run_id=run_id,
                    source=source,
                    observed_at=utcnow(),
                    actor_name=name,
                    category=category,
                )
                for name, category in actor_specs
            ]

    _FakeFeed.source = source
    return _FakeFeed()


def make_fake_artifact_feed(
    source: FeedSource, artifacts: list[MaliciousArtifact]
) -> ArtifactFeed:
    """An artifact feed that emits a fixed list of malicious artifacts."""

    class _FakeArtifactFeed(ArtifactFeed):
        def collect_artifacts(self, run_id):  # noqa: ARG002
            return list(artifacts)

    _FakeArtifactFeed.source = source
    return _FakeArtifactFeed()
