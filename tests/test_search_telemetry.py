"""Search telemetry: the client publishes what it queries, the dashboard reads it."""

from __future__ import annotations

import json
import time

import pytest

from git_warden.github import telemetry


@pytest.fixture
def log(tmp_path, monkeypatch):
    path = tmp_path / "search_telemetry.jsonl"
    monkeypatch.setattr(telemetry, "SEARCH_LOG", path)
    return path


def test_record_then_read_back(log):
    telemetry.record(event="search", query="folderOpen curl", results=3, interval=8.0)
    telemetry.record(event="search", query="tasks.json", results=0, interval=8.0)
    recent = telemetry.recent()
    assert [e["query"] for e in recent] == ["tasks.json", "folderOpen curl"]  # newest first
    assert recent[1]["results"] == 3


def test_recent_survives_a_torn_final_line(log):
    telemetry.record(event="search", query="good", results=1)
    with log.open("a", encoding="utf-8") as fh:
        fh.write('{"event": "search", "query": "hal')      # writer interrupted mid-line
    recent = telemetry.recent()
    assert [e["query"] for e in recent] == ["good"]


def test_record_never_raises_when_the_path_is_unwritable(tmp_path, monkeypatch):
    # Telemetry is best effort. A hunt must not die because a log could not be written.
    monkeypatch.setattr(telemetry, "SEARCH_LOG", tmp_path / "nope" / "\0bad" / "x.jsonl")
    telemetry.record(event="search", query="q")


def test_summary_counts_only_the_window(log):
    now = time.time()
    telemetry.record(event="search", query="old", results=5, ts=now - 5000)
    telemetry.record(event="search", query="new", results=2, ts=now - 5, interval=12.0)
    telemetry.record(event="search", query="hit", results=0, ts=now - 3, throttled=True)
    s = telemetry.summary(window_seconds=900)
    assert s["searches"] == 2            # the 5000s-old one is outside the window
    assert s["throttled"] == 1
    assert s["results"] == 2
    assert s["idle_seconds"] < 60


def test_summary_is_empty_without_a_log(tmp_path, monkeypatch):
    monkeypatch.setattr(telemetry, "SEARCH_LOG", tmp_path / "absent.jsonl")
    assert telemetry.recent() == []
    assert telemetry.summary()["searches"] == 0


def test_client_records_a_successful_search(log, monkeypatch):
    from git_warden.github.client import GitHubClient

    class Resp:
        status_code = 200
        headers: dict = {}

        def raise_for_status(self):
            pass

        def json(self):
            return {"items": [{"a": 1}, {"b": 2}]}

    client = GitHubClient(token="t")
    monkeypatch.setattr(client, "_get", lambda *a, **k: Resp())
    client._sleep = lambda s: None
    assert len(client.search_code("tasks.json folderOpen")) == 2

    events = telemetry.recent()
    assert len(events) == 1
    assert events[0]["query"] == "tasks.json folderOpen"
    assert events[0]["results"] == 2
    assert events[0]["throttled"] is False


def test_client_records_a_throttle_with_the_ratcheted_interval(log, monkeypatch):
    from git_warden.github.client import GitHubClient, GitHubRateLimitError

    class Resp:
        status_code = 403
        headers = {"Retry-After": "1"}

        def raise_for_status(self):
            pass

        def json(self):
            return {"items": []}

    client = GitHubClient(token="t")
    monkeypatch.setattr(client, "_get", lambda *a, **k: Resp())
    client._sleep = lambda s: None
    with pytest.raises(GitHubRateLimitError):
        client.search_code("q")

    events = telemetry.recent()
    assert events, "a throttle must be recorded, it is the signal an operator needs"
    assert all(e["throttled"] for e in events)
    # The interval ratchets up on every throttle, so the newest is the largest.
    assert events[0]["interval"] > events[-1]["interval"]


def test_log_is_trimmed_once_it_passes_the_cap(log, monkeypatch):
    monkeypatch.setattr(telemetry, "_MAX_BYTES", 200)
    monkeypatch.setattr(telemetry, "_KEEP_LINES", 5)
    for i in range(120):
        telemetry.record(event="search", query=f"q{i}", results=i)
    lines = log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) <= 60, "log must stay bounded"
    assert json.loads(lines[-1])["query"] == "q119", "newest entry is kept"
