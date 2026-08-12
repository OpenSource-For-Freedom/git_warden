"""The shared breadcrumb bus between warden and knorr.

Round-trips typed breadcrumbs, keeps one tool from reading its own, and gives a
cross-tool submitted set so neither re-submits the other's IOC.
"""

from __future__ import annotations

import pytest

from git_warden import intel_exchange as bus


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(bus, "SHARED_INTEL_PATH", tmp_path / "breadcrumbs.jsonl")


def test_record_and_read_back():
    bus.record("c2_host", "task-hrec.vercel.app", artifact="a/b", tags=["dprk"])
    bus.record("package", "npm/@servicetitan/startup@38.1.3")
    rows = bus.read("c2_host")
    assert len(rows) == 1
    assert rows[0]["value"] == "task-hrec.vercel.app"
    assert rows[0]["tool"] == "warden"
    assert bus.values("package") == ["npm/@servicetitan/startup@38.1.3"]


def test_a_tool_reads_only_the_other_tools_breadcrumbs():
    bus.record("c2_host", "warden-host.tld", tool="warden")
    bus.record("c2_host", "knorr-host.tld", tool="knorr")
    # warden seeds discovery from knorr's hosts, not its own
    assert bus.values("c2_host", exclude_tool="warden") == ["knorr-host.tld"]
    assert bus.values("c2_host", exclude_tool="knorr") == ["warden-host.tld"]


def test_dedup_keeps_one_per_value():
    bus.record("c2_host", "dupe.tld", artifact="a/1")
    bus.record("c2_host", "dupe.tld", artifact="a/2")
    assert bus.values("c2_host") == ["dupe.tld"]


def test_cross_tool_submitted_set():
    bus.mark_submitted("domain", "task-hrec.vercel.app", tool="warden", threat_id="t1")
    bus.mark_submitted("container", "ghcr.io/evil/img", tool="knorr", threat_id="t2")
    # either tool sees both, so neither re-submits the other's IOC
    assert bus.is_submitted("domain", "task-hrec.vercel.app")
    assert bus.is_submitted("container", "ghcr.io/evil/img")
    assert not bus.is_submitted("domain", "never-seen.tld")


def test_record_never_raises_on_unwritable_path(tmp_path, monkeypatch):
    monkeypatch.setattr(bus, "SHARED_INTEL_PATH", tmp_path / "nope" / "\0bad" / "x.jsonl")
    bus.record("c2_host", "x.tld")   # must not raise


def test_read_tolerates_a_torn_line():
    bus.record("c2_host", "good.tld")
    with bus.SHARED_INTEL_PATH.open("a", encoding="utf-8") as fh:
        fh.write('{"kind": "c2_host", "value": "tor')   # interrupted mid-write
    assert bus.values("c2_host") == ["good.tld"]


def test_unknown_kind_and_empty_value_ignored():
    bus.record("bogus", "x")
    bus.record("c2_host", "")
    assert bus.read() == []


def test_record_many():
    n = bus.record_many("path_fp", ["settings/linux?flag=", "task/mac?token="])
    assert n == 2
    assert set(bus.values("path_fp")) == {"settings/linux?flag=", "task/mac?token="}
