"""The overnight heartbeat must respect the storage boundary.

warden never reads knorr's storage; the only cross-tool surface is the shared
breadcrumb bus. The heartbeat reporter regressed once by reading knorr's artifacts
directory directly, so these tests pin the boundary at the source and behaviour level.
The reporter lives beside the sweep script it serves, not inside the package.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

NIGHT_NOTIFY = Path("F:/dev/shared_intel/night_notify.py")


@pytest.mark.skipif(not NIGHT_NOTIFY.exists(), reason="sweep reporter not present")
def test_reporter_never_names_knorr_storage():
    src = NIGHT_NOTIFY.read_text(encoding="utf-8")
    # Any path into knorr's own tree is a boundary break. The bus is the only
    # sanctioned cross-tool surface; knorr reports its own artifacts itself.
    assert not re.search(r"knorr[\\/]", src), "reporter must not reference a knorr path"
    assert "knorr/artifacts" not in src and "knorr\\artifacts" not in src


@pytest.mark.skipif(not NIGHT_NOTIFY.exists(), reason="sweep reporter not present")
def test_reporter_takes_cross_tool_signal_from_the_bus():
    src = NIGHT_NOTIFY.read_text(encoding="utf-8")
    assert "intel_exchange" in src, "knorr's numbers must come from the shared bus"


@pytest.mark.skipif(not NIGHT_NOTIFY.exists(), reason="sweep reporter not present")
def test_warden_counts_glob_only_touches_warden_artifacts():
    # Load the reporter as a module and prove its warden read never escapes the
    # warden artifacts dir (the only private store it is allowed to open).
    spec = importlib.util.spec_from_file_location("night_notify", NIGHT_NOTIFY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    seen: list[str] = []

    def fake_glob(pattern):
        seen.append(pattern)
        return []

    mod.glob.glob = fake_glob
    mod._newest_warden_counts()
    assert seen, "it must glob somewhere"
    assert all("knorr" not in p for p in seen)
    assert all(p.startswith(mod.WARDEN_ARTIFACTS) for p in seen)
