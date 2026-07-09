"""Precision regression suite: real true-positive and false-positive repo shapes.

Each directory under tests/fixtures/precision/ is a minimal repo drawn from a real
repo the hunt surfaced. The naming encodes the expected AUTO-tier verdict:

  tp_*  MUST confirm at the AUTO confidence tier (a high-precision capture).
  rv_*  MUST confirm at REVIEW (a real but noisy TP -- human-review, never auto).
  fp_*  MUST NOT reach AUTO -- it is either not confirmed at all, or at most REVIEW.

AUTO is the only tier that reaches gold + submit, so this suite is the gate that
keeps a known false positive from ever being auto-delivered again. See the README.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from git_warden.scanning.tier2 import analyze_repo

_FIXTURES = Path(__file__).parent / "fixtures" / "precision"
_CASES = sorted(p for p in _FIXTURES.iterdir() if p.is_dir()) if _FIXTURES.exists() else []


def _tier(case: Path) -> str:
    # Scanners ignore anything under a tests/fixtures/... path (attack strings as
    # DATA), so copy the fixture OUT to a neutral tmp dir before analyzing it.
    import tempfile
    work = Path(tempfile.mkdtemp()) / case.name
    shutil.copytree(case, work)
    try:
        return analyze_repo(work, f"fixture/{case.name}").confidence
    finally:
        shutil.rmtree(work, ignore_errors=True)


@pytest.mark.parametrize("case", _CASES, ids=[c.name for c in _CASES])
def test_precision_fixture_tier(case):
    tier = _tier(case)
    if case.name.startswith("tp_"):
        assert tier == "auto", f"{case.name}: expected AUTO capture, got tier={tier!r}"
    elif case.name.startswith("rv_"):
        assert tier == "review", f"{case.name}: expected REVIEW, got tier={tier!r}"
    elif case.name.startswith("fp_"):
        assert tier != "auto", f"{case.name}: false positive reached AUTO (tier={tier!r})"
    else:
        raise AssertionError(f"fixture dir must start with tp_/rv_/fp_: {case.name}")


def test_corpus_precision_and_recall():
    """Aggregate gate: AUTO-tier precision and AUTO-TP recall over the whole corpus."""
    tp = [c for c in _CASES if c.name.startswith("tp_")]   # must be AUTO
    fp = [c for c in _CASES if c.name.startswith("fp_")]   # must NOT be AUTO
    assert tp and fp, "corpus must contain both tp_ and fp_ cases"
    tp_auto = sum(1 for c in tp if _tier(c) == "auto")
    fp_auto = sum(1 for c in fp if _tier(c) == "auto")
    precision = tp_auto / (tp_auto + fp_auto) if (tp_auto + fp_auto) else 1.0
    recall = tp_auto / len(tp)
    assert precision >= 0.95, f"AUTO precision {precision:.0%} < 95% ({fp_auto} FP reached AUTO)"
    assert recall >= 0.99, f"AUTO-TP recall {recall:.0%} < 99% ({len(tp) - tp_auto} TP missed)"
