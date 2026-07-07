"""Precision regression suite: real true-positive and false-positive repo shapes.

Each directory under tests/fixtures/precision/ is a minimal repo. `tp_*` MUST
confirm as malicious; `fp_*` MUST NOT. These are drawn from real repos the hunt
surfaced, so a rule change that re-introduces a known false positive (or drops a
known true positive) fails here instead of in production. See the fixtures README.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from git_warden.scanning.tier2 import analyze_repo

_FIXTURES = Path(__file__).parent / "fixtures" / "precision"
_CASES = sorted(p for p in _FIXTURES.iterdir() if p.is_dir()) if _FIXTURES.exists() else []


def _expected_confirm(case: Path) -> bool:
    if case.name.startswith("tp_"):
        return True
    if case.name.startswith("fp_"):
        return False
    raise AssertionError(f"fixture dir must start with tp_ or fp_: {case.name}")


@pytest.mark.parametrize("case", _CASES, ids=[c.name for c in _CASES])
def test_precision_fixture_verdict(case, tmp_path):
    # The scanners ignore any path under a tests/fixtures/... dir (attack strings as
    # DATA), so copy the fixture OUT to a neutral tmp dir before analyzing it.
    work = tmp_path / case.name
    shutil.copytree(case, work)
    result = analyze_repo(work, f"fixture/{case.name}")
    want = _expected_confirm(case)
    got = result.confirmed
    if got != want:
        rules = sorted({f"{f.category}:{f.rule}" for f in result.confirming_findings})
        label = "SHOULD confirm but did not" if want else "SHOULD NOT confirm but did"
        pytest.fail(f"{case.name}: {label}. confirming={rules or '(none)'} "
                    f"score={result.bash_score}")
