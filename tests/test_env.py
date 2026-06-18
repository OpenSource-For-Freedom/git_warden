"""Tests for the minimal .env loader."""

from __future__ import annotations

import os

from git_warden.env import load_env_file


def test_loads_pairs_and_skips_comments(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(
        '# a comment\n'
        'GW_TEST_A=hello\n'
        'export GW_TEST_B="quoted value"\n'
        'no_equals_here\n'
        '\n'
        'GW_TEST_C=\n',
        encoding="utf-8",
    )
    for key in ("GW_TEST_A", "GW_TEST_B", "GW_TEST_C"):
        monkeypatch.delenv(key, raising=False)

    loaded = load_env_file(env)
    try:
        assert os.environ["GW_TEST_A"] == "hello"
        assert os.environ["GW_TEST_B"] == "quoted value"  # export + quotes stripped
        assert os.environ["GW_TEST_C"] == ""  # empty value allowed
        assert "GW_TEST_A" in loaded
    finally:
        for key in ("GW_TEST_A", "GW_TEST_B", "GW_TEST_C"):
            os.environ.pop(key, None)


def test_existing_env_var_wins(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("GW_TEST_X=from_file\n", encoding="utf-8")
    monkeypatch.setenv("GW_TEST_X", "from_env")
    load_env_file(env)
    assert os.environ["GW_TEST_X"] == "from_env"


def test_missing_file_is_noop(tmp_path):
    assert load_env_file(tmp_path / "nonexistent.env") == {}
