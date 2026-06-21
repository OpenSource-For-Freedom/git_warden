"""Minimal, read-only GitHub REST client for the scanning layer (doc 02).

Scope for the first slice: the calls Tier-1 metadata screening needs;
repository metadata, README/front-facing content, and repository search. Uses
the configured PAT for the 5,000 req/hr limit; all calls are read-only.

The HTTP session is injectable so the client is unit-testable offline (a fake
session returns canned responses); production uses ``requests``.

GraphQL (fetching metadata + README in one call, doc 02 section 2.3) is a later
optimization; REST is enough to stand up and validate access first.
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass

import requests

from ..config import GITHUB_API_URL, GITHUB_API_VERSION, GITHUB_TOKEN, HTTP_TIMEOUT, USER_AGENT

log = logging.getLogger(__name__)


@dataclass
class RateLimit:
    """Snapshot of the GitHub rate-limit headers from the last response."""

    limit: int | None = None
    remaining: int | None = None
    reset: int | None = None  # epoch seconds

    @classmethod
    def from_headers(cls, headers) -> RateLimit:
        def _int(key: str) -> int | None:
            value = headers.get(key)
            return int(value) if value is not None else None

        return cls(
            limit=_int("X-RateLimit-Limit"),
            remaining=_int("X-RateLimit-Remaining"),
            reset=_int("X-RateLimit-Reset"),
        )


class GitHubAuthError(RuntimeError):
    """Raised when GitHub rejects the token (401)."""


class GitHubRateLimitError(RuntimeError):
    """Raised when GitHub rate-limits a request (primary or secondary).

    Carries ``retry_after`` (seconds) computed from the response headers so the
    caller can wait exactly as long as GitHub asks rather than guessing. Code
    search is the tight case: ~10 requests/minute, with a separate secondary
    (abuse) limit on bursts that returns 403 + ``Retry-After``.
    """

    def __init__(self, message: str, retry_after: float):
        super().__init__(message)
        self.retry_after = retry_after


class GitHubClient:
    """Read-only REST client. Construct once, reuse across calls."""

    def __init__(self, token: str | None = None, session=None, base_url: str = GITHUB_API_URL):
        self.token = token if token is not None else GITHUB_TOKEN
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.last_rate_limit = RateLimit()

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": USER_AGENT,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _get(self, path: str, params: dict | None = None):
        resp = self.session.get(
            f"{self.base_url}{path}",
            params=params,
            headers=self._headers(),
            timeout=HTTP_TIMEOUT,
        )
        self.last_rate_limit = RateLimit.from_headers(resp.headers)
        if resp.status_code == 401:
            raise GitHubAuthError("GitHub rejected the token (401); check GW_GITHUB_TOKEN")
        return resp

    #; API surface for Tier-1 --------------------------------------------
    def rate_limit(self) -> RateLimit:
        """Query /rate_limit (does not consume quota)."""
        resp = self._get("/rate_limit")
        resp.raise_for_status()
        core = resp.json().get("resources", {}).get("core", {})
        return RateLimit(
            limit=core.get("limit"), remaining=core.get("remaining"), reset=core.get("reset")
        )

    def get_repo(self, owner: str, name: str) -> dict | None:
        """Repository metadata, or None if it does not exist / is private (404)."""
        resp = self._get(f"/repos/{owner}/{name}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    def get_readme(self, owner: str, name: str) -> str | None:
        """Decoded README text, or None if the repo has no README (404)."""
        resp = self._get(f"/repos/{owner}/{name}/readme")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        body = resp.json()
        if body.get("encoding") == "base64" and body.get("content"):
            return base64.b64decode(body["content"]).decode("utf-8", errors="replace")
        return body.get("content")

    def search_repositories(self, query: str, per_page: int = 10) -> list[dict]:
        """Search repositories; returns the ``items`` list (may be empty)."""
        resp = self._get("/search/repositories", params={"q": query, "per_page": per_page})
        resp.raise_for_status()
        return resp.json().get("items", [])

    @staticmethod
    def _rate_limit_wait(resp) -> float | None:
        """Seconds to wait if ``resp`` is a rate-limit (else None for a real 403).

        Distinguishes a throttle from a genuine 'forbidden': honors ``Retry-After``
        (secondary/abuse limit), then an exhausted primary budget
        (``X-RateLimit-Remaining: 0`` -> wait to ``X-RateLimit-Reset``), then a
        rate-limit message as a last resort. Returns None when it is truly
        forbidden (bad/missing token, insufficient scope) so we don't loop on it.
        """
        retry_after = resp.headers.get("Retry-After")
        if retry_after is not None:
            try:
                return max(1.0, float(retry_after))
            except ValueError:
                pass
        if resp.headers.get("X-RateLimit-Remaining") == "0":
            reset = resp.headers.get("X-RateLimit-Reset")
            try:
                return max(1.0, float(reset) - time.time()) if reset else 60.0
            except ValueError:
                return 60.0
        try:
            message = (resp.json() or {}).get("message", "")
        except ValueError:
            message = ""
        if "rate limit" in message.lower() or "abuse" in message.lower():
            return 60.0
        return None

    def search_code(self, query: str, per_page: int = 20) -> list[dict]:
        """Search code for a literal IOC/string; returns ``items`` (may be empty).

        Code search requires authentication and has a tight rate limit
        (~10 req/min) plus a secondary burst limit. A throttling 403/429 raises
        :class:`GitHubRateLimitError` (with the wait); a genuine 403 (bad token)
        raises ``RuntimeError`` so the caller doesn't retry a hopeless request.
        """
        resp = self._get("/search/code", params={"q": query, "per_page": per_page})
        if resp.status_code in (403, 429):
            wait = self._rate_limit_wait(resp)
            if wait is not None:
                raise GitHubRateLimitError(f"code search rate-limited ({resp.status_code})", wait)
            raise RuntimeError(
                "GitHub code search forbidden; token required or insufficient scope")
        resp.raise_for_status()
        return resp.json().get("items", [])

    def compare(
        self, base_full: str, base_branch: str, head_full: str, head_branch: str
    ) -> dict | None:
        """Compare a fork against its upstream (doc 02 5 intent change).

        Returns ``{ahead_by, files}`` (files = changed paths) or None if the
        comparison can't be made. ``ahead_by == 0`` means an unmodified mirror.
        """
        base_owner = base_full.split("/", 1)[0]
        head_owner = head_full.split("/", 1)[0]
        basehead = f"{base_owner}:{base_branch}...{head_owner}:{head_branch}"
        resp = self._get(f"/repos/{base_full}/compare/{basehead}")
        if resp.status_code != 200:
            return None
        data = resp.json()
        return {
            "ahead_by": data.get("ahead_by", 0),
            "files": [f.get("filename") for f in (data.get("files") or []) if f.get("filename")],
        }

    def list_user_repos(self, login: str, per_page: int = 100) -> list[dict]:
        """Public repos for a user or org login. [] if the account is 404.

        Used for actor-account discovery (doc 02 section 2.1): repos under a
        known threat-actor GitHub account. ``/users/{login}/repos`` serves both
        users and orgs.
        """
        resp = self._get(f"/users/{login}/repos", params={"per_page": per_page, "sort": "updated"})
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        return resp.json()

    def list_forks(
        self, owner: str, name: str, per_page: int = 100, sort: str = "newest"
    ) -> list[dict]:
        """First page of a repo's forks (newest first). [] if the repo is 404.

        Returns only the first page; the caller logs when a full page comes back
        so a silent cap is never mistaken for "no more forks".
        """
        resp = self._get(
            f"/repos/{owner}/{name}/forks", params={"per_page": per_page, "sort": sort}
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        forks = resp.json()
        if len(forks) >= per_page:
            log.info(
                "forks page full; more may exist",
                extra={"context": {"repo": f"{owner}/{name}", "page_size": per_page}},
            )
        return forks
