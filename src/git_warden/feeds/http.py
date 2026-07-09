"""HTTP access for feed adapters.

The network call is isolated behind a small :class:`HttpClient` protocol so feed
*parsing* can be unit-tested against fixtures with no network; tests inject a
fake client, production uses :class:`RequestsHttpClient`.
"""

from __future__ import annotations

from typing import Protocol

import requests

from ..config import HTTP_TIMEOUT, USER_AGENT


class HttpClient(Protocol):
    """Anything that can fetch text or bytes from a URL."""

    def get_text(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> str: ...

    def get_bytes(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> bytes: ...


class RequestsHttpClient:
    """Production HTTP client backed by ``requests``."""

    def __init__(self, timeout: int = HTTP_TIMEOUT, user_agent: str = USER_AGENT) -> None:
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = user_agent

    def get_text(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> str:
        resp = self.session.get(url, params=params, headers=headers, timeout=self.timeout)
        resp.raise_for_status()
        return resp.text

    def get_bytes(
        self,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> bytes:
        # Binary sibling of get_text for zipped/exported datasets (e.g. OSV's
        # per-ecosystem export archives) that must not be decoded as text.
        resp = self.session.get(url, params=params, headers=headers, timeout=self.timeout)
        resp.raise_for_status()
        return resp.content
