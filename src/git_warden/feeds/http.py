"""HTTP access for feed adapters.

The network call is isolated behind a small :class:`HttpClient` protocol so feed
*parsing* can be unit-tested against fixtures with no network; tests inject a
fake client, production uses :class:`RequestsHttpClient`.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Protocol
from urllib.parse import urlsplit

import requests

from ..config import HTTP_TIMEOUT, USER_AGENT


class BlockedURLError(ValueError):
    """A URL was refused before any request because it targets a non-public host."""


def _guard_url(url: str) -> None:
    """Reject a URL before fetching if it is not a public http(s) endpoint.

    This tool follows URLs that come from external threat-intel feeds and cloned
    repositories, so an attacker-influenced URL could point at loopback, the cloud
    metadata endpoint (169.254.169.254), or an internal service (CodeQL py/full-ssrf).
    Only http/https to a publicly-routable host is allowed. Every resolved address
    for the host must be public, so a name that resolves to a private IP is refused
    too.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise BlockedURLError(f"scheme not allowed: {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise BlockedURLError("missing host")
    try:
        infos = socket.getaddrinfo(host, parts.port or 0, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise BlockedURLError(f"cannot resolve host {host!r}: {exc}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            raise BlockedURLError(f"host {host!r} resolves to non-public address {ip}")


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
        _guard_url(url)
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
        _guard_url(url)
        resp = self.session.get(url, params=params, headers=headers, timeout=self.timeout)
        resp.raise_for_status()
        return resp.content
