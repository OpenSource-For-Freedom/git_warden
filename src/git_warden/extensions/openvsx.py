"""Minimal Open VSX registry client (metadata only; never downloads a .vsix).

The ``.vsix`` itself is fetched only inside the sandbox container (see
:mod:`git_warden.extensions.vsix`). The host reads JSON metadata: search results,
an extension's latest-version record, and a publisher namespace's listing.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from urllib.parse import quote

import requests

from ..config import HTTP_TIMEOUT, USER_AGENT

log = logging.getLogger(__name__)

OPENVSX_API = "https://open-vsx.org/api"
_ID_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@dataclass
class Extension:
    """One published extension version, as Open VSX describes it."""

    namespace: str
    name: str
    version: str = ""
    display_name: str = ""
    description: str = ""
    download_url: str = ""
    download_count: int = 0
    timestamp: str = ""
    verified: bool | None = None
    registry: str = "openvsx"
    reasons: list[str] = field(default_factory=list)
    score: int = 0

    @property
    def ext_id(self) -> str:
        return f"{self.namespace}.{self.name}"

    @property
    def key(self) -> str:
        """Stable store key, case-insensitive like the registry."""
        return f"{self.registry}:{self.ext_id}".casefold()

    @property
    def url(self) -> str:
        return f"https://open-vsx.org/extension/{self.namespace}/{self.name}"


def valid_id_part(part: str) -> bool:
    return bool(_ID_PART.fullmatch(part or ""))


def _from_json(d: dict) -> Extension | None:
    ns, name = d.get("namespace") or "", d.get("name") or ""
    if not (valid_id_part(ns) and valid_id_part(name)):
        return None
    files = d.get("files") or {}
    verified = d.get("verified")
    return Extension(
        namespace=ns, name=name, version=str(d.get("version") or ""),
        display_name=str(d.get("displayName") or ""),
        description=str(d.get("description") or "")[:500],
        download_url=str(files.get("download") or ""),
        download_count=int(d.get("downloadCount") or 0),
        timestamp=str(d.get("timestamp") or ""),
        verified=verified if isinstance(verified, bool) else None,
    )


class OpenVsxClient:
    """Paced JSON reads from the Open VSX API. Any failure returns empty."""

    def __init__(self, *, session=None, pace: float = 1.0, base: str = OPENVSX_API):
        self.session = session or requests.Session()
        self.pace = pace
        self.base = base.rstrip("/")
        self._last = 0.0

    def _get(self, path: str, params: dict | None = None) -> dict | None:
        wait = self.pace - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        try:
            r = self.session.get(f"{self.base}{path}", params=params, timeout=HTTP_TIMEOUT,
                                 headers={"User-Agent": USER_AGENT,
                                          "Accept": "application/json"})
            if r.status_code != 200:
                log.info("openvsx: non-200", extra={"context": {"path": path,
                                                                "status": r.status_code}})
                return None
            data = r.json()
            return data if isinstance(data, dict) else None
        except (requests.RequestException, ValueError) as exc:
            log.warning("openvsx: request failed",
                        extra={"context": {"path": path, "err": str(exc)}})
            return None

    def search(self, query: str = "", *, size: int = 50, offset: int = 0,
               sort_by: str = "relevance") -> list[Extension]:
        data = self._get("/-/search", {"query": query, "size": size, "offset": offset,
                                       "sortBy": sort_by, "sortOrder": "desc"})
        out = [_from_json(e) for e in (data or {}).get("extensions") or []
               if isinstance(e, dict)]
        return [e for e in out if e]

    def recent(self, count: int = 100) -> list[Extension]:
        """The most recently published/updated extensions, newest first."""
        out: list[Extension] = []
        while len(out) < count:
            page = self.search("", size=min(50, count - len(out)), offset=len(out),
                               sort_by="timestamp")
            if not page:
                break
            out.extend(page)
        return out

    def extension(self, namespace: str, name: str) -> Extension | None:
        """The latest-version record (has the canonical download URL)."""
        if not (valid_id_part(namespace) and valid_id_part(name)):
            return None
        data = self._get(f"/{quote(namespace)}/{quote(name)}")
        return _from_json(data) if data else None

    def namespace_extensions(self, namespace: str) -> list[str]:
        """Extension names a publisher namespace has published."""
        if not valid_id_part(namespace):
            return []
        data = self._get(f"/{quote(namespace)}") or {}
        exts = data.get("extensions") or {}
        return [n for n in exts if isinstance(n, str) and valid_id_part(n)]
