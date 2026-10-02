"""Minimal Visual Studio Marketplace client (metadata only; never downloads a .vsix).

Uses the public gallery query API that VS Code itself calls. Same interface as
:class:`~git_warden.extensions.openvsx.OpenVsxClient`, so the hunt treats both
registries alike. The ``.vsix`` is fetched only inside the sandbox container.
"""

from __future__ import annotations

import logging
import time

import requests

from ..config import HTTP_TIMEOUT, USER_AGENT
from .openvsx import Extension, valid_id_part

log = logging.getLogger(__name__)

GALLERY_QUERY = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
_VSIX_ASSET = "Microsoft.VisualStudio.Services.VSIXPackage"

# Gallery query filter types and flags (the values VS Code sends).
_F_ID_NAME, _F_TARGET, _F_SEARCH, _F_EXCLUDE = 7, 8, 10, 12
_TARGET = "Microsoft.VisualStudio.Code"
_UNPUBLISHED = "4096"
# IncludeVersions | IncludeFiles | IncludeVersionProperties | IncludeAssetUri |
# IncludeStatistics | IncludeLatestVersionOnly
_FLAGS = 0x1 | 0x2 | 0x10 | 0x80 | 0x100 | 0x200
_SORT_RELEVANCE, _SORT_LAST_UPDATED = 0, 1
_RETRY_BACKOFF = (2.0, 6.0)


def _from_json(d: dict) -> Extension | None:
    pub = d.get("publisher") or {}
    ns, name = str(pub.get("publisherName") or ""), str(d.get("extensionName") or "")
    if not (valid_id_part(ns) and valid_id_part(name)):
        return None
    versions = d.get("versions") or []
    latest = versions[0] if versions and isinstance(versions[0], dict) else {}
    download = next((f.get("source") for f in latest.get("files") or []
                     if isinstance(f, dict) and f.get("assetType") == _VSIX_ASSET), "")
    installs = next((s.get("value") for s in d.get("statistics") or []
                     if isinstance(s, dict) and s.get("statisticName") == "install"), 0)
    flags = str(pub.get("flags") or "").casefold()
    verified = bool(pub.get("isDomainVerified")) or "verified" in flags
    return Extension(
        namespace=ns, name=name, version=str(latest.get("version") or ""),
        display_name=str(d.get("displayName") or ""),
        description=str(d.get("shortDescription") or "")[:500],
        download_url=str(download or ""),
        download_count=int(installs or 0),
        timestamp=str(latest.get("lastUpdated") or d.get("lastUpdated") or ""),
        verified=verified, registry="vsmarketplace",
    )


class MarketplaceClient:
    """Paced gallery queries against the VS Marketplace. Any failure returns empty."""

    registry = "vsmarketplace"

    def __init__(self, *, session=None, pace: float = 1.0, url: str = GALLERY_QUERY):
        self.session = session or requests.Session()
        self.pace = pace
        self.url = url
        self._last = 0.0

    def _query(self, criteria: list[dict], *, size: int = 50, page: int = 1,
               sort_by: int = _SORT_RELEVANCE) -> list[Extension]:
        wait = self.pace - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        body = {"filters": [{
            "criteria": [{"filterType": _F_TARGET, "value": _TARGET},
                         {"filterType": _F_EXCLUDE, "value": _UNPUBLISHED}, *criteria],
            "pageNumber": page, "pageSize": size, "sortBy": sort_by, "sortOrder": 0}],
            "flags": _FLAGS}
        data = None
        for attempt, backoff in enumerate((*_RETRY_BACKOFF, None)):
            try:
                r = self.session.post(
                    self.url, json=body, timeout=HTTP_TIMEOUT,
                    headers={"User-Agent": USER_AGENT,
                             "Accept": "application/json;api-version=3.0-preview.1"})
                status = r.status_code
                if status == 200:
                    data = r.json()
                    break
            except requests.RequestException as exc:
                status = f"error: {exc}"
            except ValueError:
                log.warning("marketplace: unparseable response")
                return []
            # The gallery sheds load with 429/5xx (the first live run's "recent"
            # query got a 503); retry those with backoff, give up on anything else.
            transient = not isinstance(status, int) or status == 429 or status >= 500
            if backoff is None or not transient:
                log.info("marketplace: query failed",
                         extra={"context": {"status": status, "attempts": attempt + 1}})
                return []
            time.sleep(backoff)
        results = (data or {}).get("results") or [] if isinstance(data, dict) else []
        exts = (results[0] or {}).get("extensions") or [] if results else []
        out = [_from_json(e) for e in exts if isinstance(e, dict)]
        return [e for e in out if e]

    def search(self, query: str = "", *, size: int = 50, offset: int = 0,
               sort_by: str = "relevance") -> list[Extension]:
        crit = [{"filterType": _F_SEARCH, "value": query}] if query else []
        sort = _SORT_LAST_UPDATED if sort_by == "timestamp" else _SORT_RELEVANCE
        return self._query(crit, size=size, page=offset // max(size, 1) + 1, sort_by=sort)

    def recent(self, count: int = 100) -> list[Extension]:
        """The most recently updated extensions, newest first."""
        out: list[Extension] = []
        page = 1
        while len(out) < count:
            batch = self._query([], size=min(50, count - len(out)), page=page,
                                sort_by=_SORT_LAST_UPDATED)
            if not batch:
                break
            out.extend(batch)
            page += 1
        return out

    def extension(self, namespace: str, name: str) -> Extension | None:
        if not (valid_id_part(namespace) and valid_id_part(name)):
            return None
        hits = self._query([{"filterType": _F_ID_NAME, "value": f"{namespace}.{name}"}],
                           size=1)
        return hits[0] if hits else None

    def namespace_extensions(self, namespace: str) -> list[str]:
        if not valid_id_part(namespace):
            return []
        hits = self._query([{"filterType": _F_SEARCH, "value": f'publisher:"{namespace}"'}],
                           size=50)
        return [e.name for e in hits if e.namespace.casefold() == namespace.casefold()]
