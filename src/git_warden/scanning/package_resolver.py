"""Resolve a known-malicious package to its GitHub SOURCE repo (and publisher).

The highest-recall discovery path. OSM / OSV / OpenSSF catalog tens of thousands of
malicious npm and PyPI packages, but the hunt only ever code-searched their *names*.
Each package's public registry metadata carries its source repository and author, so
we turn the malicious-PACKAGE firehose into malicious-REPO candidates: the source
repo itself is a strong, Tier-2-eligible lead that the confirmation gate still has to
prove on intrinsic evidence (a typosquat that points its ``repository`` field at the
legit project's repo simply fails to confirm).

Registry APIs are public and keyless:
  npm:  https://registry.npmjs.org/<pkg>        -> .repository.url, .author
  pypi: https://pypi.org/pypi/<pkg>/json        -> .info.project_urls / .home_page
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass

from ..refs import repo_full_name

log = logging.getLogger(__name__)

_NPM = "https://registry.npmjs.org/"
_PYPI = "https://pypi.org/pypi/"
_HEADERS = {"Accept": "application/json"}


@dataclass
class PackageRepo:
    full_name: str          # owner/repo of the package's GitHub source
    package: str            # the malicious package name
    ecosystem: str          # npm | pypi | ...
    author: str | None      # publisher/author, when the registry exposes one


def _gh(url) -> str | None:
    """owner/repo from a registry repository / home-page value (GitHub only)."""
    if not url:
        return None
    s = str(url)
    if "github.com" not in s.lower():
        return None
    # normalize npm's "git+https://github.com/owner/repo.git" before parsing
    s = s.replace("git+", "")
    if s.endswith(".git"):
        s = s[:-4]
    return repo_full_name(s)


def resolve_source_repo(name: str, ecosystem: str, http) -> tuple[str | None, str | None]:
    """(github owner/repo, author) for a package from its registry, or (None, None)."""
    eco = (ecosystem or "").strip().lower()
    try:
        if eco == "npm":
            data = json.loads(http.get_text(_NPM + name, headers=_HEADERS))
            repo = data.get("repository")
            url = repo.get("url") if isinstance(repo, dict) else repo
            author = data.get("author")
            author = author.get("name") if isinstance(author, dict) else author
            return _gh(url), (str(author) if author else None)
        if eco in ("pypi", "pip", "python"):
            data = json.loads(http.get_text(f"{_PYPI}{name}/json", headers=_HEADERS))
            info = data.get("info") or {}
            author = info.get("author") or None
            for u in [info.get("home_page"), *(info.get("project_urls") or {}).values()]:
                fn = _gh(u)
                if fn:
                    return fn, author
            return None, author
    except Exception as exc:  # a removed/renamed package must not sink the run
        log.debug("package resolve failed",
                  extra={"context": {"pkg": name, "eco": eco, "err": str(exc)}})
    return None, None


def find_package_source_repos(
    db, http, *, known: set[str], limit: int = 50, pace_seconds: float = 0.0,
    resolve_cap: int = 400,
) -> list[PackageRepo]:
    """Malicious-package artifacts -> their GitHub source repos (novel, deduped).

    Bounded twice: ``resolve_cap`` registry lookups per run and ``limit`` NEW source
    repos returned. Registry APIs are lenient, so ``pace_seconds`` can stay small.
    """
    from ..config import KNOWN_GOOD_OWNERS

    out: dict[str, PackageRepo] = {}
    seen: set[str] = set()
    tried = 0
    for row in db.list_artifacts(artifact_type="package"):
        if len(out) >= limit or tried >= resolve_cap:
            break
        name, eco = row["name"], row["ecosystem"]
        if not name:
            continue
        key = f"{eco}:{name}".lower()
        if key in seen:
            continue
        seen.add(key)
        tried += 1
        fn, author = resolve_source_repo(name, eco, http)
        if pace_seconds:
            time.sleep(pace_seconds)
        if not fn:
            continue
        k = fn.casefold()
        # Skip already-known repos and well-known-legit owners up front. NOTE: a
        # COMPROMISED-legit package (malware injected into the published artifact,
        # not the repo) resolves to the legit source repo; that is still surfaced
        # as a candidate but Tier-2 will not confirm it (no malware IN the repo),
        # so precision is preserved downstream.
        if k in known or k in out or fn.split("/", 1)[0].casefold() in KNOWN_GOOD_OWNERS:
            continue
        out[k] = PackageRepo(full_name=fn, package=name, ecosystem=eco, author=author)
    return list(out.values())
