"""Package-spread analysis: how a found repo propagates a malicious package.

The manifest scanner already flags a repo that DEPENDS on a known-malicious package
(the victim side). This adds the SOURCE side: a repo that PUBLISHES or ships a
package whose exact version is on the malicious list is a node that spreads the
payload. Whoever installs that package, or installs from this repo, inherits the
ability. That is how the Chaindrop / Shai-Hulud wave moved: one compromised token
published a bad version across a whole org's packages, and every repo carrying one
became a spread source.

The malicious-package set is measured from two feeds combined: OSM's labelled
package intel (pulled in during ingest) and the bundled incident manifest. Every
match is VERSION-scoped, never name-only: a name-only match flags every user of a
popular package whose maintainer was briefly compromised, which is the false
positive class the dependency scanner already learned to avoid.

Pure and static over a cloned repo's files; nothing is executed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .bash_scanner import is_ignored_path
from .manifest_scanner import _declared_deps, _exact_pinned_version

_MAX_BYTES = 1_000_000


@dataclass(frozen=True)
class SpreadLink:
    relationship: str   # 'source' (repo publishes it) | 'vector' (repo depends on it)
    package: str
    version: str
    ecosystem: str      # 'npm' | 'pypi'
    file: str
    intel: str          # which feed listed it: 'osm' | 'manifest' | 'osm+manifest'


@dataclass
class SpreadIntel:
    """Malicious package name -> compromised versions, per ecosystem, with source."""

    npm: dict[str, set[str]] = field(default_factory=dict)
    pypi: dict[str, set[str]] = field(default_factory=dict)
    # name -> feeds that listed it, for the intel label on a link
    _origin: dict[str, set[str]] = field(default_factory=dict)

    def _add(self, eco: str, name: str, versions, origin: str) -> None:
        name = name.lower()
        target = self.npm if eco == "npm" else self.pypi
        target.setdefault(name, set()).update(v for v in versions if v)
        self._origin.setdefault(name, set()).add(origin)

    def add_osm(self, malicious_packages: dict) -> None:
        """Merge OSM's ``malicious_dependency_names()`` output (name -> versions)."""
        for eco in ("npm", "pypi"):
            for name, versions in (malicious_packages.get(eco) or {}).items():
                self._add(eco, name, versions, "osm")

    def add_manifest(self, name_to_versions: dict[str, set[str]]) -> None:
        """Merge a flat ``name -> versions`` manifest (npm; the incident export)."""
        for name, versions in (name_to_versions or {}).items():
            self._add("npm", name, versions, "manifest")

    def origin_label(self, name: str) -> str:
        origins = self._origin.get(name.lower()) or set()
        if origins == {"osm"}:
            return "osm"
        if origins == {"manifest"}:
            return "manifest"
        return "osm+manifest" if origins else "unknown"

    def bad_versions(self, eco: str, name: str) -> set[str]:
        target = self.npm if eco == "npm" else self.pypi
        return target.get(name.lower(), set())

    def total(self) -> int:
        return len(self.npm) + len(self.pypi)


def build_intel(malicious_packages: dict | None,
                manifest: dict[str, set[str]] | None) -> SpreadIntel:
    """Combine the OSM package feed and the incident manifest into one intel set."""
    intel = SpreadIntel()
    if malicious_packages:
        intel.add_osm(malicious_packages)
    if manifest:
        intel.add_manifest(manifest)
    return intel


def _iter_package_json(root: Path):
    for path in root.rglob("package.json"):
        if is_ignored_path(path):
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            yield path, path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue


def analyze_spread(root: Path | str, intel: SpreadIntel) -> list[SpreadLink]:
    """Every package-spread link in a repo, measured against ``intel``.

    A SOURCE link is the repo's own ``name@version`` (what it publishes) landing on
    the malicious list at that exact version. A VECTOR link is an exact-pinned
    dependency on a malicious version. Both are version-scoped.
    """
    root = Path(root)
    links: list[SpreadLink] = []
    seen: set[tuple[str, str, str]] = set()

    for path, text in _iter_package_json(root):
        rel = str(path.relative_to(root)).replace("\\", "/")
        try:
            pkg = json.loads(text or "{}")
        except ValueError:
            continue
        if not isinstance(pkg, dict):
            continue

        # SOURCE: the package this repo publishes, at the version it would publish.
        name = pkg.get("name")
        version = pkg.get("version")
        if isinstance(name, str) and isinstance(version, str):
            if version in intel.bad_versions("npm", name):
                key = ("source", name.lower(), version)
                if key not in seen:
                    seen.add(key)
                    links.append(SpreadLink("source", name, version, "npm", rel,
                                            intel.origin_label(name)))

        # VECTOR: a dependency pinned to a malicious version.
        for dep, spec in _declared_deps("package.json", text).items():
            bad = intel.bad_versions("npm", dep)
            if not bad:
                continue
            pinned = _exact_pinned_version(spec)
            if pinned and pinned in bad:
                key = ("vector", dep.lower(), pinned)
                if key not in seen:
                    seen.add(key)
                    links.append(SpreadLink("vector", dep, pinned, "npm", rel,
                                            intel.origin_label(dep)))
    return links


def describe_spread(links: list[SpreadLink]) -> str:
    """A plain sentence summary for the finding reasoning / gold message."""
    if not links:
        return ""
    sources = [x for x in links if x.relationship == "source"]
    vectors = [x for x in links if x.relationship == "vector"]
    parts = []
    if sources:
        names = ", ".join(f"{x.package}@{x.version}" for x in sources[:5])
        parts.append(
            f"This repository publishes {len(sources)} package version(s) that the "
            f"malicious-package feeds list as compromised ({names}), so installing "
            f"the package or building from this repository propagates the payload.")
    if vectors:
        names = ", ".join(f"{x.package}@{x.version}" for x in vectors[:5])
        parts.append(
            f"It also declares {len(vectors)} known-malicious dependency version(s) "
            f"({names}), pulling the payload in on install.")
    return " ".join(parts)
