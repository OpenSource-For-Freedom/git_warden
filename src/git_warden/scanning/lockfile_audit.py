"""Audit a project's lockfiles against a known-compromised package manifest.

Answers the defender's question after a supply-chain incident: "did we ever pull
one of these?" A malicious version is usually UNPUBLISHED within hours, so a live
registry check comes back clean while a committed lockfile, a CI cache, or an old
`node_modules` still pins the bad release. This reads the pins directly.

Parses the three ecosystems' lockfiles from their resolved-version fields, which is
what actually got installed, not the semver RANGE in package.json (a range is not a
match: it floats to a patched release). Pure and static: nothing is executed and no
network is touched.

Formats: npm package-lock.json v1/v2/v3, pnpm-lock.yaml v5/v6/v9, and yarn.lock
classic (v1) and berry (v2+). Regex extraction, no YAML dependency.
"""

from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

_LOCK_NAMES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock")
_MAX_BYTES = 20_000_000  # a huge monorepo lockfile is still bounded


@dataclass(frozen=True)
class LockHit:
    lockfile: str
    package: str
    version: str
    ecosystem: str  # 'npm' | 'pnpm' | 'yarn'


def load_compromised(path: Path | str) -> dict[str, set[str]]:
    """Read a ``name,version`` CSV manifest into ``{name: {versions}}``.

    The first row may be a header (``Package,Version``); it is skipped when it does
    not look like a real package line. Blank lines and comments (``#``) are ignored.
    """
    out: dict[str, set[str]] = defaultdict(set)
    text = Path(path).read_text(encoding="utf-8", errors="ignore")
    for row in csv.reader(text.splitlines()):
        if len(row) < 2:
            continue
        name, version = row[0].strip(), row[1].strip()
        if not name or name.startswith("#"):
            continue
        if name.lower() == "package" and version.lower() == "version":
            continue  # header
        out[name].add(version)
    return dict(out)


# --- npm: package-lock.json / npm-shrinkwrap.json -----------------------------
def parse_package_lock(text: str) -> list[tuple[str, str]]:
    """Resolved (name, version) pairs from an npm lockfile (v1, v2, or v3)."""
    try:
        data = json.loads(text or "{}")
    except ValueError:
        return []
    pairs: list[tuple[str, str]] = []

    # v2/v3: the authoritative "packages" map, keyed by install path.
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue  # "" is the root project, skip it
            # name is the segment after the last node_modules/; a scoped package
            # keeps its @scope/name. meta may also carry an explicit "name".
            name = meta.get("name")
            if not name:
                marker = "node_modules/"
                idx = path.rfind(marker)
                name = path[idx + len(marker):] if idx != -1 else path
            version = meta.get("version")
            if name and isinstance(version, str):
                pairs.append((name, version))

    # v1 (and v2's compat block): the nested "dependencies" tree.
    def walk(deps):
        if not isinstance(deps, dict):
            return
        for name, meta in deps.items():
            if isinstance(meta, dict):
                v = meta.get("version")
                if isinstance(v, str):
                    pairs.append((name, v))
                walk(meta.get("dependencies"))

    walk(data.get("dependencies"))
    return pairs


# --- pnpm: pnpm-lock.yaml ------------------------------------------------------
# A packages-section key across pnpm major versions:
#   v5:  /@scope/name/1.2.3   or  /name/1.2.3
#   v6+: /@scope/name@1.2.3   or  /name@1.2.3   (peer suffix in parens dropped)
#   v9:  @scope/name@1.2.3    (no leading slash)
_PNPM_KEY = re.compile(
    r"^\s{2,}['\"]?/?(?P<name>(?:@[^/@\s]+/)?[^/@\s]+)[/@](?P<version>\d[^\s'\"(:]*)",
)


def parse_pnpm_lock(text: str) -> list[tuple[str, str]]:
    """Resolved (name, version) pairs from a pnpm-lock.yaml (v5/v6/v9)."""
    pairs: list[tuple[str, str]] = []
    in_packages = False
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not line.startswith(" ") and stripped.endswith(":"):
            in_packages = stripped in ("packages:", "snapshots:")
            continue
        if not in_packages:
            continue
        m = _PNPM_KEY.match(line)
        if m:
            version = m.group("version").rstrip("_")
            pairs.append((m.group("name"), version))
    return pairs


# --- yarn: yarn.lock (classic v1 and berry v2+) -------------------------------
# Classic header:  "name@range", "name@range2":     (quotes optional if unscoped)
# Berry header:    "name@npm:range":
_YARN_ENTRY_NAME = re.compile(r'"?((?:@[^/@\s"]+/)?[^@\s"]+)@')
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?(?P<version>[^"\s]+)"?', re.M)


def parse_yarn_lock(text: str) -> list[tuple[str, str]]:
    """Resolved (name, version) pairs from a yarn.lock (classic or berry).

    Splits into blocks on blank lines, reads the package name from the block header
    and the resolved version from its ``version`` field.
    """
    pairs: list[tuple[str, str]] = []
    block: list[str] = []

    def flush(bl):
        # The header is the first non-comment line; yarn.lock opens with a
        # "# yarn lockfile v1" banner that can lead a block.
        header = next((ln for ln in bl if not ln.lstrip().startswith("#")), None)
        if not header or header.startswith(" "):
            return
        nm = _YARN_ENTRY_NAME.match(header.lstrip())
        vm = _YARN_VERSION.search("\n".join(bl))
        if nm and vm:
            pairs.append((nm.group(1), vm.group("version")))

    for line in (text or "").splitlines():
        if not line.strip():
            flush(block)
            block = []
        else:
            block.append(line)
    flush(block)
    return pairs


_PARSERS = {
    "package-lock.json": ("npm", parse_package_lock),
    "npm-shrinkwrap.json": ("npm", parse_package_lock),
    "pnpm-lock.yaml": ("pnpm", parse_pnpm_lock),
    "yarn.lock": ("yarn", parse_yarn_lock),
}


def audit_lockfile(path: Path | str, compromised: dict[str, set[str]]) -> list[LockHit]:
    """Every compromised pin in one lockfile. Empty if the file is clean."""
    path = Path(path)
    eco_parser = _PARSERS.get(path.name)
    if eco_parser is None:
        return []
    ecosystem, parser = eco_parser
    try:
        if path.stat().st_size > _MAX_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    hits: list[LockHit] = []
    seen: set[tuple[str, str]] = set()
    for name, version in parser(text):
        bad = compromised.get(name)
        if bad and version in bad and (name, version) not in seen:
            seen.add((name, version))
            hits.append(LockHit(str(path), name, version, ecosystem))
    return hits


_SKIP_DIRS = frozenset({".git", "node_modules", ".pnpm-store", "dist", "build",
                        ".cache", ".next", ".turbo", "vendor"})


def audit_tree(root: Path | str, compromised: dict[str, set[str]]) -> list[LockHit]:
    """Audit every lockfile under ``root``, skipping vendored/build directories.

    A committed lockfile inside node_modules is a vendored dependency's own file,
    not this project's install state, so those trees are skipped.
    """
    root = Path(root)
    hits: list[LockHit] = []
    if root.is_file():
        return audit_lockfile(root, compromised)
    for path in root.rglob("*"):
        if not path.is_file() or path.name not in _LOCK_NAMES:
            continue
        if _SKIP_DIRS & {p.lower() for p in path.parts}:
            continue
        hits.extend(audit_lockfile(path, compromised))
    return hits
