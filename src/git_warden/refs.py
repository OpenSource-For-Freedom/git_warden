"""Parsing helpers for repository references (URLs or owner/name strings)."""

from __future__ import annotations

import re

# The separator run is BOUNDED ({1,3}) on purpose. An unbounded `[/:]+` overlaps
# with the following `[^/\s]+` group on ':', so a crafted ref like
# "github.com::::::::::::::::" forces polynomial backtracking (CodeQL py/polynomial
# -redos). refs come from untrusted repo/feed data, so that is a real DoS. A real
# URL has one or two separators (`github.com/`, `git@github.com:`).
_GH = re.compile(r"github\.com[/:]{1,3}([^/\s]+)/([^/\s#?]+)", re.IGNORECASE)


def split_repo_ref(ref: str | None) -> tuple[str, str] | None:
    """Extract (owner, repo) from a GitHub URL or an "owner/repo" string.

    Returns None if no owner/repo can be parsed. Trailing slashes and a ``.git``
    suffix are stripped.
    """
    if not ref:
        return None
    ref = ref.strip()
    match = _GH.search(ref)
    if match:
        owner, repo = match.group(1), match.group(2)
    elif "/" in ref and " " not in ref and not ref.startswith("http"):
        owner, _, repo = ref.partition("/")
    else:
        return None
    repo = repo.rstrip("/")
    if repo.endswith(".git"):
        repo = repo[:-4]
    return (owner, repo) if owner and repo else None


def repo_full_name(ref: str | None) -> str | None:
    """Canonical "owner/repo" for a reference, or None."""
    parsed = split_repo_ref(ref)
    return f"{parsed[0]}/{parsed[1]}" if parsed else None
