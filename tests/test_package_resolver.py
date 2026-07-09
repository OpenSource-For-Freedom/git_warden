"""Tests for the malicious-package -> GitHub source repo resolver (lever 1)."""

from __future__ import annotations

from conftest import utcnow

from git_warden.db import Database
from git_warden.enums import ArtifactType, FeedSource
from git_warden.models import MaliciousArtifact
from git_warden.scanning.package_resolver import (
    _gh,
    find_package_source_repos,
    resolve_source_repo,
)


class FakeHttp:
    def __init__(self, responses):
        self.responses = responses

    def get_text(self, url, *, params=None, headers=None):
        for frag, body in self.responses.items():
            if frag in url:
                return body
        raise RuntimeError(f"404 {url}")


def test_gh_extracts_owner_repo_from_registry_url_shapes():
    assert _gh("git+https://github.com/evil/pkg.git") == "evil/pkg"
    assert _gh("https://github.com/evil/pkg") == "evil/pkg"
    assert _gh("git://github.com/evil/pkg.git") == "evil/pkg"
    assert _gh("https://gitlab.com/x/y") is None          # not GitHub
    assert _gh(None) is None


def test_resolve_npm_source_repo():
    http = FakeHttp({"registry.npmjs.org/badpkg":
                     '{"repository":{"url":"git+https://github.com/evil/badpkg.git"},'
                     '"author":{"name":"mallory"}}'})
    assert resolve_source_repo("badpkg", "npm", http) == ("evil/badpkg", "mallory")


def test_resolve_pypi_source_repo_from_project_urls():
    http = FakeHttp({"pypi.org/pypi/badpy/json":
                     '{"info":{"author":"evilpy","home_page":"",'
                     '"project_urls":{"Source":"https://github.com/evil/badpy"}}}'})
    assert resolve_source_repo("badpy", "pypi", http) == ("evil/badpy", "evilpy")


def test_resolve_missing_or_non_github_is_none():
    http = FakeHttp({"registry.npmjs.org/x": '{"name":"x"}'})       # no repository
    assert resolve_source_repo("x", "npm", http) == (None, None)


def test_find_package_source_repos_dedups_and_skips_known(tmp_path):
    db = Database.open(tmp_path / "p.sqlite")
    db.start_run("r1", utcnow())
    for nm in ("badpkg", "already-known-pkg"):
        db.upsert_artifact(MaliciousArtifact(
            artifact_type=ArtifactType.PACKAGE, name=nm, ecosystem="npm",
            source=FeedSource.OPEN_SOURCE_MALWARE, raw_payload={}), "r1")
    http = FakeHttp({
        "registry.npmjs.org/badpkg":
            '{"repository":{"url":"https://github.com/evil/badpkg"}}',
        "registry.npmjs.org/already-known-pkg":
            '{"repository":{"url":"https://github.com/legit/keep"}}',
    })
    repos = find_package_source_repos(db, http, known={"legit/keep"})
    names = {r.full_name for r in repos}
    assert "evil/badpkg" in names
    assert "legit/keep" not in names             # already known -> excluded
    src = next(r for r in repos if r.full_name == "evil/badpkg")
    assert src.package == "badpkg" and src.ecosystem == "npm"
    db.close()
