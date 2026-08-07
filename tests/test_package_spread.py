"""Package-spread analysis: a found repo as a supply-chain propagation node.

SOURCE = the repo publishes a package version on the malicious feeds (installing it
propagates the payload). VECTOR = the repo depends on one. Both version-scoped, so a
legit package that merely shares a name with a compromised one is never flagged.
"""

from __future__ import annotations

import json

from git_warden.scanning.package_spread import (
    SpreadIntel,
    analyze_spread,
    build_intel,
    describe_spread,
)


def write_pkg(dir_, obj):
    dir_.mkdir(parents=True, exist_ok=True)
    (dir_ / "package.json").write_text(json.dumps(obj), encoding="utf-8")


def make_intel():
    # OSM feed shape + a flat incident manifest, combined.
    osm = {"npm": {"@servicetitan/startup": frozenset({"38.1.3"})}, "pypi": {}}
    manifest = {"@servicetitan/design-system": {"14.5.4"}, "cache-manager": {"7.2.10"}}
    return build_intel(osm, manifest)


def test_source_link_when_repo_publishes_a_compromised_version(tmp_path):
    # The repo's OWN package.json declares a compromised version: it is a spread source.
    write_pkg(tmp_path, {"name": "@servicetitan/design-system", "version": "14.5.4"})
    links = analyze_spread(tmp_path, make_intel())
    assert len(links) == 1
    assert links[0].relationship == "source"
    assert (links[0].package, links[0].version) == ("@servicetitan/design-system", "14.5.4")
    assert links[0].intel == "manifest"


def test_no_source_when_published_version_is_clean(tmp_path):
    # Same package name, but the clean rolled-back version: NOT a spread node.
    write_pkg(tmp_path, {"name": "@servicetitan/design-system", "version": "14.5.3"})
    assert analyze_spread(tmp_path, make_intel()) == []


def test_vector_link_when_dependency_pins_a_compromised_version(tmp_path):
    write_pkg(tmp_path, {"name": "consumer-app", "version": "1.0.0",
                         "dependencies": {"cache-manager": "7.2.10"}})
    links = analyze_spread(tmp_path, make_intel())
    assert len(links) == 1
    assert links[0].relationship == "vector"
    assert (links[0].package, links[0].version) == ("cache-manager", "7.2.10")


def test_range_dependency_is_never_a_vector(tmp_path):
    # A caret range floats to a patched release, so it is not a match.
    write_pkg(tmp_path, {"name": "app", "version": "1.0.0",
                         "dependencies": {"cache-manager": "^7.2.10"}})
    assert analyze_spread(tmp_path, make_intel()) == []


def test_osm_and_manifest_origins_labelled(tmp_path):
    write_pkg(tmp_path, {"name": "@servicetitan/startup", "version": "38.1.3"})
    links = analyze_spread(tmp_path, make_intel())
    assert links[0].intel == "osm"  # this one came from the OSM half


def test_source_and_vector_together(tmp_path):
    write_pkg(tmp_path, {"name": "@servicetitan/startup", "version": "38.1.3",
                         "dependencies": {"cache-manager": "7.2.10"}})
    links = analyze_spread(tmp_path, make_intel())
    rels = sorted(x.relationship for x in links)
    assert rels == ["source", "vector"]


def test_monorepo_workspaces_each_counted(tmp_path):
    write_pkg(tmp_path, {"name": "root", "version": "0.0.0"})
    write_pkg(tmp_path / "packages" / "a",
              {"name": "@servicetitan/startup", "version": "38.1.3"})
    write_pkg(tmp_path / "packages" / "b",
              {"name": "@servicetitan/design-system", "version": "14.5.4"})
    links = analyze_spread(tmp_path, make_intel())
    assert {x.package for x in links} == {"@servicetitan/startup", "@servicetitan/design-system"}


def test_vendored_node_modules_ignored(tmp_path):
    write_pkg(tmp_path, {"name": "app", "version": "1.0.0"})
    write_pkg(tmp_path / "node_modules" / "@servicetitan" / "startup",
              {"name": "@servicetitan/startup", "version": "38.1.3"})
    # The vendored copy inside node_modules must not count as this repo publishing it.
    assert analyze_spread(tmp_path, make_intel()) == []


def test_empty_intel_yields_nothing(tmp_path):
    write_pkg(tmp_path, {"name": "@servicetitan/startup", "version": "38.1.3"})
    assert analyze_spread(tmp_path, SpreadIntel()) == []
    assert SpreadIntel().total() == 0


def test_describe_spread_reads_as_prose():
    intel = make_intel()
    import tempfile
    from pathlib import Path
    d = Path(tempfile.mkdtemp())
    write_pkg(d, {"name": "@servicetitan/startup", "version": "38.1.3",
                  "dependencies": {"cache-manager": "7.2.10"}})
    text = describe_spread(analyze_spread(d, intel))
    assert "publishes" in text and "propagates the payload" in text
    assert "dependency" in text
    assert "--" not in text and "—" not in text  # no dashes in operator-facing text


def test_dashboard_query_lists_spread_nodes(tmp_path):
    from git_warden.dashboard.queries import package_spread as q_spread
    from git_warden.db import Database
    db = Database.open(tmp_path / "t.sqlite")
    payload = {"confidence": "auto", "package_spread": [
        {"relationship": "source", "package": "@servicetitan/startup",
         "version": "38.1.3", "ecosystem": "npm", "file": "package.json", "intel": "manifest"},
        {"relationship": "vector", "package": "cache-manager",
         "version": "7.2.10", "ecosystem": "npm", "file": "package.json", "intel": "osm"},
    ]}
    db.conn.execute(
        "INSERT INTO repo_findings (full_name, url, detection_method, status, score, raw_payload)"
        " VALUES (?,?,?,?,?,?)",
        ("attacker/spreader", "https://github.com/attacker/spreader", "signature_match",
         "confirmed", 10, json.dumps(payload)))
    # a repo with no spread must not appear
    db.conn.execute(
        "INSERT INTO repo_findings (full_name, url, detection_method, status, score, raw_payload)"
        " VALUES (?,?,?,?,?,?)",
        ("clean/repo", "https://github.com/clean/repo", "signature_match",
         "confirmed", 5, json.dumps({"confidence": "auto"})))
    db.conn.commit()
    rows = q_spread(db)
    assert len(rows) == 1
    assert rows[0]["repo"] == "attacker/spreader"
    assert rows[0]["sources"] == ["@servicetitan/startup@38.1.3"]
    assert rows[0]["vectors"] == ["cache-manager@7.2.10"]
    db.close()
