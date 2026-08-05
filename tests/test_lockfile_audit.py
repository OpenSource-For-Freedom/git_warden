"""Lockfile audit: flag a compromised pin in npm/pnpm/yarn lockfiles, never a range.

The manifest is (name, version) exact pairs. A lockfile records the RESOLVED version
that was installed, so a match is a real exposure; a caret range in package.json is
not, because it floats to a patched release.
"""

from __future__ import annotations

import pytest

from git_warden.scanning.lockfile_audit import (
    audit_lockfile,
    audit_tree,
    load_compromised,
    parse_pnpm_lock,
)

# A slice of the real ServiceTitan Chaindrop hit plus a widely-used shared dep.
COMPROMISED = {
    "@servicetitan/design-system": {"14.5.4", "14.5.8"},
    "@servicetitan/startup": {"38.1.1", "38.1.5"},
    "cache-manager": {"7.2.10"},
}


def write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_load_manifest_skips_header_and_comments(tmp_path):
    csv = write(tmp_path, "m.csv",
                "Package,Version\n# a comment\n@servicetitan/startup,38.1.1\n"
                "@servicetitan/startup,38.1.2\ncache-manager,7.2.10\n")
    m = load_compromised(csv)
    assert m["@servicetitan/startup"] == {"38.1.1", "38.1.2"}
    assert "Package" not in m
    assert m["cache-manager"] == {"7.2.10"}


def test_npm_lockfile_v3_packages_map(tmp_path):
    lock = write(tmp_path, "package-lock.json", """
    {
      "lockfileVersion": 3,
      "packages": {
        "": {"name": "app"},
        "node_modules/@servicetitan/design-system": {"version": "14.5.4"},
        "node_modules/@servicetitan/startup": {"version": "38.0.0"},
        "node_modules/left-pad": {"version": "1.3.0"}
      }
    }""")
    hits = audit_lockfile(lock, COMPROMISED)
    got = {(h.package, h.version) for h in hits}
    assert got == {("@servicetitan/design-system", "14.5.4")}  # startup 38.0.0 is clean


def test_npm_lockfile_v1_nested_dependencies(tmp_path):
    lock = write(tmp_path, "package-lock.json", """
    {
      "lockfileVersion": 1,
      "dependencies": {
        "cache-manager": {"version": "7.2.10"},
        "safe-dep": {"version": "1.0.0", "dependencies": {
            "@servicetitan/startup": {"version": "38.1.5"}
        }}
      }
    }""")
    got = {(h.package, h.version) for h in audit_lockfile(lock, COMPROMISED)}
    assert got == {("cache-manager", "7.2.10"), ("@servicetitan/startup", "38.1.5")}


@pytest.mark.parametrize("key", [
    "  /@servicetitan/design-system/14.5.4:",          # pnpm v5
    "  /@servicetitan/design-system@14.5.4:",          # pnpm v6
    "  /@servicetitan/design-system@14.5.4(react@18.0.0):",  # v6 with peer suffix
    "  '@servicetitan/design-system@14.5.4':",         # pnpm v9 snapshots
])
def test_pnpm_key_shapes(key):
    text = "packages:\n" + key + "\n    resolution: {integrity: sha512-x}\n"
    pairs = parse_pnpm_lock(text)
    assert ("@servicetitan/design-system", "14.5.4") in pairs


def test_pnpm_clean_and_dirty(tmp_path):
    lock = write(tmp_path, "pnpm-lock.yaml", """lockfileVersion: '6.0'
packages:
  /@servicetitan/design-system@14.5.4:
    resolution: {integrity: sha512-a}
  /@servicetitan/design-system@14.5.3:
    resolution: {integrity: sha512-b}
  /cache-manager@7.2.10:
    resolution: {integrity: sha512-c}
""")
    got = {(h.package, h.version) for h in audit_lockfile(lock, COMPROMISED)}
    assert got == {("@servicetitan/design-system", "14.5.4"), ("cache-manager", "7.2.10")}
    # 14.5.3 is the clean rolled-back version and must NOT be flagged.


def test_yarn_classic(tmp_path):
    lock = write(tmp_path, "yarn.lock", '''# yarn lockfile v1
"@servicetitan/startup@^38.0.0":
  version "38.1.1"
  resolved "https://registry.npmjs.org/@servicetitan/startup/-/startup-38.1.1.tgz"

cache-manager@^7.0.0:
  version "7.1.0"
  resolved "https://registry.npmjs.org/cache-manager/-/cache-manager-7.1.0.tgz"
''')
    got = {(h.package, h.version) for h in audit_lockfile(lock, COMPROMISED)}
    # startup resolved to a bad version; cache-manager resolved to a clean one.
    assert got == {("@servicetitan/startup", "38.1.1")}


def test_yarn_berry(tmp_path):
    lock = write(tmp_path, "yarn.lock", '''"@servicetitan/design-system@npm:^14.5.0":
  version: 14.5.8
  resolution: "@servicetitan/design-system@npm:14.5.8"
''')
    got = {(h.package, h.version) for h in audit_lockfile(lock, COMPROMISED)}
    assert got == {("@servicetitan/design-system", "14.5.8")}


def test_a_range_in_package_json_is_not_a_match(tmp_path):
    # package.json is not a lockfile; only resolved lockfile versions count. Even if
    # it were parsed, a range must never match an exact compromised version.
    pkg = write(tmp_path, "package.json",
                '{"dependencies": {"@servicetitan/startup": "^38.1.1"}}')
    assert audit_lockfile(pkg, COMPROMISED) == []


def test_clean_lockfile_is_empty(tmp_path):
    lock = write(tmp_path, "package-lock.json",
                 '{"lockfileVersion": 3, "packages": '
                 '{"node_modules/react": {"version": "18.2.0"}}}')
    assert audit_lockfile(lock, COMPROMISED) == []


def test_audit_tree_skips_node_modules_and_finds_root(tmp_path):
    write(tmp_path, "package-lock.json",
          '{"lockfileVersion": 3, "packages": '
          '{"node_modules/cache-manager": {"version": "7.2.10"}}}')
    nm = tmp_path / "node_modules" / "vendored"
    nm.mkdir(parents=True)
    (nm / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": '
        '{"node_modules/@servicetitan/startup": {"version": "38.1.1"}}}',
        encoding="utf-8")
    hits = audit_tree(tmp_path, COMPROMISED)
    got = {(h.package, h.version) for h in hits}
    assert got == {("cache-manager", "7.2.10")}, "vendored node_modules lockfile is skipped"


def test_dedup_same_pin_listed_twice(tmp_path):
    lock = write(tmp_path, "yarn.lock", '''"cache-manager@^7.0.0":
  version "7.2.10"

"cache-manager@~7.2.0":
  version "7.2.10"
''')
    hits = audit_lockfile(lock, COMPROMISED)
    assert len(hits) == 1
