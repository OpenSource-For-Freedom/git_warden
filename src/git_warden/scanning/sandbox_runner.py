"""Host side of the sandboxed Tier-2 scan.

Runs the clone+scan inside a hardened, throwaway Docker container so a downloaded
repository's malware never touches the host filesystem. Mirrors git_paca's PR-1
isolation contract: read-only root, non-root user, dropped capabilities, tmpfs
scratch wiped on exit, resource caps, and ``--rm``. The one difference from
git_paca is that warden CLONES inside the container (so it needs network for the
clone) but NEVER executes the target, and results return as JSON on stdout, so no
host path is mounted at all.

``scan_candidate_sandboxed`` returns the same Tier2Result that the in-process
scanner does, so the hunt pipeline consumes it unchanged.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import uuid

from .bash_scanner import BashFinding
from .ioc import IocSet
from .tier2 import Tier2Result

log = logging.getLogger(__name__)

SANDBOX_IMAGE = os.environ.get("GW_SANDBOX_IMAGE", "warden-sandbox:latest")
_MEMORY = os.environ.get("GW_SANDBOX_MEMORY", "1g")
_CPUS = os.environ.get("GW_SANDBOX_CPUS", "2")
_PIDS = os.environ.get("GW_SANDBOX_PIDS", "512")
_TIMEOUT = int(os.environ.get("GW_SANDBOX_TIMEOUT", "300"))
# Untrusted registry values allowed onto the sandbox argv for an extension scan.
_VALID_EXT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\.[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_VALID_VSIX_URL = re.compile(r"https://[A-Za-z0-9.-]+/[A-Za-z0-9._~%/+@-]{1,1024}")


def build_run_argv(full_name: str, image: str = SANDBOX_IMAGE, *,
                   name: str | None = None, args: list[str] | None = None,
                   stdin: bool = False) -> list[str]:
    """The hardened ``docker run`` argv for one repo. Pure; printable for review.

    Network is ON only because the clone fetches from GitHub; the target is never
    executed. Every other lock from the git_paca contract is enforced, and NO host
    path is mounted (findings return on stdout), so the sample cannot reach disk.

    ``name`` lets the caller know the container name so it can force-reap a
    container that outlived its scan (a timeout kills the client before ``--rm``).
    ``args`` replaces the entrypoint arguments (default: just the repo name), e.g.
    ``["--vsix-stdin"]`` for an extension scan. ``stdin`` keeps the container's
    stdin open (``-i``) so the caller can pass the target as JSON instead of argv.
    """
    name = name or f"warden-scan-{uuid.uuid4().hex[:12]}"
    return [
        "docker", "run", *(["-i"] if stdin else []), "--rm", "--name", name,
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", "65534:65534",
        "--pids-limit", _PIDS,
        "--memory", _MEMORY,
        "--memory-swap", _MEMORY,          # no swap -> hard memory cap
        "--cpus", _CPUS,
        # writable scratch on tmpfs (RAM), never the host; wiped when the container dies
        "--tmpfs", "/work:rw,size=1024m,uid=65534,gid=65534",
        "--tmpfs", "/tmp:rw,size=256m,uid=65534,gid=65534",
        "--workdir", "/work",
        "-e", "HOME=/tmp",
        # The image ENTRYPOINT is already `python -m git_warden.sandbox_entry`,
        # so only the repo name is passed here.
        image,
        *(args if args is not None else [full_name]),
    ]


def _reap(name: str, reaper) -> None:
    """Force-remove a container that outlived its scan. Best effort.

    ``--rm`` only fires when the container exits cleanly. A timeout kills the docker
    client while the container keeps running under the daemon, so a malware-bearing
    container would be left alive. This reaps it by name. It must never raise.
    """
    try:
        reaper(["docker", "rm", "-f", name], capture_output=True, text=True, timeout=30)
    except Exception:                                    # pragma: no cover - defensive
        log.debug("sandbox container reap failed", exc_info=True)


def docker_available(image: str = SANDBOX_IMAGE, *, runner=subprocess.run) -> bool:
    """True if a Docker daemon is reachable AND the sandbox image is present.

    A reachable daemon without the image is not a usable sandbox: every scan would
    exit 125 ("Unable to find image") and be misread as a failed clone, so a run
    silently confirms nothing. Treat a missing image as "sandbox unavailable".
    """
    try:
        r = runner(["docker", "info", "--format", "{{.ServerVersion}}"],
                   capture_output=True, text=True, timeout=15)
        if r.returncode != 0 or not r.stdout.strip():
            return False
        img = runner(["docker", "image", "inspect", "--format", "{{.Id}}", image],
                     capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return False
    if img.returncode != 0:
        log.error("sandbox image missing; build it first "
                  "(docker build -f docker/Dockerfile.sandbox -t %s .)", image,
                  extra={"context": {"image": image}})
        return False
    return True


def _result_from_dict(d: dict) -> Tier2Result:
    """Rebuild a real Tier2Result from the container's JSON so hunt code is unchanged."""
    def bf(x):
        return BashFinding(x["file"], x["line"], x["category"], x["rule"], x["snippet"])
    li = IocSet()
    liw = d.get("learned_iocs") or {}
    li.webhooks.update(liw.get("webhooks", []))   # IocSet fields are Counters
    li.telegram.update(liw.get("telegram", []))
    li.domains.update(liw.get("domains", []))
    return Tier2Result(
        full_name=d["full_name"],
        code_hash=d.get("code_hash", ""),
        commit_sha=d.get("commit_sha", ""),
        bash_findings=[bf(x) for x in d.get("bash_findings", [])],
        bash_score=d.get("bash_score", 0),
        scanners=d.get("scanners", {}),
        confirmed=d.get("confirmed", False),
        confidence=d.get("confidence", "none"),
        learned_iocs=li,
        learned_signatures=list(d.get("learned_signatures", [])),
        confirming_findings=[bf(x) for x in d.get("confirming_findings", [])],
        package_spread=list(d.get("package_spread", [])),
    )


def _run_sandbox(target: str, argv: list[str], name: str, runner, reaper,
                 stdin_data: str | None = None) -> dict | None:
    """Run one hardened container and parse its single JSON result line."""
    try:
        proc = runner(argv, input=stdin_data, capture_output=True, text=True,
                      timeout=_TIMEOUT)
    except subprocess.TimeoutExpired:
        log.warning("sandbox scan timed out; reaping container",
                    extra={"context": {"target": target, "container": name}})
        _reap(name, reaper)
        return None
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("sandbox scan failed to run; reaping container",
                    extra={"context": {"target": target, "err": str(exc)}})
        _reap(name, reaper)
        return None
    if proc.returncode != 0:
        log.warning("sandbox container exited non-zero",
                    extra={"context": {"target": target, "code": proc.returncode,
                                       "stderr": (proc.stderr or "")[:300]}})
        return None
    line = (proc.stdout or "").strip().splitlines()[-1] if proc.stdout.strip() else ""
    try:
        return json.loads(line)
    except ValueError:
        log.warning("sandbox produced no parseable result",
                    extra={"context": {"target": target}})
        return None


def scan_extension_sandboxed(ext_id: str, download_url: str, *, image: str = SANDBOX_IMAGE,
                             runner=subprocess.run, reaper=None) -> dict | None:
    """Fetch + STATICALLY analyze one .vsix inside the hardened container.

    Returns the container's JSON (Tier-2 wire shape plus an ``extension`` block),
    or None when the container could not produce a result. ``fetch_failed`` in the
    returned dict means the archive was refused or missing. The extension's bytes
    exist only in the container's tmpfs; the host receives only this JSON.
    """
    # Both values come from registry JSON. They never reach the command line: the
    # argv is constant and the target travels as JSON on stdin, re-validated in
    # the container. They are also allowlisted here so a bad value is refused
    # before a container starts.
    from ..extensions.vsix import host_allowed

    if (not _VALID_EXT_ID.fullmatch(ext_id or "")
            or not _VALID_VSIX_URL.fullmatch(download_url or "")
            or not host_allowed(download_url)):
        log.warning("extension scan rejected: invalid id or download url",
                    extra={"context": {"ext": ext_id}})
        return None
    name = f"warden-vsix-{uuid.uuid4().hex[:12]}"
    argv = build_run_argv("vsix", image, name=name, args=["--vsix-stdin"], stdin=True)
    payload = json.dumps({"id": ext_id, "url": download_url})
    return _run_sandbox(ext_id, argv, name, runner, reaper or runner, stdin_data=payload)


def scan_candidate_sandboxed(full_name: str, *, image: str = SANDBOX_IMAGE,
                             runner=subprocess.run, reaper=None) -> Tier2Result | None:
    """Clone + STATICALLY scan a candidate inside the hardened container.

    Returns a Tier2Result, or None if the clone failed or the container could not
    produce a result. The repository's files exist only in the container's tmpfs and
    are destroyed with it; the host receives nothing but the JSON on stdout.

    On a timeout or a spawn failure the container may still be running, so it is
    force-reaped by name; a leaked malware container must never be left alive.
    """
    if reaper is None:
        reaper = runner
    name = f"warden-scan-{uuid.uuid4().hex[:12]}"
    argv = build_run_argv(full_name, image, name=name)
    try:
        proc = runner(argv, capture_output=True, text=True, timeout=_TIMEOUT)
    except subprocess.TimeoutExpired:
        log.warning("sandbox scan timed out; reaping container",
                    extra={"context": {"repo": full_name, "container": name}})
        _reap(name, reaper)
        return None
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("sandbox scan failed to run; reaping container",
                    extra={"context": {"repo": full_name, "err": str(exc)}})
        _reap(name, reaper)
        return None
    if proc.returncode != 0:
        log.warning("sandbox container exited non-zero",
                    extra={"context": {"repo": full_name, "code": proc.returncode,
                                       "stderr": (proc.stderr or "")[:300]}})
        return None
    line = (proc.stdout or "").strip().splitlines()[-1] if proc.stdout.strip() else ""
    try:
        d = json.loads(line)
    except ValueError:
        log.warning("sandbox produced no parseable result",
                    extra={"context": {"repo": full_name}})
        return None
    if d.get("clone_failed") or d.get("error"):
        return None
    return _result_from_dict(d)
