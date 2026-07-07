"""Container / Dockerfile threat classification.

A confirmed repo is ALSO a *container threat* when its build recipe (Dockerfile /
docker-compose) carries genuinely-malicious behaviour: a fetch-and-run from an
attacker host, credential/secret exfil, or a reverse shell at build time.

Benign Docker idioms do NOT count -- a reputable-installer ``curl | bash`` and a
``curl -f http://localhost/health`` healthcheck are normal, and the bash scanner
no longer confirms them (2026-07-06 FP fix). This module is defence-in-depth on
top of that: download/exfil categories still require an EXTERNAL attacker host, so
even the pre-fix stale findings (nodesource install, localhost healthcheck) are
never classed as a container threat.

Per operator decision these are reported to OSM as REPOSITORY reports (OSM can
verify them from the URL) that are TAGGED and surfaced SEPARATELY as container
threats, rather than a malformed ``container`` report with no image reference.
"""

from __future__ import annotations

import re

from .dprk import c2_hosts_from_flags

_DOCKER_FILE = re.compile(r"(?:^|/)(?:dockerfile|docker-compose\.ya?ml|[^/]*\.dockerfile)$", re.I)

# Build-time behaviours malicious regardless of host (a reverse shell or a secret
# grab in a Dockerfile is never legitimate).
_ALWAYS_MALICIOUS = frozenset({"reverse_shell", "credential_harvest", "credential_access"})
# Fetch/exfil behaviours that are malicious ONLY toward an external attacker host
# (installer pipes and localhost healthchecks stay benign).
_HOST_GATED = frozenset({"download_exec", "install_hook", "exfiltration", "network_exfil"})

# Public tags added to a container threat's OSM (repository) report.
CONTAINER_TAGS = ("container", "dockerfile", "build-time-rce")


def is_docker_file(path: str | None) -> bool:
    """True for a Dockerfile / docker-compose / *.dockerfile path."""
    return bool(path) and bool(_DOCKER_FILE.search(str(path).replace("\\", "/")))


def docker_findings(flags: list[dict]) -> list[dict]:
    """The genuinely-malicious Dockerfile/compose findings in a finding's evidence."""
    out: list[dict] = []
    for b in flags or []:
        if not is_docker_file(b.get("file")):
            continue
        cat = b.get("category")
        if cat in _ALWAYS_MALICIOUS:
            out.append(b)
        elif cat in _HOST_GATED and c2_hosts_from_flags([b]):
            out.append(b)
    return out


def is_container_threat(flags: list[dict]) -> bool:
    """True if the repo's container build recipe carries malicious behaviour."""
    return bool(docker_findings(flags))
