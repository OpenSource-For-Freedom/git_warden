"""Runtime configuration and well-known paths.

Kept deliberately small for Week 1. Secrets (API keys) come from the
environment so nothing sensitive is version-controlled; defaults are safe for
local runs.
"""

from __future__ import annotations

import os
from pathlib import Path

from .env import load_env_file

# Repository root = two levels up from this file (src/git_warden/config.py).
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Load .env before reading any variable below, so a local .env populates
# credentials automatically. Real environment variables take precedence.
load_env_file(PROJECT_ROOT / ".env")

DATA_DIR = PROJECT_ROOT / "data"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"

# Tier-2 clone scratch. Set GW_WORK_DIR to keep large, ephemeral clones off a
# near-full system drive (the operator points it at e.g. F:\gw-work on the host).
# None => the system temp dir, which is the right default for CI/Linux. Never
# hardcode a drive letter here; it must stay cross-platform.
_work = os.environ.get("GW_WORK_DIR")
WORK_DIR = Path(_work) if _work else None

# Cached downloads of large reference datasets (e.g. the MITRE ATT&CK bundle).
CACHE_DIR = DATA_DIR / "cache"

# Single-file, version-controllable store (PRD section 9).
DB_PATH = Path(os.environ.get("GIT_WARDEN_DB", DATA_DIR / "git_warden.sqlite"))

# Promotion threshold: an actor needs at least this many *independent* feeds
# corroborating it before the validator promotes it (PRD section 11).
MIN_CORROBORATING_SOURCES = int(os.environ.get("GIT_WARDEN_MIN_SOURCES", "2"))

# Version-controlled list of known threat actors that seed feed queries
# (PRD section 7.1, "begins from known threat-actor accounts").
SEED_ACTORS_PATH = Path(
    os.environ.get("GW_SEED_ACTORS", PROJECT_ROOT / "config" / "seed_actors.json")
)

# Curated malware code-signature search queries (deobfuscator stubs, injection
# patterns) used to hunt novel sibling repos of a confirmed campaign.
MALWARE_SIGNATURES_PATH = Path(
    os.environ.get("GW_MALWARE_SIGNATURES", PROJECT_ROOT / "config" / "malware_signatures.json")
)

# Known-good red-team tooling registry; the legitimate originals the scanner
# pins to detect weaponized clones/forks (doc 02 section 5).
REDTEAM_TOOLS_PATH = Path(
    os.environ.get("GW_REDTEAM_TOOLS", PROJECT_ROOT / "config" / "redteam_tools.json")
)

# --- Credentials (from environment / Actions secrets; never hard-coded) -----
# Reads only; see docs and .env.example for the required scopes per token.
GITHUB_TOKEN = os.environ.get("GW_GITHUB_TOKEN")
# GitHub REST API. Read-only public access; token lifts the rate limit to
# 5,000/hr and is required for GraphQL (doc 02).
GITHUB_API_URL = os.environ.get("GW_GITHUB_API_URL", "https://api.github.com")
GITHUB_API_VERSION = "2022-11-28"
# OSM: RESTful API, Bearer auth ("Authorization: Bearer osm_..."). Endpoints are
# appended to the base URL, e.g. "query-latest" (100 most recent verified
# reports; the free ingestion endpoint).
OSM_API_KEY = os.environ.get("GW_OSM_API_KEY")
OSM_BASE_URL = os.environ.get(
    "GW_OSM_BASE_URL", "https://api.opensourcemalware.com/functions/v1/"
)
# NVD is descoped (free OSINT + OSM cover the sources); no key required.
DISCORD_WEBHOOK = os.environ.get("GW_DISCORD_WEBHOOK")

# --- Feed endpoints (overridable so we can re-point or pin them) ------------
GOOGLE_NEWS_RSS_URL = os.environ.get(
    "GW_GOOGLE_NEWS_RSS_URL", "https://news.google.com/rss/search"
)
# NOTE: verify against CISA's current advisory feed before the first live run.
CISA_FEED_URL = os.environ.get(
    "GW_CISA_FEED_URL", "https://www.cisa.gov/cybersecurity-advisories/all.xml"
)
# MITRE ATT&CK enterprise bundle (authoritative actor registry; ~53 MB).
# Cached locally and refreshed only when the cache exceeds the max age, since
# it is a slow-moving truth-set rather than a fresh-intel feed.
MITRE_ATTACK_URL = os.environ.get(
    "GW_MITRE_ATTACK_URL",
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json",
)
MITRE_CACHE_MAX_AGE_DAYS = int(os.environ.get("GW_MITRE_CACHE_MAX_AGE_DAYS", "7"))

# --- HTTP politeness ---------------------------------------------------------
HTTP_TIMEOUT = int(os.environ.get("GW_HTTP_TIMEOUT", "20"))
USER_AGENT = os.environ.get(
    "GW_USER_AGENT", "git-warden/0.1 (+defensive-threat-intelligence)"
)


def osm_endpoint(path: str) -> str:
    """Join an endpoint path onto the OSM base URL."""
    return OSM_BASE_URL.rstrip("/") + "/" + path.lstrip("/")


def ensure_dirs() -> None:
    """Create the runtime directories if they do not yet exist."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if WORK_DIR:
        WORK_DIR.mkdir(parents=True, exist_ok=True)
