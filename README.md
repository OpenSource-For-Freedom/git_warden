<p align="center">
  <img src="docs/hero.png" alt="Git Warden" width="820">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-5fa8ff?style=for-the-badge&labelColor=0a0e13" alt="Version 0.1.0">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-5fa8ff?style=for-the-badge&labelColor=0a0e13" alt="MIT License"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.12+-5fa8ff?style=for-the-badge&labelColor=0a0e13&logo=python&logoColor=white" alt="Python 3.12+"></a>
</p>

<p align="center">
  <img src="docs/warden-board.png" alt="Intel feeds, static scanners, guarantees" width="900">
</p>

> **The Warden cannot see. It listens for what code *does*.**
> Git Warden never executes a target; it reads the code statically and senses the
> behaviors that betray malice, the way the Warden senses vibration in the dark.

A defensive threat-intelligence engine that discovers, analyzes, and catalogs
**malicious GitHub repositories**. Threat-intel feeds
([MITRE ATT&CK](https://attack.mitre.org), [Google News](https://news.google.com),
[CISA](https://www.cisa.gov), [OpenSourceMalware](https://opensourcemalware.com))
are *provenance breadcrumbs*; they help find and attribute the repos. The product
is the registry of malicious repos.

See [docs/](docs/) for the design and [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)
for what's built vs. planned. Guiding principle: **accuracy over volume.**

<p align="center"><img src="docs/sculk-divider.png" alt="" width="900"></p>

## How it works

```
INGEST (breadcrumbs)                 HUNT (find malicious GitHub repos)
  MITRE ATT&CK ─┐                      ┌─ IOC search: mirror OSM IOCs into
  Google News  ─┼─ corroborate ─►      │   GitHub code search ----|
  CISA         ─┘   threat actors      ├─ red-team lineage: forks/│
  OpenSourceMalware ─► malicious       │   renames of pinned tools┤
     packages/repos + IOCs ────────────┘                          ▼
                                        Tier-1 screen (name+README, no clone)
                                                          │
                                        Tier-2 (clone + bash scanner + OSS
                                          scanners + code-hash dedup)
                                                          ▼
                                        Wall of Shame ─► Discord gold
```

<p align="center"><img src="docs/sculk-divider.png" alt="" width="900"></p>

## Wall of Shame

<p align="center">
  <img src="docs/wall-of-shame.png" alt="Wall of Shame" width="900">
</p>

Repositories Git Warden confirmed malicious by static analysis, refreshed on
every run. A repo confirms only on intrinsically malicious evidence
(`eval(atob(...))` injected into a build config, a reverse shell, a credential
steal-and-send); threat-intel leads (a malicious owner, a shared signature) only
*seed* which repos get scanned, never confirm one alone.

<!-- git-warden:registry:start -->
_Top 10 of 71 repositories confirmed malicious by static analysis this run, ranked by severity. The full list ships as the run's CSV artifact and to the Discord feed; every row's evidence (file, line, rule) is in that CSV. Dispute: open an issue and we will re-review._

| Repository | Detection | Score | Attribution | First seen | Why |
|------------|-----------|-------|-------------|------------|-----|
| [`anon-exploiter/sliver-cheatsheet`](https://github.com/anon-exploiter/sliver-cheatsheet) | redteam_lineage | 55 | unattributed | hunt-20260618T201449Z | name_match of pinned red-team tool Sliver \| Tier-2 confirmed (bash score 46) |
| [`openwrt/packages`](https://github.com/openwrt/packages) | ioc_search | 37 | unattributed | hunt-20260621T214303Z | Code references OSM IOC(s) ['public-dns.info'] in ['net/banip/files/banip.feeds'] \| Tier-2 confirmed (bash score 37) |
| [`openwrt/openwrt`](https://github.com/openwrt/openwrt) | malicious_owner | 26 | unattributed | hunt-20260621T220813Z | repository under owner openwrt of a known-malicious repo \| Tier-2 confirmed (bash score 26) |
| [`yuxiangggg/shiver`](https://github.com/yuxiangggg/shiver) | redteam_lineage | 26 | unattributed | hunt-20260618T201449Z | fork of pinned red-team tool Sliver \| Tier-2 confirmed (bash score 21) |
| [`investlab/malware-sliver`](https://github.com/investlab/malware-sliver) | redteam_lineage | 25 | unattributed | hunt-20260618T201449Z | fork of pinned red-team tool Sliver \| Tier-2 confirmed (bash score 21) |
| [`joapath/pamperoc2`](https://github.com/joapath/pamperoc2) | redteam_lineage | 25 | unattributed | hunt-20260618T201449Z | fork of pinned red-team tool Sliver \| Tier-2 confirmed (bash score 21) |
| [`kaluabd/watchsliv`](https://github.com/kaluabd/watchsliv) | redteam_lineage | 25 | unattributed | hunt-20260618T201449Z | fork of pinned red-team tool Sliver \| Tier-2 confirmed (bash score 21) |
| [`lishizhendep/hacccck`](https://github.com/lishizhendep/hacccck) | redteam_lineage | 25 | unattributed | hunt-20260618T201449Z | fork of pinned red-team tool Sliver \| Tier-2 confirmed (bash score 21) |
| [`icecoldjay/infin8solution`](https://github.com/icecoldjay/infin8solution) | malicious_owner | 18 | unattributed | hunt-20260621T204101Z | repository under owner icecoldjay of a known-malicious repo \| Tier-2 confirmed (bash score 18) |
| [`openwrt/archive`](https://github.com/openwrt/archive) | malicious_owner | 18 | unattributed | hunt-20260621T220813Z | repository under owner openwrt of a known-malicious repo \| Tier-2 confirmed (bash score 18) |
<!-- git-warden:registry:end -->

> [!NOTE]
> Every row's evidence (file, line, and the rule that fired) is in the per-run
> artifacts, so each listing is falsifiable. **Dispute a listing:** open an issue
> with the repository name and we will re-review and remove false positives.

<p align="center"><img src="docs/sculk-divider.png" alt="" width="900"></p>

## Quick start

```bash
pip install -e ".[dev]"          # or run without install: python gw.py <cmd>
cp .env.example .env             # add GW_GITHUB_TOKEN, GW_OSM_API_KEY, ...
```

Credentials load from `.env` automatically (real env vars win). Tokens:

| Var | What | Notes |
|-----|------|-------|
| `GW_GITHUB_TOKEN` | GitHub PAT, **read-only public** | required for code search + 5k/hr |
| `GW_OSM_API_KEY` | OpenSourceMalware token (`osm_…`) | Bearer auth |
| `GW_DISCORD_WEBHOOK` | gold/alert channel | confirmed findings only |

(No NVD key needed; free OSINT feeds + OSM cover the intel sources for now.)

## Commands

```bash
python gw.py ingest                         # feeds -> actors + OSM artifacts
python gw.py iocs                            # IOC pivot set mined from OSM
python gw.py discover                        # IOC code search -> new repos
python gw.py lineage --tool Sliver --screen 12   # red-team clones + Tier-1
python gw.py screen-artifacts                # Tier-1 over OSM repo scan-list
python gw.py hunt --scan --gold              # full pipeline -> Wall of Shame -> Discord
python gw.py review --approve owner/repo     # analyst-validate a confirmed repo
python gw.py probe --feed github --term lazarus  # probe any feed live
```

## Deployment

GitHub Actions ([.github/workflows/](.github/workflows/)): `ci.yml` runs
lint+tests; `run.yml` runs ingest→hunt weekly (manual first, per doc 05). Every
workflow hardens the runner first (Legion egress audit).

Add these **repo Actions secrets**; the workflow maps them onto the `GW_*` env
vars the code reads (local `.env` uses the `GW_*` names directly):

| Repo secret | Maps to env var.  |
|-------------|-----------------  |
| `GH_TOKEN`  | `GW_GITHUB_TOKEN` |
| `OSM_TOKEN` | `GW_OSM_API_KEY`  |
| `DISCORD_WEBHOOK` | `GW_DISCORD_WEBHOOK` |

Orchestration knobs live in [config/settings.yaml](config/settings.yaml) and
[config/trigger.yaml](config/trigger.yaml).

## Development

```bash
ruff check src tests gw.py
pytest -q
```
