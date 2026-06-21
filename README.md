<p align="center">
  <img src="docs/hero.png" alt="Git Warden" width="820">
</p>

<p align="center">
  <a href="https://github.com/OpenSource-For-Freedom/git_warden/actions/workflows/run.yml"><img src="https://github.com/OpenSource-For-Freedom/git_warden/actions/workflows/run.yml/badge.svg" alt="The Warden"></a>
  <a href="https://github.com/OpenSource-For-Freedom/git_warden/actions/workflows/ci.yml"><img src="https://github.com/OpenSource-For-Freedom/git_warden/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/version-0.1.0-5fa8ff?style=for-the-badge&labelColor=0a0e13" alt="Version 0.1.0">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-5fa8ff?style=for-the-badge&labelColor=0a0e13" alt="MIT License"></a>
  <a href="https://www.python.org"><img src="https://img.shields.io/badge/python-3.12+-5fa8ff?style=for-the-badge&labelColor=0a0e13&logo=python&logoColor=white" alt="Python 3.12+"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/posture-defensive-22e0d6?style=for-the-badge&labelColor=0a0e13" alt="Defensive">
  <img src="https://img.shields.io/badge/analysis-static_only-22e0d6?style=for-the-badge&labelColor=0a0e13" alt="Static only">
  <img src="https://img.shields.io/badge/targets-never_executed-22e0d6?style=for-the-badge&labelColor=0a0e13" alt="Targets never executed">
  <a href="https://github.com/OpenSource-For-Freedom/Legion_runner"><img src="https://img.shields.io/badge/runner-egress_audited-5fa8ff?style=for-the-badge&labelColor=0a0e13" alt="Egress audited"></a>
  <a href="#wall-of-shame"><img src="https://img.shields.io/badge/wall_of_shame-live-ff5d6c?style=for-the-badge&labelColor=0a0e13" alt="Wall of Shame"></a>
</p>

<p align="center">
  <a href="https://opensourcemalware.com"><img src="https://img.shields.io/badge/malware-OpenSourceMalware-ff5d6c?style=for-the-badge&labelColor=0a0e13" alt="OpenSourceMalware"></a>
  <a href="https://attack.mitre.org"><img src="https://img.shields.io/badge/TTPs-MITRE_ATT%26CK-ff5d6c?style=for-the-badge&labelColor=0a0e13" alt="MITRE ATT&CK"></a>
  <a href="https://www.cisa.gov"><img src="https://img.shields.io/badge/advisories-CISA-ff5d6c?style=for-the-badge&labelColor=0a0e13" alt="CISA"></a>
  <a href="https://news.google.com"><img src="https://img.shields.io/badge/OSINT-Google_News-ff5d6c?style=for-the-badge&labelColor=0a0e13" alt="Google News"></a>
</p>

<p align="center">
  <a href="https://semgrep.dev"><img src="https://img.shields.io/badge/SAST-Semgrep-39d98a?style=for-the-badge&labelColor=0a0e13&logo=semgrep&logoColor=white" alt="Semgrep"></a>
  <a href="https://github.com/DataDog/guarddog"><img src="https://img.shields.io/badge/supply_chain-GuardDog-39d98a?style=for-the-badge&labelColor=0a0e13" alt="GuardDog"></a>
  <a href="https://docs.astral.sh/ruff/"><img src="https://img.shields.io/badge/lint-Ruff-39d98a?style=for-the-badge&labelColor=0a0e13&logo=ruff&logoColor=white" alt="Ruff"></a>
  <a href="https://docs.pytest.org/"><img src="https://img.shields.io/badge/tests-pytest-39d98a?style=for-the-badge&labelColor=0a0e13&logo=pytest&logoColor=white" alt="pytest"></a>
</p>

> **The Warden cannot see. It listens for what code *does*.**
> Git Warden never executes a target; it reads the code statically and senses the
> behaviors that betray malice, the way the Warden senses vibration in the dark.

A defensive threat-intelligence engine that discovers, analyzes, and catalogs
**malicious GitHub repositories**. Threat-intel feeds (MITRE ATT&CK, Google
News, CISA, OpenSourceMalware) are *provenance breadcrumbs*; they help find and
attribute the repos. The product is the registry of malicious repos.

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
_12 repositories confirmed malicious by static analysis, regenerated each run. Every row's evidence (file, line, rule) is in the run artifacts CSV. Dispute: open an issue and we will re-review._

| Repository | Detection | Score | Attribution | First seen | Why |
|------------|-----------|-------|-------------|------------|-----|
| [`alexsander532/projeto_dashboard_versao1`](https://github.com/alexsander532/projeto_dashboard_versao1) | malicious_owner | 14 | unattributed | hunt-20260620T053126Z | repository under owner Alexsander532 of a known-malicious repo \| Tier-2 confirmed (bash score 14) |
| [`usmanaliashraf/portfolio`](https://github.com/usmanaliashraf/portfolio) | signature_match | 12 | unattributed | hunt-20260620T052811Z | Shares a confirmed-malware code signature ['Jzt2YXIgXyRfMWU0Mj0oZnVuY3Rpb24obCxlKXt2YXIgaD1sLm'] \| Tier-2 confirmed (bash score 12) |
| [`icecoldjay/bri`](https://github.com/icecoldjay/bri) | signature_match | 11 | unattributed | hunt-20260620T052811Z | Shares a confirmed-malware code signature ['eval atob filename:tailwind.config.js'] \| Tier-2 confirmed (bash score 11) |
| [`alexsander532/atlas_landingpage`](https://github.com/alexsander532/atlas_landingpage) | signature_match | 9 | unattributed | hunt-20260620T052811Z | Shares a confirmed-malware code signature ['Jzt2YXIgXyRfMWU0Mj0oZnVuY3Rpb24obCxlKXt2YXIgaD1sLm'] \| Tier-2 confirmed (bash score 8) |
| [`alexsander532/mvp_wain_group130`](https://github.com/alexsander532/mvp_wain_group130) | signature_match | 9 | unattributed | hunt-20260620T052811Z | Shares a confirmed-malware code signature ['Jzt2YXIgXyRfMWU0Mj0oZnVuY3Rpb24obCxlKXt2YXIgaD1sLm'] \| Tier-2 confirmed (bash score 8) |
| [`alexsander532/synapseai_landingpage`](https://github.com/alexsander532/synapseai_landingpage) | signature_match | 9 | unattributed | hunt-20260620T052811Z | Shares a confirmed-malware code signature ['Jzt2YXIgXyRfMWU0Mj0oZnVuY3Rpb24obCxlKXt2YXIgaD1sLm'] \| Tier-2 confirmed (bash score 8) |
| [`agrawalchirag/corex`](https://github.com/agrawalchirag/corex) | osm_repository | 8 | DPRK (North Korea) (per OSM) | hunt-20260620T043523Z | Obfuscated eval(atob(...)) payload injected into postcss.config.js after the legit tailwind config (Tier-2 static detection). Lead: OSM quer |
| [`alexsander532/portfolio-pessoal`](https://github.com/alexsander532/portfolio-pessoal) | malicious_owner | 8 | unattributed | hunt-20260620T053126Z | repository under owner Alexsander532 of a known-malicious repo \| Tier-2 confirmed (bash score 8) |
| [`alexsander532/synapse_ai`](https://github.com/alexsander532/synapse_ai) | malicious_owner | 8 | unattributed | hunt-20260620T053126Z | repository under owner Alexsander532 of a known-malicious repo \| Tier-2 confirmed (bash score 8) |
| [`alexsander532/synapseai`](https://github.com/alexsander532/synapseai) | signature_match | 8 | unattributed | hunt-20260620T052811Z | Shares a confirmed-malware code signature ['Jzt2YXIgXyRfMWU0Mj0oZnVuY3Rpb24obCxlKXt2YXIgaD1sLm'] \| Tier-2 confirmed (bash score 8) |
| [`haroontaufiq/cosmic-questionnaire`](https://github.com/haroontaufiq/cosmic-questionnaire) | signature_match | 8 | unattributed | hunt-20260620T052811Z | Shares a confirmed-malware code signature ['Jzt2YXIgXyRfMWU0Mj0oZnVuY3Rpb24obCxlKXt2YXIgaD1sLm'] \| Tier-2 confirmed (bash score 8) |
| [`usmanaliashraf/rag-bot-uet-science-society`](https://github.com/usmanaliashraf/rag-bot-uet-science-society) | malicious_owner | 8 | unattributed | hunt-20260620T053126Z | repository under owner UsmanAliAshraf of a known-malicious repo \| Tier-2 confirmed (bash score 8) |
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
