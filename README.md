<p align="center">
  <img src="docs/hero.png" alt="Git Warden" width="820">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/DEFENSIVE-OSINT-22e0d6?style=for-the-badge&labelColor=0a0e13" alt="Defensive OSINT">
  <img src="https://img.shields.io/badge/SCAN-STATIC--ONLY-22e0d6?style=for-the-badge&labelColor=0a0e13" alt="Static only">
  <img src="https://img.shields.io/badge/RUNNER-EGRESS--AUDITED-5fa8ff?style=for-the-badge&labelColor=0a0e13" alt="Egress audited">
  <img src="https://img.shields.io/badge/REGISTRY-HUMAN--VALIDATED-39d98a?style=for-the-badge&labelColor=0a0e13" alt="Human validated">
  <img src="https://img.shields.io/badge/PYTHON-3.12+-869cb2?style=for-the-badge&labelColor=0a0e13" alt="Python 3.12+">
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

## 🟦 How it works

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

## 💀 Wall of Shame

<p align="center">
  <img src="docs/wall-of-shame.png" alt="Wall of Shame" width="900">
</p>

> [!CAUTION]
> A public list is an accusation, and a false positive is a real harm. So a repo
> reaches the wall in **two stages**:
>
> 1. **Machine-confirm.** It confirms only on intrinsically malicious static
>    evidence (`eval(atob(...))` injected into a build config, a reverse shell, a
>    credential steal-and-send). Intel leads (a malicious owner, a shared
>    signature) only *seed* which repos get scanned; they never confirm alone.
> 2. **Analyst-validate.** A human reviews the evidence and runs
>    `gw review --approve owner/repo`. Machine-confirmed but unreviewed findings
>    stay internal (Discord, *pending validation*) and never appear here.

<!-- git-warden:registry:start -->
_0 analyst-validated malicious repositories. Regenerated each run; only findings a human reviewed and approved appear here. Each row's evidence (file, line, rule) is in the run artifacts._

| Repository | Detection | Score | Attribution | First seen | Why |
|------------|-----------|-------|-------------|------------|-----|
| _none yet_ |  |  |  |  |  |
<!-- git-warden:registry:end -->

> [!NOTE]
> Every row's evidence (file, line, and the rule that fired) is recorded in the
> per-run artifacts, so each listing is falsifiable. **Dispute a listing:** open
> an issue with the repository name and we will re-review and remove false
> positives.

<p align="center"><img src="docs/sculk-divider.png" alt="" width="900"></p>

## ⚡ Quick start

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

## ⚔️ Commands

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

## 🛡️ Deployment

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

## 🧪 Development

```bash
ruff check src tests gw.py
pytest -q
```
