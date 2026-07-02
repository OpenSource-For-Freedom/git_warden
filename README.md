<p align="center">
  <img src="docs/hero.png" alt="Git Warden" width="820">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.0.1-5fa8ff?style=for-the-badge&labelColor=0a0e13" alt="Version 0.0.1">
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
[Hacker News](https://news.ycombinator.com),
[CISA](https://www.cisa.gov), [OpenSourceMalware](https://opensourcemalware.com))
are *provenance breadcrumbs*; they help find and attribute the repos. The product
is the registry of malicious repos, each confirmed on its own static evidence.

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

**Discovery methods** (each breadcrumb widens the net, then Tier-2 confirms on
the repo's own code):

* **IOC search**: mirror a confirmed repo's exfil domains / webhook ids into
  GitHub code search to surface sibling repos on the same infrastructure.
* **Malware-signature engine**: mine a reusable code signature from a confirmed
  payload (an `eval(atob(...))` deobfuscator stub, a `folderOpen` auto-run task)
  and code-search it to find novel campaign members OSM never catalogued.
* **Owner / package / actor pivots**: enumerate the other repos of an account we
  proved malicious, repos that install a version-pinned known-malicious package,
  and repos under a promoted threat actor.
* **News pivot**: Hacker News and Google News writeups that name a repo as
  malicious (free, keyless), screened like any cold search hit.
* **Red-team lineage**: weaponized forks/renames of pinned offensive tools.

**Precision (accuracy over volume).** A repo is CONFIRMED only when Tier-2 finds
its own intrinsic evidence, and confirmation is deliberately conservative:

* **Tier-A (confirm alone)** is reserved for near-zero-base-rate signatures: a
  reverse shell, a *verified* decode-and-execute (the payload is decoded and
  checked for malicious indicators, not just pattern-matched), a whole-env dump,
  a fetch/decode-and-run install hook, a `.vscode/tasks.json` that auto-runs a
  remote payload on folder-open, a secret-file exfil, or a **version-pinned**
  known-malicious dependency.
* **Tier-B (corroborated)** needs a steal-and-send pair in the same file.
* **Dual-use signals never confirm alone.** Crypto keys and file magic, `gdb -p`
  / `ptrace`, `LD_PRELOAD` of an allocator, wait-for-port `/dev/tcp` health
  checks, `String.fromCharCode` builders, and a caret/range dependency spec are
  scored for ranking but cannot brand a repo malicious.
* **What is never evidence:** code in comments or docstrings, test fixtures
  (`*.test.*`, Go `*_test.go`, `test-cases/`), a security tool's own detection
  rules or compromised-package lists, and vendored/generated trees.

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
_Top 10 of 13 repositories confirmed malicious by static analysis this run, ranked by severity. The full list ships as the run's CSV artifact and to the Discord feed; every row's evidence (file, line, rule) is in that CSV. Dispute: open an issue and we will re-review._

| Repository | Detection | Score | Attribution | Proof (file:line rule) |
|------------|-----------|-------|-------------|------------------------|
| [`boredchilada/pkgward-oss`](https://github.com/boredchilada/pkgward-oss) | package_ref | 46 | unattributed | pkgward/analyze/malware_patterns.py:390 credential_access/env-dump  (+19 more) |
| [`usmanaliashraf/portfolio`](https://github.com/usmanaliashraf/portfolio) | signature_match | 12 | unattributed | postcss.config.mjs:12 obfuscation/eval-decoded  (+8 more) |
| [`icecoldjay/bri`](https://github.com/icecoldjay/bri) | signature_match | 11 | unattributed | client/tailwind.config.js:61 obfuscation/eval-decoded  (+3 more) |
| [`dawit212119/prismamonorepoplugin`](https://github.com/dawit212119/prismamonorepoplugin) | osm_repository | 10 | unattributed | src/index.ts:3 code_execution/node-child-process  (+2 more) |
| [`alexsander532/atlas_landingpage`](https://github.com/alexsander532/atlas_landingpage) | signature_match | 9 | unattributed | astro.config.mjs:7 obfuscation/eval-decoded  (+1 more) |
| [`alexsander532/mvp_wain_group130`](https://github.com/alexsander532/mvp_wain_group130) | signature_match | 9 | unattributed | frontend/postcss.config.mjs:9 obfuscation/eval-decoded  (+1 more) |
| [`alexsander532/synapseai_landingpage`](https://github.com/alexsander532/synapseai_landingpage) | signature_match | 9 | unattributed | postcss.config.mjs:12 obfuscation/eval-decoded  (+1 more) |
| [`alexsander532/synapseai`](https://github.com/alexsander532/synapseai) | signature_match | 8 | unattributed | postcss.config.mjs:11 obfuscation/eval-decoded  (+1 more) |
| [`bambao1-lang/bambao1-lang.github.io`](https://github.com/bambao1-lang/bambao1-lang.github.io) | signature_match | 8 | unattributed | package.json:49 enumeration/host-recon  (+2 more) |
| [`haroontaufiq/cosmic-questionnaire`](https://github.com/haroontaufiq/cosmic-questionnaire) | signature_match | 8 | unattributed | postcss.config.mjs:9 obfuscation/eval-decoded  (+3 more) |
<!-- git-warden:registry:end -->

> [!NOTE]
> Every row's evidence (file, line, and the rule that fired) is in the per-run
> artifacts, so each listing is falsifiable. **Dispute a listing:** open an issue
> with the repository name and we will re-review and remove false positives.

<p align="center"><img src="docs/sculk-divider.png" alt="" width="900"></p>

## Bad Owners

Repositories whose **owner** ships malware we confirmed elsewhere, but which carry
no malicious evidence in their *own* code. Owner reputation is a provenance
breadcrumb, not proof, so these never reach the Wall of Shame above or the report
queue. They are listed here as elevated risk, with the owner's evidence-confirmed
repos as the provenance.

<!-- git-warden:badowners:start -->
_These repositories are NOT confirmed malicious on their own code. They appear only because their OWNER also publishes repositories we confirmed by static evidence (linked below, and on the Wall of Shame). Owner reputation is a provenance breadcrumb, not proof, so these never enter the registry or the report queue; treat them as elevated risk pending their own review._

| Repository | Owner | Owner provenance (repos confirmed on evidence) | Score |
|------------|-------|------------------------------------------------|-------|
| [`cs-joy/odysseus`](https://github.com/cs-joy/odysseus) | cs-joy | _known-malicious owner_ | 25 |
| [`cs-joy/model-viewer`](https://github.com/cs-joy/model-viewer) | cs-joy | _known-malicious owner_ | 19 |
| [`cs-joy/tauri`](https://github.com/cs-joy/tauri) | cs-joy | _known-malicious owner_ | 19 |
| [`cs-joy/whatsapp-evo`](https://github.com/cs-joy/whatsapp-evo) | cs-joy | _known-malicious owner_ | 19 |
| [`cs-joy/stellar-core`](https://github.com/cs-joy/stellar-core) | cs-joy | _known-malicious owner_ | 18 |
| [`icecoldjay/infin8solution`](https://github.com/icecoldjay/infin8solution) | icecoldjay | [`icecoldjay/bri`](https://github.com/icecoldjay/bri) | 18 |
| [`nccgroup/gitpwnd`](https://github.com/nccgroup/gitpwnd) | nccgroup | _known-malicious owner_ | 18 |
| [`cs-joy/aider`](https://github.com/cs-joy/aider) | cs-joy | _known-malicious owner_ | 17 |
| [`alexsander532/projeto_dashboard_versao1`](https://github.com/alexsander532/projeto_dashboard_versao1) | alexsander532 | [`alexsander532/atlas_landingpage`](https://github.com/alexsander532/atlas_landingpage), [`alexsander532/mvp_wain_group130`](https://github.com/alexsander532/mvp_wain_group130), [`alexsander532/synapseai`](https://github.com/alexsander532/synapseai)  (+1 more) | 14 |
| [`cs-joy/container`](https://github.com/cs-joy/container) | cs-joy | _known-malicious owner_ | 11 |
<!-- git-warden:badowners:end -->

<p align="center"><img src="docs/sculk-divider.png" alt="" width="900"></p>

## Quick start

```bash
make install                     # pip install -e ".[dev]"  (or skip it: python gw.py <cmd>)
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

A `Makefile` wraps the common flow (`make help` lists every target). It runs the
same on Linux and Windows, shelling out only to Python so there is no
bash-vs-cmd dependency (on Windows: Git Bash, scoop, or `choco install make`):

```bash
make ingest                      # feeds -> actors + OSM artifacts
make iocs                        # IOC pivot set mined from OSM
make discover                    # IOC code search -> new repos
make hunt                        # full pipeline -> Wall of Shame -> Discord (LIMIT=N caps it)
make review                      # list confirmed repos (ARGS="--approve owner/repo")
make serve                       # live telemetry dashboard
make check                       # lint + tests, run before pushing
```

Each target is a thin wrapper over the CLI, so without make you run it directly
(`python gw.py <cmd>`, or the installed `git-warden <cmd>`):

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

## Dashboard

`make serve` (or `python gw.py serve`) runs a live, read-only telemetry
dashboard over the registry. It renders a force-graph of repos, owners,
signatures, threat actors, and payload campaigns, and a click on any repo
explains the finding in plain language: the **attack vector** (e.g. VS Code
folder-open auto-run, obfuscated `eval(atob)` loader), the **C2 / payload
hosts** pulled from the evidence, and the decoded payload, instead of a raw
blob. Side panels cover the **threat actors** and their repos, **source yield
and precision** per discovery method, the **attack-vector** and **C2
infrastructure** breakdowns, the **rejected (false-positive)** list, and a
per-run timeline.

## Running it

Git Warden runs entirely **locally**; there is no CI. It reads and writes a
single local SQLite registry, so run the pipeline on demand or on a schedule you
control (cron, Task Scheduler, a systemd timer):

```bash
python gw.py ingest && python gw.py hunt --scan --gold
python gw.py review --reconcile          # optional: self-heal the wall
python gw.py serve                        # live telemetry dashboard
```

Credentials come from `.env` (see [Quick start](#quick-start)); real environment
variables win. Orchestration knobs live in
[config/settings.yaml](config/settings.yaml).

## Development

```bash
make check                       # ruff + pytest (run before pushing)
make fmt                         # auto-fix lint findings
```

Or invoke the tools directly: `ruff check src tests gw.py` and `pytest -q`.
