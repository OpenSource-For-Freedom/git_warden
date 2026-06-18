# Implementation status

What's built vs. what the design docs (01–05) still describe as future. This
file is the bridge between the `.docx` designs and the code. Hardened by an
adversarial multi-agent evaluation (18 findings fixed; see git history).

## Built and tested

### Ingestion layer (MVP Week 1 — doc 01)
- Data contract (`enums.py`, `models.py`), SQLite store (`db/`) with forward-only
  column migrations.
- Feeds (`feeds/`): Google News RSS + CISA RSS (actor corroboration), MITRE
  ATT&CK (authoritative actor registry, cached), OpenSourceMalware
  (`query-latest`, per-ecosystem; indicator/artifact source).
- Validator (`validator.py`): ≥2 independent feeds → `promoted`, else
  `quarantined`; `rejected` is sticky (PRD §11).
- Pipeline + run artifacts + CLI `ingest`.

### GitHub scanning layer (MVP Week 2 — doc 02)
- Read-only GitHub REST client (`github/`): repo metadata, README, search,
  forks, user repos, code search; rate-limit aware.
- **Three discovery paths** → candidate repos:
  - **IOC search** (`scanning/ioc.py`, `discovery.py`) — mine OSM IOCs → GitHub
    code search → new repos. Defensive-aggregator filter (source/config *use*
    overrides a defensive name), attacker-host pattern selection.
  - **Red-team lineage** (`scanning/lineage.py`) — forks + renamed/obscured
    clones of pinned tools (`config/redteam_tools.json`).
  - **Actor accounts** (`scanning/actor_search.py`) — repos under *promoted*
    threat-actor GitHub handles (handles are operator-curated; query gated to
    promoted actors).
- Tier-1 screening (`scanning/screening.py`): name + README joint scoring with
  **homoglyph/confusable normalization** (NFKC + Cyrillic/Greek/leet skeleton),
  edit-distance typosquatting, obfuscation/exfil/remote-exec signals (doc 02 §2.2/3.1).
- Tier-2 (`scanning/tier2.py`): validated/bounded clone (allowlisted name, `--`,
  size caps) + whole-repo code-hash + OSS scanner orchestration (Semgrep via
  `--json` results, YARA/GuardDog graceful-skip) + **custom bash Layer-1
  scanner** (`bash_scanner.py`, doc 03). Bash-only confirmation requires a
  high-signal category.
- Malicious-repo registry (`repo_findings`) — the product. Gold output to Discord
  with file-path IOCs + scanner/rule provenance (`notify.py`, doc 02 §6).
- `hunt` pipeline; method-aware run capping.
- **Learning loop**: mine IOCs from confirmed repos' code → grow the search
  corpus (compounding discovery).

### Cross-platform backbone (doc 04, architecture only)
- `repo_findings.platform` + `code_hash` columns; `cross_platform_clusters()`
  groups the same malicious core (shared code hash) across platforms into one
  tracked entity with multiple locations (doc 04 §6).
- The scanning pipeline is **client-agnostic** (duck-typed): adding GitLab/Gitea
  is a parallel client class (same methods, different base-URL/auth) + a new
  `Platform` value — "clone the client, change the variables."

### Orchestration (doc 05)
- Self-healing executor (`orchestration/`): YAML playbooks
  (`config/settings.yaml`, `trigger.yaml`) → classified retry/backoff,
  queue/defer, skip, or flag-for-manual; `RunHealth` thresholds → Discord alerts.
  Wired into the ingest pipeline.
- GitHub Actions: `ci.yml` (lint+tests), `run.yml` (weekly ingest→hunt).

## Deferred (until the GitHub core is solid + confirmed repos flowing)
- **GitLab & Gitea clients** (doc 04) — architecture + cross-platform dedup are
  ready; only the per-platform client classes + OAuth remain.
- **Bash scanner Layer 2** — sandboxed behavioral execution (doc 03 §3.2); the
  heavy lift (container/gVisor isolation, tracing, egress control).
- **Actor→GitHub-handle seeding** — the actor-account path is built but only
  fires once verified handles are curated into the seed identifiers.
- **Gated web dashboard** (PRD §6).

## Descoped
- **NVD** — free OSINT + OSM cover the sources; no NVD key required.
- **Baseline name corpus** (doc 02 §2.2 "To expand") — homoglyph/typosquat
  detection is implemented; the reference-distribution corpus is not yet.
