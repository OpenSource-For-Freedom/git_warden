# Implementation status

What is built versus what the design docs (01 to 05) still describe as future.
This file is the bridge between the `.docx` designs and the code. Guiding
principle: accuracy over volume.

Every feature below is written to be verified, not taken on faith. Findings carry
the exact `file:line` and rule that fired, and a golden fixture corpus gates the
precision numbers in CI.

## Built and tested

### Ingestion layer (doc 01)
- Data contract (`enums.py`, `models.py`) and a SQLite store (`db/`) with
  forward-only column migrations, WAL journaling, and a read-only open path for the
  dashboard so a live viewer never contends with a running hunt.
- Feeds (`feeds/`): Google News RSS and CISA RSS for actor corroboration, MITRE
  ATT&CK as the authoritative actor registry (cached), and OpenSourceMalware
  (`query-latest`, per ecosystem) as the indicator and artifact source.
- Validator (`validator.py`): two or more independent feeds promote an actor,
  otherwise it is quarantined. A `rejected` verdict is sticky (PRD section 11).
- Ingest pipeline, per-run artifacts, and the CLI `ingest` command.

### Discovery layer (doc 02)
Read-only GitHub REST client (`github/`) for repo metadata, README, search, forks,
user repos, and code search. Discovery mines the ingested actors and IOCs and turns
them into candidate repos through several paths:

- **IOC search** (`scanning/ioc.py`, `discovery.py`): mine OSM IOCs, run them through
  GitHub code search, keep repos that are genuinely new. A defensive-aggregator
  filter means a match inside executable or config source overrides a defensive name.
- **Malware signatures**: code-search a curated signature set
  (`config/malware_signatures.json`), front-loaded on the DPRK `.vscode/tasks.json`
  folderOpen dropper, which is the highest-precision vein.
- **Owner pivot**: enumerate the other repos of an owner who already ships a
  confirmed lure. One seed confirmation maps a whole actor network.
- **Actor accounts** (`scanning/actor_search.py`): repos under promoted
  threat-actor handles (operator curated, gated to promoted actors).
- **OSM repos**, **package to source repo** (`scanning/package_resolver.py`),
  **news mentions** (`scanning/newsdiscovery.py`), and **red-team lineage**
  (`scanning/lineage.py`, forks and renamed clones of pinned tools).

**Self-pacing code search.** GitHub enforces a secondary (abuse) rate limit that
throttles bursts even under the documented ten per minute. `search_code` now
enforces a minimum interval between searches that ratchets up when GitHub pushes
back and relaxes on clean runs. It honors `Retry-After` in full and retries before
giving up. The result is that a long, methodical sweep keeps discovering instead of
abandoning after the first burst. The interval is tunable with
`GW_SEARCH_MIN_INTERVAL` (default eight seconds).

### Tier-1 screening (`scanning/screening.py`, `scanning/discovery.py`)
Name and README joint scoring with homoglyph and confusable normalization
(NFKC plus Cyrillic, Greek, and leet skeletons), edit-distance typosquatting, and
obfuscation, exfil, and remote-exec signals (doc 02 sections 2.2 and 3.1). A repo
whose README reads as a security or research tool, offensive or defensive, is kept
as a breadcrumb and never confirmed. Known-good owners (large legitimate orgs) never
reach Tier-2 at all.

### Tier-2 static analysis (`scanning/tier2.py`)
A validated, bounded clone (allowlisted name, `--` before the URL, size caps) plus a
whole-repo code hash, analyzed **statically only**. The target is never executed.
Three first-party scanners run together:

- the **bash Layer-1 scanner** (`bash_scanner.py`),
- the **install-hook and manifest scanner** (`manifest_scanner.py`: npm lifecycle
  hooks, `setup.py` exec, embedded VS Code tasks), and
- the **JS and Python content scanner** (`content_scanner.py`: eval, atob, base64
  and marshal obfuscation, child_process, webhook exfil).

The OSS scanners **GuardDog** (ecosystem-aware) and **YARA** may confirm on their
own; **Semgrep** runs as enrichment only. Confirmation is precision-first: one
high-signal Tier-A rule, or two distinct Tier-B signals in a steal-and-send pair.
A malformed manifest in one repo can never abort a run, and any per-repo scanner
error is logged and skipped so a long pipeline keeps going.

Red-team lineage confirms only on `WEAPONIZATION_CATEGORIES` and an intent-change
gate (GitHub `compare`: unmodified forks are dropped, only diverged files count),
and even then only when the added code reaches the AUTO tier below. A breach-and-
attack tool like Infection Monkey never confirms on its own attack code.

### Confidence tiering (the submit gate)
Confirmation used to be binary, so a localhost health check and a real dropper both
looked submit-ready. Every finding now carries a confidence tier set by its
confirming mechanism:

- **AUTO**: a delivery, exfil, or dependency mechanism (fetch-and-run, install hook,
  reverse shell, steal-and-send, OSM-listed dependency), or a malware-scanner flag.
  This is the only tier that reaches Discord gold and the submit queue.
- **REVIEW**: a lone broad signal (standalone obfuscation or decode-exec, a bare
  env-dump). Stored for a human, never auto-delivered or auto-submitted.
- **none**: not confirmed, or a security-tool breadcrumb.

The tier is stored on the finding, surfaces in the run counts (`confirmed_auto`
versus `confirmed_review`), gates `gold_for_submission`, and gates Discord delivery.

### Precision golden corpus (`tests/fixtures/precision/`)
A labelled set of minimal repos drawn from real false positives and true positives.
Each `tp_` fixture must confirm at AUTO, each `rv_` fixture must confirm at REVIEW,
and each `fp_` fixture must not reach AUTO. `test_precision_fixtures.py` asserts the
per-fixture verdict and an aggregate AUTO precision floor, so a rule change that
brings back a known false positive fails CI instead of production. Classes covered
include variable-fed decode-exec, folderOpen tasks that fetch reputable registries,
localhost and private IPs, `python -m json.tool` piping, `2>/dev/null` redirects,
installer allowlists, defensive-scanner self-match, vendored front-end libraries,
and benign `node -e` package-manager guards.

### Threat attribution (`dprk.py`, `actors.py`)
Multi-signal, country-level attribution across the 18 seeded actors mapped to five
origins (North Korea, Russia, China, Iran, Cybercrime). Adding a country is a data
entry in `ACTOR_ORIGIN`. A country is asserted only on two or more independent
evidence signals (Contagious-Interview tradecraft vector, self-sourced C2-infra
overlap, a decoded BeaverTail or InvisibleFerret family fingerprint, or a
malicious dependency), or a specific named-group intel tag (APT28, Lazarus,
Kimsuky, and so on). A lone tradecraft vector or a bare nation tag stays a lead.
Confidence tiers (confirmed, probable, possible, unattributed) each carry the
evidence behind them. North Korea has full evidence detectors today, and other
origins attribute from named intel until their own detectors are added.

### Container threats (`containers.py`)
A confirmed repo is also flagged a container threat when its Docker build recipe
carries genuinely malicious behavior: an external-host fetch-and-run, secret exfil,
or a reverse shell at build time. Benign idioms never qualify. A reputable-installer
`curl | bash` (nodesource, rustup) and a `curl -f http://localhost/health` check are
excluded at the scanner and again by a host-gated classifier. It is reported to OSM
as a repository report, docker-tagged.

### OSM submission (`osm_submit.py`)
Contribute confirmed findings back to OpenSourceMalware. The submitter is safe by
design: dry-run by default, it uses your own API key and contributor name, and it
runs several checks before any send.

- **Full-history dedup**: OSM's `query-latest` is only a recent window, so a
  months-old or another researcher's report was invisible to it and produced
  duplicates. The submitter now cross-checks OSM's full history through the search
  endpoint across every `resource_identifier` spelling before sending.
- **Liveness recheck**: each repo's payload is re-fetched at HEAD before sending, so
  a repo whose payload was removed is never submitted only to fail OSM review.
- **Verified IOCs**: each report carries a `verified_iocs` field (C2 host, exact
  payload URL, the download-and-run command, and the dropper file path) so OSM
  indexes them as pivotable indicators instead of leaving them in prose.
- **SHA-pinned evidence**: evidence links pin to the scanned commit, so proof stays
  valid even after the file is removed.
- Only novel AUTO-tier findings with their own `file:line` evidence are eligible.
  Corroborated C2 hosts (seen in two or more confirmed repos, no shorteners) are
  emitted as linked domain IOC reports.

Supporting commands: `--queue` shows the AUTO submit queue ready for review,
`--audit` reports each submission's current standing in OSM and flags duplicates,
`--reconcile` compares your reports against OSM's live state, and `--wizard` walks a
non-technical operator through it step by step.

### DB hygiene (`git-warden revalidate`)
Re-scan confirmed but unsubmitted findings under the current rules. Anything that no
longer confirms, or now reads as a security tool, is demoted to `rejected`, and the
confidence tier on the rest is refreshed. This keeps a stale confirmation from ever
reaching gold or the submit queue after a precision fix lands.

### Observability
`hunt --progress` renders a live, TTY-aware view on stderr (per-source discovery
counters, Tier-1 and Tier-2 progress, a run number, and a learning-corpus delta), so
the "yield compounds by run three" behavior is visible instead of silent. A
per-candidate decision log records every CONFIRMED, NOT_CONFIRMED, REJECTED,
SCREENED, and CLONE_FAILED with its reason, which is the audit trail for chasing
false positives and gaps. `GW_LOG_LEVEL` turns on full-verbosity logging without a
code change, and transport-library noise is suppressed so the signal stays on
git_warden's own decisions.

### Telemetry dashboard (`dashboard/`, PRD section 6)
Read-only FastAPI plus a force-graph over the registry. It shows the discovered
product only (it hides `osm_repository` re-validations), colors each repo node by
attribution confidence, clusters nodes under their origin-country hub, and exposes
the confidence tier. Click a repo for the full evidence, the country attribution
with signals, the decoded payload, and a container-threat badge. The campaign graph
supports scroll-to-zoom, drag-to-pan, and reset controls. An optional bearer-token
gate plus access logging protects a deployment.

### Cross-platform backbone (doc 04, architecture only)
`repo_findings.platform` and `code_hash` columns, and `cross_platform_clusters()`
that groups the same malicious core (shared code hash) across platforms into one
tracked entity. The scanning pipeline is client-agnostic (duck-typed), so adding
GitLab or Gitea is a parallel client class plus a new `Platform` value.

### Orchestration and CI (doc 05)
A self-healing executor (`orchestration/`) reads YAML playbooks
(`config/settings.yaml`, `trigger.yaml`) and classifies each failure into retry,
backoff, queue, defer, skip, or flag-for-manual, with `RunHealth` thresholds that
raise Discord alerts. GitHub Actions: `ci.yml` runs lint and tests, `run.yml` runs
ingest then hunt on demand. Every workflow hardens the runner first.

### Resumable long runs (`hunt --resume`)
A long sweep can be killed or rate-limited. With `--resume`, a re-run skips any repo
that already carries a stored code hash from a prior Tier-2 scan, so it continues
where it stopped instead of re-cloning everything.

## Deferred (until the GitHub core is solid and confirmed repos are flowing)
- **GitLab and Gitea clients** (doc 04): the architecture and cross-platform dedup
  are ready, only the per-platform client classes and OAuth remain.
- **Bash scanner Layer 2**: sandboxed behavioral execution (doc 03 section 3.2),
  the heavy lift of container isolation, tracing, and egress control.
- **Actor to GitHub-handle seeding**: the path and plumbing are built and tested,
  gated to promoted actors. It fires once an operator curates verified GitHub
  usernames or orgs into `config/seed_actors.json`.
- **Evidence detectors for non-DPRK origins**: the engine attributes Russia, China,
  and Iran from named-group intel today. Their own tradecraft, family, and infra
  detectors are a per-profile data addition as they are built.

## Descoped
- **NVD**: free OSINT plus OSM cover the sources, so no NVD key is required.
- **Baseline name corpus** (doc 02 section 2.2 "To expand"): homoglyph and typosquat
  detection is implemented, the reference-distribution corpus is not yet.
