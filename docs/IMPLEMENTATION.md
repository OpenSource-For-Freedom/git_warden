# Implementation status

What's built vs. what the design docs (01–05) still describe as future. This
file is the bridge between the `.docx` designs and the code.

## Built and tested

### Ingestion layer (MVP Week 1 — doc 01)
- Data contract: `enums.py`, `models.py` (Pydantic), SQLite store (`db/`).
- Feeds (`feeds/`): Google News RSS + CISA RSS (actor corroboration), MITRE
  ATT&CK (authoritative actor registry, cached ~53 MB), OpenSourceMalware
  (`query-latest`, per-ecosystem; indicator/artifact source).
- Validator (`validator.py`): ≥2 independent feeds → `promoted`, else
  `quarantined`; `rejected` is sticky (PRD §11).
- Pipeline + artifacts + CLI `ingest`. Run artifacts (CSV/JSON) for transparency.

**Decision (not in docs, found by probing):** CISA `all.xml` carries no named
actors, so actor corroboration is Google News + MITRE. OSM has no author field
in the free tier, so it's an *indicator* source feeding the scan list, not actor
attribution. See the `corroboration-and-osm-design` memory.

### GitHub scanning layer (MVP Week 2 — doc 02)
- GitHub REST client (`github/`): repo metadata, README, search, forks, code
  search; rate-limit aware; read-only.
- Red-team registry (`config/redteam_tools.json`, 15 verified anchors) +
  lineage detection (`scanning/lineage.py`): forks + renamed/obscured clones.
- **IOC multiplier** (`scanning/ioc.py`, `discovery.py`): mine OSM IOCs → GitHub
  code search → new candidate repos; defensive-aggregator filter; attacker-host
  pattern selection.
- Tier-1 screening (`scanning/screening.py`): name + README scoring with
  homoglyph/typosquat + obfuscation/exfil/remote-exec signals; decides Tier-2.
- Tier-2 (`scanning/tier2.py`): clone + whole-repo code-hash dedup (doc 02 §4) +
  OSS scanner orchestration (Semgrep/YARA/GuardDog, graceful skip when absent).
- **Custom bash scanner — Layer 1** (`scanning/bash_scanner.py`, doc 03):
  static/signature detection across the full attack surface; recursive,
  bash-bearing file detection; categorized per-file findings.
- Malicious-repo registry (`repo_findings` table, `models.RepoFinding`) — the product.
- `hunt` pipeline + Discord gold output (`notify.py`, doc 02 §6).
- Deployment: GitHub Actions (`ci.yml`, `run.yml`) + orchestration playbooks
  (`config/settings.yaml`, `trigger.yaml`, doc 05).

## Not yet built (future phases)
- **Bash scanner Layer 2** — sandboxed behavioral execution (doc 03 §3.2). The
  heavy lift; needs container/gVisor isolation, tracing, egress control.
- **GitLab & Gitea expansion** (doc 04) — per-platform pipelines, OAuth.
- **Orchestration self-healing** (doc 05) — the YAML playbooks exist as config;
  the classified-retry executor that consumes them is not wired yet.
- **Gated web dashboard** (PRD §6).
- Threat-actor → GitHub username/org seeding for the actor-account search path.

## Descoped (for now)
- **NVD** — deprioritized; free OSINT feeds + OSM cover the intel sources. No
  NVD API key is required. (Listed as a source in doc 01; revisit if needed.)
