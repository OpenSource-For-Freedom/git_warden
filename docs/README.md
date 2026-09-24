# Git Warden engineering documentation

Git Warden discovers and confirms malicious GitHub repositories without executing target code.

This directory separates system design from operator procedure. The root README is the product overview; these files describe the implementation contract.

## Design

| Document | Purpose |
|---|---|
| [architecture.md](architecture.md) | System boundaries, pipeline stages, trust boundaries, and failure behavior. |
| [finding-storage.md](finding-storage.md) | Finding ownership, SQLite state, shared intelligence, lifecycle, and durability. |
| [../src/git_warden/intel_exchange.py](../src/git_warden/intel_exchange.py) | Wire format for the append-only KNÖRR/Warden intelligence bus. |

## Operations

| Document | Purpose |
|---|---|
| [team-hunt.md](team-hunt.md) | How Warden participates in the joint KNÖRR + Warden hunt. |
| [submit.md](submit.md) | OSM validation and submission rules, including the human approval boundary. |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | Feature inventory and implementation notes. |

## Investigation reports

Campaign reports are point-in-time research records. They are evidence, not architecture. Do not infer current control-plane behavior from an old campaign report.

## Non-negotiable invariants

1. Target repositories are never executed.
2. Tier-2 work runs in the hardened sandbox; there is no host-clone fallback.
3. Threat-intelligence provenance can seed discovery but cannot confirm a repository by itself.
4. AUTO confidence requires intrinsic repository evidence.
5. OSM submission is fail-closed and requires a current live validation.
6. Joint-hunt submission is gated by the protected `osm-submission` environment.
7. Warden owns repository findings. KNÖRR owns container findings. Shared intelligence is correlation state, not a replacement for either database.
