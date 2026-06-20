"""Live threat-telemetry dashboard (PRD section 6 -- gated web dashboard).

A read-only view over the SQLite registry that correlates code, repos, and flags:
campaign clusters (shared code-signature / owner / code-hash), per-finding
drill-down (file:line flags + payload + provenance), and run telemetry.

`queries` is pure (takes a Database, returns JSON-able data) so it is unit-tested
with no web server; `app` is the thin FastAPI layer.
"""

from .queries import (
    campaign_clusters,
    finding_detail,
    findings,
    flag_telemetry,
    graph,
    runs_timeline,
    signature_yield,
    summary,
)

__all__ = [
    "summary",
    "findings",
    "finding_detail",
    "campaign_clusters",
    "flag_telemetry",
    "graph",
    "signature_yield",
    "runs_timeline",
]
