"""FastAPI layer for the telemetry dashboard (PRD section 6).

Read-only over the registry. Every endpoint opens a short-lived
:class:`~git_warden.db.Database` so it always reflects the latest committed hunt
writes (live) and is thread-safe. A gating hook (optional bearer token +
access logging) is built in for the PRD's "authenticated and logged" requirement.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from ..config import DB_PATH
from ..db import Database
from . import queries

log = logging.getLogger(__name__)
_STATIC = Path(__file__).parent / "static"


def create_app(db_path=DB_PATH):
    """Build the FastAPI app bound to ``db_path``. Imports FastAPI lazily."""
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import FileResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles

    app = FastAPI(title="Git Warden — Threat Telemetry", docs_url=None, redoc_url=None)
    # Serve the dashboard's own assets (the watermark image, etc.) under /static.
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

    @app.middleware("http")
    async def gate(request: Request, call_next):
        # PRD section 6: authenticated + logged. Token gating is opt-in via env so
        # local use is frictionless; deployments set GW_DASHBOARD_TOKEN.
        client = request.client.host if request.client else "?"
        log.info("dashboard request",
                 extra={"context": {"path": request.url.path, "client": client}})
        token = os.environ.get("GW_DASHBOARD_TOKEN")
        if token and request.url.path.startswith("/api"):
            if request.headers.get("Authorization") != f"Bearer {token}":
                return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)

    def _q(fn, *args):
        # READ-ONLY: the dashboard must never take a write lock, or a live viewer
        # contends with a running hunt (that combination stalled the DB on Windows).
        db = Database.open_readonly(db_path)
        try:
            return fn(db, *args)
        finally:
            db.close()

    @app.get("/api/summary")
    def api_summary():
        return _q(queries.summary)

    @app.get("/api/findings")
    def api_findings(status: str | None = None):
        return _q(queries.findings, status)

    @app.get("/api/finding/{owner}/{name}")
    def api_finding(owner: str, name: str):
        detail = _q(queries.finding_detail, f"{owner}/{name}")
        if detail is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return detail

    @app.get("/api/bad-owners")
    def api_bad_owners():
        return _q(queries.bad_owners)

    @app.get("/api/runs")
    def api_runs():
        return _q(queries.recent_runs)

    @app.get("/api/campaigns")
    def api_campaigns():
        return _q(queries.campaign_clusters)

    @app.get("/api/graph")
    def api_graph(scope: str = "confirmed"):
        return _q(queries.graph, scope)

    @app.get("/api/funnel")
    def api_funnel():
        return _q(queries.funnel)

    @app.get("/api/actors")
    def api_actors():
        return _q(queries.actor_contributions)

    @app.get("/api/telemetry")
    def api_telemetry():
        return {
            "flags": _q(queries.flag_telemetry),
            "signature_yield": _q(queries.signature_yield),
            "runs": _q(queries.runs_timeline),
            "source_yield": _q(queries.source_yield),
        }

    @app.get("/api/rejected")
    def api_rejected():
        return _q(queries.rejected_findings)

    @app.get("/api/vectors")
    def api_vectors():
        return _q(queries.attack_vectors)

    @app.get("/api/c2")
    def api_c2():
        return _q(queries.c2_infrastructure)

    @app.get("/")
    def index():
        return FileResponse(_STATIC / "index.html")

    return app


def serve(db_path=DB_PATH, host: str = "127.0.0.1", port: int = 8787) -> None:
    """Run the dashboard with uvicorn (blocking)."""
    import uvicorn

    log.info("dashboard serving", extra={"context": {"host": host, "port": port}})
    uvicorn.run(create_app(db_path), host=host, port=port, log_level="warning")
