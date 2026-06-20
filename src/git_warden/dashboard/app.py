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

    app = FastAPI(title="Git Warden — Threat Telemetry", docs_url=None, redoc_url=None)

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
        db = Database.open(db_path)
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

    @app.get("/api/campaigns")
    def api_campaigns():
        return _q(queries.campaign_clusters)

    @app.get("/api/graph")
    def api_graph():
        return _q(queries.graph)

    @app.get("/api/telemetry")
    def api_telemetry():
        return {
            "flags": _q(queries.flag_telemetry),
            "signature_yield": _q(queries.signature_yield),
            "runs": _q(queries.runs_timeline),
        }

    @app.get("/")
    def index():
        return FileResponse(_STATIC / "index.html")

    return app


def serve(db_path=DB_PATH, host: str = "127.0.0.1", port: int = 8787) -> None:
    """Run the dashboard with uvicorn (blocking)."""
    import uvicorn

    log.info("dashboard serving", extra={"context": {"host": host, "port": port}})
    uvicorn.run(create_app(db_path), host=host, port=port, log_level="warning")
