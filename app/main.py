"""FastAPI entry point and HTTP API for CyberWatch."""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import Settings
from app.database import Database
from app.detection import DetectionEngine
from app.models import (
    Alert,
    AlertStatus,
    BatchIngestResult,
    DashboardSummary,
    LogEvent,
    LogEventCreate,
    Severity,
)

STATIC_DIR = Path(__file__).parent / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    current_settings = settings or Settings.from_environment()
    database = Database(current_settings.database_path)
    detector = DetectionEngine(database)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        database.initialize()
        yield

    app = FastAPI(
        title="CyberWatch Mini-SIEM",
        description="Security event ingestion, rule-based detection, and alert triage.",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.state.database = database
    app.state.detector = detector
    app.state.settings = current_settings

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(current_settings.allowed_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Content-Type", "X-API-Key"],
    )
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    def require_api_key(
        x_api_key: Annotated[str | None, Header()] = None,
    ) -> None:
        if x_api_key is None or not secrets.compare_digest(x_api_key, current_settings.api_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="A valid X-API-Key header is required",
            )

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "healthy", "service": "cyberwatch", "version": "1.0.0"}

    @app.post(
        "/api/events",
        response_model=LogEvent,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_api_key)],
        tags=["events"],
    )
    def ingest_event(payload: LogEventCreate, request: Request) -> LogEvent:
        event = request.app.state.database.insert_event(payload)
        request.app.state.detector.evaluate(event)
        return event

    @app.post(
        "/api/events/batch",
        response_model=BatchIngestResult,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(require_api_key)],
        tags=["events"],
    )
    def ingest_events(payloads: list[LogEventCreate], request: Request) -> BatchIngestResult:
        if not payloads or len(payloads) > 500:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Batch size must be between 1 and 500 events",
            )
        ids: list[int] = []
        alert_count = 0
        for payload in payloads:
            event = request.app.state.database.insert_event(payload)
            ids.append(event.id)
            alert_count += len(request.app.state.detector.evaluate(event))
        return BatchIngestResult(accepted=len(ids), generated_alerts=alert_count, event_ids=ids)

    @app.get("/api/events", response_model=list[LogEvent], tags=["events"])
    def list_events(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        event_type: str | None = None,
        source_ip: str | None = None,
    ) -> list[LogEvent]:
        return request.app.state.database.list_events(
            limit=limit, event_type=event_type, source_ip=source_ip
        )

    @app.get("/api/alerts", response_model=list[Alert], tags=["alerts"])
    def list_alerts(
        request: Request,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        alert_status: Annotated[AlertStatus | None, Query(alias="status")] = None,
        severity: Severity | None = None,
    ) -> list[Alert]:
        return request.app.state.database.list_alerts(
            limit=limit, status=alert_status, severity=severity
        )

    @app.patch(
        "/api/alerts/{alert_id}/acknowledge",
        response_model=Alert,
        dependencies=[Depends(require_api_key)],
        tags=["alerts"],
    )
    def acknowledge_alert(alert_id: int, request: Request) -> Alert:
        alert = request.app.state.database.acknowledge_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return alert

    @app.get("/api/dashboard/summary", response_model=DashboardSummary, tags=["dashboard"])
    def dashboard_summary(request: Request) -> DashboardSummary:
        return DashboardSummary(**request.app.state.database.dashboard_summary())

    return app


app = create_app()
