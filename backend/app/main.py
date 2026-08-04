from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from backend.app.analyzers.locks import AnalysisLeaseManager
from backend.app.api.router import router
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.network import (
    approval_matches_destination,
    inspect_mobsf_destination,
)
from backend.app.core.security import ApiSecurityMiddleware, WebSocketTicketStore
from backend.app.core.status import RunStatus
from backend.app.database.base import utcnow
from backend.app.database.models import DiagnosticRun, Project
from backend.app.database.session import SessionLocal, init_database
from backend.app.frida.library import seed_builtin_scripts, validate_builtin_scripts
from backend.app.orchestration import DiagnosticOrchestrator


async def _invalidate_changed_mobsf_approvals(settings: AppSettings) -> None:
    with SessionLocal() as db:
        approvals = [
            {
                "id": item.id,
                "destination": item.external_analyzer_destination,
                "addresses": item.external_analyzer_addresses,
                "certificate": item.external_analyzer_certificate_sha256,
            }
            for item in db.scalars(
                select(Project).where(Project.external_analyzer_allowed.is_(True))
            ).all()
        ]
    if not approvals:
        return
    try:
        snapshot = await inspect_mobsf_destination(settings)
    except ValueError:
        snapshot = None
    invalid_ids = [
        item["id"]
        for item in approvals
        if snapshot is None
        or not approval_matches_destination(
            snapshot,
            approved_destination=item["destination"],
            approved_addresses=item["addresses"],
            approved_certificate_sha256=item["certificate"],
        )
    ]
    if invalid_ids:
        with SessionLocal() as db:
            projects = db.scalars(
                select(Project).where(Project.id.in_(invalid_ids))
            ).all()
            for project in projects:
                project.external_analyzer_allowed = False
                project.external_analyzer_approved_by = None
                project.external_analyzer_approved_at = None
                project.external_analyzer_destination = None
                project.external_analyzer_addresses = []
                project.external_analyzer_certificate_sha256 = None
            db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.ensure_directories()
    init_database()
    with SessionLocal() as db:
        interrupted = db.scalars(
            select(DiagnosticRun).where(
                DiagnosticRun.status.in_(
                    [
                        RunStatus.CREATED.value,
                        RunStatus.RUNNING.value,
                        RunStatus.PAUSE_REQUESTED.value,
                        RunStatus.SAFELY_PAUSED.value,
                        RunStatus.PAUSED.value,
                    ]
                )
            )
        ).all()
        for run in interrupted:
            run.status = RunStatus.INTERRUPTED.value
            run.current_stage = "interrupted"
            run.error = "서버 재시작으로 이전 진단을 중단 상태로 복구했습니다."
            run.finished_at = utcnow()
        db.commit()
        seed_builtin_scripts(db)
        await validate_builtin_scripts(db, settings)
    await _invalidate_changed_mobsf_approvals(settings)
    app.state.settings = settings
    app.state.orchestrator = DiagnosticOrchestrator(settings)
    try:
        yield
    finally:
        await app.state.orchestrator.shutdown()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Mobile Security Workbench",
        version="0.2.0",
        description="Evidence-first local mobile application security diagnostics",
        lifespan=lifespan,
        docs_url="/docs" if settings.enable_api_docs else None,
        redoc_url="/redoc" if settings.enable_api_docs else None,
        openapi_url="/openapi.json" if settings.enable_api_docs else None,
    )
    ticket_store = WebSocketTicketStore()
    app.state.ws_tickets = ticket_store
    app.state.analysis_leases = AnalysisLeaseManager()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:5173",
            "http://localhost:5173",
            "http://127.0.0.1:8765",
            "http://localhost:8765",
        ],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(
        ApiSecurityMiddleware,
        settings=settings,
        ticket_store=ticket_store,
    )
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.effective_trusted_hosts,
    )
    app.include_router(router)

    assets = settings.frontend_dist / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def frontend(full_path: str):
        index = settings.frontend_dist / "index.html"
        requested = (settings.frontend_dist / full_path).resolve()
        if (
            full_path
            and settings.frontend_dist.resolve() in requested.parents
            and requested.is_file()
        ):
            return FileResponse(requested)
        if index.is_file():
            return FileResponse(index)
        return JSONResponse(
            {
                "service": "Mobile Security Workbench",
                "status": "backend_ready",
                "message": "frontend 빌드가 없습니다. frontend에서 npm install && npm run build를 실행하세요.",
                "api_docs": "/docs" if settings.enable_api_docs else None,
            }
        )
    return app


app = create_app()
