from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.app.api.router import router
from backend.app.core.config import get_settings
from backend.app.database.session import SessionLocal, init_database
from backend.app.database.models import DiagnosticRun
from backend.app.core.status import RunStatus
from sqlalchemy import select
from backend.app.database.base import utcnow
from backend.app.frida.library import seed_builtin_scripts, validate_builtin_scripts
from backend.app.orchestration import DiagnosticOrchestrator


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
    app.state.settings = settings
    app.state.orchestrator = DiagnosticOrchestrator(settings)
    try:
        yield
    finally:
        await app.state.orchestrator.shutdown()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Mobile Security Workbench",
        version="0.2.0",
        description="Evidence-first local mobile application security diagnostics",
        lifespan=lifespan,
    )
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
    app.include_router(router)

    settings = get_settings()
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
                "api_docs": "/docs",
            }
        )
    return app


app = create_app()
