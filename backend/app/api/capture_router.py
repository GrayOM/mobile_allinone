from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from backend.app.auth import OrganizationIdentity
from backend.app.capture import ACTIVE_CAPTURE_STATUSES, CaptureJobManager
from backend.app.database.models import CaptureJob, DiagnosticRun, Project
from backend.app.database.session import SessionLocal


router = APIRouter(prefix="/api")


class CaptureCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    run_id: str | None = None
    device_id: str = Field(min_length=1, max_length=255)
    device_adapter: Literal["mock", "android_adb", "ios_windows"]
    kind: Literal["device_logs", "screen_record"]
    max_duration_seconds: int = Field(default=300, ge=10, le=3_600)


class CaptureOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    run_id: str | None
    device_id: str
    device_adapter: str
    kind: str
    status: str
    max_duration_seconds: int
    mime_type: str | None
    sha256: str | None
    size_bytes: int
    error: str | None
    started_by: str
    synthetic: bool
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    download_available: bool = False


def _manager(request: Request) -> CaptureJobManager:
    return request.app.state.capture_manager


def _actor_name(request: Request) -> str:
    actor: OrganizationIdentity | None = getattr(
        request.state, "organization_actor", None
    )
    return actor.username if actor else "local-operator"


def _capture_out(job: CaptureJob, raw_access_enabled: bool) -> CaptureOut:
    return CaptureOut.model_validate(
        {
            **{column.name: getattr(job, column.name) for column in CaptureJob.__table__.columns},
            "download_available": bool(job.output_path and raw_access_enabled),
        }
    )


@router.post("/capture-jobs", response_model=CaptureOut, status_code=202)
async def start_capture(payload: CaptureCreate, request: Request) -> CaptureOut:
    with SessionLocal() as db:
        project = db.get(Project, payload.project_id)
        if not project:
            raise HTTPException(404, "프로젝트를 찾을 수 없습니다.")
        if project.run_mode == "mock" and payload.device_adapter != "mock":
            raise HTTPException(422, "Mock 프로젝트는 Mock 단말에서만 캡처할 수 있습니다.")
        if project.run_mode == "live" and payload.device_adapter == "mock":
            raise HTTPException(422, "Live 프로젝트는 Mock 단말 캡처를 사용할 수 없습니다.")
        run = db.get(DiagnosticRun, payload.run_id) if payload.run_id else None
        if payload.run_id and not run:
            raise HTTPException(404, "진단 Run을 찾을 수 없습니다.")
        if run and (
            run.project_id != project.id
            or run.device_id != payload.device_id
            or run.device_adapter != payload.device_adapter
        ):
            raise HTTPException(422, "Run·프로젝트·단말·Adapter가 일치하지 않습니다.")
        raw_access_enabled = project.raw_access_enabled
        synthetic = project.run_mode == "mock"
        adapter = request.app.state.orchestrator.device_for_run(db, run) if run else None
    try:
        job = await _manager(request).start(
            project_id=payload.project_id,
            run_id=payload.run_id,
            device_id=payload.device_id,
            device_adapter=payload.device_adapter,
            kind=payload.kind,
            max_duration_seconds=payload.max_duration_seconds,
            started_by=_actor_name(request),
            synthetic=synthetic,
            adapter=adapter,
        )
    except FileExistsError as exc:
        raise HTTPException(409, str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(409, str(exc)) from exc
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc
    return _capture_out(job, raw_access_enabled)


@router.get("/capture-jobs", response_model=list[CaptureOut])
def list_captures(
    project_id: str,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[CaptureOut]:
    with SessionLocal() as db:
        project = db.get(Project, project_id)
        if not project:
            raise HTTPException(404, "프로젝트를 찾을 수 없습니다.")
        jobs = db.scalars(
            select(CaptureJob)
            .where(CaptureJob.project_id == project_id)
            .order_by(CaptureJob.created_at.desc())
            .limit(limit)
        ).all()
        return [_capture_out(job, project.raw_access_enabled) for job in jobs]


@router.post("/capture-jobs/{job_id}/stop", response_model=CaptureOut)
async def stop_capture(job_id: str, request: Request) -> CaptureOut:
    with SessionLocal() as db:
        job = db.get(CaptureJob, job_id)
        if not job:
            raise HTTPException(404, "캡처 Job을 찾을 수 없습니다.")
        project = db.get(Project, job.project_id)
        raw_access_enabled = bool(project and project.raw_access_enabled)
    try:
        stopped = await _manager(request).stop(job_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return _capture_out(stopped, raw_access_enabled)


@router.get("/capture-jobs/{job_id}/download")
def download_capture(job_id: str, request: Request):
    with SessionLocal() as db:
        job = db.get(CaptureJob, job_id)
        if not job:
            raise HTTPException(404, "캡처 Job을 찾을 수 없습니다.")
        project = db.get(Project, job.project_id)
        if not project or not project.raw_access_enabled:
            raise HTTPException(403, "프로젝트에서 Raw 데이터 열람을 먼저 허용해야 합니다.")
        if job.status in ACTIVE_CAPTURE_STATUSES or not job.output_path:
            raise HTTPException(409, "완료된 캡처 원본이 아직 없습니다.")
        output = Path(job.output_path).resolve()
        root = request.app.state.settings.captures_dir.resolve()
        if root not in output.parents or not output.is_file() or output.is_symlink():
            raise HTTPException(404, "캡처 원본 파일을 찾을 수 없습니다.")
        media_type = job.mime_type or "application/octet-stream"
        suffix = ".txt" if job.kind == "device_logs" else ".zip"
        return FileResponse(
            output,
            media_type=media_type,
            filename=f"msw-{job.kind}-{job.id}{suffix}",
        )
