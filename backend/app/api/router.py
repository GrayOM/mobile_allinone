from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import uuid
import zipfile
from pathlib import Path
from typing import Any

import yaml
from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Request,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.ai import AIProviderChain, MockAIProvider
from backend.app.analyzers import (
    APKiDAnalyzerAdapter,
    AndroguardAnalyzerAdapter,
    MobSFAnalyzerAdapter,
    SemgrepAnalyzerAdapter,
    StaticAnalyzer,
    replace_analysis_records,
)
from backend.app.catalog import CATALOG_SOURCE, MASTG_CONTROLS
from backend.app.core.config import ROOT_DIR, AppSettings, get_settings
from backend.app.core.events import event_bus
from backend.app.core.status import CapabilityStatus, Platform
from backend.app.database.models import (
    AIInvocation,
    AppArtifact,
    DiagnosticRun,
    Evidence,
    Finding,
    FridaScript,
    ControlTest,
    FindingSource,
    IOSDeviceProfile,
    Project,
    ProxyFlow,
    RawFinding,
    ToolRun,
)
from backend.app.database.session import get_db
from backend.app.demo import create_demo_apk
from backend.app.devices import AndroidDeviceAdapter, IOSDeviceAdapter, MockDeviceAdapter
from backend.app.evidence.report import EvidenceReportRenderer
from backend.app.frida import FridaManager
from backend.app.orchestration import DiagnosticOrchestrator
from backend.app.proxy import (
    BurpProxyAdapter,
    FiddlerProxyAdapter,
    MitmProxyAdapter,
    MockProxyAdapter,
)
from backend.app.runtime import DrozerRuntimeAdapter, ObjectionRuntimeAdapter
from backend.app.schemas import (
    AppArtifactOut,
    EvidenceOut,
    FindingOut,
    FridaScriptCreate,
    FridaScriptOut,
    IOSDeviceProfileCreate,
    IOSDeviceProfileOut,
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
    ProxyFlowOut,
    RunCreate,
    RunOut,
)


router = APIRouter(prefix="/api")
PACKAGE_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$")


def _orchestrator(request: Request) -> DiagnosticOrchestrator:
    return request.app.state.orchestrator


def _settings(request: Request) -> AppSettings:
    return request.app.state.settings


def _project_or_404(db: Session, project_id: str) -> Project:
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "프로젝트를 찾을 수 없습니다.")
    return project


def _run_or_404(db: Session, run_id: str) -> DiagnosticRun:
    run = db.get(DiagnosticRun, run_id)
    if not run:
        raise HTTPException(404, "진단 실행을 찾을 수 없습니다.")
    return run


def _app_or_404(db: Session, app_id: str) -> AppArtifact:
    app = db.get(AppArtifact, app_id)
    if not app:
        raise HTTPException(404, "앱 파일을 찾을 수 없습니다.")
    return app


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "mobile-security-workbench"}


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)) -> dict[str, Any]:
    projects = db.scalar(select(func.count(Project.id))) or 0
    runs = db.scalar(select(func.count(DiagnosticRun.id))) or 0
    findings = db.scalar(select(func.count(Finding.id))) or 0
    evidence = db.scalar(select(func.count(Evidence.id))) or 0
    recent_runs = db.scalars(
        select(DiagnosticRun).order_by(DiagnosticRun.created_at.desc()).limit(6)
    ).all()
    recent_findings = db.scalars(
        select(Finding).order_by(Finding.created_at.desc()).limit(6)
    ).all()
    return {
        "counts": {
            "projects": projects,
            "runs": runs,
            "findings": findings,
            "evidence": evidence,
        },
        "recent_runs": [RunOut.model_validate(item) for item in recent_runs],
        "recent_findings": [
            FindingOut.model_validate(item) for item in recent_findings
        ],
    }


@router.get("/projects", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db)):
    return db.scalars(select(Project).order_by(Project.updated_at.desc())).all()


@router.post("/projects", response_model=ProjectOut, status_code=201)
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    project = Project(**payload.model_dump())
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: str, db: Session = Depends(get_db)):
    return _project_or_404(db, project_id)


@router.patch("/projects/{project_id}", response_model=ProjectOut)
def update_project(
    project_id: str, payload: ProjectUpdate, db: Session = Depends(get_db)
):
    project = _project_or_404(db, project_id)
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(project, key, value)
    db.commit()
    db.refresh(project)
    return project


@router.delete("/projects/{project_id}")
def delete_project(
    request: Request, project_id: str, db: Session = Depends(get_db)
):
    project = _project_or_404(db, project_id)
    settings = _settings(request)
    apps = list(project.apps)
    runs = list(project.runs)
    findings = list(project.findings)
    ai_rows = db.scalars(
        select(AIInvocation).where(AIInvocation.project_id == project_id)
    ).all()
    directory_targets = [settings.uploads_dir / project.id]
    directory_targets.extend(
        settings.data_dir / "analysis" / Path(app.stored_path).stem for app in apps
    )
    directory_targets.extend(settings.evidence_dir / run.id for run in runs)
    file_targets = [settings.reports_dir / f"{finding.id}.html" for finding in findings]
    file_targets.extend(settings.data_dir / "proxy" / f"{run.id}.jsonl" for run in runs)
    file_targets.extend(
        Path(item.raw_response_path)
        for item in ai_rows
        if item.raw_response_path
    )
    for item in ai_rows:
        db.delete(item)
    db.delete(project)
    db.commit()

    removed: list[str] = []
    for target in directory_targets:
        resolved = target.resolve()
        if (
            resolved != settings.data_dir.resolve()
            and settings.data_dir.resolve() in resolved.parents
            and resolved.is_dir()
        ):
            shutil.rmtree(resolved)
            removed.append(str(resolved))
    for target in file_targets:
        resolved = target.resolve()
        if settings.data_dir.resolve() in resolved.parents and resolved.is_file():
            resolved.unlink()
            removed.append(str(resolved))
    return {
        "status": "deleted",
        "project_id": project_id,
        "removed_paths": removed,
        "recoverable": False,
        "message": "프로젝트 메타데이터와 로컬 원본 파일을 삭제했습니다.",
    }


@router.get("/projects/{project_id}/apps", response_model=list[AppArtifactOut])
def list_apps(project_id: str, db: Session = Depends(get_db)):
    _project_or_404(db, project_id)
    return db.scalars(
        select(AppArtifact)
        .where(AppArtifact.project_id == project_id)
        .order_by(AppArtifact.created_at.desc())
    ).all()


async def _store_and_analyze(
    *,
    project: Project,
    source_path: Path,
    original_name: str,
    settings: AppSettings,
    db: Session,
) -> AppArtifact:
    analyzer = StaticAnalyzer(settings)
    analysis_dir = settings.data_dir / "analysis" / source_path.stem
    try:
        result = await analyzer.analyze(source_path, analysis_dir)
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        source_path.unlink(missing_ok=True)
        raise HTTPException(422, f"앱 분석 실패: {exc}") from exc
    artifact = AppArtifact(
        project_id=project.id,
        original_name=original_name,
        stored_path=str(source_path),
        sha256=result.sha256,
        size_bytes=result.file_size,
        platform=result.platform,
        app_name=result.app_name,
        package_name=result.package_name,
        version=result.version,
        analysis_status=result.status,
        analysis_result=result.to_dict(),
    )
    db.add(artifact)
    db.flush()
    replace_analysis_records(
        db, project=project, artifact=artifact, result=result
    )
    db.commit()
    db.refresh(artifact)
    return artifact


@router.post("/apps/{app_id}/reanalyze", response_model=AppArtifactOut)
async def reanalyze_app(
    request: Request,
    app_id: str,
    db: Session = Depends(get_db),
):
    artifact = _app_or_404(db, app_id)
    project = _project_or_404(db, artifact.project_id)
    source_path = Path(artifact.stored_path)
    if not source_path.is_file():
        raise HTTPException(404, "등록된 앱 원본 파일을 찾을 수 없습니다.")
    settings = _settings(request)
    analyzer = StaticAnalyzer(settings)
    result = await analyzer.analyze(
        source_path, settings.analysis_dir / source_path.stem
    )
    artifact.sha256 = result.sha256
    artifact.size_bytes = result.file_size
    artifact.platform = result.platform
    artifact.app_name = result.app_name
    artifact.package_name = result.package_name
    artifact.version = result.version
    artifact.analysis_status = result.status
    artifact.analysis_result = result.to_dict()
    replace_analysis_records(
        db, project=project, artifact=artifact, result=result
    )
    db.commit()
    db.refresh(artifact)
    return artifact


@router.get("/apps/{app_id}/analysis/overview")
def app_analysis_overview(app_id: str, db: Session = Depends(get_db)):
    artifact = _app_or_404(db, app_id)
    tool_runs = db.scalars(
        select(ToolRun)
        .where(ToolRun.app_id == app_id)
        .order_by(ToolRun.started_at)
    ).all()
    raw_findings = db.scalars(
        select(RawFinding)
        .where(RawFinding.app_id == app_id)
        .order_by(RawFinding.created_at)
    ).all()
    controls = db.scalars(
        select(ControlTest)
        .where(
            ControlTest.app_id == app_id,
            ControlTest.run_id.is_(None),
        )
        .order_by(ControlTest.masvs_id, ControlTest.mastg_id)
    ).all()
    return {
        "app_id": app_id,
        "analysis_status": artifact.analysis_status,
        "catalog_source": CATALOG_SOURCE,
        "tool_runs": [
            {
                "id": item.id,
                "tool_name": item.tool_name,
                "tool_version": item.tool_version,
                "status": item.status,
                "command": item.command,
                "raw_output_path": item.raw_output_path,
                "raw_sha256": item.raw_sha256,
                "error": item.error,
                "metadata": item.metadata_json,
                "started_at": item.started_at,
                "finished_at": item.finished_at,
            }
            for item in tool_runs
        ],
        "raw_findings": [
            {
                "id": item.id,
                "source_tool": item.source_tool,
                "rule_id": item.rule_id,
                "fingerprint": item.fingerprint,
                "title": item.title,
                "category": item.category,
                "severity": item.severity,
                "location": item.location,
                "confidence": item.confidence,
                "references": item.references,
            }
            for item in raw_findings
        ],
        "controls": [_control_to_dict(item) for item in controls],
    }


def _control_to_dict(item: ControlTest) -> dict[str, Any]:
    return {
        "id": item.id,
        "project_id": item.project_id,
        "app_id": item.app_id,
        "run_id": item.run_id,
        "mastg_id": item.mastg_id,
        "masvs_id": item.masvs_id,
        "platform": item.platform,
        "title": item.title,
        "automation": item.automation,
        "status": item.status,
        "result": item.result,
        "summary": item.summary,
        "replacement_ids": item.replacement_ids,
        "source_url": item.source_url,
        "evidence_ids": item.evidence_ids,
        "updated_at": item.updated_at,
    }


@router.post(
    "/projects/{project_id}/apps/upload",
    response_model=AppArtifactOut,
    status_code=201,
)
async def upload_app(
    request: Request,
    project_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    project = _project_or_404(db, project_id)
    settings = _settings(request)
    filename = Path(file.filename or "upload.bin").name
    extension = Path(filename).suffix.lower()
    if extension not in {".apk", ".ipa"}:
        raise HTTPException(415, "APK 또는 IPA 파일만 업로드할 수 있습니다.")
    target_dir = settings.uploads_dir / project.id
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{uuid.uuid4()}{extension}"
    total = 0
    limit = settings.max_upload_mb * 1024 * 1024
    try:
        with target.open("wb") as stream:
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > limit:
                    raise HTTPException(
                        413, f"업로드 제한 {settings.max_upload_mb}MB를 초과했습니다."
                    )
                stream.write(chunk)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    finally:
        await file.close()
    return await _store_and_analyze(
        project=project,
        source_path=target,
        original_name=filename,
        settings=settings,
        db=db,
    )


@router.post("/demo/bootstrap")
async def bootstrap_demo(request: Request, db: Session = Depends(get_db)):
    settings = _settings(request)
    project = Project(
        name="Mock 모바일 진단 데모",
        description="외부 단말·도구 없이 전체 증적 흐름을 확인하는 로컬 데모",
        ai_enabled=True,
        external_ai_allowed=False,
        mock_mode=True,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    target = settings.uploads_dir / project.id / f"{uuid.uuid4()}.apk"
    create_demo_apk(target)
    artifact = await _store_and_analyze(
        project=project,
        source_path=target,
        original_name="msw-demo-bank.apk",
        settings=settings,
        db=db,
    )
    return {
        "project": ProjectOut.model_validate(project),
        "app": AppArtifactOut.model_validate(artifact),
        "next": "Mock Android 단말을 선택해 진단을 시작하세요.",
    }


@router.get("/devices")
async def list_devices(request: Request):
    settings = _settings(request)
    adapters = [
        MockDeviceAdapter(),
        MockDeviceAdapter(platform=Platform.MOCK_IOS),
        AndroidDeviceAdapter(settings),
        IOSDeviceAdapter(settings),
    ]
    ios_host = os.getenv("MSW_IOS_SSH_HOST")
    if ios_host:
        adapters.append(
            IOSDeviceAdapter(
                settings,
                host=ios_host,
                port=int(os.getenv("MSW_IOS_SSH_PORT", "22")),
                username=os.getenv("MSW_IOS_SSH_USER", "root"),
                include_usb=False,
            )
        )
    from backend.app.database.session import SessionLocal

    with SessionLocal() as profile_db:
        profiles = profile_db.scalars(
            select(IOSDeviceProfile).order_by(IOSDeviceProfile.created_at)
        ).all()
        adapters.extend(
            IOSDeviceAdapter(
                settings,
                host=profile.host,
                port=profile.ssh_port,
                username=profile.username,
                include_usb=False,
            )
            for profile in profiles
        )
    discovered = await asyncio.gather(
        *(adapter.discover() for adapter in adapters), return_exceptions=True
    )
    devices = []
    adapter_errors = []
    for adapter, result in zip(adapters, discovered):
        if isinstance(result, Exception):
            adapter_errors.append({"adapter": adapter.name, "error": str(result)})
        else:
            devices.extend(item.to_dict() for item in result)
    return {"devices": devices, "adapter_errors": adapter_errors}


@router.get("/devices/ios/profiles", response_model=list[IOSDeviceProfileOut])
def list_ios_profiles(db: Session = Depends(get_db)):
    return db.scalars(
        select(IOSDeviceProfile).order_by(IOSDeviceProfile.created_at.desc())
    ).all()


@router.post(
    "/devices/ios/profiles",
    response_model=IOSDeviceProfileOut,
    status_code=201,
)
def create_ios_profile(
    payload: IOSDeviceProfileCreate, db: Session = Depends(get_db)
):
    profile = IOSDeviceProfile(**payload.model_dump())
    db.add(profile)
    db.commit()
    db.refresh(profile)
    return profile


@router.delete("/devices/ios/profiles/{profile_id}")
def delete_ios_profile(profile_id: str, db: Session = Depends(get_db)):
    profile = db.get(IOSDeviceProfile, profile_id)
    if not profile:
        raise HTTPException(404, "iOS 단말 프로필을 찾을 수 없습니다.")
    db.delete(profile)
    db.commit()
    return {"status": "deleted", "profile_id": profile_id}


class DeviceAction(BaseModel):
    adapter: str = "mock"
    device_id: str
    action: str
    package_name: str | None = None
    app_id: str | None = None
    remote_path: str | None = None
    local_port: int | None = Field(default=None, ge=1, le=65535)
    remote_port: int | None = Field(default=None, ge=1, le=65535)


@router.post("/devices/action")
async def device_action(
    request: Request, payload: DeviceAction, db: Session = Depends(get_db)
):
    settings = _settings(request)
    if payload.adapter == "android_adb":
        adapter = AndroidDeviceAdapter(settings)
    elif payload.adapter == "ios_windows":
        ssh_host = os.getenv("MSW_IOS_SSH_HOST")
        ssh_port = int(os.getenv("MSW_IOS_SSH_PORT", "22"))
        if payload.device_id.startswith("ios-ssh:"):
            parts = payload.device_id.split(":")
            if len(parts) >= 3:
                ssh_host = parts[1]
                try:
                    ssh_port = int(parts[2])
                except ValueError:
                    raise HTTPException(422, "iOS SSH 단말 ID의 포트가 올바르지 않습니다.")
        adapter = IOSDeviceAdapter(
            settings,
            host=ssh_host,
            port=ssh_port,
            username=os.getenv("MSW_IOS_SSH_USER", "root"),
        )
    else:
        adapter = MockDeviceAdapter()
    if payload.package_name and not PACKAGE_PATTERN.fullmatch(payload.package_name):
        raise HTTPException(422, "패키지명 형식이 올바르지 않습니다.")
    actions = {
        "list_packages": lambda: adapter.list_packages(payload.device_id),
        "start": lambda: adapter.start_app(
            payload.device_id, payload.package_name or "com.example.demo"
        ),
        "stop": lambda: adapter.stop_app(
            payload.device_id, payload.package_name or "com.example.demo"
        ),
        "uninstall": lambda: adapter.uninstall_app(
            payload.device_id, payload.package_name or "com.example.demo"
        ),
        "process": lambda: adapter.process_info(
            payload.device_id, payload.package_name or "com.example.demo"
        ),
        "frida_status": lambda: adapter.frida_status(payload.device_id),
        "forward_port": lambda: adapter.forward_port(
            payload.device_id, payload.local_port or 27042, payload.remote_port or 27042
        ),
    }
    if payload.action == "install":
        if not payload.app_id:
            raise HTTPException(422, "install에는 app_id가 필요합니다.")
        app = _app_or_404(db, payload.app_id)
        operation = await adapter.install_app(payload.device_id, Path(app.stored_path))
    elif payload.action in {"screenshot", "logs", "pull_file"}:
        action_dir = settings.evidence_dir / "manual-actions"
        action_dir.mkdir(parents=True, exist_ok=True)
        if payload.action == "screenshot":
            operation = await adapter.screenshot(
                payload.device_id, action_dir / f"{uuid.uuid4()}.png"
            )
        elif payload.action == "logs":
            operation = await adapter.collect_logs(
                payload.device_id, action_dir / f"{uuid.uuid4()}.log"
            )
        else:
            if not payload.remote_path:
                raise HTTPException(422, "pull_file에는 remote_path가 필요합니다.")
            operation = await adapter.pull_file(
                payload.device_id,
                payload.remote_path,
                action_dir / f"{uuid.uuid4()}-{Path(payload.remote_path).name}",
            )
    elif payload.action in actions:
        operation = await actions[payload.action]()
    else:
        raise HTTPException(422, "지원하지 않는 단말 작업입니다.")
    return operation.to_dict()


@router.get("/projects/{project_id}/runs", response_model=list[RunOut])
def list_runs(project_id: str, db: Session = Depends(get_db)):
    _project_or_404(db, project_id)
    return db.scalars(
        select(DiagnosticRun)
        .where(DiagnosticRun.project_id == project_id)
        .order_by(DiagnosticRun.created_at.desc())
    ).all()


@router.post("/runs", response_model=RunOut, status_code=201)
async def create_run(
    request: Request, payload: RunCreate, db: Session = Depends(get_db)
):
    project = _project_or_404(db, payload.project_id)
    if payload.app_id:
        app = _app_or_404(db, payload.app_id)
        if app.project_id != project.id:
            raise HTTPException(422, "앱이 선택한 프로젝트에 속하지 않습니다.")
    options = dict(payload.options)
    options.update(
        {
            "frida_script_ids": payload.frida_script_ids,
            "pause_for_login": payload.pause_for_login,
        }
    )
    run = DiagnosticRun(
        project_id=project.id,
        app_id=payload.app_id,
        device_id=payload.device_id,
        device_adapter=payload.device_adapter,
        proxy_adapter=payload.proxy_adapter,
        status="created",
        current_stage="ready",
        progress=0,
        options=options,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    _orchestrator(request).launch(run.id)
    return run


@router.get("/runs/{run_id}", response_model=RunOut)
def get_run(run_id: str, db: Session = Depends(get_db)):
    return _run_or_404(db, run_id)


@router.post("/runs/{run_id}/pause")
async def pause_run(request: Request, run_id: str, db: Session = Depends(get_db)):
    _run_or_404(db, run_id)
    if not await _orchestrator(request).pause(run_id):
        raise HTTPException(409, "실행 중인 진단이 아닙니다.")
    return {"status": "paused"}


@router.post("/runs/{run_id}/resume")
async def resume_run(request: Request, run_id: str, db: Session = Depends(get_db)):
    _run_or_404(db, run_id)
    if not await _orchestrator(request).resume(run_id):
        raise HTTPException(409, "재개할 수 있는 진단이 아닙니다.")
    return {"status": "running"}


@router.post("/runs/{run_id}/stop")
async def stop_run(request: Request, run_id: str, db: Session = Depends(get_db)):
    _run_or_404(db, run_id)
    if not await _orchestrator(request).stop(run_id):
        raise HTTPException(409, "실행 중인 진단이 아닙니다.")
    return {"status": "stopping"}


@router.get("/runs/{run_id}/evidence", response_model=list[EvidenceOut])
def list_evidence(run_id: str, db: Session = Depends(get_db)):
    _run_or_404(db, run_id)
    return db.scalars(
        select(Evidence)
        .where(Evidence.run_id == run_id)
        .order_by(Evidence.sequence, Evidence.captured_at)
    ).all()


@router.get("/runs/{run_id}/flows", response_model=list[ProxyFlowOut])
def list_flows(run_id: str, db: Session = Depends(get_db)):
    _run_or_404(db, run_id)
    return db.scalars(
        select(ProxyFlow)
        .where(ProxyFlow.run_id == run_id)
        .order_by(ProxyFlow.captured_at)
    ).all()


@router.websocket("/runs/{run_id}/ws")
async def run_websocket(websocket: WebSocket, run_id: str):
    await websocket.accept()
    queue = event_bus.subscribe(run_id)
    try:
        await websocket.send_json(
            {
                "type": "connected",
                "channel": run_id,
                "data": {"message": "실시간 진단 채널에 연결되었습니다."},
            }
        )
        while True:
            event_task = asyncio.create_task(queue.get())
            receive_task = asyncio.create_task(websocket.receive())
            done, pending = await asyncio.wait(
                {event_task, receive_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            if receive_task in done:
                message = receive_task.result()
                if message.get("type") == "websocket.disconnect":
                    break
            if event_task in done:
                await websocket.send_json(event_task.result())
    except WebSocketDisconnect:
        pass
    finally:
        event_bus.unsubscribe(run_id, queue)


@router.get("/findings", response_model=list[FindingOut])
def list_findings(
    project_id: str | None = None,
    run_id: str | None = None,
    db: Session = Depends(get_db),
):
    query = select(Finding)
    if project_id:
        query = query.where(Finding.project_id == project_id)
    if run_id:
        query = query.where(Finding.run_id == run_id)
    return db.scalars(query.order_by(Finding.created_at.desc())).all()


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "발견항목을 찾을 수 없습니다.")
    return finding


@router.get("/findings/{finding_id}/sources")
def get_finding_sources(finding_id: str, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "발견항목을 찾을 수 없습니다.")
    sources = db.scalars(
        select(FindingSource)
        .where(FindingSource.finding_id == finding_id)
        .order_by(FindingSource.created_at)
    ).all()
    return [
        {
            "id": item.id,
            "source_tool": item.source_tool,
            "source_rule_id": item.source_rule_id,
            "fingerprint": item.fingerprint,
            "raw_finding_id": item.raw_finding_id,
            "evidence_ids": item.evidence_ids,
            "created_at": item.created_at,
        }
        for item in sources
    ]


@router.get("/evidence/{evidence_id}/download")
def download_evidence(
    request: Request, evidence_id: str, db: Session = Depends(get_db)
):
    evidence = db.get(Evidence, evidence_id)
    if not evidence or not evidence.file_path:
        raise HTTPException(404, "원본 증적 파일이 없습니다.")
    path = Path(evidence.file_path).resolve()
    data_dir = _settings(request).data_dir.resolve()
    if data_dir not in path.parents or not path.is_file():
        raise HTTPException(403, "허용된 증적 저장소 밖의 파일입니다.")
    return FileResponse(
        path,
        media_type=evidence.mime_type or "application/octet-stream",
        filename=path.name,
    )


@router.post("/findings/{finding_id}/report")
def create_report(
    request: Request, finding_id: str, db: Session = Depends(get_db)
):
    try:
        path = EvidenceReportRenderer(_settings(request)).render(db, finding_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return {
        "status": "created",
        "finding_id": finding_id,
        "url": f"/api/findings/{finding_id}/report",
        "file": path.name,
    }


@router.get("/findings/{finding_id}/report")
def view_report(
    request: Request, finding_id: str, db: Session = Depends(get_db)
):
    try:
        path = EvidenceReportRenderer(_settings(request)).render(db, finding_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return FileResponse(path, media_type="text/html")


@router.get("/frida/scripts", response_model=list[FridaScriptOut])
def list_frida_scripts(
    platform: str | None = None,
    category: str | None = None,
    db: Session = Depends(get_db),
):
    query = select(FridaScript)
    if platform:
        query = query.where(FridaScript.platform == platform)
    if category:
        query = query.where(FridaScript.category == category)
    return db.scalars(query.order_by(FridaScript.category, FridaScript.name)).all()


@router.post("/frida/scripts", response_model=FridaScriptOut, status_code=201)
async def create_frida_script(
    request: Request, payload: FridaScriptCreate, db: Session = Depends(get_db)
):
    manager = FridaManager(_settings(request))
    syntax_status, _ = await manager.check_syntax(payload.content)
    script = FridaScript(
        **payload.model_dump(),
        approval_status="pending_approval",
        syntax_status=syntax_status.value,
    )
    db.add(script)
    db.commit()
    db.refresh(script)
    return script


@router.post("/frida/scripts/{script_id}/approve", response_model=FridaScriptOut)
async def approve_frida_script(
    request: Request, script_id: str, db: Session = Depends(get_db)
):
    script = db.get(FridaScript, script_id)
    if not script:
        raise HTTPException(404, "Frida 스크립트를 찾을 수 없습니다.")
    status, message = await FridaManager(_settings(request)).check_syntax(script.content)
    script.syntax_status = status.value
    if status == CapabilityStatus.FAILED:
        db.commit()
        raise HTTPException(422, f"구문 검사 실패: {message}")
    script.approval_status = "approved"
    db.commit()
    db.refresh(script)
    return script


class FridaExecuteRequest(BaseModel):
    device_id: str = "mock-android-01"
    target: str = "com.example.demo"
    mode: str = "spawn"
    mock: bool = True


@router.post("/frida/scripts/{script_id}/execute")
async def execute_frida_script(
    request: Request,
    script_id: str,
    payload: FridaExecuteRequest,
    db: Session = Depends(get_db),
):
    script = db.get(FridaScript, script_id)
    if not script:
        raise HTTPException(404, "Frida 스크립트를 찾을 수 없습니다.")
    if script.approval_status != "approved":
        raise HTTPException(409, "승인된 스크립트만 실행할 수 있습니다.")
    result = await FridaManager(_settings(request)).execute(
        device_id=payload.device_id,
        target=payload.target,
        script_name=script.name,
        script_content=script.content,
        mode=payload.mode,
        mock=payload.mock,
    )
    if result.status == CapabilityStatus.AVAILABLE:
        script.success_count += 1
    else:
        script.failure_count += 1
    db.commit()
    return result.to_dict()


class FridaGenerateRequest(BaseModel):
    project_id: str
    platform: str = Field(pattern="^(android|ios)$")
    category: str = Field(default="Custom", max_length=100)
    target_framework: str = Field(default="generic", max_length=100)
    task: str = Field(default="실패한 Frida 스크립트 수정 후보 생성", max_length=500)
    code_excerpt: str = Field(default="", max_length=20000)
    runtime_log: str = Field(default="", max_length=20000)
    failed_script: str = Field(default="", max_length=30000)
    failure_message: str = Field(default="", max_length=8000)
    use_mock: bool = False
    simulate_nvidia_failure: bool = False


@router.post("/frida/scripts/generate")
async def generate_frida_script(
    request: Request,
    payload: FridaGenerateRequest,
    db: Session = Depends(get_db),
):
    project = _project_or_404(db, payload.project_id)
    if not project.ai_enabled:
        raise HTTPException(409, "이 프로젝트는 AI 사용이 비활성화되어 있습니다.")
    if not payload.use_mock and not project.mock_mode and not project.external_ai_allowed:
        raise HTTPException(409, "이 프로젝트는 외부 AI 전송이 비활성화되어 있습니다.")

    context = {
        "platform": payload.platform,
        "category": payload.category,
        "target_framework": payload.target_framework,
        "code_excerpt": payload.code_excerpt,
        "runtime_log": payload.runtime_log,
        "failed_script": payload.failed_script,
        "failure_message": payload.failure_message,
        "simulate_nvidia_failure": payload.simulate_nvidia_failure,
    }
    settings = _settings(request)
    if payload.use_mock or project.mock_mode:
        selected = await MockAIProvider().generate_frida_script(
            payload.task, context, masked=True
        )
        attempts = [selected]
    else:
        selected, attempts = await AIProviderChain(
            settings=settings
        ).generate_frida_script(
            payload.task,
            context,
            masked=settings.mask_external_ai_data,
        )

    for attempt in attempts:
        raw_path = None
        if attempt.raw_response:
            raw_path = settings.ai_raw_dir / (
                f"frida-{project.id}-{uuid.uuid4()}-{attempt.provider}.json"
            )
            raw_path.write_text(attempt.raw_response, encoding="utf-8")
        db.add(
            AIInvocation(
                project_id=project.id,
                provider=attempt.provider,
                model=attempt.model,
                task="frida_script_generation",
                status=attempt.status.value,
                masked=attempt.masked,
                quality_score=attempt.quality_score,
                raw_response_path=str(raw_path) if raw_path else None,
                error=(
                    attempt.message
                    if attempt.status != CapabilityStatus.AVAILABLE
                    else None
                ),
            )
        )

    script = None
    syntax_message = None
    if selected.status == CapabilityStatus.AVAILABLE and selected.candidate:
        candidate = selected.candidate
        syntax_status, syntax_message = await FridaManager(
            settings
        ).check_syntax(candidate.content)
        script = FridaScript(
            name=candidate.name,
            platform=candidate.platform,
            category=candidate.category,
            target_framework=candidate.target_framework,
            conditions=candidate.conditions,
            risk=candidate.risk,
            content=candidate.content,
            source=f"ai:{selected.provider}",
            approval_status="pending_approval",
            syntax_status=syntax_status.value,
        )
        db.add(script)
    db.commit()
    if script:
        db.refresh(script)
    return {
        "selected": selected.to_dict(),
        "attempts": [item.to_dict() for item in attempts],
        "script": FridaScriptOut.model_validate(script).model_dump(mode="json")
        if script
        else None,
        "syntax_message": syntax_message,
        "execution_policy": "never_auto_execute; syntax_check_then_user_approval",
    }


@router.get("/proxy/adapters")
async def proxy_adapters(request: Request):
    settings = _settings(request)
    adapters = [
        MockProxyAdapter(),
        MitmProxyAdapter(settings),
        FiddlerProxyAdapter(),
        BurpProxyAdapter(),
    ]
    statuses = await asyncio.gather(*(item.status() for item in adapters))
    return [
        {"name": adapter.name, **status.to_dict()}
        for adapter, status in zip(adapters, statuses)
    ]


@router.get("/analysis/tools")
async def analysis_tools(request: Request):
    settings = _settings(request)
    adapters = (
        AndroguardAnalyzerAdapter(settings),
        APKiDAnalyzerAdapter(settings),
        SemgrepAnalyzerAdapter(settings),
        MobSFAnalyzerAdapter(settings),
    )
    return await asyncio.gather(*(adapter.health() for adapter in adapters))


@router.get("/runtime/adapters")
async def runtime_adapters(request: Request):
    settings = _settings(request)
    adapters = (
        ObjectionRuntimeAdapter(settings),
        DrozerRuntimeAdapter(settings),
    )
    return await asyncio.gather(*(adapter.health() for adapter in adapters))


class RuntimeExecuteRequest(BaseModel):
    adapter: str
    device_id: str
    target: str
    action: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    approved: bool = False


@router.post("/runtime/execute")
async def execute_runtime_tool(
    request: Request,
    payload: RuntimeExecuteRequest,
):
    settings = _settings(request)
    adapters = {
        "objection": ObjectionRuntimeAdapter(settings),
        "drozer": DrozerRuntimeAdapter(settings),
    }
    adapter = adapters.get(payload.adapter)
    if not adapter:
        raise HTTPException(422, "지원하지 않는 런타임 Adapter입니다.")
    result = await adapter.execute(
        device_id=payload.device_id,
        target=payload.target,
        action=payload.action,
        arguments=payload.arguments,
        approved=payload.approved,
    )
    return result.to_dict()


@router.get("/coverage")
def coverage(
    project_id: str | None = None,
    app_id: str | None = None,
    run_id: str | None = None,
    scope: str = "template",
    platform: str | None = None,
    db: Session = Depends(get_db),
):
    query = select(ControlTest)
    if project_id:
        query = query.where(ControlTest.project_id == project_id)
    if app_id:
        query = query.where(ControlTest.app_id == app_id)
    if run_id:
        query = query.where(ControlTest.run_id == run_id)
    elif scope == "template":
        query = query.where(ControlTest.run_id.is_(None))
    if platform:
        query = query.where(ControlTest.platform == platform)
    rows = db.scalars(
        query.order_by(ControlTest.masvs_id, ControlTest.mastg_id)
    ).all()
    counts: dict[str, int] = {}
    result_counts: dict[str, int] = {}
    for item in rows:
        counts[item.status] = counts.get(item.status, 0) + 1
        result_counts[item.result] = result_counts.get(item.result, 0) + 1
    return {
        "source": CATALOG_SOURCE,
        "total_catalog": len(
            [item for item in MASTG_CONTROLS if not platform or item.platform == platform]
        ),
        "counts": counts,
        "result_counts": result_counts,
        "tests": [_control_to_dict(item) for item in rows],
    }


class AITestRequest(BaseModel):
    task: str = "연결 테스트"
    context: dict[str, Any] = Field(default_factory=lambda: {"platform": "android"})
    use_mock: bool = False
    simulate_nvidia_failure: bool = False


@router.post("/ai/test")
async def test_ai(request: Request, payload: AITestRequest):
    context = dict(payload.context)
    context["simulate_nvidia_failure"] = payload.simulate_nvidia_failure
    if payload.use_mock:
        result = await MockAIProvider().analyze(payload.task, context)
        return {"selected": result.to_dict(), "attempts": [result.to_dict()]}
    result, attempts = await AIProviderChain(settings=_settings(request)).analyze(
        payload.task,
        context,
        masked=_settings(request).mask_external_ai_data,
    )
    return {
        "selected": result.to_dict(),
        "attempts": [item.to_dict() for item in attempts],
    }


@router.get("/settings")
def read_settings(request: Request):
    settings = _settings(request)
    install_hints = {
        "adb": "Android SDK Platform-Tools 설치",
        "apktool": "apktool 공식 Windows 설치",
        "jadx": "jadx 릴리스 또는 winget 설치",
        "aapt": "Android SDK Build-Tools 설치",
        "apkanalyzer": "Android SDK Command-line Tools 설치",
        "frida": "py -m pip install frida-tools",
        "frida_ps": "py -m pip install frida-tools",
        "mitmdump": "py -m pip install mitmproxy",
        "node": "winget install OpenJS.NodeJS.LTS",
        "ssh": "Windows 선택적 기능 OpenSSH Client 설치",
        "scp": "Windows 선택적 기능 OpenSSH Client 설치",
        "apkid": "py -m pip install apkid; GPL/상용 라이선스 확인",
        "semgrep": "py -m pip install semgrep",
        "objection": "py -m pip install objection",
        "drozer": "pipx install drozer 및 승인된 단말에 drozer Agent 설치",
        "pymobiledevice3": "py -m pip install pymobiledevice3",
        "idevice_id": "libimobiledevice Windows 빌드의 idevice_id.exe",
        "ideviceinfo": "libimobiledevice Windows 빌드의 ideviceinfo.exe",
        "ideviceinstaller": "libimobiledevice Windows 빌드의 ideviceinstaller.exe",
        "idevicesyslog": "libimobiledevice Windows 빌드의 idevicesyslog.exe",
        "idevicescreenshot": "libimobiledevice Windows 빌드의 idevicescreenshot.exe",
    }
    tools = []
    for name in settings.tools.model_fields:
        configured = getattr(settings.tools, name)
        resolved = settings.resolved_tool(name)
        tools.append(
            {
                "name": name,
                "status": "available" if resolved else "not_configured",
                "configured_path": configured,
                "resolved_path": resolved,
                "install_hint": install_hints.get(
                    name, "설정 화면에서 실행 파일 경로 지정"
                ),
            }
        )
    return {
        "server": {
            "host": settings.host,
            "port": settings.port,
            "data_dir": str(settings.data_dir),
            "max_upload_mb": settings.max_upload_mb,
        },
        "ai": {
            "nvidia_configured": bool(settings.nvidia_api_key),
            "nvidia_model": settings.nvidia_model,
            "claude_configured": bool(settings.claude_api_key),
            "claude_model": settings.claude_model,
            "mask_external_ai_data": settings.mask_external_ai_data,
        },
        "analysis": {
            "mobsf_configured": bool(
                settings.mobsf_url and settings.mobsf_api_key
            ),
            "mobsf_url": settings.mobsf_url,
            "semgrep_rules_path": str(settings.semgrep_rules_path),
            "catalog": CATALOG_SOURCE,
        },
        "tools": tools,
    }


class ToolSettingsUpdate(BaseModel):
    tools: dict[str, str]


@router.put("/settings/tools")
def update_tool_settings(payload: ToolSettingsUpdate):
    allowed = set(get_settings().tools.model_fields)
    unknown = set(payload.tools) - allowed
    if unknown:
        raise HTTPException(422, f"알 수 없는 도구: {', '.join(sorted(unknown))}")
    config_path = ROOT_DIR / "config.yaml"
    current: dict[str, Any] = {}
    if config_path.is_file():
        current = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    current.setdefault("tools", {}).update(
        {key: str(Path(value)) for key, value in payload.tools.items()}
    )
    config_path.write_text(
        yaml.safe_dump(current, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    return {
        "status": "saved",
        "restart_required": True,
        "message": "도구 경로를 config.yaml에 저장했습니다. 서버 재시작 후 적용됩니다.",
    }
