from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import uuid
import zipfile
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import yaml
from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Request,
    Response,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from backend.app.ai import AIProviderChain, MockAIProvider
from backend.app.ai.masking import mask_context
from backend.app.analyzers import (
    APKiDAnalyzerAdapter,
    AndroguardAnalyzerAdapter,
    MobSFAnalyzerAdapter,
    SemgrepAnalyzerAdapter,
    StaticAnalyzer,
    replace_analysis_records,
)
from backend.app.catalog import CATALOG_SOURCE, MASTG_CONTROLS
from backend.app.control_validation import (
    ControlScopeError,
    active_control_scope,
    network_host_allowed,
    normalize_control_validation_request,
)
from backend.app.component_validation import (
    ComponentCandidateError,
    build_component_candidates,
    resolve_component_candidate,
)
from backend.app.core.config import ROOT_DIR, AppSettings, get_settings
from backend.app.core.events import event_bus
from backend.app.core.network import (
    approval_matches_destination,
    inspect_mobsf_destination,
)
from backend.app.core.status import CapabilityStatus, Platform, RunMode, RunStatus
from backend.app.core.targets import (
    is_valid_app_identifier,
    normalize_platform,
    platform_for_adapter,
    require_app_identifier,
)
from backend.app.database.models import (
    AIInvocation,
    AnalysisRun,
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
from backend.app.devices import (
    AndroidDeviceAdapter,
    DeviceOperation,
    IOSDeviceAdapter,
    MockDeviceAdapter,
)
from backend.app.evidence.report import EvidenceReportRenderer
from backend.app.evidence.service import EvidenceService
from backend.app.frida import FridaManager, FridaSessionScript
from backend.app.frida.policy import is_safe_automatic_script, script_applies_to_app
from backend.app.orchestration import DiagnosticOrchestrator, ManualActionInProgress
from backend.app.navigation import (
    NavigationApprovalError,
    NavigationLimits,
    NavigationRiskPolicy,
    normalized_navigation_candidate,
    pending_navigation_candidates,
    resolve_navigation_candidate,
)
from backend.app.network_testing import (
    LiveNetworkExecutionError,
    LiveReadOnlyNetworkExecutor,
    NetworkApprovalError,
    resolve_network_candidate,
)
from backend.app.orchestration.approvals import (
    ApprovalError,
    consume_approval,
    issue_approval,
)
from backend.app.orchestration.resources import allocate_available_port
from backend.app.ai.storage import save_ai_raw_response
from backend.app.proxy import (
    BurpProxyAdapter,
    FiddlerProxyAdapter,
    MitmProxyAdapter,
    MockProxyAdapter,
    ProxyFlowData,
)
from backend.app.proxy.manual import ManualProxyAdapter
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


async def _mobsf_approval_values(settings: AppSettings) -> dict[str, Any]:
    if not settings.mobsf_url or not settings.mobsf_api_key:
        raise HTTPException(409, "MobSF URL과 API 키를 설정한 뒤 외부 분석 전송을 승인하세요.")
    try:
        snapshot = await inspect_mobsf_destination(settings)
    except ValueError as exc:
        raise HTTPException(422, f"MobSF 목적지 승인 실패: {exc}") from exc
    return {
        "external_analyzer_allowed": True,
        "external_analyzer_approved_by": "local_user",
        "external_analyzer_approved_at": datetime.now(timezone.utc),
        "external_analyzer_destination": snapshot.base_url,
        "external_analyzer_addresses": list(snapshot.addresses),
        "external_analyzer_certificate_sha256": snapshot.certificate_sha256,
    }


def _clear_mobsf_approval(project: Project) -> None:
    project.external_analyzer_allowed = False
    project.external_analyzer_approved_by = None
    project.external_analyzer_approved_at = None
    project.external_analyzer_destination = None
    project.external_analyzer_addresses = []
    project.external_analyzer_certificate_sha256 = None


def _normalize_control_validation_options(
    options: dict[str, Any],
    run_mode: RunMode,
    selected_device_id: str | None = None,
) -> dict[str, Any] | None:
    """Validate a locally recorded, authorised control-validation request.

    This mode records the user's approved test boundary for observation and
    evidence collection. It never changes device security state or permits
    automatic evasion of security controls.
    """
    raw = options.get("control_validation")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise HTTPException(422, "통제 검증 설정은 객체여야 합니다.")
    enabled = raw.get("enabled", False)
    if not isinstance(enabled, bool):
        raise HTTPException(422, "통제 검증 활성화 값은 boolean이어야 합니다.")
    if not enabled:
        return {
            "enabled": False,
            "execution_policy": "observation_only",
            "automatic_control_evasion": False,
            "external_ai_excluded": True,
        }
    if not selected_device_id:
        raise HTTPException(422, "통제 검증에는 승인된 테스트 단말 식별값이 필요합니다.")
    try:
        return normalize_control_validation_request(raw, run_mode, selected_device_id)
    except ControlScopeError as exc:
        raise HTTPException(422, str(exc)) from exc


def _analysis_run_directory(
    settings: AppSettings, source_path: Path
) -> tuple[str, Path]:
    analysis_run_id = str(uuid.uuid4())
    directory = (
        settings.analysis_dir
        / source_path.stem
        / "runs"
        / analysis_run_id
    )
    directory.mkdir(parents=True, exist_ok=False)
    return analysis_run_id, directory


def _activate_analysis_result(
    settings: AppSettings,
    source_path: Path,
    *,
    analysis_run_id: str,
    output_dir: Path,
    sha256: str,
) -> tuple[Path, bytes | None]:
    root = settings.analysis_dir / source_path.stem
    root.mkdir(parents=True, exist_ok=True)
    resolved_output = output_dir.resolve()
    resolved_root = root.resolve()
    if not resolved_output.is_dir() or resolved_root not in resolved_output.parents:
        raise OSError("검증된 분석 Run 출력 디렉터리가 아닙니다.")
    latest = root / "latest.json"
    previous = latest.read_bytes() if latest.is_file() else None
    temporary = root / f".latest-{uuid.uuid4()}.tmp"
    try:
        temporary.write_text(
            json.dumps(
                {
                    "analysis_run_id": analysis_run_id,
                    "output_dir": str(output_dir),
                    "artifact_sha256": sha256,
                    "activated_at": datetime.now(timezone.utc).isoformat(),
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        os.replace(temporary, latest)
    finally:
        temporary.unlink(missing_ok=True)
    return latest, previous


def _restore_analysis_pointer(latest: Path, previous: bytes | None) -> None:
    if previous is None:
        latest.unlink(missing_ok=True)
        return
    temporary = latest.parent / f".latest-restore-{uuid.uuid4()}.tmp"
    try:
        temporary.write_bytes(previous)
        os.replace(temporary, latest)
    finally:
        temporary.unlink(missing_ok=True)


def _activate_analysis_run(
    *,
    db: Session,
    settings: AppSettings,
    source_path: Path,
    project: Project,
    artifact: AppArtifact,
    analysis_run: AnalysisRun,
    result: Any,
) -> None:
    latest, previous_pointer = _activate_analysis_result(
        settings,
        source_path,
        analysis_run_id=analysis_run.id,
        output_dir=Path(analysis_run.output_dir),
        sha256=result.sha256,
    )
    previous_active_id = artifact.active_analysis_run_id
    try:
        artifact.sha256 = result.sha256
        artifact.size_bytes = result.file_size
        artifact.platform = result.platform
        artifact.app_name = result.app_name
        artifact.package_name = result.package_name
        artifact.version = result.version
        artifact.analysis_status = result.status
        artifact.analysis_result = result.to_dict()
        artifact.active_analysis_run_id = analysis_run.id
        analysis_run.status = "active"
        analysis_run.activated_at = datetime.now(timezone.utc)
        if previous_active_id and previous_active_id != analysis_run.id:
            previous_active = db.get(AnalysisRun, previous_active_id)
            if previous_active:
                previous_active.status = "superseded"
        replace_analysis_records(
            db, project=project, artifact=artifact, result=result
        )
        db.commit()
    except Exception:
        db.rollback()
        _restore_analysis_pointer(latest, previous_pointer)
        failed = db.get(AnalysisRun, analysis_run.id)
        if failed:
            failed.status = "failed"
            failed.error = "활성 분석 결과를 DB에 원자적으로 전환하지 못했습니다."
            db.commit()
        raise


def _scoped_run(
    db: Session,
    *,
    project_id: str,
    run_id: str,
    require_paused: bool = True,
) -> tuple[Project, DiagnosticRun, AppArtifact | None]:
    project = _project_or_404(db, project_id)
    run = _run_or_404(db, run_id)
    if run.project_id != project.id:
        raise HTTPException(422, "진단 실행이 선택한 프로젝트에 속하지 않습니다.")
    if require_paused and run.status != RunStatus.SAFELY_PAUSED.value:
        raise HTTPException(
            409,
            "직접 작업은 자동 Task가 checkpoint에서 안전하게 멈춘 뒤에만 실행할 수 있습니다.",
        )
    app = db.get(AppArtifact, run.app_id) if run.app_id else None
    return project, run, app


def _target_for_app(app: AppArtifact | None, *, live: bool) -> str:
    if not app:
        if live:
            raise HTTPException(422, "Live 진단에는 app_id가 필요합니다.")
        raise HTTPException(422, "직접 작업에는 대상 앱이 연결된 진단이 필요합니다.")
    try:
        return require_app_identifier(app.platform, app.package_name)
    except ValueError as exc:
        status_code = 409 if live else 422
        raise HTTPException(status_code, f"대상 앱 식별자 확인이 필요합니다: {exc}") from exc


def _validate_app_device_platform(
    app: AppArtifact, *, device_adapter: str, device_id: str
) -> str:
    try:
        app_platform = normalize_platform(app.platform)
        device_platform = platform_for_adapter(device_adapter, device_id)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    if app_platform != device_platform:
        raise HTTPException(
            422,
            f"{app_platform} 앱은 {device_platform} 단말 Adapter에서 실행할 수 없습니다.",
        )
    return app_platform


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
async def create_project(
    request: Request, payload: ProjectCreate, db: Session = Depends(get_db)
):
    values = payload.model_dump(mode="json")
    values["run_mode"] = payload.run_mode.value
    values["mock_mode"] = payload.run_mode == RunMode.MOCK
    if payload.external_analyzer_allowed:
        values.update(await _mobsf_approval_values(_settings(request)))
    project = Project(**values)
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: str, db: Session = Depends(get_db)):
    return _project_or_404(db, project_id)


@router.patch("/projects/{project_id}", response_model=ProjectOut)
async def update_project(
    request: Request,
    project_id: str,
    payload: ProjectUpdate,
    db: Session = Depends(get_db),
):
    project = _project_or_404(db, project_id)
    changes = payload.model_dump(exclude_unset=True, mode="json")
    requested_mode = changes.get("run_mode")
    if requested_mode and requested_mode != project.run_mode and (project.apps or project.runs):
        raise HTTPException(409, "앱 또는 진단 이력이 있는 프로젝트의 실행 모드는 변경할 수 없습니다.")
    for key, value in changes.items():
        setattr(project, key, value)
    if "external_analyzer_allowed" in changes:
        if changes["external_analyzer_allowed"]:
            for key, value in (
                await _mobsf_approval_values(_settings(request))
            ).items():
                setattr(project, key, value)
        else:
            _clear_mobsf_approval(project)
    if requested_mode:
        project.mock_mode = requested_mode == RunMode.MOCK.value
    db.commit()
    db.refresh(project)
    return project


@router.delete("/projects/{project_id}")
def delete_project(
    request: Request, project_id: str, db: Session = Depends(get_db)
):
    project = _project_or_404(db, project_id)
    active = db.scalar(
        select(DiagnosticRun.id).where(
            DiagnosticRun.project_id == project_id,
            DiagnosticRun.status.in_(
                [
                    RunStatus.CREATED.value,
                    RunStatus.RUNNING.value,
                    RunStatus.PAUSE_REQUESTED.value,
                    RunStatus.SAFELY_PAUSED.value,
                    RunStatus.PAUSED.value,
                ]
            ),
        ).limit(1)
    )
    if active:
        raise HTTPException(409, "실행 중인 진단을 중지한 뒤 프로젝트를 삭제하세요.")
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
    analyzer = StaticAnalyzer(
        settings,
        # Upload registration never transmits an app. MobSF requires a second,
        # artifact-hash-bound confirmation from the reanalysis endpoint.
        external_analyzers_allowed=False,
    )
    analysis_run_id, analysis_dir = _analysis_run_directory(settings, source_path)
    try:
        result = await analyzer.analyze(source_path, analysis_dir)
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        source_path.unlink(missing_ok=True)
        raise HTTPException(422, f"앱 분석 실패: {exc}") from exc
    result.structure["analysis_run_id"] = analysis_run_id
    result.structure["analysis_output_dir"] = str(analysis_dir)
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
        synthetic=project.run_mode == RunMode.MOCK.value,
    )
    db.add(artifact)
    db.flush()
    analysis_run = AnalysisRun(
        id=analysis_run_id,
        app_id=artifact.id,
        status="ready",
        output_dir=str(analysis_dir),
        artifact_sha256=result.sha256,
        result=result.to_dict(),
    )
    db.add(analysis_run)
    db.flush()
    try:
        _activate_analysis_run(
            db=db,
            settings=settings,
            source_path=source_path,
            project=project,
            artifact=artifact,
            analysis_run=analysis_run,
            result=result,
        )
    except (OSError, ValueError) as exc:
        db.rollback()
        source_path.unlink(missing_ok=True)
        raise HTTPException(422, f"분석 결과 활성화 실패: {exc}") from exc
    db.refresh(artifact)
    return artifact


class ReanalyzeRequest(BaseModel):
    confirm_external_analyzer: bool = False
    expected_destination: str | None = Field(default=None, max_length=2048)
    expected_sha256: str | None = Field(default=None, pattern="^[a-f0-9]{64}$")


@router.post("/apps/{app_id}/reanalyze", response_model=AppArtifactOut)
async def reanalyze_app(
    request: Request,
    app_id: str,
    payload: ReanalyzeRequest | None = None,
    db: Session = Depends(get_db),
):
    artifact = _app_or_404(db, app_id)
    project = _project_or_404(db, artifact.project_id)
    source_path = Path(artifact.stored_path)
    if not source_path.is_file():
        raise HTTPException(404, "등록된 앱 원본 파일을 찾을 수 없습니다.")
    settings = _settings(request)
    confirmation = payload or ReanalyzeRequest()
    allow_external = False
    if confirmation.confirm_external_analyzer:
        if not project.external_analyzer_allowed:
            raise HTTPException(409, "프로젝트에서 MobSF 외부 전송을 먼저 승인하세요.")
        if (
            confirmation.expected_destination != project.external_analyzer_destination
            or confirmation.expected_sha256 != artifact.sha256
        ):
            raise HTTPException(409, "확인한 MobSF 목적지 또는 앱 SHA-256이 현재 값과 다릅니다.")
        try:
            snapshot = await inspect_mobsf_destination(settings)
        except ValueError as exc:
            _clear_mobsf_approval(project)
            db.commit()
            raise HTTPException(409, f"MobSF 목적지가 변경되거나 검증에 실패해 승인을 취소했습니다: {exc}") from exc
        if not approval_matches_destination(
            snapshot,
            approved_destination=project.external_analyzer_destination,
            approved_addresses=project.external_analyzer_addresses,
            approved_certificate_sha256=project.external_analyzer_certificate_sha256,
        ):
            _clear_mobsf_approval(project)
            db.commit()
            raise HTTPException(409, "MobSF 목적지·DNS·TLS 정보가 변경되어 프로젝트 승인을 취소했습니다.")
        allow_external = True
    if not await request.app.state.analysis_leases.try_acquire(artifact.id):
        raise HTTPException(409, "analysis_in_progress: 동일 앱의 재분석이 이미 실행 중입니다.")
    analysis_run: AnalysisRun | None = None
    try:
        analysis_run_id, analysis_dir = _analysis_run_directory(settings, source_path)
        analysis_run = AnalysisRun(
            id=analysis_run_id,
            app_id=artifact.id,
            status="running",
            output_dir=str(analysis_dir),
        )
        db.add(analysis_run)
        db.commit()
        analyzer = StaticAnalyzer(
            settings,
            external_analyzers_allowed=allow_external,
            external_analyzer_approved_by=project.external_analyzer_approved_by,
            external_analyzer_destination=project.external_analyzer_destination,
            external_analyzer_addresses=project.external_analyzer_addresses,
            external_analyzer_certificate_sha256=project.external_analyzer_certificate_sha256,
            expected_artifact_sha256=(
                confirmation.expected_sha256 if allow_external else None
            ),
        )
        result = await analyzer.analyze(
            source_path, analysis_dir
        )
        result.structure["analysis_run_id"] = analysis_run_id
        result.structure["analysis_output_dir"] = str(analysis_dir)
        analysis_run.status = "ready"
        analysis_run.artifact_sha256 = result.sha256
        analysis_run.result = result.to_dict()
        db.commit()
        _activate_analysis_run(
            db=db,
            settings=settings,
            source_path=source_path,
            project=project,
            artifact=artifact,
            analysis_run=analysis_run,
            result=result,
        )
        db.refresh(artifact)
        return artifact
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        db.rollback()
        if analysis_run:
            failed = db.get(AnalysisRun, analysis_run.id)
            if failed:
                failed.status = "failed"
                failed.error = f"{type(exc).__name__}: {exc}"
                db.commit()
        raise HTTPException(422, f"앱 재분석 실패: {exc}") from exc
    except asyncio.CancelledError:
        db.rollback()
        if analysis_run:
            interrupted = db.get(AnalysisRun, analysis_run.id)
            if interrupted:
                interrupted.status = "interrupted"
                interrupted.error = "재분석 요청이 취소되었습니다."
                db.commit()
        raise
    except Exception as exc:
        db.rollback()
        if analysis_run:
            failed = db.get(AnalysisRun, analysis_run.id)
            if failed:
                failed.status = "failed"
                failed.error = f"{type(exc).__name__}: {exc}"
                db.commit()
        raise
    finally:
        await request.app.state.analysis_leases.release(artifact.id)


@router.get("/apps/{app_id}/analysis/overview")
def app_analysis_overview(app_id: str, db: Session = Depends(get_db)):
    artifact = _app_or_404(db, app_id)
    analysis_runs = db.scalars(
        select(AnalysisRun)
        .where(AnalysisRun.app_id == app_id)
        .order_by(AnalysisRun.created_at.desc())
    ).all()
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
        "active_analysis_run_id": artifact.active_analysis_run_id,
        "analysis_runs": [
            {
                "id": item.id,
                "status": item.status,
                "output_dir": item.output_dir,
                "artifact_sha256": item.artifact_sha256,
                "error": item.error,
                "activated_at": item.activated_at,
                "created_at": item.created_at,
            }
            for item in analysis_runs
        ],
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
                "synthetic": item.synthetic,
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
                "synthetic": item.synthetic,
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
        "synthetic": item.synthetic,
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
        run_mode=RunMode.MOCK.value,
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
    configured_errors: list[dict[str, str]] = []
    adapters = [
        MockDeviceAdapter(),
        MockDeviceAdapter(platform=Platform.MOCK_IOS),
        AndroidDeviceAdapter(settings),
        IOSDeviceAdapter(settings),
    ]
    ios_host = os.getenv("MSW_IOS_SSH_HOST")
    if ios_host:
        try:
            adapters.append(
                IOSDeviceAdapter(
                    settings,
                    host=ios_host,
                    port=int(os.getenv("MSW_IOS_SSH_PORT", "22")),
                    username=os.getenv("MSW_IOS_SSH_USER", "root"),
                    frida_endpoint=os.getenv("MSW_IOS_FRIDA_ENDPOINT"),
                    profile_name="environment",
                    include_usb=False,
                )
            )
        except (TypeError, ValueError) as exc:
            configured_errors.append({"adapter": "ios_windows:env", "error": str(exc)})
    from backend.app.database.session import SessionLocal

    with SessionLocal() as profile_db:
        profiles = profile_db.scalars(
            select(IOSDeviceProfile).order_by(IOSDeviceProfile.created_at)
        ).all()
        for profile in profiles:
            try:
                adapters.append(
                    IOSDeviceAdapter(
                        settings,
                        host=profile.host,
                        port=profile.ssh_port,
                        username=profile.username,
                        frida_endpoint=profile.frida_endpoint,
                        profile_id=profile.id,
                        profile_name=profile.name,
                        include_usb=False,
                    )
                )
            except (TypeError, ValueError) as exc:
                configured_errors.append(
                    {"adapter": f"ios_windows:{profile.id}", "error": str(exc)}
                )
    discovered = await asyncio.gather(
        *(adapter.discover() for adapter in adapters), return_exceptions=True
    )
    devices = []
    adapter_errors = list(configured_errors)
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
    project_id: str | None = None
    run_id: str | None = None
    approval_token: str | None = None
    package_name: str | None = None
    app_id: str | None = None
    remote_path: str | None = None
    local_port: int | None = Field(default=None, ge=1, le=65535)
    remote_port: int | None = Field(default=None, ge=1, le=65535)


class ApprovalIssueRequest(BaseModel):
    project_id: str
    run_id: str
    resource_type: str = Field(
        pattern="^(device|runtime|frida|component|ui_action|network_candidate)$"
    )
    action: str = Field(min_length=1, max_length=100)
    approved_by: str = Field(default="local_user", min_length=1, max_length=100)
    candidate_id: str | None = Field(default=None, pattern="^[a-f0-9]{24}$")


def _proxy_flow_data(row: ProxyFlow) -> ProxyFlowData:
    return ProxyFlowData(
        method=row.method,
        url=row.url,
        request_headers={
            str(key): str(value) for key, value in (row.request_headers or {}).items()
        },
        request_body=row.request_body or "",
        status_code=row.status_code,
        response_headers={
            str(key): str(value) for key, value in (row.response_headers or {}).items()
        },
        response_body=row.response_body or "",
        captured_at=row.captured_at,
        sensitive_candidates=list(row.sensitive_candidates or []),
        source_ip=row.source_ip,
        synthetic=row.synthetic,
    )


def _network_candidate_for_run(
    db: Session, run: DiagnosticRun, candidate_id: str
):
    summary = run.options.get("network_testing")
    stored = (
        next(
            (
                item
                for item in summary.get("candidates", [])
                if isinstance(item, dict) and item.get("id") == candidate_id
            ),
            None,
        )
        if isinstance(summary, dict)
        else None
    )
    if not stored:
        raise NetworkApprovalError(
            "현재 Run의 API Candidate 원장에서 후보를 찾을 수 없습니다."
        )
    source_flow_id = str(stored.get("source_flow_id") or "")
    row = db.get(ProxyFlow, source_flow_id)
    if not row or row.run_id != run.id:
        raise NetworkApprovalError(
            "API Candidate의 원본 Flow가 현재 Run에 속하지 않습니다."
        )
    source = _proxy_flow_data(row)
    candidate = resolve_network_candidate(
        run.options,
        candidate_id,
        source,
        source_flow_id=row.id,
    )
    executions = summary.get("executions", []) if isinstance(summary, dict) else []
    if any(
        isinstance(item, dict) and item.get("candidate_id") == candidate_id
        for item in executions
    ):
        raise NetworkApprovalError(
            "이 API Candidate는 이미 실행되어 반복 재전송할 수 없습니다."
        )
    return candidate, row, source


@router.post("/approvals", status_code=201)
def create_operation_approval(
    payload: ApprovalIssueRequest, db: Session = Depends(get_db)
):
    _, run, app = _scoped_run(
        db, project_id=payload.project_id, run_id=payload.run_id
    )
    if payload.resource_type == "component":
        if payload.action != "verify" or not payload.candidate_id or not app:
            raise HTTPException(422, "컴포넌트 승인에는 정적 후보 ID와 verify 작업이 필요합니다.")
        try:
            candidate = resolve_component_candidate(
                payload.candidate_id,
                platform=normalize_platform(app.platform),
                package_name=app.package_name,
                analysis_result=app.analysis_result,
            )
        except ComponentCandidateError as exc:
            raise HTTPException(422, str(exc)) from exc
        if candidate["execution_status"] != "approval_required":
            raise HTTPException(409, "이 후보는 자동 호출 대상이 아니며 수동 재검증이 필요합니다.")
        target = candidate["id"]
    elif payload.resource_type == "ui_action":
        if payload.action != "tap" or not payload.candidate_id or not app:
            raise HTTPException(422, "UI 동작 승인에는 후보 ID와 tap 작업이 필요합니다.")
        if run.status != RunStatus.SAFELY_PAUSED.value:
            raise HTTPException(409, "UI 동작 승인은 Run이 안전 일시정지 상태일 때만 발급합니다.")
        try:
            candidate = resolve_navigation_candidate(
                run.options, payload.candidate_id
            )
        except NavigationApprovalError as exc:
            raise HTTPException(409, str(exc)) from exc
        target_package = _target_for_app(
            app, live=run.run_mode == RunMode.LIVE.value
        )
        if candidate.get("package") != target_package:
            raise HTTPException(409, "UI 후보의 package가 현재 진단 대상과 다릅니다.")
        if run.run_mode == RunMode.LIVE.value:
            try:
                if active_control_scope(run.options, run.device_id) is None:
                    raise ControlScopeError(
                        "Live UI 동작에는 활성화된 승인 통제 검증 범위가 필요합니다."
                    )
            except ControlScopeError as exc:
                raise HTTPException(409, str(exc)) from exc
        target = candidate["id"]
    elif payload.resource_type == "network_candidate":
        if payload.action != "replay_read_only" or not payload.candidate_id:
            raise HTTPException(
                422, "API Candidate 승인에는 후보 ID와 replay_read_only 작업이 필요합니다."
            )
        if run.run_mode != RunMode.LIVE.value:
            raise HTTPException(409, "승인형 API 재현은 실제 Live Run에서만 수행합니다.")
        if run.status != RunStatus.SAFELY_PAUSED.value:
            raise HTTPException(409, "API 재현 승인은 Run이 안전 일시정지 상태일 때만 발급합니다.")
        try:
            candidate, _, source = _network_candidate_for_run(
                db, run, payload.candidate_id
            )
            scope = active_control_scope(run.options, run.device_id)
            if scope is None:
                raise ControlScopeError(
                    "Live API 재현에는 활성화된 승인 통제 검증 범위가 필요합니다."
                )
            if not network_host_allowed(
                source.url and urlsplit(source.url).hostname,
                list(scope["allowed_network_hosts"]),
            ):
                raise ControlScopeError(
                    "API Candidate 목적지가 현재 승인된 테스트 서버 범위 밖입니다."
                )
        except (NetworkApprovalError, ControlScopeError, ValueError) as exc:
            raise HTTPException(409, str(exc)) from exc
        target = candidate.id
    else:
        if payload.candidate_id is not None:
            raise HTTPException(422, "이 작업 유형에는 Candidate ID를 사용할 수 없습니다.")
        target = _target_for_app(app, live=run.run_mode == RunMode.LIVE.value)
    approval, token = issue_approval(
        db,
        project_id=payload.project_id,
        run_id=payload.run_id,
        resource_type=payload.resource_type,
        action=payload.action,
        device_id=run.device_id,
        target=target,
        approved_by=payload.approved_by,
    )
    return {
        "id": approval.id,
        "token": token,
        "expires_at": approval.expires_at,
        "scope": {
            "project_id": approval.project_id,
            "run_id": approval.run_id,
            "resource_type": approval.resource_type,
            "action": approval.action,
            "device_id": approval.device_id,
            "target": approval.target,
        },
    }


def _component_candidates_for_run(
    db: Session, run: DiagnosticRun, app: AppArtifact
) -> list[dict[str, Any]]:
    candidates = build_component_candidates(
        platform=normalize_platform(app.platform),
        package_name=app.package_name,
        analysis_result=app.analysis_result,
    )
    finding_ids = (
        select(FindingSource.finding_id)
        .join(RawFinding, FindingSource.raw_finding_id == RawFinding.id)
        .where(RawFinding.app_id == app.id)
    )
    findings = db.scalars(
        select(Finding).where(
            Finding.id.in_(finding_ids),
            Finding.category == "exposed_component",
        )
    ).all()
    finding_by_location = {item.location: item.id for item in findings}
    result_evidence = db.scalars(
        select(Evidence)
        .where(
            Evidence.run_id == run.id,
            Evidence.evidence_type == "component_validation_result",
        )
        .order_by(Evidence.sequence.desc())
    ).all()
    latest_by_candidate: dict[str, Evidence] = {}
    for evidence in result_evidence:
        data = evidence.inline_data if isinstance(evidence.inline_data, dict) else {}
        candidate_id = str(data.get("candidate_id") or "")
        if candidate_id and candidate_id not in latest_by_candidate:
            latest_by_candidate[candidate_id] = evidence
    for candidate in candidates:
        candidate["finding_id"] = finding_by_location.get(candidate["location"])
        latest = latest_by_candidate.get(candidate["id"])
        if latest:
            data = latest.inline_data if isinstance(latest.inline_data, dict) else {}
            candidate["last_result"] = {
                "status": data.get("status"),
                "reachable": data.get("reachable"),
                "evidence_id": latest.id,
                "captured_at": latest.captured_at.isoformat(),
            }
        else:
            candidate["last_result"] = None
    return candidates


@router.get("/runs/{run_id}/component-candidates")
def list_component_candidates(run_id: str, db: Session = Depends(get_db)):
    run = _run_or_404(db, run_id)
    app = db.get(AppArtifact, run.app_id) if run.app_id else None
    if not app:
        raise HTTPException(422, "컴포넌트 검증에는 대상 앱이 연결된 진단이 필요합니다.")
    _validate_app_device_platform(
        app, device_adapter=run.device_adapter, device_id=run.device_id
    )
    return {
        "run_id": run.id,
        "requires_safe_pause": True,
        "candidates": _component_candidates_for_run(db, run, app),
    }


class ComponentVerifyRequest(BaseModel):
    approval_token: str = Field(min_length=32, max_length=200)


@router.post("/runs/{run_id}/component-candidates/{candidate_id}/verify")
async def verify_component_candidate(
    request: Request,
    run_id: str,
    candidate_id: str,
    payload: ComponentVerifyRequest,
    db: Session = Depends(get_db),
):
    run = _run_or_404(db, run_id)
    project, run, app = _scoped_run(
        db, project_id=run.project_id, run_id=run.id
    )
    if not app:
        raise HTTPException(422, "컴포넌트 검증에는 대상 앱이 연결된 진단이 필요합니다.")
    app_platform = _validate_app_device_platform(
        app, device_adapter=run.device_adapter, device_id=run.device_id
    )
    package_name = _target_for_app(app, live=run.run_mode == RunMode.LIVE.value)
    try:
        candidate = resolve_component_candidate(
            candidate_id,
            platform=app_platform,
            package_name=package_name,
            analysis_result=app.analysis_result,
        )
    except ComponentCandidateError as exc:
        raise HTTPException(422, str(exc)) from exc
    if candidate["execution_status"] != "approval_required":
        raise HTTPException(409, "이 후보는 자동 호출 대상이 아니며 수동 재검증이 필요합니다.")
    if run.run_mode == RunMode.LIVE.value:
        try:
            if active_control_scope(run.options, run.device_id) is None:
                raise ControlScopeError(
                    "Live 컴포넌트 검증에는 활성화된 승인 통제 검증 범위가 필요합니다."
                )
        except ControlScopeError as exc:
            raise HTTPException(409, str(exc)) from exc

    orchestrator = _orchestrator(request)
    if not await orchestrator.begin_manual_action(run.id):
        raise HTTPException(409, "자동 Task가 안전하게 대기 중이거나 다른 수동 작업이 끝난 뒤 실행하세요.")
    manual_claimed = True
    lease_acquired = False
    try:
        try:
            approval = consume_approval(
                db,
                payload.approval_token,
                project_id=project.id,
                run_id=run.id,
                resource_type="component",
                action="verify",
                device_id=run.device_id,
                target=candidate["id"],
            )
            lease_acquired = await orchestrator.leases.acquire(
                run.id, run.device_id, None
            )
        except ApprovalError as exc:
            raise HTTPException(409, str(exc)) from exc

        try:
            device = orchestrator.device_for_run(db, run)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        settings = _settings(request)
        evidence_service = EvidenceService(settings)
        action_dir = evidence_service.run_dir(run.id) / "component-validation" / candidate["id"]
        action_dir.mkdir(parents=True, exist_ok=True)
        finding_id = next(
            (
                item.get("finding_id")
                for item in _component_candidates_for_run(db, run, app)
                if item["id"] == candidate["id"]
            ),
            None,
        )

        before = await device.screenshot(run.device_id, action_dir / f"{uuid.uuid4()}-before.png")
        before_evidence = evidence_service.add(
            db,
            run_id=run.id,
            finding_id=finding_id,
            evidence_type="component_validation_before",
            title=f"컴포넌트 검증 전 화면 · {candidate['label']}",
            description=before.message,
            command=before.command,
            file_path=before.file_path,
            inline_data={"candidate_id": candidate["id"], "operation": before.to_dict()},
        )
        if before.status != CapabilityStatus.AVAILABLE:
            operation = before
            operation.status = CapabilityStatus.MANUAL_REQUIRED
            operation.message = "검증 전 화면을 확보하지 못해 컴포넌트 호출을 실행하지 않았습니다."
        else:
            operation = await device.validate_component_candidate(
                run.device_id, package_name, candidate
            )
        action_evidence = evidence_service.add(
            db,
            run_id=run.id,
            finding_id=finding_id,
            evidence_type="component_validation_action",
            title=f"승인형 컴포넌트 호출 · {candidate['label']}",
            description=operation.message,
            command=operation.command,
            inline_data={
                "candidate": candidate,
                "operation": operation.to_dict(),
                "approval_id": approval.id,
                "approved_by": approval.approved_by,
                "approved_at": approval.approved_at.isoformat(),
            },
        )
        after = await device.screenshot(run.device_id, action_dir / f"{uuid.uuid4()}-after.png")
        after_evidence = evidence_service.add(
            db,
            run_id=run.id,
            finding_id=finding_id,
            evidence_type="component_validation_after",
            title=f"컴포넌트 검증 후 화면 · {candidate['label']}",
            description=after.message,
            command=after.command,
            file_path=after.file_path,
            inline_data={"candidate_id": candidate["id"], "operation": after.to_dict()},
        )
        logs = await device.collect_logs(
            run.device_id, action_dir / f"{uuid.uuid4()}-log.txt"
        )
        log_evidence = evidence_service.add(
            db,
            run_id=run.id,
            finding_id=finding_id,
            evidence_type="component_validation_log",
            title=f"컴포넌트 검증 로그 · {candidate['label']}",
            description=logs.message,
            command=logs.command,
            file_path=logs.file_path,
            inline_data={"candidate_id": candidate["id"], "operation": logs.to_dict()},
        )
        reachable = operation.status == CapabilityStatus.AVAILABLE
        result_evidence = evidence_service.add_json(
            db,
            run_id=run.id,
            finding_id=finding_id,
            filename=f"component-validation/{candidate['id']}/{uuid.uuid4()}-result.json",
            evidence_type="component_validation_result",
            title=f"컴포넌트 검증 결과 · {candidate['label']}",
            description=(
                "외부 진입 성공 신호를 확인했습니다. 민감 기능 영향은 별도로 판정해야 합니다."
                if reachable
                else operation.message
            ),
            data={
                "candidate_id": candidate["id"],
                "kind": candidate["kind"],
                "target": candidate["target"],
                "status": operation.status.value,
                "reachable": reachable,
                "impact_confirmed": False,
                "approval_id": approval.id,
                "evidence_ids": [
                    before_evidence.id,
                    action_evidence.id,
                    after_evidence.id,
                    log_evidence.id,
                ],
            },
        )
        options = dict(run.options)
        history = list(options.get("component_validations") or [])
        history.append(
            {
                "candidate_id": candidate["id"],
                "status": operation.status.value,
                "reachable": reachable,
                "impact_confirmed": False,
                "result_evidence_id": result_evidence.id,
                "verified_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        options["component_validations"] = history[-100:]
        run.options = options
        db.commit()
        await event_bus.publish(
            run.id,
            "evidence",
            {
                "id": result_evidence.id,
                "type": result_evidence.evidence_type,
                "title": result_evidence.title,
                "sequence": result_evidence.sequence,
                "captured_at": result_evidence.captured_at.isoformat(),
            },
        )
        return {
            "status": operation.status.value,
            "reachable": reachable,
            "impact_confirmed": False,
            "candidate": candidate,
            "result_evidence_id": result_evidence.id,
            "evidence_ids": [
                before_evidence.id,
                action_evidence.id,
                after_evidence.id,
                log_evidence.id,
            ],
        }
    finally:
        if lease_acquired:
            await orchestrator.leases.release(run.id)
        if manual_claimed:
            await orchestrator.end_manual_action(run.id)


@router.get("/runs/{run_id}/ui-action-candidates")
def list_ui_action_candidates(run_id: str, db: Session = Depends(get_db)):
    run = _run_or_404(db, run_id)
    app = db.get(AppArtifact, run.app_id) if run.app_id else None
    if not app:
        raise HTTPException(422, "UI 동작 검증에는 대상 앱이 연결된 진단이 필요합니다.")
    target_package = _target_for_app(
        app, live=run.run_mode == RunMode.LIVE.value
    )
    candidates = pending_navigation_candidates(run.options)
    for candidate in candidates:
        candidate["approval_eligible"] = (
            candidate.get("risk") == "medium"
            and candidate.get("action_type") == "tap"
            and candidate.get("package") == target_package
        )
    navigation = run.options.get("navigation")
    history = (
        navigation.get("approved_actions", [])
        if isinstance(navigation, dict)
        else []
    )
    return {
        "run_id": run.id,
        "requires_safe_pause": True,
        "candidates": candidates,
        "history": history if isinstance(history, list) else [],
    }


class ApprovedCandidateExecutionRequest(BaseModel):
    approval_token: str = Field(min_length=32, max_length=200)


@router.post("/runs/{run_id}/ui-action-candidates/{candidate_id}/execute")
async def execute_ui_action_candidate(
    request: Request,
    run_id: str,
    candidate_id: str,
    payload: ApprovedCandidateExecutionRequest,
    db: Session = Depends(get_db),
):
    run = _run_or_404(db, run_id)
    project, run, app = _scoped_run(
        db, project_id=run.project_id, run_id=run.id
    )
    if not app:
        raise HTTPException(422, "UI 동작 검증에는 대상 앱이 연결된 진단이 필요합니다.")
    package_name = _target_for_app(
        app, live=run.run_mode == RunMode.LIVE.value
    )
    try:
        candidate = resolve_navigation_candidate(run.options, candidate_id)
    except NavigationApprovalError as exc:
        raise HTTPException(409, str(exc)) from exc
    if candidate.get("package") != package_name:
        raise HTTPException(409, "UI 후보의 package가 현재 진단 대상과 다릅니다.")
    if run.run_mode == RunMode.LIVE.value:
        try:
            if active_control_scope(run.options, run.device_id) is None:
                raise ControlScopeError(
                    "Live UI 동작에는 활성화된 승인 통제 검증 범위가 필요합니다."
                )
        except ControlScopeError as exc:
            raise HTTPException(409, str(exc)) from exc

    orchestrator = _orchestrator(request)
    if not await orchestrator.begin_manual_action(run.id):
        raise HTTPException(
            409, "자동 Task가 안전하게 대기 중이거나 다른 수동 작업이 끝난 뒤 실행하세요."
        )
    manual_claimed = True
    lease_acquired = False
    try:
        try:
            approval = consume_approval(
                db,
                payload.approval_token,
                project_id=project.id,
                run_id=run.id,
                resource_type="ui_action",
                action="tap",
                device_id=run.device_id,
                target=candidate["id"],
            )
            lease_acquired = await orchestrator.leases.acquire(
                run.id, run.device_id, None
            )
        except ApprovalError as exc:
            raise HTTPException(409, str(exc)) from exc

        try:
            device = orchestrator.device_for_run(db, run)
            driver = orchestrator.ui_driver_for_run(
                run, device, package_name
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if driver is None:
            raise HTTPException(409, "현재 단말에는 승인형 UI 실행 Driver가 없습니다.")

        limits = NavigationLimits.from_options(
            run.options.get("navigation_limits")
        )
        try:
            before_state = await asyncio.wait_for(
                driver.dump_ui(), timeout=limits.action_timeout
            )
        except (asyncio.TimeoutError, RuntimeError, ValueError) as exc:
            raise HTTPException(409, f"실행 전 UI Tree 확인 실패: {exc}") from exc
        element = before_state.element(str(candidate["element_id"]))
        if (
            before_state.fingerprint != candidate["state_fingerprint"]
            or before_state.package != package_name
            or element is None
        ):
            raise HTTPException(
                409, "현재 화면이 승인 후보 생성 시점과 달라 stale UI 동작을 차단했습니다."
            )
        rechecked = NavigationRiskPolicy().classify(element, package_name)
        current_candidate = normalized_navigation_candidate(
            {
                **rechecked.to_dict(),
                "state_fingerprint": before_state.fingerprint,
                "package": before_state.package,
                "activity": before_state.activity,
                "status": "pending_approval",
                "queued_at": candidate.get("queued_at"),
            }
        )
        if (
            current_candidate["id"] != candidate["id"]
            or current_candidate["risk"] != "medium"
            or current_candidate["action_type"] != "tap"
        ):
            raise HTTPException(
                409, "실행 직전 위험 정책 결과가 승인 내용과 달라 UI 동작을 차단했습니다."
            )

        evidence_service = EvidenceService(_settings(request))
        action_dir = (
            evidence_service.run_dir(run.id)
            / "approved-ui-actions"
            / candidate["id"]
        )
        action_dir.mkdir(parents=True, exist_ok=True)
        before_screen = await driver.screenshot(
            action_dir / f"{uuid.uuid4()}-before.png"
        )
        before_screen_evidence = evidence_service.add(
            db,
            run_id=run.id,
            evidence_type="approved_ui_action_before",
            title=f"승인 UI 동작 전 화면 · {candidate['label']}",
            description=before_screen.message,
            command=before_screen.command,
            file_path=before_screen.file_path,
            inline_data={
                "candidate_id": candidate["id"],
                "operation": before_screen.to_dict(),
            },
        )
        before_tree_evidence = evidence_service.add_json(
            db,
            run_id=run.id,
            filename=f"approved-ui-actions/{candidate['id']}/{uuid.uuid4()}-before-ui.json",
            evidence_type="approved_ui_action_before_tree",
            title=f"승인 UI 동작 전 Tree · {candidate['label']}",
            data={
                "candidate_id": candidate["id"],
                "state": before_state.to_dict(),
                "raw_xml": before_state.raw_xml,
            },
        )
        scope_evidence = evidence_service.add_json(
            db,
            run_id=run.id,
            filename=f"approved-ui-actions/{candidate['id']}/{uuid.uuid4()}-scope.json",
            evidence_type="approved_ui_action_scope",
            title=f"승인 UI 동작 범위 · {candidate['label']}",
            data={
                "candidate": candidate,
                "approval_id": approval.id,
                "approved_by": approval.approved_by,
                "approved_at": approval.approved_at.isoformat(),
                "execution_policy": "one_time_medium_risk_tap",
            },
        )

        if before_screen.status != CapabilityStatus.AVAILABLE:
            operation = DeviceOperation(
                CapabilityStatus.MANUAL_REQUIRED,
                "동작 전 화면을 확보하지 못해 승인 UI 동작을 실행하지 않았습니다.",
                synthetic=run.synthetic,
            )
            after_state = before_state
        else:
            x, y = element.bounds.center
            try:
                operation = await asyncio.wait_for(
                    driver.tap(x, y), timeout=limits.action_timeout
                )
                after_state = (
                    await asyncio.wait_for(
                        driver.wait_for_idle(limits.action_timeout),
                        timeout=limits.action_timeout + 0.5,
                    )
                    if operation.status == CapabilityStatus.AVAILABLE
                    else await driver.dump_ui()
                )
            except (asyncio.TimeoutError, RuntimeError, ValueError) as exc:
                operation = DeviceOperation(
                    CapabilityStatus.FAILED,
                    f"승인 UI 동작 실행 실패: {type(exc).__name__}: {exc}",
                    synthetic=run.synthetic,
                )
                after_state = before_state

        action_evidence = evidence_service.add(
            db,
            run_id=run.id,
            evidence_type="approved_ui_action",
            title=f"승인 UI 동작 · {candidate['label']}",
            description=operation.message,
            command=operation.command,
            inline_data={
                "candidate_id": candidate["id"],
                "operation": operation.to_dict(),
            },
        )
        after_screen = await driver.screenshot(
            action_dir / f"{uuid.uuid4()}-after.png"
        )
        after_screen_evidence = evidence_service.add(
            db,
            run_id=run.id,
            evidence_type="approved_ui_action_after",
            title=f"승인 UI 동작 후 화면 · {candidate['label']}",
            description=after_screen.message,
            command=after_screen.command,
            file_path=after_screen.file_path,
            inline_data={
                "candidate_id": candidate["id"],
                "operation": after_screen.to_dict(),
            },
        )
        after_tree_evidence = evidence_service.add_json(
            db,
            run_id=run.id,
            filename=f"approved-ui-actions/{candidate['id']}/{uuid.uuid4()}-after-ui.json",
            evidence_type="approved_ui_action_after_tree",
            title=f"승인 UI 동작 후 Tree · {candidate['label']}",
            data={
                "candidate_id": candidate["id"],
                "state": after_state.to_dict(),
                "raw_xml": after_state.raw_xml,
            },
        )
        evidence_ids = [
            before_screen_evidence.id,
            before_tree_evidence.id,
            scope_evidence.id,
            action_evidence.id,
            after_screen_evidence.id,
            after_tree_evidence.id,
        ]
        result_evidence = evidence_service.add_json(
            db,
            run_id=run.id,
            filename=f"approved-ui-actions/{candidate['id']}/{uuid.uuid4()}-result.json",
            evidence_type="approved_ui_action_result",
            title=f"승인 UI 동작 결과 · {candidate['label']}",
            description=operation.message,
            data={
                "candidate_id": candidate["id"],
                "status": operation.status.value,
                "source_state": before_state.fingerprint,
                "destination_state": after_state.fingerprint,
                "evidence_ids": evidence_ids,
                "synthetic": run.synthetic,
            },
        )
        evidence_ids.append(result_evidence.id)

        db.refresh(run)
        options = dict(run.options)
        navigation = dict(options.get("navigation") or {})
        pending = [
            item
            for item in pending_navigation_candidates(options)
            if item["id"] != candidate["id"]
        ]
        actions = list(navigation.get("actions") or [])
        action_record = {
            "sequence": len(actions) + 1,
            "action_type": "approved_tap",
            "element_id": candidate["element_id"],
            "label": candidate["label"],
            "risk": candidate["risk"],
            "source_state": before_state.fingerprint,
            "destination_state": after_state.fingerprint,
            "result": operation.status.value,
            "message": operation.message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "evidence_ids": evidence_ids,
            "synthetic": run.synthetic,
        }
        actions.append(action_record)
        states = list(navigation.get("states") or [])
        if not any(
            isinstance(item, dict)
            and item.get("fingerprint") == after_state.fingerprint
            for item in states
        ):
            states.append(after_state.to_dict(include_elements=False))
        history = list(navigation.get("approved_actions") or [])
        history.append(
            {
                **candidate,
                "status": operation.status.value,
                "result_evidence_id": result_evidence.id,
                "executed_at": action_record["timestamp"],
            }
        )
        navigation.update(
            {
                "pending_approval": pending,
                "approved_actions": history[-100:],
                "actions": actions,
                "action_count": len(actions),
                "states": states,
                "state_count": len(states),
            }
        )
        options["navigation"] = navigation
        options["pending_navigation_actions"] = pending
        run.options = options
        db.commit()
        await event_bus.publish(
            run.id,
            "evidence",
            {
                "id": result_evidence.id,
                "type": result_evidence.evidence_type,
                "title": result_evidence.title,
                "sequence": result_evidence.sequence,
                "captured_at": result_evidence.captured_at.isoformat(),
            },
        )
        return {
            "status": operation.status.value,
            "candidate_id": candidate["id"],
            "result_evidence_id": result_evidence.id,
            "evidence_ids": evidence_ids,
        }
    finally:
        if lease_acquired:
            await orchestrator.leases.release(run.id)
        if manual_claimed:
            await orchestrator.end_manual_action(run.id)


@router.post("/runs/{run_id}/network-candidates/{candidate_id}/execute")
async def execute_network_candidate(
    request: Request,
    run_id: str,
    candidate_id: str,
    payload: ApprovedCandidateExecutionRequest,
    db: Session = Depends(get_db),
):
    run = _run_or_404(db, run_id)
    project, run, _ = _scoped_run(
        db, project_id=run.project_id, run_id=run.id
    )
    if run.run_mode != RunMode.LIVE.value:
        raise HTTPException(409, "승인형 API 재현은 실제 Live Run에서만 수행합니다.")
    try:
        candidate, row, source = _network_candidate_for_run(
            db, run, candidate_id
        )
        scope = active_control_scope(run.options, run.device_id)
        if scope is None:
            raise ControlScopeError(
                "Live API 재현에는 활성화된 승인 통제 검증 범위가 필요합니다."
            )
    except (NetworkApprovalError, ControlScopeError) as exc:
        raise HTTPException(409, str(exc)) from exc

    orchestrator = _orchestrator(request)
    if not await orchestrator.begin_manual_action(run.id):
        raise HTTPException(
            409, "자동 Task가 안전하게 대기 중이거나 다른 수동 작업이 끝난 뒤 실행하세요."
        )
    manual_claimed = True
    lease_acquired = False
    try:
        try:
            approval = consume_approval(
                db,
                payload.approval_token,
                project_id=project.id,
                run_id=run.id,
                resource_type="network_candidate",
                action="replay_read_only",
                device_id=run.device_id,
                target=candidate.id,
            )
            lease_acquired = await orchestrator.leases.acquire(
                run.id, run.device_id, None
            )
        except ApprovalError as exc:
            raise HTTPException(409, str(exc)) from exc

        executor = LiveReadOnlyNetworkExecutor()
        try:
            execution, response_data = await executor.execute(
                candidate,
                source,
                allowed_hosts=list(scope["allowed_network_hosts"]),
            )
        except LiveNetworkExecutionError as exc:
            raise HTTPException(409, str(exc)) from exc

        evidence_service = EvidenceService(_settings(request))
        scope_evidence = evidence_service.add_json(
            db,
            run_id=run.id,
            filename=f"approved-network-replay/{candidate.id}/{uuid.uuid4()}-scope.json",
            evidence_type="approved_network_replay_scope",
            title=f"승인 API 재현 범위 · {candidate.method} {candidate.endpoint}",
            data={
                "candidate_id": candidate.id,
                "source_flow_id": row.id,
                "approval_id": approval.id,
                "approved_by": approval.approved_by,
                "approved_at": approval.approved_at.isoformat(),
                "method_policy": "GET_HEAD_ONLY",
                "redirect_policy": "disabled",
                "allowed_network_hosts": list(scope["allowed_network_hosts"]),
            },
        )
        result_evidence = evidence_service.add_json(
            db,
            run_id=run.id,
            filename=f"approved-network-replay/{candidate.id}/{uuid.uuid4()}-result.json",
            evidence_type="approved_network_replay_result",
            title=f"승인 API 재현 결과 · {candidate.method} {candidate.endpoint}",
            description=execution.message,
            data={
                "candidate_id": candidate.id,
                "source_flow_id": row.id,
                "request": {
                    "method": candidate.method,
                    "url": source.url,
                    "body_sent": False,
                },
                "response": response_data,
                "comparison": (
                    execution.comparison.to_dict()
                    if execution.comparison
                    else None
                ),
                "status": execution.status,
                "synthetic": False,
            },
        )
        execution.evidence_ids.extend([scope_evidence.id, result_evidence.id])

        db.refresh(run)
        options = dict(run.options)
        summary = dict(options.get("network_testing") or {})
        candidates = []
        for item in summary.get("candidates", []):
            if not isinstance(item, dict) or item.get("id") != candidate.id:
                candidates.append(item)
                continue
            candidates.append(
                {
                    **item,
                    "status": execution.status,
                    "last_result": {
                        "status": execution.status,
                        "evidence_id": result_evidence.id,
                        "executed_at": execution.executed_at,
                    },
                }
            )
        executions = list(summary.get("executions") or [])
        executions.append(execution.to_dict())
        pending = [
            item
            for item in summary.get("pending_approval", [])
            if isinstance(item, dict) and item.get("id") != candidate.id
        ]
        summary.update(
            {
                "candidates": candidates,
                "executions": executions,
                "executed_count": len(executions),
                "pending_approval": pending,
                "pending_count": len(pending),
            }
        )
        options["network_testing"] = summary
        options["pending_network_tests"] = pending
        run.options = options
        db.commit()
        await event_bus.publish(
            run.id,
            "evidence",
            {
                "id": result_evidence.id,
                "type": result_evidence.evidence_type,
                "title": result_evidence.title,
                "sequence": result_evidence.sequence,
                "captured_at": result_evidence.captured_at.isoformat(),
            },
        )
        return {
            "status": execution.status,
            "candidate_id": candidate.id,
            "comparison": (
                execution.comparison.to_dict() if execution.comparison else None
            ),
            "result_evidence_id": result_evidence.id,
            "evidence_ids": execution.evidence_ids,
        }
    finally:
        if lease_acquired:
            await orchestrator.leases.release(run.id)
        if manual_claimed:
            await orchestrator.end_manual_action(run.id)


@router.post("/devices/action")
async def device_action(
    request: Request, payload: DeviceAction, db: Session = Depends(get_db)
):
    settings = _settings(request)
    read_only_unscoped = {"list_packages", "frida_status"}
    controlled_actions = {
        "install",
        "uninstall",
        "start",
        "stop",
        "screenshot",
        "logs",
        "pull_file",
        "forward_port",
    }
    if payload.adapter == "android_adb":
        adapter = AndroidDeviceAdapter(settings)
    elif payload.adapter == "ios_windows":
        if payload.device_id.startswith("ios-ssh:"):
            profiles = db.scalars(select(IOSDeviceProfile)).all()
            profile = next(
                (
                    item
                    for item in profiles
                    if IOSDeviceAdapter.ssh_device_id(item.host, item.ssh_port)
                    == payload.device_id
                ),
                None,
            )
            if profile:
                adapter = IOSDeviceAdapter(
                    settings,
                    host=profile.host,
                    port=profile.ssh_port,
                    username=profile.username,
                    frida_endpoint=profile.frida_endpoint,
                    profile_id=profile.id,
                    profile_name=profile.name,
                    include_usb=False,
                )
            else:
                ssh_host = os.getenv("MSW_IOS_SSH_HOST")
                ssh_port = int(os.getenv("MSW_IOS_SSH_PORT", "22"))
                if (
                    not ssh_host
                    or IOSDeviceAdapter.ssh_device_id(ssh_host, ssh_port)
                    != payload.device_id
                ):
                    raise HTTPException(422, "등록된 iOS SSH 단말 프로필을 찾을 수 없습니다.")
                adapter = IOSDeviceAdapter(
                    settings,
                    host=ssh_host,
                    port=ssh_port,
                    username=os.getenv("MSW_IOS_SSH_USER", "root"),
                    frida_endpoint=os.getenv("MSW_IOS_FRIDA_ENDPOINT"),
                    profile_name="environment",
                    include_usb=False,
                )
        else:
            adapter = IOSDeviceAdapter(settings)
    else:
        if payload.adapter != "mock":
            raise HTTPException(422, "지원하지 않는 단말 Adapter입니다.")
        adapter = MockDeviceAdapter(
            platform=(Platform.MOCK_IOS if "ios" in payload.device_id.lower() else Platform.MOCK_ANDROID)
        )

    scoped = payload.action not in read_only_unscoped
    run = None
    app = None
    target = payload.package_name
    approval = None
    lease_acquired = False
    manual_claimed = False
    if scoped:
        if not payload.project_id or not payload.run_id:
            raise HTTPException(422, "이 단말 작업에는 project_id와 run_id가 필요합니다.")
        _, run, app = _scoped_run(
            db, project_id=payload.project_id, run_id=payload.run_id
        )
        if payload.device_id != run.device_id or payload.adapter != run.device_adapter:
            raise HTTPException(422, "요청 단말이 진단 실행에 임대된 단말과 일치하지 않습니다.")
        if app:
            _validate_app_device_platform(
                app, device_adapter=run.device_adapter, device_id=run.device_id
            )
        target = _target_for_app(app, live=run.run_mode == RunMode.LIVE.value)
        if payload.package_name and payload.package_name != target:
            raise HTTPException(422, "직접 입력한 대상값이 진단 앱 식별자와 일치하지 않습니다.")
        if not await _orchestrator(request).begin_manual_action(run.id):
            raise HTTPException(409, "자동 Task가 안전하게 대기 중이거나 다른 수동 작업이 끝난 뒤 실행하세요.")
        manual_claimed = True
        try:
            if payload.action in controlled_actions:
                approval = consume_approval(
                    db,
                    payload.approval_token,
                    project_id=payload.project_id,
                    run_id=payload.run_id,
                    resource_type="device",
                    action=payload.action,
                    device_id=run.device_id,
                    target=target,
                )
            lease_acquired = await _orchestrator(request).leases.acquire(
                run.id, run.device_id, None
            )
        except ApprovalError as exc:
            await _orchestrator(request).end_manual_action(run.id)
            manual_claimed = False
            raise HTTPException(409, str(exc)) from exc
        except Exception:
            await _orchestrator(request).end_manual_action(run.id)
            manual_claimed = False
            raise

    actions = {
        "list_packages": lambda: adapter.list_packages(payload.device_id),
        "start": lambda: adapter.start_app(payload.device_id, str(target)),
        "stop": lambda: adapter.stop_app(payload.device_id, str(target)),
        "uninstall": lambda: adapter.uninstall_app(payload.device_id, str(target)),
        "process": lambda: adapter.process_info(payload.device_id, str(target)),
        "frida_status": lambda: adapter.frida_status(payload.device_id),
        "forward_port": lambda: adapter.forward_port(
            payload.device_id, payload.local_port or 27042, payload.remote_port or 27042
        ),
    }
    try:
        if payload.action == "install":
            if not app or not payload.app_id or payload.app_id != app.id:
                raise HTTPException(422, "install의 app_id는 진단 실행의 대상 앱이어야 합니다.")
            operation = await adapter.install_app(payload.device_id, Path(app.stored_path))
        elif payload.action in {"screenshot", "logs", "pull_file"}:
            if not run:
                raise HTTPException(422, "증적 수집 작업에는 진단 실행 범위가 필요합니다.")
            action_dir = EvidenceService(settings).run_dir(run.id) / "manual-actions"
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

        result = operation.to_dict()
        if run:
            evidence = EvidenceService(settings).add(
                db,
                run_id=run.id,
                evidence_type="manual_device_action",
                title=f"직접 단말 작업 · {payload.action}",
                description=operation.message,
                command=operation.command,
                file_path=operation.file_path,
                inline_data={
                    "operation": result,
                    "approval_id": approval.id if approval else None,
                    "approved_by": approval.approved_by if approval else None,
                    "approved_at": approval.approved_at.isoformat() if approval else None,
                },
            )
            result["evidence_id"] = evidence.id
        return result
    finally:
        if run and lease_acquired:
            await _orchestrator(request).leases.release(run.id)
        if run and manual_claimed:
            await _orchestrator(request).end_manual_action(run.id)


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
    allowed_devices = {"mock", "android_adb", "ios_windows"}
    allowed_proxies = {"mock", "mitmproxy", "burp", "fiddler"}
    if payload.device_adapter not in allowed_devices:
        raise HTTPException(422, "지원하지 않는 단말 Adapter입니다.")
    if payload.proxy_adapter not in allowed_proxies:
        raise HTTPException(422, "지원하지 않는 프록시 Adapter입니다.")
    run_mode = RunMode(project.run_mode)
    if run_mode == RunMode.LIVE and (
        payload.device_adapter == "mock" or payload.proxy_adapter == "mock"
    ):
        raise HTTPException(422, "Live 프로젝트에서는 Mock 단말·프록시를 사용할 수 없습니다.")
    if run_mode == RunMode.MOCK and (
        payload.device_adapter != "mock" or payload.proxy_adapter != "mock"
    ):
        raise HTTPException(422, "Mock 프로젝트는 Mock 단말과 Mock 프록시만 사용할 수 있습니다.")
    if payload.device_adapter == "mock" and not payload.device_id.startswith("mock-"):
        raise HTTPException(422, "Mock Adapter에는 Mock 단말 ID가 필요합니다.")
    app = None
    if run_mode == RunMode.LIVE and not payload.app_id:
        raise HTTPException(422, "Live 진단에는 app_id가 필요합니다.")
    if payload.app_id:
        app = _app_or_404(db, payload.app_id)
        if app.project_id != project.id:
            raise HTTPException(422, "앱이 선택한 프로젝트에 속하지 않습니다.")
        app_platform = _validate_app_device_platform(
            app,
            device_adapter=payload.device_adapter,
            device_id=payload.device_id,
        )
        if run_mode == RunMode.LIVE:
            _target_for_app(app, live=True)
    else:
        try:
            app_platform = platform_for_adapter(payload.device_adapter, payload.device_id)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    try:
        provisional_run = DiagnosticRun(
            device_adapter=payload.device_adapter,
            device_id=payload.device_id,
        )
        selected_device_adapter = _orchestrator(request).device_for_run(
            db, provisional_run
        )
        discovered_devices = await selected_device_adapter.discover()
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            422,
            "선택한 단말 Adapter 상태를 확인하지 못했습니다. 연결·권한·실행 파일 설정을 점검하세요.",
        ) from exc
    selected_device = next(
        (item for item in discovered_devices if item.id == payload.device_id), None
    )
    if selected_device is None:
        raise HTTPException(
            422,
            "선택한 단말을 찾을 수 없습니다. 단말 연결·디버깅 승인·Adapter 설정을 새로고침한 뒤 다시 선택하세요.",
        )
    if selected_device.availability != CapabilityStatus.AVAILABLE:
        raise HTTPException(
            422,
            f"선택한 단말은 준비되지 않았습니다 ({selected_device.availability.value}). "
            "단말 연결·권한과 관련 실행 파일 설정을 확인한 뒤 다시 시도하세요.",
        )

    selected_script_ids = list(dict.fromkeys(payload.frida_script_ids))
    if selected_script_ids:
        selected_scripts = db.scalars(
            select(FridaScript).where(FridaScript.id.in_(selected_script_ids))
        ).all()
        if len(selected_scripts) != len(selected_script_ids):
            raise HTTPException(422, "선택한 Frida 스크립트 중 존재하지 않는 ID가 있습니다.")
        incompatible = []
        for script in selected_scripts:
            try:
                compatible = normalize_platform(script.platform) == app_platform
            except ValueError:
                compatible = False
            if not compatible:
                incompatible.append(script.name)
        if incompatible:
            raise HTTPException(
                422,
                f"앱 플랫폼과 맞지 않는 Frida 스크립트입니다: {', '.join(incompatible)}",
            )
        if not app:
            raise HTTPException(422, "Frida 자동 실행에는 대상 앱이 필요합니다.")
        unsafe = [
            script.name
            for script in selected_scripts
            if not is_safe_automatic_script(script)
        ]
        if unsafe:
            raise HTTPException(
                422,
                "자동 진단에서는 builtin·low 스크립트만 실행할 수 있습니다. "
                f"다음 스크립트는 safely_paused Run에서 일회성 승인 후 직접 실행하세요: {', '.join(unsafe)}",
            )
        not_applicable = [
            f"{script.name} ({script_applies_to_app(script, app)[1]})"
            for script in selected_scripts
            if not script_applies_to_app(script, app)[0]
        ]
        if not_applicable:
            raise HTTPException(
                422,
                f"대상 앱 적용 조건을 충족하지 않는 Frida 스크립트입니다: {', '.join(not_applicable)}",
            )
    options = dict(payload.options)
    control_validation = _normalize_control_validation_options(
        options,
        run_mode,
        payload.device_id,
    )
    if control_validation is not None:
        options["control_validation"] = control_validation
    frida_mode = str(options.get("frida_mode") or "attach")
    if frida_mode not in {"spawn", "attach"}:
        raise HTTPException(422, "Frida 연결 방식은 spawn 또는 attach여야 합니다.")
    auto_navigation = options.get(
        "auto_navigation",
        run_mode == RunMode.MOCK and app_platform == "android",
    )
    if not isinstance(auto_navigation, bool):
        raise HTTPException(422, "auto_navigation은 boolean이어야 합니다.")
    if auto_navigation and app_platform != "android":
        raise HTTPException(422, "자동 UI 탐색은 현재 Android에서만 지원합니다.")
    dynamic_storage = options.get(
        "dynamic_storage",
        run_mode == RunMode.MOCK and app_platform == "android",
    )
    if not isinstance(dynamic_storage, bool):
        raise HTTPException(422, "dynamic_storage는 boolean이어야 합니다.")
    if dynamic_storage and app_platform != "android":
        raise HTTPException(422, "동적 저장소 수집은 현재 Android에서만 지원합니다.")
    pause_for_approval_candidates = options.get(
        "pause_for_approval_candidates", False
    )
    if not isinstance(pause_for_approval_candidates, bool):
        raise HTTPException(
            422, "pause_for_approval_candidates는 boolean이어야 합니다."
        )
    navigation_options = options.get("navigation_limits", {})
    if not isinstance(navigation_options, dict):
        raise HTTPException(422, "navigation_limits는 객체여야 합니다.")
    options.update(
        {
            "frida_script_ids": selected_script_ids,
            "auto_select_frida": payload.auto_select_frida,
            "pause_for_login": payload.pause_for_login,
            "frida_mode": frida_mode,
            "auto_navigation": auto_navigation,
            "dynamic_storage": dynamic_storage,
            "pause_for_approval_candidates": pause_for_approval_candidates,
            "navigation_limits": NavigationLimits.from_options(
                navigation_options
            ).to_dict(),
        }
    )
    active_device_run = db.scalar(
        select(DiagnosticRun.id).where(
            DiagnosticRun.device_id == payload.device_id,
            DiagnosticRun.status.in_(
                [
                    RunStatus.CREATED.value,
                    RunStatus.RUNNING.value,
                    RunStatus.PAUSE_REQUESTED.value,
                    RunStatus.SAFELY_PAUSED.value,
                    RunStatus.PAUSED.value,
                ]
            ),
        ).limit(1)
    )
    if active_device_run:
        raise HTTPException(409, f"선택한 단말은 진단 {active_device_run}에서 사용 중입니다.")
    if payload.proxy_adapter == "mitmproxy":
        listen_host = str(options.get("proxy_listen_host") or _settings(request).proxy_listen_host)
        if listen_host in {"0.0.0.0", "::", "*"}:
            raise HTTPException(422, "mitmproxy는 특정 Windows LAN IP에만 바인딩해야 합니다.")
        try:
            listener_ip = ipaddress.ip_address(listen_host)
        except ValueError as exc:
            raise HTTPException(422, "프록시 Listener는 Windows의 특정 IP 주소여야 합니다.") from exc
        if listener_ip.is_unspecified or listener_ip.is_multicast or listener_ip.is_loopback:
            raise HTTPException(422, "프록시 Listener에는 단말이 접근 가능한 특정 Windows LAN IP가 필요합니다.")
        allowed_client = str(options.get("proxy_allowed_client_ip") or "").strip()
        if not allowed_client:
            raise HTTPException(422, "mitmproxy에는 진단 단말의 허용 IP가 필요합니다.")
        try:
            ipaddress.ip_address(allowed_client)
        except ValueError as exc:
            raise HTTPException(422, "프록시 허용 단말 IP 형식이 올바르지 않습니다.") from exc
        try:
            proxy_port = int(options.get("proxy_port") or allocate_available_port(listen_host))
        except (OSError, ValueError) as exc:
            raise HTTPException(422, f"프록시 Listener를 준비할 수 없습니다: {exc}") from exc
        if not 1 <= proxy_port <= 65535:
            raise HTTPException(422, "프록시 포트 범위가 올바르지 않습니다.")
        options.update(
            {
                "proxy_listen_host": listen_host,
                "proxy_allowed_client_ip": allowed_client,
                "proxy_port": proxy_port,
            }
        )
    elif payload.proxy_adapter in {"burp", "fiddler"}:
        listen_host = str(options.get("proxy_listen_host") or "").strip()
        if not listen_host:
            raise HTTPException(422, "수동 프록시에는 단말이 접근할 Windows Listener IP가 필요합니다.")
        try:
            listener_ip = ipaddress.ip_address(listen_host)
        except ValueError as exc:
            raise HTTPException(422, "수동 프록시 Listener IP 형식이 올바르지 않습니다.") from exc
        if listener_ip.is_unspecified or listener_ip.is_multicast or listener_ip.is_loopback:
            raise HTTPException(422, "수동 프록시는 특정 Windows LAN IP에 바인딩해야 합니다.")
        try:
            proxy_port = int(options.get("proxy_port") or 8080)
        except (TypeError, ValueError) as exc:
            raise HTTPException(422, "수동 프록시 포트 형식이 올바르지 않습니다.") from exc
        if not 1 <= proxy_port <= 65535:
            raise HTTPException(422, "수동 프록시 포트 범위가 올바르지 않습니다.")
        options.update(
            {"proxy_listen_host": listen_host, "proxy_port": proxy_port}
        )
    run = DiagnosticRun(
        project_id=project.id,
        app_id=payload.app_id,
        device_id=payload.device_id,
        device_adapter=payload.device_adapter,
        proxy_adapter=payload.proxy_adapter,
        run_mode=run_mode.value,
        synthetic=run_mode == RunMode.MOCK,
        status="created",
        current_stage="ready",
        progress=0,
        options=options,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    if control_validation and control_validation["enabled"]:
        db.add(
            Evidence(
                run_id=run.id,
                evidence_type="approval_record",
                title="승인된 통제 검증 동의 기록",
                description=(
                    "승인자·만료·단말·테스트 계정·허용 서버를 실행 범위에 고정했습니다. "
                    "범위 밖 목적지는 차단 또는 자동 중단하며 승인 정보를 외부 AI에 전송하지 않습니다."
                ),
                sequence=0,
                inline_data=control_validation,
                synthetic=False,
            )
        )
        db.commit()
    _orchestrator(request).launch(run.id)
    return run


@router.get("/runs/{run_id}", response_model=RunOut)
def get_run(run_id: str, db: Session = Depends(get_db)):
    return _run_or_404(db, run_id)


@router.get("/runs/{run_id}/frida/health")
def get_run_frida_health(
    request: Request, run_id: str, db: Session = Depends(get_db)
):
    run = _run_or_404(db, run_id)
    live = _orchestrator(request).frida_sessions.health(run_id)
    if live.get("active"):
        return live
    saved = run.options.get("frida_health")
    if isinstance(saved, dict):
        return saved
    return live


@router.post("/runs/{run_id}/pause")
async def pause_run(request: Request, run_id: str, db: Session = Depends(get_db)):
    _run_or_404(db, run_id)
    if not await _orchestrator(request).pause(run_id):
        raise HTTPException(409, "실행 중인 진단이 아닙니다.")
    return {"status": RunStatus.PAUSE_REQUESTED.value}


@router.post("/runs/{run_id}/resume")
async def resume_run(request: Request, run_id: str, db: Session = Depends(get_db)):
    run = _run_or_404(db, run_id)
    if (
        run.proxy_adapter in {"burp", "fiddler"}
        and run.current_stage == "proxy_manual_setup"
        and not bool(run.options.get("manual_proxy_setup_confirmed"))
    ):
        raise HTTPException(409, "Listener와 단말 프록시 설정을 확인한 뒤 진단을 재개하세요.")
    if (
        run.proxy_adapter in {"burp", "fiddler"}
        and run.current_stage == "proxy_capture_import"
        and not bool(run.options.get("manual_proxy_imported"))
    ):
        raise HTTPException(409, "동적 조작 후 최종 HAR/JSON Import를 완료한 뒤 재개하세요.")
    if not await _orchestrator(request).resume(run_id):
        raise HTTPException(409, "안전 일시정지 상태이거나 수동 작업이 끝난 뒤에만 재개할 수 있습니다.")
    return {"status": "running"}


@router.post("/runs/{run_id}/proxy/confirm-setup")
async def confirm_manual_proxy_setup(
    request: Request, run_id: str, db: Session = Depends(get_db)
):
    run = _run_or_404(db, run_id)
    if run.proxy_adapter not in {"burp", "fiddler"}:
        raise HTTPException(422, "설정 확인은 Burp/Fiddler 수동 프록시 Run에만 적용됩니다.")
    _scoped_run(db, project_id=run.project_id, run_id=run.id)
    if run.current_stage != "proxy_manual_setup":
        raise HTTPException(409, "수동 프록시 설정 단계에서만 확인할 수 있습니다.")
    if not await _orchestrator(request).begin_manual_action(run.id):
        raise HTTPException(409, "다른 수동 작업이 끝난 뒤 프록시 설정을 확인하세요.")
    try:
        options = dict(run.options)
        options["manual_proxy_setup_confirmed"] = True
        run.options = options
        db.commit()
        return {
            "status": CapabilityStatus.AVAILABLE.value,
            "message": "프록시 설정 확인을 기록했습니다. 앱 진단을 재개할 수 있습니다.",
        }
    finally:
        await _orchestrator(request).end_manual_action(run.id)


@router.post("/runs/{run_id}/proxy/import")
async def import_manual_proxy_capture(
    request: Request,
    run_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    run = _run_or_404(db, run_id)
    if run.proxy_adapter not in {"burp", "fiddler"}:
        raise HTTPException(422, "HAR Import는 Burp/Fiddler 수동 프록시 Run에서만 사용할 수 있습니다.")
    _scoped_run(db, project_id=run.project_id, run_id=run.id)
    if run.current_stage != "proxy_capture_import":
        raise HTTPException(409, "앱 동적 조작이 끝난 최종 캡처 단계에서만 HAR를 가져올 수 있습니다.")
    adapter = _orchestrator(request).proxy_adapter(run.id)
    if not isinstance(adapter, ManualProxyAdapter):
        raise HTTPException(409, "이 Run의 수동 프록시 Adapter가 활성 상태가 아닙니다.")
    if not await _orchestrator(request).begin_manual_action(run.id):
        raise HTTPException(409, "자동 Task가 안전하게 대기 중이거나 다른 수동 작업이 끝난 뒤 가져오세요.")
    filename = Path(file.filename or "capture.har").name
    if Path(filename).suffix.lower() not in {".har", ".json"}:
        await _orchestrator(request).end_manual_action(run.id)
        raise HTTPException(415, "HAR 또는 JSON 파일만 가져올 수 있습니다.")
    destination = (
        EvidenceService(_settings(request)).run_dir(run.id)
        / "manual-proxy"
        / f"{uuid.uuid4()}{Path(filename).suffix.lower()}"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    limit = min(_settings(request).max_upload_mb, 64) * 1024 * 1024
    total = 0
    try:
        with destination.open("wb") as stream:
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > limit:
                    raise HTTPException(413, "프록시 Import 파일은 최대 64MB까지 허용합니다.")
                stream.write(chunk)
        try:
            flows = await asyncio.to_thread(adapter.import_har, run.id, destination)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise HTTPException(422, f"HAR 구조를 해석할 수 없습니다: {exc}") from exc
        if not flows:
            raise HTTPException(422, "진단 증적으로 연결할 프록시 흐름이 1개 이상 필요합니다.")
        evidence = EvidenceService(_settings(request)).add(
            db,
            run_id=run.id,
            evidence_type="manual_proxy_import",
            title=f"{run.proxy_adapter} HAR Import",
            description=f"사용자가 가져온 HAR/JSON에서 {len(flows)}개 흐름을 확인했습니다.",
            file_path=destination,
            mime_type="application/json",
            inline_data={
                "adapter": run.proxy_adapter,
                "flow_count": len(flows),
                "original_name": filename,
            },
        )
        options = dict(run.options)
        options.update(
            {
                "manual_proxy_imported": True,
                "manual_proxy_flow_count": len(flows),
                "manual_proxy_import_evidence_id": evidence.id,
            }
        )
        run.options = options
        db.commit()
        await event_bus.publish(
            run.id,
            "evidence",
            {
                "id": evidence.id,
                "type": evidence.evidence_type,
                "title": evidence.title,
                "sequence": evidence.sequence,
                "captured_at": evidence.captured_at.isoformat(),
            },
        )
        return {
            "status": "available",
            "adapter": run.proxy_adapter,
            "flow_count": len(flows),
            "evidence_id": evidence.id,
            "message": "최종 Import가 확인되었습니다. 이제 분석과 마무리를 재개할 수 있습니다.",
        }
    finally:
        await file.close()
        if not bool(run.options.get("manual_proxy_imported")):
            destination.unlink(missing_ok=True)
        await _orchestrator(request).end_manual_action(run.id)


@router.post("/runs/{run_id}/stop")
async def stop_run(request: Request, run_id: str, db: Session = Depends(get_db)):
    _run_or_404(db, run_id)
    try:
        stopped = await _orchestrator(request).stop(run_id)
    except ManualActionInProgress as exc:
        raise HTTPException(409, f"manual_action_in_progress: {exc}") from exc
    if not stopped:
        raise HTTPException(409, "실행 중인 진단이 아닙니다.")
    db.expire_all()
    run = _run_or_404(db, run_id)
    return {"status": run.status}


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
    rows = db.scalars(
        select(ProxyFlow)
        .where(ProxyFlow.run_id == run_id)
        .order_by(ProxyFlow.captured_at)
    ).all()
    masked = []
    for row in rows:
        payload = ProxyFlowOut.model_validate(row).model_dump()
        serialized, _ = mask_context(
            {
                "request_headers": payload["request_headers"],
                "request_body": payload["request_body"],
                "response_headers": payload["response_headers"],
                "response_body": payload["response_body"],
            }
        )
        sanitized = json.loads(serialized)
        payload.update(sanitized)
        masked.append(payload)
    return masked


@router.get("/runs/{run_id}/flows/raw", response_model=list[ProxyFlowOut])
def list_raw_flows(
    run_id: str,
    response: Response,
    db: Session = Depends(get_db),
):
    """Explicit authenticated raw-data action; the default endpoint is masked."""
    _run_or_404(db, run_id)
    response.headers["Cache-Control"] = "no-store"
    return db.scalars(
        select(ProxyFlow)
        .where(ProxyFlow.run_id == run_id)
        .order_by(ProxyFlow.captured_at)
    ).all()


class WebSocketTicketRequest(BaseModel):
    run_id: str


@router.post("/ws-ticket", status_code=201)
async def create_websocket_ticket(
    request: Request,
    payload: WebSocketTicketRequest,
    db: Session = Depends(get_db),
):
    _run_or_404(db, payload.run_id)
    client_host = request.client.host if request.client else ""
    token, expires_in = await request.app.state.ws_tickets.issue(
        payload.run_id, client_host
    )
    return {
        "ticket": token,
        "run_id": payload.run_id,
        "expires_in": expires_in,
        "single_use": True,
    }


@router.websocket("/runs/{run_id}/ws")
async def run_websocket(websocket: WebSocket, run_id: str):
    origin = websocket.headers.get("origin")
    host = websocket.headers.get("host")
    if origin and host:
        expected_scheme = "https" if websocket.url.scheme == "wss" else "http"
        if origin.rstrip("/") != f"{expected_scheme}://{host}":
            await websocket.close(code=4403)
            return
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
        run = _run_or_404(db, run_id)
        run_scope = [Finding.run_id == run_id]
        if run.app_id:
            static_finding_ids = (
                select(FindingSource.finding_id)
                .join(
                    RawFinding,
                    FindingSource.raw_finding_id == RawFinding.id,
                )
                .where(RawFinding.app_id == run.app_id)
            )
            run_scope.append(
                and_(
                    Finding.run_id.is_(None),
                    Finding.id.in_(static_finding_ids),
                )
            )
        query = query.where(or_(*run_scope))
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
        **{**payload.model_dump(), "source": "custom"},
        approval_status="pending_approval",
        syntax_status=syntax_status.value,
    )
    db.add(script)
    db.commit()
    db.refresh(script)
    return script


class FridaApproveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approver: str = Field(default="local_user", min_length=1, max_length=100)
    review_acknowledged: Literal[True]
    reviewed_sha256: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
        description="승인자가 화면에서 검토한 현재 스크립트 내용의 SHA-256",
    )


@router.post("/frida/scripts/{script_id}/approve", response_model=FridaScriptOut)
async def approve_frida_script(
    request: Request,
    script_id: str,
    payload: FridaApproveRequest | None = None,
    db: Session = Depends(get_db),
):
    script = db.get(FridaScript, script_id)
    if not script:
        raise HTTPException(404, "Frida 스크립트를 찾을 수 없습니다.")
    status, message = await FridaManager(_settings(request)).check_syntax(script.content)
    script.syntax_status = status.value
    if status != CapabilityStatus.AVAILABLE:
        script.approval_status = "pending_validation"
        script.approved_by = None
        script.approved_at = None
        script.approved_sha256 = None
        db.commit()
        raise HTTPException(422, f"완전한 구문 검사가 필요합니다: {message}")
    if payload is None:
        raise HTTPException(422, "스크립트 내용 검토 확인과 현재 SHA-256이 필요합니다.")
    current_sha256 = hashlib.sha256(script.content.encode("utf-8")).hexdigest()
    if payload.reviewed_sha256 != current_sha256:
        raise HTTPException(
            409,
            "검토한 스크립트 내용이 현재 버전과 다릅니다. 내용을 다시 확인한 뒤 승인하세요.",
        )
    script.approval_status = "approved"
    script.approved_by = payload.approver
    script.approved_at = datetime.now(timezone.utc)
    script.approved_sha256 = current_sha256
    db.commit()
    db.refresh(script)
    return script


class FridaExecuteRequest(BaseModel):
    project_id: str | None = None
    run_id: str | None = None
    mode: str = Field(default="spawn", pattern="^(spawn|attach)$")
    approval_token: str | None = None


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
    content_sha256 = hashlib.sha256(script.content.encode("utf-8")).hexdigest()
    if not script.approved_sha256 or script.approved_sha256 != content_sha256:
        script.approval_status = "pending_approval"
        script.approved_by = None
        script.approved_at = None
        script.approved_sha256 = None
        db.commit()
        raise HTTPException(409, "승인 후 스크립트 내용이 변경되어 재승인이 필요합니다.")
    if script.syntax_status != CapabilityStatus.AVAILABLE.value:
        raise HTTPException(409, "Node.js 구문 검사를 통과한 스크립트만 실행할 수 있습니다.")
    if not payload.project_id or not payload.run_id:
        raise HTTPException(422, "Frida 직접 실행에는 project_id와 run_id가 필요합니다.")
    project, run, app = _scoped_run(
        db, project_id=payload.project_id, run_id=payload.run_id
    )
    if not app:
        raise HTTPException(422, "Frida 실행에는 대상 앱이 연결된 진단이 필요합니다.")
    app_platform = _validate_app_device_platform(
        app, device_adapter=run.device_adapter, device_id=run.device_id
    )
    if normalize_platform(script.platform) != app_platform:
        raise HTTPException(422, "Frida 스크립트 플랫폼이 대상 앱과 일치하지 않습니다.")
    target = _target_for_app(app, live=run.run_mode == RunMode.LIVE.value)
    try:
        device_adapter = _orchestrator(request).device_for_run(db, run)
        frida_target = _orchestrator(request).frida_target_for_device(
            device_adapter, run.device_id
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    action_scope = f"execute:{script.id}"
    if not await _orchestrator(request).begin_manual_action(run.id):
        raise HTTPException(409, "자동 Task가 안전하게 대기 중이거나 다른 수동 작업이 끝난 뒤 실행하세요.")
    manual_claimed = True
    try:
        approval = consume_approval(
            db,
            payload.approval_token,
            project_id=project.id,
            run_id=run.id,
            resource_type="frida",
            action=action_scope,
            device_id=run.device_id,
            target=target,
        )
    except ApprovalError as exc:
        await _orchestrator(request).end_manual_action(run.id)
        manual_claimed = False
        raise HTTPException(409, str(exc)) from exc
    try:
        lease_acquired = await _orchestrator(request).leases.acquire(
            run.id, run.device_id, None
        )
    except Exception:
        await _orchestrator(request).end_manual_action(run.id)
        raise
    try:
        session_manager = _orchestrator(request).frida_sessions
        lifecycle_evidence_ids: list[str] = []
        session_was_active = session_manager.is_active(run.id)
        evidence_service = EvidenceService(_settings(request))

        async def record_lifecycle(title: str, operation) -> None:
            evidence = evidence_service.add(
                db,
                run_id=run.id,
                evidence_type="command_log",
                title=title,
                description=operation.message,
                command=operation.command,
                file_path=operation.file_path,
                inline_data=operation.to_dict(),
            )
            lifecycle_evidence_ids.append(evidence.id)

        if not session_was_active:
            if payload.mode == "spawn":
                stopped = await device_adapter.stop_app(run.device_id, target)
                await record_lifecycle("직접 Frida Spawn 전 앱 정상 종료", stopped)
                if stopped.status != CapabilityStatus.AVAILABLE:
                    raise HTTPException(
                        409, f"Frida Spawn 전 앱 종료 실패: {stopped.message}"
                    )
                stopped_process = await _orchestrator(
                    request
                )._wait_for_process_state(
                    device_adapter,
                    run.device_id,
                    target,
                    expected_running=False,
                )
                await record_lifecycle(
                    "직접 Frida Spawn 전 프로세스 종료 확인", stopped_process
                )
                if (
                    stopped_process.status != CapabilityStatus.AVAILABLE
                    or _orchestrator(request)._process_running(
                        stopped_process, target
                    )
                ):
                    raise HTTPException(
                        409, "Frida Spawn 전 대상 앱 프로세스 종료를 확인하지 못했습니다."
                    )
            else:
                attach_process = await _orchestrator(
                    request
                )._wait_for_process_state(
                    device_adapter,
                    run.device_id,
                    target,
                    expected_running=True,
                )
                await record_lifecycle(
                    "직접 Frida Attach 대상 프로세스 확인", attach_process
                )
                if not _orchestrator(request)._process_running(
                    attach_process, target
                ):
                    raise HTTPException(
                        409, "Frida Attach 대상 앱 프로세스 실행을 확인하지 못했습니다."
                    )
        session_script = FridaSessionScript(
            script_id=script.id,
            name=script.name,
            content=script.content,
        )
        if session_manager.is_active(run.id):
            result = await session_manager.load_script(run.id, session_script)
        else:
            loop = asyncio.get_running_loop()

            def publish_message(item: dict[str, Any]) -> None:
                masked_json, _ = mask_context(
                    {"message": item}, settings.ai_sensitive_keys
                )
                masked_item = json.loads(masked_json)["message"]
                loop.call_soon_threadsafe(
                    asyncio.create_task,
                    event_bus.publish(
                        run.id,
                        "frida_log",
                        {
                            "status": CapabilityStatus.AVAILABLE.value,
                            "persistent": True,
                            "messages": [masked_item],
                            "masked": True,
                            "health": session_manager.health(run.id),
                        },
                    ),
                )

            result = await session_manager.start(
                run_id=run.id,
                frida_target=frida_target,
                target=target,
                scripts=[session_script],
                mode=payload.mode,
                mock=run.run_mode == RunMode.MOCK.value,
                on_message=publish_message,
            )
        if result.status == CapabilityStatus.AVAILABLE and not session_was_active:
            if payload.mode == "spawn":
                note_resume = getattr(
                    device_adapter, "note_frida_spawn_resumed", None
                )
                if callable(note_resume):
                    note_resume(target)
            resumed_process = await _orchestrator(
                request
            )._wait_for_process_state(
                device_adapter,
                run.device_id,
                target,
                expected_running=True,
            )
            await record_lifecycle(
                (
                    "직접 Frida Spawn 후 프로세스 실행 확인"
                    if payload.mode == "spawn"
                    else "직접 Frida Attach 후 프로세스 유지 확인"
                ),
                resumed_process,
            )
            if not _orchestrator(request)._process_running(
                resumed_process, target
            ):
                await session_manager.stop(run.id)
                result.status = CapabilityStatus.FAILED
                result.message = (
                    "Frida 연결 후 대상 앱 프로세스 실행을 확인하지 못했습니다."
                )
        if run.run_mode == RunMode.LIVE.value and result.status == CapabilityStatus.AVAILABLE:
            script.success_count += 1
        elif run.run_mode == RunMode.LIVE.value:
            script.failure_count += 1
        result_data = result.to_dict()
        evidence = EvidenceService(_settings(request)).add(
            db,
            run_id=run.id,
            evidence_type="frida_script",
            title=f"직접 Frida 실행 · {script.name}",
            description=result.message,
            command=result.command,
            inline_data={
                "script_id": script.id,
                "result": result_data,
                "approval_id": approval.id,
                "approved_by": approval.approved_by,
                "approved_at": approval.approved_at.isoformat(),
                "lifecycle_evidence_ids": lifecycle_evidence_ids,
            },
        )
        db.commit()
        result_data["evidence_id"] = evidence.id
        return result_data
    finally:
        if lease_acquired:
            await _orchestrator(request).leases.release(run.id)
        if manual_claimed:
            await _orchestrator(request).end_manual_action(run.id)


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
    if payload.use_mock and project.run_mode != RunMode.MOCK.value:
        raise HTTPException(422, "Live 프로젝트에서는 Mock AI를 사용할 수 없습니다.")
    if not payload.use_mock and project.run_mode == RunMode.LIVE.value and not project.external_ai_allowed:
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
    if project.run_mode == RunMode.MOCK.value:
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
        raw_path = save_ai_raw_response(
            settings,
            f"frida-{project.id}-{uuid.uuid4()}-{attempt.provider}.json",
            attempt.raw_response,
        )
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
                synthetic=project.run_mode == RunMode.MOCK.value,
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
            platform=payload.platform,
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
    project_id: str
    run_id: str
    action: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    approval_token: str | None = None


@router.post("/runtime/execute")
async def execute_runtime_tool(
    request: Request,
    payload: RuntimeExecuteRequest,
    db: Session = Depends(get_db),
):
    settings = _settings(request)
    adapters = {
        "objection": ObjectionRuntimeAdapter(settings),
        "drozer": DrozerRuntimeAdapter(settings),
    }
    adapter = adapters.get(payload.adapter)
    if not adapter:
        raise HTTPException(422, "지원하지 않는 런타임 Adapter입니다.")
    _, run, app = _scoped_run(
        db, project_id=payload.project_id, run_id=payload.run_id
    )
    if not app:
        raise HTTPException(422, "런타임 작업에는 대상 앱이 연결된 진단이 필요합니다.")
    app_platform = _validate_app_device_platform(
        app, device_adapter=run.device_adapter, device_id=run.device_id
    )
    if payload.adapter == "drozer" and app_platform != "android":
        raise HTTPException(422, "drozer는 Android 앱과 단말에서만 실행할 수 있습니다.")
    target = _target_for_app(app, live=run.run_mode == RunMode.LIVE.value)
    action_details = adapter.actions.get(payload.action)
    if not action_details:
        raise HTTPException(422, "지원하지 않는 런타임 작업입니다.")
    risk = action_details[0]
    approval = None
    action_scope = f"{payload.adapter}:{payload.action}"
    if not await _orchestrator(request).begin_manual_action(run.id):
        raise HTTPException(409, "자동 Task가 안전하게 대기 중이거나 다른 수동 작업이 끝난 뒤 실행하세요.")
    manual_claimed = True
    try:
        if risk in {"medium", "high"}:
            approval = consume_approval(
                db,
                payload.approval_token,
                project_id=payload.project_id,
                run_id=payload.run_id,
                resource_type="runtime",
                action=action_scope,
                device_id=run.device_id,
                target=target,
            )
        lease_acquired = await _orchestrator(request).leases.acquire(
            run.id, run.device_id, None
        )
    except ApprovalError as exc:
        await _orchestrator(request).end_manual_action(run.id)
        manual_claimed = False
        raise HTTPException(409, str(exc)) from exc
    except Exception:
        await _orchestrator(request).end_manual_action(run.id)
        manual_claimed = False
        raise
    try:
        result = await adapter.execute(
            device_id=run.device_id,
            target=target,
            action=payload.action,
            arguments=payload.arguments,
            approved=approval is not None,
        )
        result_data = result.to_dict()
        evidence = EvidenceService(settings).add(
            db,
            run_id=run.id,
            evidence_type="runtime_tool",
            title=f"직접 런타임 작업 · {payload.adapter}:{payload.action}",
            description=result.message,
            command=result.command,
            inline_data={
                "operation": result_data,
                "approval_id": approval.id if approval else None,
                "approved_by": approval.approved_by if approval else None,
                "approved_at": approval.approved_at.isoformat() if approval else None,
            },
        )
        result_data["evidence_id"] = evidence.id
        return result_data
    finally:
        if lease_acquired:
            await _orchestrator(request).leases.release(run.id)
        if manual_claimed:
            await _orchestrator(request).end_manual_action(run.id)


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
    model_config = ConfigDict(extra="forbid")

    use_mock: bool = False
    simulate_nvidia_failure: bool = False


@router.post("/ai/test")
async def test_ai(request: Request, payload: AITestRequest):
    task = "고정 합성 데이터 기반 AI Provider 연결 테스트"
    context = {
        "platform": "android",
        "static_signals": {"sample": [{"value": "synthetic-test-only"}]},
        "runtime_log": "Synthetic provider connectivity test; no project data.",
        "proxy_flows": [
            {
                "method": "GET",
                "url": "https://provider-test.invalid/health",
                "status_code": 200,
            }
        ],
        "evidence_ids": ["synthetic-evidence-id"],
        "simulate_nvidia_failure": payload.simulate_nvidia_failure,
    }
    if payload.use_mock:
        result = await MockAIProvider().analyze(task, context)
        return {"selected": result.to_dict(), "attempts": [result.to_dict()]}
    result, attempts = await AIProviderChain(settings=_settings(request)).analyze(
        task,
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
            "lan_access": settings.lan_access,
            "authentication_required": settings.lan_access,
            "api_docs_enabled": settings.enable_api_docs,
            "trusted_hosts": settings.effective_trusted_hosts,
        },
        "ai": {
            "nvidia_configured": bool(settings.nvidia_api_key),
            "nvidia_model": settings.nvidia_model,
            "claude_configured": bool(settings.claude_api_key),
            "claude_model": settings.claude_model,
            "mask_external_ai_data": settings.mask_external_ai_data,
            "store_raw_responses": settings.store_ai_raw_responses,
            "custom_sensitive_key_count": len(settings.ai_sensitive_keys),
        },
        "proxy": {
            "default_listen_host": settings.proxy_listen_host,
            "binding_policy": "specific_ip_only",
            "client_allowlist_required": True,
            "port_policy": "per_run_dynamic",
        },
        "analysis": {
            "mobsf_configured": bool(
                settings.mobsf_url and settings.mobsf_api_key
            ),
            "mobsf_url": settings.mobsf_url,
            "mobsf_allowed_networks": settings.mobsf_allowed_networks,
            "mobsf_allowed_hosts": settings.mobsf_allowed_hosts,
            "semgrep_rules_path": str(settings.semgrep_rules_path),
            "catalog": CATALOG_SOURCE,
            "archive_limits": {
                "max_entries": settings.archive_max_entries,
                "max_uncompressed_mb": settings.archive_max_uncompressed_mb,
                "max_entry_mb": settings.archive_max_entry_mb,
                "max_entry_ratio": settings.archive_max_entry_ratio,
                "max_total_ratio": settings.archive_max_total_ratio,
                "max_nested_count": settings.archive_max_nested_count,
                "max_nested_mb": settings.archive_max_nested_mb,
            },
            "external_tool_limits": {
                "memory_mb": settings.external_tool_memory_mb,
                "cpu_seconds": settings.external_tool_cpu_seconds,
            },
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
