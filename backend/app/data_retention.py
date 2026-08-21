from __future__ import annotations

import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.core.config import AppSettings
from backend.app.database.models import (
    AIInvocation,
    ControlTest,
    DiagnosticRun,
    Evidence,
    Finding,
    OperationApproval,
    Project,
    ProxyFlow,
    ToolRun,
)


RETENTION_TERMINAL_STATUSES = {
    "completed",
    "completed_with_gaps",
    "manual_required",
    "failed",
    "stopped",
    "interrupted",
}


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _safe_data_path(settings: AppSettings, value: Path) -> Path | None:
    root = settings.data_dir.resolve()
    resolved = value.resolve()
    if resolved == root or root not in resolved.parents:
        return None
    return resolved


def _path_size(path: Path) -> int:
    if not path.exists() or path.is_symlink():
        return 0
    if path.is_file():
        return path.stat().st_size
    total = 0
    for item in path.rglob("*"):
        if item.is_file() and not item.is_symlink():
            total += item.stat().st_size
    return total


def _run_paths(
    settings: AppSettings,
    run: DiagnosticRun,
    findings: Iterable[Finding],
    ai_rows: Iterable[AIInvocation],
) -> list[Path]:
    paths = [
        settings.evidence_dir / run.id,
        settings.data_dir / "proxy" / f"{run.id}.jsonl",
    ]
    paths.extend(settings.reports_dir / f"{item.id}.html" for item in findings)
    profile = str(run.options.get("assessment_profile") or "")
    if profile:
        paths.append(
            settings.reports_dir / f"{run.id}-{profile}-vulnerabilities.docx"
        )
    paths.extend(
        Path(item.raw_response_path)
        for item in ai_rows
        if item.raw_response_path
    )
    safe: list[Path] = []
    seen: set[Path] = set()
    for item in paths:
        resolved = _safe_data_path(settings, item)
        if resolved is not None and resolved not in seen:
            safe.append(resolved)
            seen.add(resolved)
    return safe


def retention_run_ids(
    project: Project,
    runs: Iterable[DiagnosticRun],
    *,
    now: datetime | None = None,
) -> list[str]:
    current = _utc(now or datetime.now(timezone.utc))
    cutoff = current - timedelta(days=project.retention_days)
    return sorted(
        run.id
        for run in runs
        if run.status in RETENTION_TERMINAL_STATUSES
        and _utc(run.finished_at or run.created_at) <= cutoff
    )


def project_data_inventory(
    db: Session,
    settings: AppSettings,
    project: Project,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _utc(now or datetime.now(timezone.utc))
    cutoff = current - timedelta(days=project.retention_days)
    runs = db.scalars(
        select(DiagnosticRun)
        .where(DiagnosticRun.project_id == project.id)
        .order_by(DiagnosticRun.created_at.desc())
    ).all()
    expired_ids = set(retention_run_ids(project, runs, now=current))
    rows: list[dict[str, Any]] = []
    total_disk_bytes = 0
    for run in runs:
        findings = db.scalars(
            select(Finding).where(Finding.run_id == run.id)
        ).all()
        ai_rows = db.scalars(
            select(AIInvocation).where(AIInvocation.run_id == run.id)
        ).all()
        evidence_count = int(
            db.scalar(
                select(func.count(Evidence.id)).where(Evidence.run_id == run.id)
            )
            or 0
        )
        evidence_file_count = int(
            db.scalar(
                select(func.count(Evidence.id)).where(
                    Evidence.run_id == run.id,
                    Evidence.file_path.is_not(None),
                )
            )
            or 0
        )
        flow_count = int(
            db.scalar(
                select(func.count(ProxyFlow.id)).where(ProxyFlow.run_id == run.id)
            )
            or 0
        )
        disk_bytes = sum(
            _path_size(path)
            for path in _run_paths(settings, run, findings, ai_rows)
        )
        total_disk_bytes += disk_bytes
        basis = _utc(run.finished_at or run.created_at)
        rows.append(
            {
                "run_id": run.id,
                "status": run.status,
                "created_at": _utc(run.created_at).isoformat(),
                "retention_basis_at": basis.isoformat(),
                "expires_at": (
                    basis + timedelta(days=project.retention_days)
                ).isoformat(),
                "expired": run.id in expired_ids,
                "synthetic": run.synthetic,
                "evidence_count": evidence_count,
                "evidence_file_count": evidence_file_count,
                "flow_count": flow_count,
                "finding_count": len(findings),
                "ai_invocation_count": len(ai_rows),
                "ai_raw_response_count": sum(
                    bool(item.raw_response_path) for item in ai_rows
                ),
                "has_frida_transcript": (
                    settings.evidence_dir / run.id / "frida-session.jsonl"
                ).is_file(),
                "disk_bytes": disk_bytes,
            }
        )
    return {
        "project_id": project.id,
        "project_name": project.name,
        "retention_days": project.retention_days,
        "raw_access_enabled": project.raw_access_enabled,
        "generated_at": current.isoformat(),
        "cutoff_at": cutoff.isoformat(),
        "automatic_deletion": False,
        "confirmation_policy": "reviewed_exact_run_ids_and_project_name",
        "run_count": len(rows),
        "expired_run_count": len(expired_ids),
        "total_disk_bytes": total_disk_bytes,
        "expired_run_ids": sorted(expired_ids),
        "runs": rows,
    }


def purge_retention_runs(
    db: Session,
    settings: AppSettings,
    project: Project,
    run_ids: Iterable[str],
) -> dict[str, Any]:
    expected = sorted(set(run_ids))
    runs = db.scalars(
        select(DiagnosticRun).where(
            DiagnosticRun.project_id == project.id,
            DiagnosticRun.id.in_(expected),
        )
    ).all()
    if sorted(item.id for item in runs) != expected:
        raise ValueError("정리 대상 Run이 현재 프로젝트 원장과 일치하지 않습니다.")

    paths: list[Path] = []
    removed_database = {
        "runs": 0,
        "findings": 0,
        "evidence": 0,
        "flows": 0,
        "control_tests": 0,
        "ai_invocations": 0,
        "approvals": 0,
    }
    for run in runs:
        findings = db.scalars(
            select(Finding).where(Finding.run_id == run.id)
        ).all()
        ai_rows = db.scalars(
            select(AIInvocation).where(AIInvocation.run_id == run.id)
        ).all()
        paths.extend(_run_paths(settings, run, findings, ai_rows))
        removed_database["findings"] += len(findings)
        removed_database["evidence"] += int(
            db.scalar(
                select(func.count(Evidence.id)).where(Evidence.run_id == run.id)
            )
            or 0
        )
        removed_database["flows"] += int(
            db.scalar(
                select(func.count(ProxyFlow.id)).where(ProxyFlow.run_id == run.id)
            )
            or 0
        )
        controls = db.scalars(
            select(ControlTest).where(ControlTest.run_id == run.id)
        ).all()
        approvals = db.scalars(
            select(OperationApproval).where(OperationApproval.run_id == run.id)
        ).all()
        tools = db.scalars(
            select(ToolRun).where(ToolRun.run_id == run.id)
        ).all()
        removed_database["control_tests"] += len(controls)
        removed_database["ai_invocations"] += len(ai_rows)
        removed_database["approvals"] += len(approvals)
        for row in controls:
            db.delete(row)
        for row in ai_rows:
            db.delete(row)
        for row in approvals:
            db.delete(row)
        for row in tools:
            row.run_id = None
        db.delete(run)
        removed_database["runs"] += 1
    db.commit()

    removed_path_count = 0
    removal_errors: list[str] = []
    removed_bytes = 0
    for path in dict.fromkeys(paths):
        if not path.exists():
            continue
        size = _path_size(path)
        try:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.is_file() and not path.is_symlink():
                path.unlink()
            else:
                continue
        except OSError as exc:
            removal_errors.append(
                f"{type(exc).__name__}: 로컬 원본 하나를 정리하지 못했습니다."
            )
        else:
            removed_path_count += 1
            removed_bytes += size
    return {
        "status": "completed" if not removal_errors else "completed_with_gaps",
        "project_id": project.id,
        "removed_run_ids": expected,
        "removed_database": removed_database,
        "removed_path_count": removed_path_count,
        "removed_bytes": removed_bytes,
        "removal_errors": removal_errors,
        "recoverable": False,
    }
