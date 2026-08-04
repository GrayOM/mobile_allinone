from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.database.models import OperationApproval


class ApprovalError(ValueError):
    pass


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_approval(
    db: Session,
    *,
    project_id: str,
    run_id: str,
    resource_type: str,
    action: str,
    device_id: str,
    target: str | None,
    approved_by: str,
    lifetime_seconds: int = 300,
) -> tuple[OperationApproval, str]:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    approval = OperationApproval(
        project_id=project_id,
        run_id=run_id,
        resource_type=resource_type,
        action=action,
        device_id=device_id,
        target=target,
        token_sha256=_token_hash(token),
        approved_by=approved_by,
        approved_at=now,
        expires_at=now + timedelta(seconds=lifetime_seconds),
        status="issued",
    )
    db.add(approval)
    db.commit()
    db.refresh(approval)
    return approval, token


def consume_approval(
    db: Session,
    token: str | None,
    *,
    project_id: str,
    run_id: str,
    resource_type: str,
    action: str,
    device_id: str,
    target: str | None,
) -> OperationApproval:
    if not token:
        raise ApprovalError("이 작업에는 서버가 발급한 1회 승인 토큰이 필요합니다.")
    approval = db.scalar(
        select(OperationApproval).where(
            OperationApproval.token_sha256 == _token_hash(token),
            OperationApproval.status == "issued",
        )
    )
    if not approval:
        raise ApprovalError("승인 토큰이 없거나 이미 사용되었습니다.")
    now = datetime.now(timezone.utc)
    expires_at = approval.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= now:
        approval.status = "expired"
        db.commit()
        raise ApprovalError("승인 토큰이 만료되었습니다.")
    expected = (
        project_id,
        run_id,
        resource_type,
        action,
        device_id,
        target or None,
    )
    actual = (
        approval.project_id,
        approval.run_id,
        approval.resource_type,
        approval.action,
        approval.device_id,
        approval.target or None,
    )
    if actual != expected:
        raise ApprovalError("승인 토큰의 프로젝트·실행·대상 범위가 요청과 일치하지 않습니다.")
    approval.status = "consumed"
    approval.consumed_at = now
    db.commit()
    db.refresh(approval)
    return approval
