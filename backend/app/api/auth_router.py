from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import select

from backend.app.auth import AuditService, OrganizationAuthService, OrganizationIdentity
from backend.app.database.models import AuditLog, OrganizationUser
from backend.app.database.session import SessionLocal


router = APIRouter(prefix="/api")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AuthConfigOut(StrictModel):
    enabled: bool
    lan_access: bool
    session_hours: int


class IdentityOut(StrictModel):
    id: str
    username: str
    display_name: str
    role: Literal["viewer", "operator", "admin"]


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=64)
    password: SecretStr = Field(min_length=1, max_length=128)


class LoginOut(StrictModel):
    token: str
    expires_at: datetime
    user: IdentityOut


class UserCreate(StrictModel):
    username: str = Field(min_length=3, max_length=64)
    display_name: str = Field(min_length=1, max_length=120)
    role: Literal["viewer", "operator", "admin"]
    password: SecretStr = Field(min_length=12, max_length=128)


class UserUpdate(StrictModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    role: Literal["viewer", "operator", "admin"] | None = None
    enabled: bool | None = None
    password: SecretStr | None = None


class UserOut(IdentityOut):
    enabled: bool
    last_login_at: datetime | None
    created_at: datetime


class AuditLogOut(StrictModel):
    id: str
    actor_username: str
    actor_role: str
    action: str
    method: str
    path: str
    status_code: int
    outcome: str
    client_host: str
    request_id: str
    resource_type: str | None
    resource_id: str | None
    details: dict
    previous_hash: str
    entry_hash: str
    created_at: datetime


def _auth(request: Request) -> OrganizationAuthService:
    return request.app.state.organization_auth


def _audit(request: Request) -> AuditService:
    return request.app.state.audit_service


def _actor(request: Request) -> OrganizationIdentity:
    identity = getattr(request.state, "organization_actor", None)
    if not identity:
        raise HTTPException(401, "조직 사용자 로그인이 필요합니다.")
    return identity


def _identity_out(identity: OrganizationIdentity) -> IdentityOut:
    return IdentityOut(
        id=identity.user_id,
        username=identity.username,
        display_name=identity.display_name,
        role=identity.role,
    )


def _user_out(user: OrganizationUser) -> UserOut:
    return UserOut(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        role=user.role,
        enabled=user.enabled,
        last_login_at=user.last_login_at,
        created_at=user.created_at,
    )


@router.get("/auth/config", response_model=AuthConfigOut)
def auth_config(request: Request) -> AuthConfigOut:
    settings = request.app.state.settings
    return AuthConfigOut(
        enabled=settings.organization_auth,
        lan_access=settings.lan_access,
        session_hours=settings.organization_session_hours,
    )


@router.post("/auth/login", response_model=LoginOut)
def login(payload: LoginRequest, request: Request) -> LoginOut:
    settings = request.app.state.settings
    if not settings.organization_auth:
        raise HTTPException(404, "조직 인증이 활성화되지 않았습니다.")
    client_host = str(request.client.host if request.client else "")
    user_agent = request.headers.get("user-agent", "")[:1_000]
    try:
        identity, token, expires_at = _auth(request).authenticate(
            username=payload.username,
            password=payload.password.get_secret_value(),
            client_host=client_host,
            user_agent=user_agent,
        )
    except PermissionError as exc:
        _audit(request).append(
            actor=None,
            action="auth.login_failed",
            method="POST",
            path="/api/auth/login",
            status_code=401,
            client_host=client_host,
            request_id=getattr(request.state, "request_id", None),
            outcome="denied",
        )
        raise HTTPException(401, str(exc)) from exc
    _audit(request).append(
        actor=identity,
        action="auth.login",
        method="POST",
        path="/api/auth/login",
        status_code=200,
        client_host=client_host,
        request_id=getattr(request.state, "request_id", None),
    )
    return LoginOut(token=token, expires_at=expires_at, user=_identity_out(identity))


@router.get("/auth/me", response_model=IdentityOut)
def current_identity(request: Request) -> IdentityOut:
    return _identity_out(_actor(request))


@router.post("/auth/logout")
def logout(request: Request) -> dict[str, str]:
    _auth(request).revoke(_actor(request).session_id)
    return {"status": "logged_out"}


@router.get("/auth/users", response_model=list[UserOut])
def list_users() -> list[UserOut]:
    with SessionLocal() as db:
        users = db.scalars(select(OrganizationUser).order_by(OrganizationUser.username)).all()
        return [_user_out(user) for user in users]


@router.post("/auth/users", response_model=UserOut, status_code=201)
def create_user(payload: UserCreate, request: Request) -> UserOut:
    actor = _actor(request)
    try:
        user = _auth(request).create_user(
            username=payload.username,
            display_name=payload.display_name,
            role=payload.role,
            password=payload.password.get_secret_value(),
            created_by=actor.user_id,
        )
    except FileExistsError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return _user_out(user)


@router.patch("/auth/users/{user_id}", response_model=UserOut)
def update_user(user_id: str, payload: UserUpdate, request: Request) -> UserOut:
    try:
        user = _auth(request).update_user(
            user_id,
            display_name=payload.display_name,
            role=payload.role,
            enabled=payload.enabled,
            password=payload.password.get_secret_value() if payload.password else None,
        )
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(409, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return _user_out(user)


@router.get("/audit-logs", response_model=list[AuditLogOut])
def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    outcome: Literal["success", "denied", "failed"] | None = None,
) -> list[AuditLogOut]:
    statement = select(AuditLog)
    if outcome:
        statement = statement.where(AuditLog.outcome == outcome)
    statement = statement.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
    with SessionLocal() as db:
        rows = db.scalars(statement).all()
        return [AuditLogOut.model_validate(row, from_attributes=True) for row in rows]


@router.get("/audit-logs/verify")
def verify_audit_logs(request: Request) -> dict[str, object]:
    valid, checked_count, failed_id = _audit(request).verify_chain()
    return {
        "valid": valid,
        "checked_count": checked_count,
        "failed_entry_id": failed_id,
    }
