from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from sqlalchemy import select

from backend.app.core.config import AppSettings
from backend.app.database.base import utcnow
from backend.app.database.models import AuditLog, OrganizationSession, OrganizationUser
from backend.app.database.session import SessionLocal


ROLES = {"viewer", "operator", "admin"}
ROLE_RANK = {"viewer": 10, "operator": 20, "admin": 30}
USERNAME_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{2,63}$")
ZERO_HASH = "0" * 64


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def validate_username(value: str) -> str:
    normalized = value.strip().lower()
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError("사용자명은 영문 소문자로 시작하는 3~64자의 영문·숫자·._-만 허용합니다.")
    return normalized


def validate_password(value: str) -> str:
    if len(value) < 12 or len(value) > 128:
        raise ValueError("비밀번호는 12~128자여야 합니다.")
    return value


@dataclass(frozen=True, slots=True)
class OrganizationIdentity:
    user_id: str
    username: str
    display_name: str
    role: str
    session_id: str

    def permits(self, required_role: str) -> bool:
        return ROLE_RANK.get(self.role, 0) >= ROLE_RANK.get(required_role, 100)


class OrganizationAuthService:
    def __init__(self, settings: AppSettings):
        self.settings = settings
        self.password_hasher = PasswordHasher(
            time_cost=3,
            memory_cost=65_536,
            parallelism=2,
            hash_len=32,
            salt_len=16,
        )
        self._dummy_hash = self.password_hasher.hash(secrets.token_urlsafe(24))

    def bootstrap(self) -> None:
        if not self.settings.organization_auth:
            return
        with SessionLocal() as db:
            if db.scalar(select(OrganizationUser.id).limit(1)):
                return
            if not self.settings.bootstrap_admin_password:
                raise RuntimeError(
                    "조직 인증을 처음 활성화할 때 MSW_BOOTSTRAP_ADMIN_PASSWORD(12자 이상)가 필요합니다."
                )
            username = validate_username(self.settings.bootstrap_admin_username)
            password = validate_password(self.settings.bootstrap_admin_password)
            db.add(
                OrganizationUser(
                    username=username,
                    display_name="Workbench Administrator",
                    role="admin",
                    password_hash=self.password_hasher.hash(password),
                    enabled=True,
                    created_by="bootstrap",
                )
            )
            db.commit()

    def authenticate(
        self,
        *,
        username: str,
        password: str,
        client_host: str,
        user_agent: str,
    ) -> tuple[OrganizationIdentity, str, datetime]:
        try:
            normalized = validate_username(username)
        except ValueError:
            normalized = "invalid-user"
        now = utcnow()
        with SessionLocal() as db:
            user = db.scalar(
                select(OrganizationUser).where(OrganizationUser.username == normalized)
            )
            password_ok = False
            try:
                password_ok = self.password_hasher.verify(
                    user.password_hash if user else self._dummy_hash,
                    password,
                )
            except (VerifyMismatchError, InvalidHashError):
                password_ok = False
            locked_until = _aware(user.locked_until) if user else None
            usable = bool(
                user
                and user.enabled
                and (locked_until is None or locked_until <= now)
                and password_ok
            )
            if not usable:
                if user and user.enabled:
                    user.failed_login_count += 1
                    if user.failed_login_count >= 5:
                        user.locked_until = now + timedelta(minutes=15)
                        user.failed_login_count = 0
                    db.commit()
                raise PermissionError("사용자명 또는 비밀번호를 확인할 수 없습니다.")

            if self.password_hasher.check_needs_rehash(user.password_hash):
                user.password_hash = self.password_hasher.hash(password)
            user.failed_login_count = 0
            user.locked_until = None
            user.last_login_at = now
            token = secrets.token_urlsafe(32)
            expires_at = now + timedelta(hours=self.settings.organization_session_hours)
            session = OrganizationSession(
                user_id=user.id,
                token_hash=_token_hash(token),
                expires_at=expires_at,
                client_host=client_host[:64],
                user_agent_hash=hashlib.sha256(user_agent.encode("utf-8")).hexdigest(),
                last_seen_at=now,
            )
            db.add(session)
            db.commit()
            identity = OrganizationIdentity(
                user_id=user.id,
                username=user.username,
                display_name=user.display_name,
                role=user.role,
                session_id=session.id,
            )
            return identity, token, expires_at

    def resolve(
        self,
        token: str,
        *,
        client_host: str,
        user_agent: str,
    ) -> OrganizationIdentity | None:
        if not token:
            return None
        now = utcnow()
        with SessionLocal() as db:
            session = db.scalar(
                select(OrganizationSession).where(
                    OrganizationSession.token_hash == _token_hash(token)
                )
            )
            if (
                not session
                or session.revoked_at is not None
                or (_aware(session.expires_at) or now) <= now
                or not secrets.compare_digest(session.client_host, client_host[:64])
                or not secrets.compare_digest(
                    session.user_agent_hash,
                    hashlib.sha256(user_agent.encode("utf-8")).hexdigest(),
                )
            ):
                return None
            user = db.get(OrganizationUser, session.user_id)
            if not user or not user.enabled or user.role not in ROLES:
                return None
            last_seen = _aware(session.last_seen_at) or now
            if now - last_seen >= timedelta(minutes=5):
                session.last_seen_at = now
                db.commit()
            return OrganizationIdentity(
                user_id=user.id,
                username=user.username,
                display_name=user.display_name,
                role=user.role,
                session_id=session.id,
            )

    def revoke(self, session_id: str) -> None:
        with SessionLocal() as db:
            session = db.get(OrganizationSession, session_id)
            if session and session.revoked_at is None:
                session.revoked_at = utcnow()
                db.commit()

    def create_user(
        self,
        *,
        username: str,
        display_name: str,
        role: str,
        password: str,
        created_by: str,
    ) -> OrganizationUser:
        normalized = validate_username(username)
        validate_password(password)
        if role not in ROLES:
            raise ValueError("역할은 viewer, operator, admin 중 하나여야 합니다.")
        display = display_name.strip()
        if not display or len(display) > 120:
            raise ValueError("표시 이름은 1~120자여야 합니다.")
        with SessionLocal() as db:
            if db.scalar(
                select(OrganizationUser.id).where(
                    OrganizationUser.username == normalized
                )
            ):
                raise FileExistsError("이미 존재하는 사용자명입니다.")
            user = OrganizationUser(
                username=normalized,
                display_name=display,
                role=role,
                password_hash=self.password_hasher.hash(password),
                enabled=True,
                created_by=created_by,
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            db.expunge(user)
            return user

    def update_user(
        self,
        user_id: str,
        *,
        display_name: str | None,
        role: str | None,
        enabled: bool | None,
        password: str | None,
    ) -> OrganizationUser:
        if role is not None and role not in ROLES:
            raise ValueError("역할은 viewer, operator, admin 중 하나여야 합니다.")
        if password is not None:
            validate_password(password)
        with SessionLocal() as db:
            user = db.get(OrganizationUser, user_id)
            if not user:
                raise LookupError("사용자를 찾을 수 없습니다.")
            removes_admin = (role is not None and role != "admin") or enabled is False
            if user.role == "admin" and user.enabled and removes_admin:
                admins = db.scalars(
                    select(OrganizationUser.id).where(
                        OrganizationUser.role == "admin",
                        OrganizationUser.enabled.is_(True),
                    )
                ).all()
                if len(admins) <= 1:
                    raise PermissionError("마지막 활성 관리자는 비활성화하거나 강등할 수 없습니다.")
            if display_name is not None:
                display = display_name.strip()
                if not display or len(display) > 120:
                    raise ValueError("표시 이름은 1~120자여야 합니다.")
                user.display_name = display
            if role is not None:
                user.role = role
            if enabled is not None:
                user.enabled = enabled
            if password is not None:
                user.password_hash = self.password_hasher.hash(password)
                for session in db.scalars(
                    select(OrganizationSession).where(
                        OrganizationSession.user_id == user.id,
                        OrganizationSession.revoked_at.is_(None),
                    )
                ).all():
                    session.revoked_at = utcnow()
            if enabled is False:
                for session in db.scalars(
                    select(OrganizationSession).where(
                        OrganizationSession.user_id == user.id,
                        OrganizationSession.revoked_at.is_(None),
                    )
                ).all():
                    session.revoked_at = utcnow()
            db.commit()
            db.refresh(user)
            db.expunge(user)
            return user


class AuditService:
    def __init__(self):
        self._lock = threading.Lock()

    @staticmethod
    def action_for(method: str, path: str) -> str:
        normalized = path.removeprefix("/api/").strip("/").replace("/", ".")
        return f"{method.lower()}.{normalized or 'api'}"[:100]

    def append(
        self,
        *,
        actor: OrganizationIdentity | None,
        action: str,
        method: str,
        path: str,
        status_code: int,
        client_host: str,
        request_id: str | None = None,
        outcome: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditLog:
        request_id = request_id or str(uuid.uuid4())
        safe_details = details or {}
        with self._lock, SessionLocal() as db:
            created_at = utcnow()
            previous = db.scalar(
                select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(1)
            )
            previous_hash = previous.entry_hash if previous else ZERO_HASH
            payload = {
                "actor_id": actor.user_id if actor else None,
                "actor_username": actor.username if actor else "anonymous",
                "actor_role": actor.role if actor else "none",
                "action": action[:100],
                "method": method[:12],
                "path": path[:500],
                "status_code": status_code,
                "outcome": outcome or ("success" if status_code < 400 else "denied"),
                "client_host": client_host[:64],
                "request_id": request_id,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "details": safe_details,
                "previous_hash": previous_hash,
                "created_at": created_at.isoformat(),
            }
            entry_hash = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            ).hexdigest()
            record = AuditLog(
                **{**payload, "created_at": created_at, "entry_hash": entry_hash}
            )
            db.add(record)
            db.commit()
            db.refresh(record)
            db.expunge(record)
            return record

    def verify_chain(self) -> tuple[bool, int, str | None]:
        with SessionLocal() as db:
            rows = db.scalars(
                select(AuditLog).order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
            ).all()
        previous_hash = ZERO_HASH
        for index, row in enumerate(rows):
            created_at = _aware(row.created_at) or row.created_at
            payload = {
                "actor_id": row.actor_id,
                "actor_username": row.actor_username,
                "actor_role": row.actor_role,
                "action": row.action,
                "method": row.method,
                "path": row.path,
                "status_code": row.status_code,
                "outcome": row.outcome,
                "client_host": row.client_host,
                "request_id": row.request_id,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "details": row.details or {},
                "previous_hash": row.previous_hash,
                "created_at": created_at.isoformat(),
            }
            expected = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            ).hexdigest()
            if row.previous_hash != previous_hash or not secrets.compare_digest(row.entry_hash, expected):
                return False, index, row.id
            previous_hash = row.entry_hash
        return True, len(rows), None
