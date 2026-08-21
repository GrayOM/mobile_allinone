from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import secrets
import time
import uuid
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from starlette.responses import JSONResponse

from backend.app.core.config import AppSettings
from backend.app.core.targets import is_loopback_host
from backend.app.auth import AuditService, OrganizationAuthService, OrganizationIdentity


@dataclass(frozen=True, slots=True)
class WebSocketTicket:
    run_id: str
    client_host: str
    expires_at: float


class WebSocketTicketStore:
    def __init__(self, ttl_seconds: int = 30):
        self.ttl_seconds = ttl_seconds
        self._tickets: dict[str, WebSocketTicket] = {}
        self._lock = asyncio.Lock()

    async def issue(self, run_id: str, client_host: str) -> tuple[str, int]:
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        async with self._lock:
            self._purge()
            self._tickets[digest] = WebSocketTicket(
                run_id=run_id,
                client_host=client_host,
                expires_at=time.monotonic() + self.ttl_seconds,
            )
        return token, self.ttl_seconds

    async def consume(self, token: str, run_id: str, client_host: str) -> bool:
        if not token:
            return False
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        async with self._lock:
            self._purge()
            ticket = self._tickets.pop(digest, None)
        return bool(
            ticket
            and ticket.run_id == run_id
            and ticket.client_host == client_host
            and ticket.expires_at >= time.monotonic()
        )

    def _purge(self) -> None:
        now = time.monotonic()
        self._tickets = {
            digest: ticket
            for digest, ticket in self._tickets.items()
            if ticket.expires_at >= now
        }


class ApiSecurityMiddleware:
    def __init__(
        self,
        app,
        settings: AppSettings,
        ticket_store: WebSocketTicketStore | None = None,
        auth_service: OrganizationAuthService | None = None,
        audit_service: AuditService | None = None,
    ):
        self.app = app
        self.settings = settings
        self.ticket_store = ticket_store or WebSocketTicketStore()
        self.auth_service = auth_service
        self.audit_service = audit_service

    @staticmethod
    def _headers(scope) -> dict[bytes, bytes]:
        return {key.lower(): value for key, value in scope.get("headers", [])}

    @staticmethod
    def _bearer(headers: dict[bytes, bytes]) -> str:
        value = headers.get(b"authorization", b"").decode("latin-1")
        scheme, _, token = value.partition(" ")
        return token if scheme.lower() == "bearer" else ""

    async def _reject_http(
        self,
        scope,
        receive,
        send,
        status: int,
        detail: str,
        *,
        request_id: str | None = None,
    ):
        response = JSONResponse({"detail": detail}, status_code=status)
        if request_id:
            response.headers["X-MSW-Request-ID"] = request_id
        await response(scope, receive, send)

    @staticmethod
    def _required_role(method: str, path: str) -> str:
        if path.startswith("/api/auth/users") or path.startswith("/api/audit-logs"):
            return "admin"
        if method == "PUT" and path == "/api/settings/tools":
            return "admin"
        if method == "POST" and path.endswith("/retention/apply"):
            return "admin"
        if method in {"GET", "HEAD", "OPTIONS"} or path in {
            "/api/ws-ticket",
            "/api/auth/logout",
        }:
            return "viewer"
        return "operator"

    def _audit(
        self,
        *,
        actor: OrganizationIdentity | None,
        method: str,
        path: str,
        status_code: int,
        client_host: str,
        request_id: str,
        action: str | None = None,
    ) -> None:
        if not self.audit_service or path in {"/api/auth/login", "/api/auth/config"}:
            return
        try:
            self.audit_service.append(
                actor=actor,
                action=action or self.audit_service.action_for(method, path),
                method=method,
                path=path,
                status_code=status_code,
                client_host=client_host,
                request_id=request_id,
            )
        except Exception:
            # 감사 저장 장애가 원래 API 응답을 변경하지 않게 한다. 서버 로그에는
            # 토큰이나 요청 본문을 전달하지 않는다.
            return

    def _is_local_request(self, scope, headers: dict[bytes, bytes]) -> bool:
        server_host = str((scope.get("server") or ("", 0))[0])
        if is_loopback_host(server_host):
            return True
        if not self.settings.docker_loopback_bridge:
            return False
        if any(
            name in headers
            for name in (b"forwarded", b"x-forwarded-for", b"x-forwarded-host")
        ):
            return False
        authority = headers.get(b"host", b"").decode("latin-1")
        request_host = urlsplit(f"//{authority}").hostname or ""
        if not is_loopback_host(request_host):
            return False
        client_host = str((scope.get("client") or ("", 0))[0])
        try:
            client_ip = ipaddress.ip_address(client_host)
        except ValueError:
            return False
        return client_ip.is_loopback or client_ip.is_private

    async def __call__(self, scope, receive, send):
        scope_type = scope.get("type")
        path = str(scope.get("path") or "")
        if scope_type not in {"http", "websocket"} or not path.startswith("/api"):
            await self.app(scope, receive, send)
            return

        headers = self._headers(scope)
        if scope_type == "websocket":
            if not self.settings.lan_access and not self._is_local_request(scope, headers):
                await send({"type": "websocket.close", "code": 4403})
                return
            query = parse_qs(scope.get("query_string", b"").decode("utf-8"))
            ticket = str((query.get("ticket") or [""])[0])
            client_host = str((scope.get("client") or ("", 0))[0])
            run_id = str(scope.get("path_params", {}).get("run_id") or "")
            if not run_id:
                parts = path.rstrip("/").split("/")
                run_id = parts[-2] if len(parts) >= 2 and parts[-1] == "ws" else ""
            if not await self.ticket_store.consume(ticket, run_id, client_host):
                await send({"type": "websocket.close", "code": 4401})
                return
            await self.app(scope, receive, send)
            return

        request_id = str(uuid.uuid4())
        method = str(scope.get("method") or "GET").upper()
        client_host = str((scope.get("client") or ("", 0))[0])
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_request_id(message):
            if message.get("type") == "http.response.start":
                response_headers = list(message.get("headers", []))
                response_headers.append((b"x-msw-request-id", request_id.encode("ascii")))
                message = {**message, "headers": response_headers}
            await send(message)

        local_request = self._is_local_request(scope, headers)

        if not self.settings.lan_access:
            if not local_request:
                self._audit(
                    actor=None,
                    method=method,
                    path=path,
                    status_code=403,
                    client_host=client_host,
                    request_id=request_id,
                    action="access.network_denied",
                )
                await self._reject_http(
                    scope,
                    receive,
                    send,
                    403,
                    "서버가 loopback 모드이므로 외부 주소의 API 요청을 거부했습니다.",
                    request_id=request_id,
                )
                return
        if method == "OPTIONS":
            await self.app(scope, receive, send_with_request_id)
            return

        if self.settings.lan_access:
            if self.settings.organization_auth:
                network_token = headers.get(b"x-msw-network-token", b"").decode("latin-1")
            else:
                network_token = self._bearer(headers)
            if not secrets.compare_digest(network_token, self.settings.api_token or ""):
                self._audit(
                    actor=None,
                    method=method,
                    path=path,
                    status_code=401,
                    client_host=client_host,
                    request_id=request_id,
                    action="access.network_token_denied",
                )
                await self._reject_http(
                    scope,
                    receive,
                    send,
                    401,
                    "LAN API 접근 토큰이 필요합니다.",
                    request_id=request_id,
                )
                return

        if not self.settings.organization_auth:
            if self.settings.lan_access and method not in {"GET", "HEAD", "OPTIONS"} and path != "/api/ws-ticket":
                admin = headers.get(b"x-msw-admin-token", b"").decode("latin-1")
                if not secrets.compare_digest(admin, self.settings.admin_token or ""):
                    await self._reject_http(
                        scope,
                        receive,
                        send,
                        403,
                        "상태 변경 API에는 별도 관리자 토큰이 필요합니다.",
                        request_id=request_id,
                    )
                    return
            await self.app(scope, receive, send_with_request_id)
            return

        if path in {"/api/auth/config", "/api/auth/login"}:
            await self.app(scope, receive, send_with_request_id)
            return
        identity = (
            self.auth_service.resolve(
                self._bearer(headers),
                client_host=client_host,
                user_agent=headers.get(b"user-agent", b"").decode("latin-1")[:1_000],
            )
            if self.auth_service
            else None
        )
        if identity is None:
            self._audit(
                actor=None,
                method=method,
                path=path,
                status_code=401,
                client_host=client_host,
                request_id=request_id,
                action="access.session_denied",
            )
            await self._reject_http(
                scope,
                receive,
                send,
                401,
                "조직 사용자 로그인이 필요합니다.",
                request_id=request_id,
            )
            return
        required = self._required_role(method, path)
        if not identity.permits(required):
            self._audit(
                actor=identity,
                method=method,
                path=path,
                status_code=403,
                client_host=client_host,
                request_id=request_id,
                action="access.role_denied",
            )
            await self._reject_http(
                scope,
                receive,
                send,
                403,
                f"이 작업에는 {required} 역할이 필요합니다.",
                request_id=request_id,
            )
            return
        scope.setdefault("state", {})["organization_actor"] = identity
        status_code = 500

        async def audited_send(message):
            nonlocal status_code
            if message.get("type") == "http.response.start":
                status_code = int(message.get("status", 500))
            await send_with_request_id(message)

        await self.app(scope, receive, audited_send)
        if method not in {"GET", "HEAD", "OPTIONS"}:
            self._audit(
                actor=identity,
                method=method,
                path=path,
                status_code=status_code,
                client_host=client_host,
                request_id=request_id,
            )


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def secured_send(message):
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {name.lower() for name, _ in headers}
                additions = [
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self' ws: wss:; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
                    (b"cache-control", b"no-store"),
                ]
                headers.extend(item for item in additions if item[0] not in existing)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, secured_send)
