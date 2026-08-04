from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
from dataclasses import dataclass
from urllib.parse import parse_qs

from starlette.responses import JSONResponse

from backend.app.core.config import AppSettings
from backend.app.core.targets import is_loopback_host


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
    ):
        self.app = app
        self.settings = settings
        self.ticket_store = ticket_store or WebSocketTicketStore()

    @staticmethod
    def _headers(scope) -> dict[bytes, bytes]:
        return {key.lower(): value for key, value in scope.get("headers", [])}

    @staticmethod
    def _bearer(headers: dict[bytes, bytes]) -> str:
        value = headers.get(b"authorization", b"").decode("latin-1")
        scheme, _, token = value.partition(" ")
        return token if scheme.lower() == "bearer" else ""

    async def _reject_http(self, scope, receive, send, status: int, detail: str):
        response = JSONResponse({"detail": detail}, status_code=status)
        await response(scope, receive, send)

    async def __call__(self, scope, receive, send):
        scope_type = scope.get("type")
        path = str(scope.get("path") or "")
        if scope_type not in {"http", "websocket"} or not path.startswith("/api"):
            await self.app(scope, receive, send)
            return

        server_host = str((scope.get("server") or ("", 0))[0])
        if scope_type == "websocket":
            if not self.settings.lan_access and not is_loopback_host(server_host):
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

        if not self.settings.lan_access:
            if is_loopback_host(server_host):
                await self.app(scope, receive, send)
                return
            if scope_type == "websocket":
                await send({"type": "websocket.close", "code": 4403})
            else:
                await self._reject_http(
                    scope,
                    receive,
                    send,
                    403,
                    "서버가 loopback 모드이므로 외부 주소의 API 요청을 거부했습니다.",
                )
            return

        headers = self._headers(scope)
        if str(scope.get("method") or "").upper() == "OPTIONS":
            await self.app(scope, receive, send)
            return
        if not secrets.compare_digest(
            self._bearer(headers), self.settings.api_token or ""
        ):
            await self._reject_http(
                scope, receive, send, 401, "LAN API 접근 토큰이 필요합니다."
            )
            return
        method = str(scope.get("method") or "GET").upper()
        if method not in {"GET", "HEAD", "OPTIONS"} and path != "/api/ws-ticket":
            admin = headers.get(b"x-msw-admin-token", b"").decode("latin-1")
            if not secrets.compare_digest(admin, self.settings.admin_token or ""):
                await self._reject_http(
                    scope,
                    receive,
                    send,
                    403,
                    "상태 변경 API에는 별도 관리자 토큰이 필요합니다.",
                )
                return
        await self.app(scope, receive, send)
