from __future__ import annotations

import secrets
from urllib.parse import parse_qs

from starlette.responses import JSONResponse

from backend.app.core.config import AppSettings
from backend.app.core.targets import is_loopback_host


class ApiSecurityMiddleware:
    def __init__(self, app, settings: AppSettings):
        self.app = app
        self.settings = settings

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
        if scope_type == "websocket":
            query = parse_qs(scope.get("query_string", b"").decode("utf-8"))
            token = str((query.get("access_token") or [""])[0])
            if not secrets.compare_digest(token, self.settings.api_token or ""):
                await send({"type": "websocket.close", "code": 4401})
                return
            await self.app(scope, receive, send)
            return

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
        if method not in {"GET", "HEAD", "OPTIONS"}:
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
