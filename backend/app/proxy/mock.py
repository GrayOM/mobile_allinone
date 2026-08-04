from __future__ import annotations

import asyncio
import json
from pathlib import Path

from backend.app.core.status import CapabilityStatus
from backend.app.proxy.base import ProxyAdapter, ProxyCapture, ProxyFlowData
from backend.app.proxy.detection import detect_sensitive


class MockProxyAdapter(ProxyAdapter):
    name = "mock"

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self._flows: dict[str, list[ProxyFlowData]] = {}

    async def status(self) -> ProxyCapture:
        return ProxyCapture(
            CapabilityStatus.AVAILABLE,
            "Mock Proxy를 사용할 수 있습니다.",
            self.host,
            self.port,
            synthetic=True,
        )

    async def start(self, run_id: str) -> ProxyCapture:
        await asyncio.sleep(0.04)
        request_headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer mock-demo-token-not-real",
        }
        request_body = '{"email":"demo.user@example.invalid","password":"[masked]"}'
        response_headers = {
            "Content-Type": "application/json",
            "Set-Cookie": "session=mock-session-id; Secure; HttpOnly",
        }
        response_body = '{"access_token":"mock-access-token-value","expires_in":3600}'
        candidates = detect_sensitive(
            request_headers, request_body, side="request"
        ) + detect_sensitive(response_headers, response_body, side="response")
        self._flows[run_id] = [
            ProxyFlowData(
                "POST",
                "https://api.demo.invalid/v1/session",
                request_headers,
                request_body,
                200,
                response_headers,
                response_body,
                sensitive_candidates=candidates,
                source_ip="127.0.0.1",
                synthetic=True,
            ),
            ProxyFlowData(
                "GET",
                "https://api.demo.invalid/v1/profile",
                {"Authorization": "Bearer mock-demo-token-not-real"},
                "",
                200,
                {"Content-Type": "application/json"},
                '{"user_id":"demo-100","name":"Demo User"}',
                sensitive_candidates=[
                    {
                        "type": "authorization",
                        "side": "request",
                        "location": "header:authorization",
                        "masked": "Bear…real",
                    }
                ],
                source_ip="127.0.0.1",
                synthetic=True,
            ),
        ]
        return ProxyCapture(
            CapabilityStatus.AVAILABLE,
            "Mock 패킷 캡처를 시작했습니다.",
            self.host,
            self.port,
            process_id=0,
            instructions=[
                f"Mock 단말 프록시 주소를 {self.host}:{self.port}로 간주합니다.",
                "데이터 생성·수정·삭제 요청은 이 데모에서 자동 재전송하지 않습니다.",
            ],
            synthetic=True,
        )

    async def stop(self, run_id: str) -> ProxyCapture:
        return ProxyCapture(
            CapabilityStatus.AVAILABLE,
            "Mock 패킷 캡처를 종료했습니다.",
            self.host,
            self.port,
            synthetic=True,
        )

    async def read_flows(self, run_id: str) -> list[ProxyFlowData]:
        return list(self._flows.get(run_id, []))

    async def export(self, run_id: str, destination: Path) -> ProxyCapture:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(
                [flow.to_dict() for flow in await self.read_flows(run_id)],
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return ProxyCapture(
            CapabilityStatus.AVAILABLE,
            "Mock 패킷을 JSON으로 저장했습니다.",
            self.host,
            self.port,
            capture_file=str(destination),
            synthetic=True,
        )
