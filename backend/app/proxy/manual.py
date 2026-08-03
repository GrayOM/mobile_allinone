from __future__ import annotations

import json
from pathlib import Path

from backend.app.core.status import CapabilityStatus
from backend.app.proxy.base import ProxyAdapter, ProxyCapture, ProxyFlowData
from backend.app.proxy.detection import detect_sensitive


class ManualProxyAdapter(ProxyAdapter):
    product_name = "Proxy"

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self._imports: dict[str, list[ProxyFlowData]] = {}

    def _instructions(self) -> list[str]:
        return [
            f"{self.product_name} 리스너를 {self.host}:{self.port}에 설정합니다.",
            "단말과 PC가 통신 가능한지 확인하고 단말 Wi-Fi 프록시를 같은 주소로 설정합니다.",
            "HTTPS 진단은 권한을 받은 단말에만 CA 인증서를 설치합니다.",
            "캡처를 HAR 또는 JSON으로 내보낸 뒤 이 작업대에 가져옵니다.",
            "POST·PUT·PATCH·DELETE 재전송은 화면에서 승인한 경우에만 수행합니다.",
        ]

    async def status(self) -> ProxyCapture:
        return ProxyCapture(
            CapabilityStatus.MANUAL_REQUIRED,
            f"{self.product_name}는 수동 연동 설정이 필요합니다.",
            self.host,
            self.port,
            instructions=self._instructions(),
        )

    async def start(self, run_id: str) -> ProxyCapture:
        return await self.status()

    async def stop(self, run_id: str) -> ProxyCapture:
        return ProxyCapture(
            CapabilityStatus.MANUAL_REQUIRED,
            f"{self.product_name}에서 캡처를 수동으로 중지하세요.",
            self.host,
            self.port,
        )

    async def read_flows(self, run_id: str) -> list[ProxyFlowData]:
        return self._imports.get(run_id, [])

    async def export(self, run_id: str, destination: Path) -> ProxyCapture:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(
                [item.to_dict() for item in await self.read_flows(run_id)],
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        return ProxyCapture(
            CapabilityStatus.AVAILABLE,
            "가져온 흐름을 JSON으로 저장했습니다.",
            self.host,
            self.port,
            capture_file=str(destination),
        )

    def import_har(self, run_id: str, path: Path) -> list[ProxyFlowData]:
        data = json.loads(path.read_text(encoding="utf-8"))
        entries = data.get("log", {}).get("entries", [])
        flows: list[ProxyFlowData] = []
        for entry in entries:
            request = entry.get("request", {})
            response = entry.get("response", {})
            request_headers = {
                item.get("name", ""): item.get("value", "")
                for item in request.get("headers", [])
            }
            response_headers = {
                item.get("name", ""): item.get("value", "")
                for item in response.get("headers", [])
            }
            request_body = request.get("postData", {}).get("text", "")
            response_body = response.get("content", {}).get("text", "")
            candidates = detect_sensitive(
                request_headers, request_body, side="request"
            ) + detect_sensitive(response_headers, response_body, side="response")
            flows.append(
                ProxyFlowData(
                    request.get("method", "GET"),
                    request.get("url", ""),
                    request_headers,
                    request_body,
                    response.get("status"),
                    response_headers,
                    response_body,
                    sensitive_candidates=candidates,
                )
            )
        self._imports[run_id] = flows
        return flows


class FiddlerProxyAdapter(ManualProxyAdapter):
    name = "fiddler"
    product_name = "Fiddler"


class BurpProxyAdapter(ManualProxyAdapter):
    name = "burp"
    product_name = "Burp Suite"

