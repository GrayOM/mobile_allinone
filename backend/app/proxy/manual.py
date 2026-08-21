from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit

from backend.app.core.config import AppSettings, get_settings
from backend.app.core.process import subprocess_group_options, terminate_process_tree
from backend.app.core.status import CapabilityStatus
from backend.app.proxy.base import ProxyAdapter, ProxyCapture, ProxyFlowData
from backend.app.proxy.detection import detect_sensitive


class ManualProxyAdapter(ProxyAdapter):
    product_name = "Proxy"

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        *,
        settings: AppSettings | None = None,
    ):
        self.host = host
        self.port = port
        self.settings = settings or get_settings()
        self._imports: dict[str, list[ProxyFlowData]] = {}
        self._processes: dict[str, asyncio.subprocess.Process] = {}

    @property
    def executable(self) -> str | None:
        return self.settings.resolved_tool(self.name)

    def _instructions(self) -> list[str]:
        return [
            f"{self.product_name} 리스너를 {self.host}:{self.port}에 설정합니다.",
            "단말과 PC가 통신 가능한지 확인하고 단말 Wi-Fi 프록시를 같은 주소로 설정합니다.",
            "HTTPS 진단은 권한을 받은 단말에만 CA 인증서를 설치합니다.",
            "캡처를 HAR 또는 JSON으로 내보낸 뒤 이 작업대에 가져옵니다.",
            "POST·PUT·PATCH·DELETE 재전송은 화면에서 승인한 경우에만 수행합니다.",
        ]

    async def status(self) -> ProxyCapture:
        executable = self.executable
        return ProxyCapture(
            CapabilityStatus.MANUAL_REQUIRED,
            (
                f"{self.product_name} 실행 파일이 확인되었습니다. 작업대에서 세션 프로세스를 시작할 수 있지만 리스너 확인과 캡처 반입은 수동입니다."
                if executable
                else f"{self.product_name} 실행 파일을 설정하면 세션 기동·종료를 제어할 수 있습니다. 현재는 완전 수동 연동입니다."
            ),
            self.host,
            self.port,
            instructions=self._instructions(),
        )

    async def start(self, run_id: str) -> ProxyCapture:
        existing = self._processes.get(run_id)
        if existing and existing.returncode is None:
            status = await self.status()
            status.process_id = existing.pid
            status.message = f"{self.product_name} 세션 프로세스가 이미 실행 중입니다. 리스너 설정을 확인하세요."
            return status
        executable = self.executable
        if not executable:
            return await self.status()
        try:
            process = await asyncio.create_subprocess_exec(
                executable,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                **subprocess_group_options(),
            )
        except OSError as exc:
            return ProxyCapture(
                CapabilityStatus.FAILED,
                f"{self.product_name} 세션 프로세스를 시작하지 못했습니다: {type(exc).__name__}",
                self.host,
                self.port,
                instructions=self._instructions(),
            )
        self._processes[run_id] = process
        await asyncio.sleep(0.1)
        if process.returncode is not None:
            self._processes.pop(run_id, None)
            return ProxyCapture(
                CapabilityStatus.MANUAL_REQUIRED,
                f"{self.product_name} 실행기가 종료되었습니다. 제품 창과 리스너 상태를 직접 확인하세요.",
                self.host,
                self.port,
                instructions=self._instructions(),
            )
        return ProxyCapture(
            CapabilityStatus.MANUAL_REQUIRED,
            f"{self.product_name} 세션 프로세스를 시작했습니다. 리스너·단말 프록시 설정 확인 후 계속하세요.",
            self.host,
            self.port,
            process_id=process.pid,
            instructions=self._instructions(),
        )

    async def stop(self, run_id: str) -> ProxyCapture:
        process = self._processes.pop(run_id, None)
        if process and process.returncode is None:
            await terminate_process_tree(process)
            return ProxyCapture(
                CapabilityStatus.AVAILABLE,
                f"작업대가 시작한 {self.product_name} 세션 프로세스를 종료했습니다.",
                self.host,
                self.port,
                process_id=process.pid,
            )
        return ProxyCapture(
            CapabilityStatus.MANUAL_REQUIRED,
            f"작업대가 관리하는 {self.product_name} 프로세스가 없습니다. 제품에서 캡처를 직접 중지하세요.",
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
        if isinstance(data, dict):
            entries = data.get("log", {}).get("entries")
            if not isinstance(entries, list):
                raise ValueError("HAR log.entries 배열이 필요합니다.")
            source = "har"
        elif isinstance(data, list):
            entries = data
            source = "json"
        else:
            raise ValueError("HAR 객체 또는 Proxy Flow JSON 배열이 필요합니다.")
        if len(entries) > 10_000:
            raise ValueError("프록시 흐름은 한 번에 최대 10,000개까지 가져올 수 있습니다.")
        flows: list[ProxyFlowData] = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("각 프록시 흐름은 JSON 객체여야 합니다.")
            if source == "har":
                request = entry.get("request", {})
                response = entry.get("response", {})
                request_headers = self._headers(request.get("headers", []))
                response_headers = self._headers(response.get("headers", []))
                request_body = str(request.get("postData", {}).get("text", ""))
                response_body = str(response.get("content", {}).get("text", ""))
                method = str(request.get("method", "GET"))
                url = str(request.get("url", ""))
                status = response.get("status")
            else:
                request_headers = self._header_object(entry.get("request_headers", {}))
                response_headers = self._header_object(entry.get("response_headers", {}))
                request_body = str(entry.get("request_body", ""))
                response_body = str(entry.get("response_body", ""))
                method = str(entry.get("method", "GET"))
                url = str(entry.get("url", ""))
                status = entry.get("status_code")
            method = method.upper()
            if not method.isalpha() or len(method) > 16:
                raise ValueError("HTTP Method 형식이 올바르지 않습니다.")
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or len(url) > 8192:
                raise ValueError("프록시 URL은 길이가 제한된 http/https 주소여야 합니다.")
            if len(request_body.encode("utf-8")) > 1024 * 1024 or len(response_body.encode("utf-8")) > 1024 * 1024:
                raise ValueError("프록시 흐름 본문은 요청·응답 각각 최대 1MB입니다.")
            if status is not None:
                status = int(status)
                if not 100 <= status <= 599:
                    raise ValueError("HTTP 응답 상태 코드가 올바르지 않습니다.")
            candidates = detect_sensitive(
                request_headers, request_body, side="request"
            ) + detect_sensitive(response_headers, response_body, side="response")
            flows.append(
                ProxyFlowData(
                    method,
                    url,
                    request_headers,
                    request_body,
                    status,
                    response_headers,
                    response_body,
                    sensitive_candidates=candidates,
                )
            )
        self._imports[run_id] = flows
        return flows

    @staticmethod
    def _headers(value) -> dict[str, str]:
        if not isinstance(value, list) or len(value) > 200:
            raise ValueError("HAR Header 배열은 최대 200개여야 합니다.")
        result: dict[str, str] = {}
        for item in value:
            if not isinstance(item, dict):
                raise ValueError("HAR Header 항목은 객체여야 합니다.")
            name = str(item.get("name", ""))[:200]
            header_value = str(item.get("value", ""))[:16_384]
            if name:
                result[name] = header_value
        return result

    @staticmethod
    def _header_object(value) -> dict[str, str]:
        if not isinstance(value, dict) or len(value) > 200:
            raise ValueError("Header 객체는 최대 200개 항목이어야 합니다.")
        return {str(key)[:200]: str(item)[:16_384] for key, item in value.items()}


class FiddlerProxyAdapter(ManualProxyAdapter):
    name = "fiddler"
    product_name = "Fiddler"


class BurpProxyAdapter(ManualProxyAdapter):
    name = "burp"
    product_name = "Burp Suite"
