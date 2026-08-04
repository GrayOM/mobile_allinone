from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from backend.app.core.config import ROOT_DIR, AppSettings, get_settings
from backend.app.core.status import CapabilityStatus
from backend.app.core.process import subprocess_group_options, terminate_process_tree
from backend.app.proxy.base import ProxyAdapter, ProxyCapture, ProxyFlowData
from backend.app.proxy.detection import detect_sensitive


class MitmProxyAdapter(ProxyAdapter):
    name = "mitmproxy"

    def __init__(
        self,
        settings: AppSettings | None = None,
        host: str = "127.0.0.1",
        port: int = 8080,
        allowed_client_ip: str | None = None,
    ):
        self.settings = settings or get_settings()
        self.host = host
        self.port = port
        self.allowed_client_ip = allowed_client_ip
        self.mitmdump = self.settings.resolved_tool("mitmdump")
        self.capture_dir = self.settings.data_dir / "proxy"
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self._processes: dict[str, asyncio.subprocess.Process] = {}

    def _path(self, run_id: str) -> Path:
        return self.capture_dir / f"{run_id}.jsonl"

    async def status(self) -> ProxyCapture:
        if not self.mitmdump:
            return ProxyCapture(
                CapabilityStatus.NOT_CONFIGURED,
                "mitmdump를 찾을 수 없습니다. `py -m pip install mitmproxy` 후 경로를 설정하세요.",
                self.host,
                self.port,
                instructions=[
                    "mitmproxy 설치 후 설정 화면에서 mitmdump.exe 경로를 지정합니다.",
                    f"단말 프록시는 PC IP:{self.port}로 설정합니다.",
                ],
            )
        return ProxyCapture(
            CapabilityStatus.AVAILABLE,
            "mitmproxy 캡처를 시작할 수 있습니다.",
            self.host,
            self.port,
        )

    async def start(self, run_id: str) -> ProxyCapture:
        current = self._processes.get(run_id)
        if current and current.returncode is None:
            return ProxyCapture(
                CapabilityStatus.AVAILABLE,
                "mitmproxy 캡처가 이미 실행 중입니다.",
                self.host,
                self.port,
                str(self._path(run_id)),
                current.pid,
            )
        if not self.mitmdump:
            return await self.status()
        capture_path = self._path(run_id)
        capture_path.unlink(missing_ok=True)
        env = os.environ.copy()
        env["MSW_MITM_OUTPUT"] = str(capture_path)
        if self.allowed_client_ip:
            env["MSW_MITM_ALLOWED_CLIENT_IP"] = self.allowed_client_ip
        addon = ROOT_DIR / "scripts" / "mitm_capture_addon.py"
        process = await asyncio.create_subprocess_exec(
            self.mitmdump,
            "--listen-host",
            self.host,
            "--listen-port",
            str(self.port),
            "-s",
            str(addon),
            "--set",
            "block_global=true",
            env=env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            **subprocess_group_options(),
        )
        # Register before the readiness wait so cancellation during startup can still
        # find and terminate the process in the orchestrator's finally block.
        self._processes[run_id] = process
        ready = False
        for _ in range(15):
            await asyncio.sleep(0.1)
            if process.returncode is not None:
                break
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port), timeout=0.2
                )
                writer.close()
                await writer.wait_closed()
                ready = True
                break
            except (OSError, asyncio.TimeoutError):
                continue
        if process.returncode is not None or not ready:
            self._processes.pop(run_id, None)
            if process.returncode is None:
                await terminate_process_tree(process)
            return ProxyCapture(
                CapabilityStatus.FAILED,
                (
                    f"mitmdump Listener 준비 실패(exit={process.returncode}). "
                    "포트 바인딩과 설치 상태를 확인하세요."
                ),
                self.host,
                self.port,
            )
        return ProxyCapture(
            CapabilityStatus.AVAILABLE,
            "mitmproxy 패킷 캡처를 시작했습니다.",
            self.host,
            self.port,
            str(capture_path),
            process.pid,
            [
                f"단말 프록시를 Windows PC의 LAN IP:{self.port}로 설정합니다.",
                "단말에서 http://mitm.it 에 접속해 승인된 테스트 CA를 설치할 수 있습니다.",
                "앱의 인증서 고정이 있으면 보안통제 우회 내성 검증에서 별도로 확인합니다.",
            ],
            allowed_client_ip=self.allowed_client_ip,
        )

    async def stop(self, run_id: str) -> ProxyCapture:
        process = self._processes.pop(run_id, None)
        if process and process.returncode is None:
            await terminate_process_tree(process)
        return ProxyCapture(
            CapabilityStatus.AVAILABLE,
            "mitmproxy 캡처를 종료했습니다.",
            self.host,
            self.port,
            str(self._path(run_id)),
        )

    async def read_flows(self, run_id: str) -> list[ProxyFlowData]:
        path = self._path(run_id)
        if not path.is_file():
            return []
        flows: list[ProxyFlowData] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                item = json.loads(line)
                request_headers = item.get("request_headers", {})
                response_headers = item.get("response_headers", {})
                request_body = item.get("request_body", "")
                response_body = item.get("response_body", "")
                flows.append(
                    ProxyFlowData(
                        method=item.get("method", "GET"),
                        url=item.get("url", ""),
                        request_headers=request_headers,
                        request_body=request_body,
                        status_code=item.get("status_code"),
                        response_headers=response_headers,
                        response_body=response_body,
                        sensitive_candidates=detect_sensitive(
                            request_headers, request_body, side="request"
                        )
                        + detect_sensitive(
                            response_headers, response_body, side="response"
                        ),
                        source_ip=item.get("source_ip"),
                    )
                )
            except (json.JSONDecodeError, TypeError):
                continue
        return flows

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
            "mitmproxy 흐름을 JSON으로 저장했습니다.",
            self.host,
            self.port,
            str(destination),
        )
