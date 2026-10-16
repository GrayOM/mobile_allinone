from __future__ import annotations

from pathlib import Path

from backend.app.core.status import CapabilityStatus
from backend.app.proxy.base import ProxyAdapter, ProxyCapture, ProxyFlowData


class DisabledProxyAdapter(ProxyAdapter):
    """Explicit device-only diagnostic mode.

    This adapter is intentionally different from MockProxyAdapter: it never
    creates synthetic traffic and records that network capture was outside the
    selected Run scope.
    """

    name = "none"

    async def status(self) -> ProxyCapture:
        return ProxyCapture(
            CapabilityStatus.AVAILABLE,
            "단말 전용 진단으로 네트워크 캡처를 실행하지 않습니다.",
            "127.0.0.1",
            0,
        )

    async def start(self, run_id: str) -> ProxyCapture:
        return await self.status()

    async def stop(self, run_id: str) -> ProxyCapture:
        return await self.status()

    async def read_flows(self, run_id: str) -> list[ProxyFlowData]:
        return []

    async def export(self, run_id: str, destination: Path) -> ProxyCapture:
        return await self.status()
