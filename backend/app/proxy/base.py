from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.app.core.status import CapabilityStatus


@dataclass(slots=True)
class ProxyFlowData:
    method: str
    url: str
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    status_code: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    captured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sensitive_candidates: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["captured_at"] = self.captured_at.isoformat()
        return result


@dataclass(slots=True)
class ProxyCapture:
    status: CapabilityStatus
    message: str
    host: str
    port: int
    capture_file: str | None = None
    process_id: int | None = None
    instructions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        return result


class ProxyAdapter(ABC):
    name: str

    @abstractmethod
    async def status(self) -> ProxyCapture:
        raise NotImplementedError

    @abstractmethod
    async def start(self, run_id: str) -> ProxyCapture:
        raise NotImplementedError

    @abstractmethod
    async def stop(self, run_id: str) -> ProxyCapture:
        raise NotImplementedError

    @abstractmethod
    async def read_flows(self, run_id: str) -> list[ProxyFlowData]:
        raise NotImplementedError

    @abstractmethod
    async def export(self, run_id: str, destination: Path) -> ProxyCapture:
        raise NotImplementedError

