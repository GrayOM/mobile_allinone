from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any

from backend.app.core.status import CapabilityStatus


@dataclass(slots=True)
class RuntimeOperation:
    status: CapabilityStatus
    tool: str
    action: str
    risk: str
    message: str
    command: str | None = None
    output: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        return value


class RuntimeToolAdapter(ABC):
    name: str

    @abstractmethod
    async def health(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def execute(
        self,
        *,
        device_id: str,
        target: str,
        action: str,
        arguments: dict[str, Any] | None = None,
        approved: bool = False,
    ) -> RuntimeOperation:
        raise NotImplementedError

