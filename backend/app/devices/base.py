from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from backend.app.core.status import CapabilityStatus, Platform


@dataclass(slots=True)
class DeviceInfo:
    id: str
    platform: Platform
    model: str
    os_version: str
    architecture: str
    connection: str
    privileged: bool | None
    frida_status: CapabilityStatus
    proxy_status: CapabilityStatus
    availability: CapabilityStatus
    capabilities: list[str] = field(default_factory=list)
    adapter: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    synthetic: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["platform"] = self.platform.value
        data["frida_status"] = self.frida_status.value
        data["proxy_status"] = self.proxy_status.value
        data["availability"] = self.availability.value
        return data


@dataclass(slots=True)
class DeviceOperation:
    status: CapabilityStatus
    message: str
    command: str | None = None
    output: str = ""
    file_path: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    synthetic: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


class DeviceAdapter(ABC):
    name: str

    @abstractmethod
    async def discover(self) -> list[DeviceInfo]:
        raise NotImplementedError

    @abstractmethod
    async def list_packages(self, device_id: str) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def install_app(self, device_id: str, app_path: Path) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def uninstall_app(self, device_id: str, package_name: str) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def start_app(self, device_id: str, package_name: str) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def stop_app(self, device_id: str, package_name: str) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def screenshot(self, device_id: str, destination: Path) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def start_screen_recording(
        self, device_id: str, destination: Path, duration_seconds: int = 15
    ) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def collect_logs(
        self, device_id: str, destination: Path, duration_seconds: int = 5
    ) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def pull_file(
        self, device_id: str, remote_path: str, destination: Path
    ) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def process_info(self, device_id: str, package_name: str) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def frida_status(self, device_id: str) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def forward_port(
        self, device_id: str, local_port: int, remote_port: int
    ) -> DeviceOperation:
        raise NotImplementedError
