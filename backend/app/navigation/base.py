from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from backend.app.devices.base import DeviceOperation

from .models import UIState


class UIDriver(ABC):
    """Capability-oriented mobile UI driver.

    Implementations execute only the fixed operations below. Planners never
    supply shell commands or unverified coordinates.
    """

    platform = "android"

    @abstractmethod
    async def dump_ui(self) -> UIState:
        raise NotImplementedError

    @abstractmethod
    async def screenshot(self, destination: Path) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def tap(self, x: int, y: int) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def long_press(
        self, x: int, y: int, duration_ms: int = 800
    ) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def input_text(self, text: str) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def back(self) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def swipe(
        self, start_x: int, start_y: int, end_x: int, end_y: int, duration_ms: int = 400
    ) -> DeviceOperation:
        raise NotImplementedError

    @abstractmethod
    async def current_package(self) -> str:
        raise NotImplementedError

    @abstractmethod
    async def current_activity(self) -> str:
        raise NotImplementedError

    @abstractmethod
    async def wait_for_idle(self, timeout_seconds: float = 5.0) -> UIState:
        raise NotImplementedError
