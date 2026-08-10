from __future__ import annotations

import asyncio
from pathlib import Path
from xml.sax.saxutils import quoteattr

from backend.app.core.status import CapabilityStatus
from backend.app.devices.base import DeviceOperation
from backend.app.devices.mock import MockDeviceAdapter

from .base import UIDriver
from .models import UIState


class MockAndroidUIDriver(UIDriver):
    """Deterministic synthetic UI graph used by the full Mock workflow."""

    def __init__(
        self,
        device_id: str = "mock-android-01",
        package_name: str = "com.example.demo",
        device_adapter: MockDeviceAdapter | None = None,
    ):
        self.device_id = device_id
        self.package_name = package_name
        self.device = device_adapter or MockDeviceAdapter()
        self._screen = "home"
        self._history: list[str] = []

    @property
    def _screens(self) -> dict[str, tuple[str, list[dict[str, str]]]]:
        return {
            "home": (
                ".MainActivity",
                [
                    self._node("계정", "account", 30, 180, 330, 250),
                    self._node("설정", "settings", 30, 270, 330, 340),
                    self._node("송금", "transfer", 30, 590, 330, 660),
                ],
            ),
            "account": (
                ".AccountActivity",
                [
                    self._node("프로필 정보", "profile_details", 30, 180, 330, 250),
                    self._node("보안 정보", "security", 30, 270, 330, 340),
                    self._node("로그아웃", "logout", 30, 590, 330, 660),
                ],
            ),
            "profile": (
                ".ProfileActivity",
                [self._node("앱 정보", "about", 30, 180, 330, 250)],
            ),
            "security": (
                ".SecurityActivity",
                [self._node("인증서 정보", "certificate", 30, 180, 330, 250)],
            ),
            "settings": (
                ".SettingsActivity",
                [self._node("도움말", "help", 30, 180, 330, 250)],
            ),
            "about": (".AboutActivity", []),
            "certificate": (".CertificateActivity", []),
            "help": (".HelpActivity", []),
        }

    def _node(
        self, text: str, resource: str, left: int, top: int, right: int, bottom: int
    ) -> dict[str, str]:
        return {
            "text": text,
            "resource-id": f"{self.package_name}:id/{resource}",
            "class": "android.widget.Button",
            "package": self.package_name,
            "content-desc": "",
            "bounds": f"[{left},{top}][{right},{bottom}]",
            "clickable": "true",
            "enabled": "true",
            "scrollable": "false",
            "password": "false",
            "selected": "false",
            "checked": "false",
        }

    def _xml(self) -> str:
        _, nodes = self._screens[self._screen]
        rendered = []
        for index, attributes in enumerate(nodes):
            values = " ".join(
                f"{name}={quoteattr(value)}"
                for name, value in {"index": str(index), **attributes}.items()
            )
            rendered.append(f"<node {values} />")
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<hierarchy rotation="0">'
            + "".join(rendered)
            + "</hierarchy>"
        )

    async def dump_ui(self) -> UIState:
        await asyncio.sleep(0.01)
        activity, _ = self._screens[self._screen]
        component = f"{self.package_name}/{activity}"
        return UIState.from_xml(
            self._xml(),
            package=self.package_name,
            activity=activity,
            window=component,
        )

    async def screenshot(self, destination: Path) -> DeviceOperation:
        return await self.device.screenshot(self.device_id, destination)

    async def tap(self, x: int, y: int) -> DeviceOperation:
        state = await self.dump_ui()
        selected = next(
            (
                item
                for item in state.elements
                if item.bounds.left <= x <= item.bounds.right
                and item.bounds.top <= y <= item.bounds.bottom
            ),
            None,
        )
        if not selected:
            return DeviceOperation(
                CapabilityStatus.FAILED,
                "Mock UI 좌표에 실행 가능한 요소가 없습니다.",
                synthetic=True,
            )
        resource = selected.resource_id.rsplit("/", 1)[-1]
        destination = {
            "account": "account",
            "settings": "settings",
            "profile_details": "profile",
            "security": "security",
            "about": "about",
            "certificate": "certificate",
            "help": "help",
        }.get(resource)
        if not destination:
            return DeviceOperation(
                CapabilityStatus.FAILED,
                "Mock 위험 동작은 자동 실행되지 않습니다.",
                command=f"mock ui tap {selected.element_id}",
                synthetic=True,
            )
        self._history.append(self._screen)
        self._screen = destination
        return DeviceOperation(
            CapabilityStatus.AVAILABLE,
            f"Mock UI에서 {selected.label} 화면으로 이동했습니다.",
            command=f"mock ui tap {selected.element_id}",
            synthetic=True,
        )

    async def long_press(
        self, x: int, y: int, duration_ms: int = 800
    ) -> DeviceOperation:
        return DeviceOperation(
            CapabilityStatus.UNSUPPORTED,
            "Mock 자동 탐색은 long press를 사용하지 않습니다.",
            synthetic=True,
        )

    async def input_text(self, text: str) -> DeviceOperation:
        return DeviceOperation(
            CapabilityStatus.MANUAL_REQUIRED,
            "로그인과 개인정보 입력은 Mock에서도 사용자 단계로 분리합니다.",
            synthetic=True,
        )

    async def back(self) -> DeviceOperation:
        if not self._history:
            return DeviceOperation(
                CapabilityStatus.AVAILABLE,
                "Mock UI 최상위 화면입니다.",
                command="mock ui back",
                synthetic=True,
            )
        self._screen = self._history.pop()
        return DeviceOperation(
            CapabilityStatus.AVAILABLE,
            "Mock UI에서 뒤로 이동했습니다.",
            command="mock ui back",
            synthetic=True,
        )

    async def swipe(
        self, start_x: int, start_y: int, end_x: int, end_y: int, duration_ms: int = 400
    ) -> DeviceOperation:
        return DeviceOperation(
            CapabilityStatus.UNSUPPORTED,
            "Mock 화면에는 스크롤 가능한 영역이 없습니다.",
            synthetic=True,
        )

    async def current_package(self) -> str:
        return self.package_name

    async def current_activity(self) -> str:
        return self._screens[self._screen][0]

    async def wait_for_idle(self, timeout_seconds: float = 5.0) -> UIState:
        await asyncio.sleep(min(max(timeout_seconds, 0.01), 0.05))
        return await self.dump_ui()
