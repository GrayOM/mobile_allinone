from __future__ import annotations

import asyncio
import re
from pathlib import Path

from backend.app.core.command import CommandResult, run_command
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus
from backend.app.devices.android import AndroidDeviceAdapter
from backend.app.devices.base import DeviceOperation

from .base import UIDriver
from .models import UIState


FOCUS_PATTERNS = (
    re.compile(r"mCurrentFocus=.*?\s([A-Za-z0-9._]+/[A-Za-z0-9.$_]+)"),
    re.compile(r"mFocusedApp=.*?\s([A-Za-z0-9._]+/[A-Za-z0-9.$_]+)"),
    re.compile(r"topResumedActivity=.*?\s([A-Za-z0-9._]+/[A-Za-z0-9.$_]+)"),
)


class AndroidADBUIDriver(UIDriver):
    """Serverless Android UI driver using ADB and UIAutomator XML."""

    def __init__(
        self,
        device_id: str,
        *,
        settings: AppSettings | None = None,
        device_adapter: AndroidDeviceAdapter | None = None,
    ):
        self.settings = settings or get_settings()
        self.device_id = device_id
        self.device = device_adapter or AndroidDeviceAdapter(self.settings)
        self.adb = self.device.adb

    def _missing(self) -> DeviceOperation:
        return DeviceOperation(
            CapabilityStatus.NOT_CONFIGURED,
            "ADB를 찾을 수 없어 UI 자동 탐색을 시작할 수 없습니다.",
        )

    async def _adb(self, *args: str, timeout: int | None = None) -> CommandResult | None:
        if not self.adb:
            return None
        return await run_command(
            [self.adb, "-s", self.device_id, *args],
            timeout=timeout or self.settings.command_timeout_seconds,
        )

    @staticmethod
    def _operation(result: CommandResult | None, success: str) -> DeviceOperation:
        if result is None:
            return DeviceOperation(
                CapabilityStatus.NOT_CONFIGURED, "ADB 실행 파일이 설정되지 않았습니다."
            )
        return DeviceOperation(
            result.status,
            success if result.ok else (result.error or result.stderr.strip() or "ADB UI 명령 실패"),
            command=result.display_command,
            output=result.stdout or result.stderr,
        )

    async def _focused_component(self) -> str:
        result = await self._adb("shell", "dumpsys", "window", "windows", timeout=15)
        if not result or not result.ok:
            fallback = await self._adb(
                "shell", "dumpsys", "activity", "activities", timeout=15
            )
            result = fallback if fallback and fallback.ok else result
        output = result.stdout if result and result.ok else ""
        for pattern in FOCUS_PATTERNS:
            match = pattern.search(output)
            if match:
                return match.group(1)
        return ""

    async def dump_ui(self) -> UIState:
        if not self.adb:
            raise RuntimeError(self._missing().message)
        remote_path = "/sdcard/msw-window.xml"
        dumped = await self._adb(
            "shell", "uiautomator", "dump", "--compressed", remote_path, timeout=20
        )
        if not dumped or not dumped.ok:
            message = dumped.error if dumped else self._missing().message
            raise RuntimeError(f"UIAutomator hierarchy dump failed: {message}")
        fetched = await self._adb("exec-out", "cat", remote_path, timeout=20)
        await self._adb("shell", "rm", "-f", remote_path, timeout=10)
        if not fetched or not fetched.ok:
            message = fetched.error if fetched else self._missing().message
            raise RuntimeError(f"UIAutomator hierarchy read failed: {message}")
        raw_xml = fetched.stdout
        xml_start = raw_xml.find("<?xml")
        xml_end = raw_xml.rfind("</hierarchy>")
        if xml_start < 0 or xml_end < xml_start:
            raise RuntimeError("UIAutomator output did not contain a hierarchy XML document")
        raw_xml = raw_xml[xml_start : xml_end + len("</hierarchy>")]
        component = await self._focused_component()
        package, _, activity = component.partition("/")
        return UIState.from_xml(
            raw_xml,
            package=package,
            activity=activity,
            window=component,
        )

    async def screenshot(self, destination: Path) -> DeviceOperation:
        return await self.device.screenshot(self.device_id, destination)

    @staticmethod
    def _valid_coordinate(value: int) -> bool:
        return 0 <= value <= 20_000

    async def tap(self, x: int, y: int) -> DeviceOperation:
        if not self._valid_coordinate(x) or not self._valid_coordinate(y):
            return DeviceOperation(CapabilityStatus.FAILED, "화면 좌표 범위를 벗어났습니다.")
        result = await self._adb("shell", "input", "tap", str(x), str(y), timeout=15)
        return self._operation(result, "UI 요소를 탭했습니다.")

    async def long_press(
        self, x: int, y: int, duration_ms: int = 800
    ) -> DeviceOperation:
        if not self._valid_coordinate(x) or not self._valid_coordinate(y):
            return DeviceOperation(CapabilityStatus.FAILED, "화면 좌표 범위를 벗어났습니다.")
        duration = min(max(int(duration_ms), 300), 3000)
        result = await self._adb(
            "shell", "input", "swipe", str(x), str(y), str(x), str(y), str(duration), timeout=15
        )
        return self._operation(result, "UI 요소를 길게 눌렀습니다.")

    async def input_text(self, text: str) -> DeviceOperation:
        if len(text) > 512 or not re.fullmatch(r"[A-Za-z0-9@._+\- ]*", text):
            return DeviceOperation(
                CapabilityStatus.FAILED,
                "ADB 자동 입력은 512자 이하의 제한된 안전 문자만 허용합니다.",
            )
        encoded = text.replace(" ", "%s")
        result = await self._adb("shell", "input", "text", encoded, timeout=15)
        return self._operation(result, "텍스트를 입력했습니다.")

    async def back(self) -> DeviceOperation:
        result = await self._adb("shell", "input", "keyevent", "KEYCODE_BACK", timeout=15)
        return self._operation(result, "뒤로 이동했습니다.")

    async def swipe(
        self, start_x: int, start_y: int, end_x: int, end_y: int, duration_ms: int = 400
    ) -> DeviceOperation:
        coordinates = (start_x, start_y, end_x, end_y)
        if not all(self._valid_coordinate(value) for value in coordinates):
            return DeviceOperation(CapabilityStatus.FAILED, "화면 좌표 범위를 벗어났습니다.")
        duration = min(max(int(duration_ms), 100), 3000)
        result = await self._adb(
            "shell",
            "input",
            "swipe",
            *(str(value) for value in coordinates),
            str(duration),
            timeout=15,
        )
        return self._operation(result, "화면을 스와이프했습니다.")

    async def current_package(self) -> str:
        return (await self._focused_component()).partition("/")[0]

    async def current_activity(self) -> str:
        return (await self._focused_component()).partition("/")[2]

    async def wait_for_idle(self, timeout_seconds: float = 5.0) -> UIState:
        deadline = asyncio.get_running_loop().time() + min(max(timeout_seconds, 0.5), 30.0)
        previous: UIState | None = None
        latest: UIState | None = None
        while asyncio.get_running_loop().time() < deadline:
            latest = await self.dump_ui()
            if previous and previous.fingerprint == latest.fingerprint:
                return latest
            previous = latest
            await asyncio.sleep(0.25)
        if latest:
            return latest
        raise RuntimeError("UI가 idle 상태에 도달하지 못했습니다.")
