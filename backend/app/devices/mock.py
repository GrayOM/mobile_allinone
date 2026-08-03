from __future__ import annotations

import asyncio
import binascii
import json
import struct
import zlib
from pathlib import Path

from backend.app.core.status import CapabilityStatus, Platform
from backend.app.devices.base import DeviceAdapter, DeviceInfo, DeviceOperation


def _mock_screen_png() -> bytes:
    """Create a deterministic 360x720 diagnostic app screen with stdlib only."""
    width, height = 360, 720
    pixels = bytearray((238, 243, 241) * width * height)

    def rectangle(x: int, y: int, w: int, h: int, color: tuple[int, int, int]) -> None:
        x2, y2 = min(width, x + w), min(height, y + h)
        row = bytes(color) * max(0, x2 - x)
        for current_y in range(max(0, y), y2):
            start = (current_y * width + max(0, x)) * 3
            pixels[start : start + len(row)] = row

    # App chrome, security banner, two content cards and a deliberate action button.
    rectangle(0, 0, width, 34, (11, 32, 39))
    rectangle(0, 34, width, 78, (16, 42, 50))
    rectangle(18, 58, 9, 31, (223, 107, 53))
    rectangle(42, 59, 160, 8, (245, 249, 248))
    rectangle(42, 75, 108, 5, (123, 151, 155))
    rectangle(18, 132, 324, 70, (216, 238, 235))
    rectangle(31, 150, 22, 22, (12, 133, 128))
    rectangle(69, 149, 190, 7, (16, 42, 50))
    rectangle(69, 164, 238, 5, (88, 112, 120))
    rectangle(18, 222, 324, 176, (255, 255, 255))
    rectangle(34, 244, 98, 10, (16, 42, 50))
    rectangle(34, 266, 270, 5, (184, 199, 200))
    rectangle(34, 280, 238, 5, (214, 223, 222))
    rectangle(34, 310, 292, 54, (237, 242, 241))
    rectangle(51, 326, 36, 20, (12, 133, 128))
    rectangle(102, 326, 178, 6, (43, 81, 89))
    rectangle(102, 340, 124, 5, (160, 176, 178))
    rectangle(18, 418, 324, 184, (255, 255, 255))
    rectangle(34, 441, 122, 10, (16, 42, 50))
    for offset in range(4):
        rectangle(34, 470 + offset * 24, 12, 12, (12, 133, 128))
        rectangle(60, 472 + offset * 24, 224 - offset * 18, 6, (117, 139, 143))
    rectangle(34, 565, 292, 2, (216, 224, 223))
    rectangle(18, 628, 324, 54, (223, 107, 53))
    rectangle(118, 649, 124, 8, (255, 255, 255))
    rectangle(0, 704, width, 16, (16, 42, 50))

    raw = b"".join(
        b"\x00" + bytes(pixels[row * width * 3 : (row + 1) * width * 3])
        for row in range(height)
    )

    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


MOCK_SCREEN_PNG = _mock_screen_png()


class MockDeviceAdapter(DeviceAdapter):
    name = "mock"

    def __init__(self, platform: Platform = Platform.MOCK_ANDROID):
        self.platform = platform
        self.started_packages: set[str] = set()

    async def _delay(self) -> None:
        await asyncio.sleep(0.04)

    async def discover(self) -> list[DeviceInfo]:
        await self._delay()
        is_ios = self.platform == Platform.MOCK_IOS
        return [
            DeviceInfo(
                id="mock-ios-01" if is_ios else "mock-android-01",
                platform=self.platform,
                model="iPhone Mock Lab" if is_ios else "Pixel Mock Lab",
                os_version="17.5" if is_ios else "14",
                architecture="arm64-v8a",
                connection="virtual",
                privileged=True,
                frida_status=CapabilityStatus.AVAILABLE,
                proxy_status=CapabilityStatus.AVAILABLE,
                availability=CapabilityStatus.AVAILABLE,
                capabilities=[
                    "packages",
                    "install",
                    "uninstall",
                    "launch",
                    "screenshot",
                    "screen_record",
                    "logs",
                    "pull_file",
                    "process",
                    "frida_status",
                    "port_forward",
                ],
                adapter=self.name,
                details={"demo": True, "safe": True},
            )
        ]

    async def list_packages(self, device_id: str) -> DeviceOperation:
        await self._delay()
        return DeviceOperation(
            CapabilityStatus.AVAILABLE,
            "Mock 앱 목록을 조회했습니다.",
            data={"packages": ["com.example.demo", "com.example.securebank"]},
        )

    async def install_app(self, device_id: str, app_path: Path) -> DeviceOperation:
        await self._delay()
        return DeviceOperation(
            CapabilityStatus.AVAILABLE,
            f"Mock 단말에 {app_path.name} 설치를 모의했습니다.",
            command=f"mock install {app_path.name}",
        )

    async def uninstall_app(self, device_id: str, package_name: str) -> DeviceOperation:
        await self._delay()
        return DeviceOperation(CapabilityStatus.AVAILABLE, "Mock 앱을 삭제했습니다.")

    async def start_app(self, device_id: str, package_name: str) -> DeviceOperation:
        await self._delay()
        self.started_packages.add(package_name)
        return DeviceOperation(
            CapabilityStatus.AVAILABLE,
            "Mock 앱을 실행했습니다.",
            command=f"mock launch {package_name}",
            output="ActivityTaskManager: Displayed com.example.demo/.MainActivity",
        )

    async def stop_app(self, device_id: str, package_name: str) -> DeviceOperation:
        await self._delay()
        self.started_packages.discard(package_name)
        return DeviceOperation(CapabilityStatus.AVAILABLE, "Mock 앱을 종료했습니다.")

    async def screenshot(self, device_id: str, destination: Path) -> DeviceOperation:
        await self._delay()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(MOCK_SCREEN_PNG)
        return DeviceOperation(
            CapabilityStatus.AVAILABLE,
            "Mock 화면을 캡처했습니다.",
            command="mock screencap",
            file_path=str(destination),
        )

    async def start_screen_recording(
        self, device_id: str, destination: Path, duration_seconds: int = 15
    ) -> DeviceOperation:
        await self._delay()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"MOCK_MP4_EVIDENCE")
        return DeviceOperation(
            CapabilityStatus.AVAILABLE,
            "Mock 화면 녹화를 생성했습니다.",
            file_path=str(destination),
        )

    async def collect_logs(
        self, device_id: str, destination: Path, duration_seconds: int = 5
    ) -> DeviceOperation:
        await self._delay()
        destination.parent.mkdir(parents=True, exist_ok=True)
        log = (
            "07-30 10:00:01.010 I ActivityTaskManager: START com.example.demo/.MainActivity\n"
            "07-30 10:00:01.310 W SecurityControl: emulator signal observed; continuing demo\n"
            "07-30 10:00:02.120 I NetworkClient: POST https://api.demo.invalid/session\n"
        )
        destination.write_text(log, encoding="utf-8")
        return DeviceOperation(
            CapabilityStatus.AVAILABLE,
            "Mock Logcat을 수집했습니다.",
            command="mock logcat",
            output=log,
            file_path=str(destination),
        )

    async def pull_file(
        self, device_id: str, remote_path: str, destination: Path
    ) -> DeviceOperation:
        await self._delay()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps({"source": remote_path, "mock": True}, ensure_ascii=False),
            encoding="utf-8",
        )
        return DeviceOperation(
            CapabilityStatus.AVAILABLE,
            "Mock 파일을 수집했습니다.",
            file_path=str(destination),
        )

    async def process_info(self, device_id: str, package_name: str) -> DeviceOperation:
        await self._delay()
        running = package_name in self.started_packages
        return DeviceOperation(
            CapabilityStatus.AVAILABLE,
            "Mock 프로세스 정보를 확인했습니다.",
            data={"pids": ["4242"] if running else [], "running": running},
        )

    async def frida_status(self, device_id: str) -> DeviceOperation:
        return DeviceOperation(
            CapabilityStatus.AVAILABLE,
            "Mock Frida Server가 연결되었습니다.",
            data={"version": "mock-16.x"},
        )

    async def forward_port(
        self, device_id: str, local_port: int, remote_port: int
    ) -> DeviceOperation:
        await self._delay()
        return DeviceOperation(
            CapabilityStatus.AVAILABLE,
            f"Mock 포트 포워딩 {local_port} → {remote_port}을 설정했습니다.",
        )
