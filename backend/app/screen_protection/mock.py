from __future__ import annotations

from pathlib import Path

from backend.app.core.status import CapabilityStatus

from .models import WindowProtection


class MockScreenProtectionInspector:
    """Deterministic, network-free stand-in that mirrors the Android inspector API."""

    def __init__(self, package_name: str):
        self.package_name = package_name
        self.available = True
        self.home_pressed = False

    async def window_protection(self) -> tuple[list[WindowProtection], bool | None, str]:
        windows = [
            WindowProtection(
                name=f"{self.package_name}/{self.package_name}.MainActivity",
                secure=False,
                focused=True,
                flags="LAYOUT_IN_SCREEN LAYOUT_INSET_DECOR HARDWARE_ACCELERATED",
            )
        ]
        return windows, False, "mock dumpsys window windows"

    async def task_id(self) -> int | None:
        return 42

    async def press_home(self) -> bool:
        self.home_pressed = True
        return True

    async def open_recents(self) -> bool:
        return True

    async def restore_foreground(self) -> bool:
        self.home_pressed = False
        return True

    async def task_snapshot(self, task_id: int | None, destination: Path) -> dict[str, object]:
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Smallest valid JPEG markers so the evidence pipeline hashes a real file.
        destination.write_bytes(b"\xff\xd8\xff\xe0SYNTHETIC MOCK TASK SNAPSHOT\xff\xd9")
        return {
            "status": CapabilityStatus.AVAILABLE.value,
            "task_id": task_id,
            "directory": "/data/system_ce/0/snapshots",
            "entries": [{"name": f"{task_id}.jpg", "size": 38}, {"name": f"{task_id}.proto", "size": 96}],
            "file_path": str(destination),
            "file_size": 38,
            "command": "mock ls -l /data/system_ce/0/snapshots",
            "message": "Mock 대상 Task의 시스템 스냅샷 파일 2개를 합성했습니다.",
            "synthetic": True,
        }
