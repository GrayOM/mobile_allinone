"""Observe whether the target app protects its screen when backgrounded.

The inspector only reads window attributes of the target package, sends the
standard HOME / APP_SWITCH key events that any user can press, and, on a
rooted device, reads the system task-snapshot file that belongs to the
target task. It never changes app data and never touches other packages.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from backend.app.core.command import run_binary_command, run_command
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus
from backend.app.core.targets import is_valid_app_identifier

from .models import WindowProtection


FLAG_SECURE = 0x2000
TASK_SNAPSHOT_DIR = "/data/system_ce/0/snapshots"
_WINDOW_HEADER = re.compile(r"^\s*Window #\d+ Window\{[0-9a-f]+ u\d+ (?P<name>[^}]+)\}:", re.M)
_CURRENT_FOCUS = re.compile(r"mCurrentFocus=Window\{[0-9a-f]+ u\d+ (?P<name>[^}]+)\}")
_FLAGS = re.compile(r"\bfl=(?P<flags>#?[0-9A-Za-z_ ]+?)(?=\s+\w+=|\}|$)", re.M)
_SNAPSHOT_ENTRY = re.compile(r"^\S+\s+\d+\s+\S+\s+\S+\s+(?P<size>\d+)\s+.*?\s(?P<name>\S+)$")


def parse_window_protection(output: str, package_name: str) -> tuple[list[WindowProtection], bool | None]:
    """Return the target package's windows with their FLAG_SECURE state."""
    text = output or ""
    focus = _CURRENT_FOCUS.search(text)
    focused_name = focus.group("name") if focus else None
    headers = list(_WINDOW_HEADER.finditer(text))
    windows: list[WindowProtection] = []
    focused_secure: bool | None = None
    for index, header in enumerate(headers):
        name = header.group("name").strip()
        if not (name == package_name or name.startswith(f"{package_name}/")):
            continue
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        section = text[header.end() : end]
        flags_match = _FLAGS.search(section)
        secure: bool | None = None
        flags = ""
        if flags_match:
            flags = flags_match.group("flags").strip()
            if flags.startswith("#"):
                try:
                    secure = bool(int(flags[1:], 16) & FLAG_SECURE)
                except ValueError:
                    secure = None
            else:
                secure = "SECURE" in flags.split()
        focused = focused_name == name
        if focused:
            focused_secure = secure
        windows.append(WindowProtection(name=name, secure=secure, focused=focused, flags=flags))
    return windows, focused_secure


def parse_task_id(output: str, package_name: str) -> int | None:
    """Find the task id that hosts ``package_name`` in ``dumpsys activity activities``."""
    escaped = re.escape(package_name)
    pattern = re.compile(
        rf"#(?P<id>\d+)\s+(?:type=\w+\s+)?A=(?:\d+:)?{escaped}(?=[\s/}}])"
    )
    match = pattern.search(output or "")
    return int(match.group("id")) if match else None


def parse_snapshot_listing(output: str, task_id: int) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for line in (output or "").splitlines():
        match = _SNAPSHOT_ENTRY.match(line.strip())
        if not match:
            continue
        name = match.group("name")
        if name.startswith(f"{task_id}.") or name.startswith(f"{task_id}_"):
            entries.append({"name": name, "size": int(match.group("size"))})
    return entries


class AndroidScreenProtectionInspector:
    def __init__(
        self,
        device_id: str,
        package_name: str,
        *,
        privileged: bool | None,
        settings: AppSettings | None = None,
    ):
        if not is_valid_app_identifier("android", package_name):
            raise ValueError("Android screen protection target package is invalid")
        self.settings = settings or get_settings()
        self.device_id = device_id
        self.package_name = package_name
        self.privileged = privileged
        self.adb = self.settings.resolved_tool("adb")

    @property
    def available(self) -> bool:
        return bool(self.adb)

    async def _shell(self, *args: str, timeout: int | None = None):
        return await run_command(
            [self.adb, "-s", self.device_id, "shell", *args],
            timeout=timeout or self.settings.command_timeout_seconds,
        )

    async def window_protection(self) -> tuple[list[WindowProtection], bool | None, str]:
        result = await self._shell("dumpsys", "window", "windows")
        if not result.ok:
            return [], None, result.error or result.stderr.strip() or "dumpsys window 실패"
        windows, focused_secure = parse_window_protection(result.stdout, self.package_name)
        return windows, focused_secure, result.display_command

    async def task_id(self) -> int | None:
        result = await self._shell("dumpsys", "activity", "activities")
        if not result.ok:
            return None
        return parse_task_id(result.stdout, self.package_name)

    async def press_home(self) -> bool:
        result = await self._shell("input", "keyevent", "KEYCODE_HOME")
        return result.ok

    async def open_recents(self) -> bool:
        result = await self._shell("input", "keyevent", "KEYCODE_APP_SWITCH")
        return result.ok

    async def restore_foreground(self) -> bool:
        result = await self._shell(
            "monkey", "-p", self.package_name, "-c", "android.intent.category.LAUNCHER", "1"
        )
        return result.ok

    async def task_snapshot(self, task_id: int | None, destination: Path) -> dict[str, object]:
        """Read the system snapshot file of the target task (rooted devices only)."""
        if task_id is None:
            return {
                "status": CapabilityStatus.UNSUPPORTED.value,
                "message": "대상 앱 Task ID를 찾지 못해 시스템 스냅샷 파일을 확인하지 않았습니다.",
            }
        if self.privileged is not True:
            return {
                "status": CapabilityStatus.UNSUPPORTED.value,
                "message": "시스템 Task 스냅샷 파일은 Root 단말에서만 확인합니다.",
                "task_id": task_id,
            }
        listing = await self._shell(
            "su", "-c", shlex.quote(f"ls -l {TASK_SNAPSHOT_DIR}")
        )
        if not listing.ok:
            return {
                "status": CapabilityStatus.FAILED.value,
                "message": listing.error or listing.stderr.strip() or "스냅샷 디렉터리 조회 실패",
                "task_id": task_id,
                "command": listing.display_command,
            }
        entries = parse_snapshot_listing(listing.stdout, task_id)
        payload: dict[str, object] = {
            "status": CapabilityStatus.AVAILABLE.value,
            "task_id": task_id,
            "directory": TASK_SNAPSHOT_DIR,
            "entries": entries,
            "command": listing.display_command,
            "message": (
                f"대상 Task의 시스템 스냅샷 파일 {len(entries)}개를 확인했습니다."
                if entries
                else "대상 Task의 시스템 스냅샷 파일이 없습니다."
            ),
        }
        image = next((item for item in entries if item["name"] == f"{task_id}.jpg"), None)
        if image is None:
            return payload
        remote = f"{TASK_SNAPSHOT_DIR}/{task_id}.jpg"
        result, data = await run_binary_command(
            [self.adb, "-s", self.device_id, "exec-out", "su", "-c", shlex.quote(f"cat {remote}")],
            timeout=self.settings.command_timeout_seconds,
            max_output_bytes=self.settings.storage_database_max_bytes,
        )
        if result.ok and data.startswith(b"\xff\xd8"):
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            payload["file_path"] = str(destination)
            payload["file_size"] = len(data)
        else:
            payload["pull_error"] = result.error or result.stderr.strip() or "JPEG 스냅샷을 읽지 못했습니다."
        return payload
