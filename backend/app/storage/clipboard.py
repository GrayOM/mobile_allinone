"""Clipboard attribution for the target package.

The workbench never stores clipboard text. Only a SHA-256, the observed
length and ownership metadata (owner uid, appops write/read timing) are
kept so a change can be attributed to the target app without mixing in
data another app placed on the clipboard.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from backend.app.core.command import run_command
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus
from backend.app.core.targets import is_valid_app_identifier


_UID_LINE = re.compile(r"^package:(?P<package>\S+)\s+uid:(?P<uid>\d+)\s*$", re.M)
_DUMPSYS_USERID = re.compile(r"\buserId=(?P<uid>\d+)\b")
_CLIP_UID = re.compile(r"\b(?:m)?[Pp]rimaryClipUid=(?P<uid>-?\d+)\b")
_CLIP_PACKAGE = re.compile(r"\b(?:m)?[Pp]rimaryClipPackage=(?P<package>[A-Za-z0-9_.]+)")
_CLIP_TEXT = re.compile(r"\{T:(?P<text>.*?)\}(?=\s*(?:\{|\})|\s*$)", re.S)
_CLIP_PRESENT = re.compile(r"\b(?:m)?[Pp]rimaryClip=(?P<value>.+)")
_APPOPS_LINE = re.compile(
    r"^\s*(?P<op>READ_CLIPBOARD|WRITE_CLIPBOARD):\s*(?P<mode>\w+)(?P<rest>.*)$", re.M
)
_APPOPS_TIME = re.compile(r"\btime=\+?(?P<age>[0-9hmsd]+)\s+ago")
_DURATION_PART = re.compile(r"(?P<value>\d+)(?P<unit>d|h|ms|m|s)")


def parse_package_uid(output: str, package_name: str) -> int | None:
    """Read the uid for ``package_name`` from ``pm list packages -U`` or ``dumpsys package``."""
    for match in _UID_LINE.finditer(output or ""):
        if match.group("package") == package_name:
            return int(match.group("uid"))
    match = _DUMPSYS_USERID.search(output or "")
    return int(match.group("uid")) if match else None


def parse_relative_age(value: str) -> float | None:
    """Convert appops ``+1h2m3s456ms`` style ages to seconds."""
    if not value:
        return None
    total = 0.0
    consumed = 0
    for match in _DURATION_PART.finditer(value):
        amount = int(match.group("value"))
        unit = match.group("unit")
        total += amount * {"d": 86400.0, "h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}[unit]
        consumed += len(match.group(0))
    if consumed != len(value):
        return None
    return total


def parse_clipboard_appops(output: str) -> dict[str, Any]:
    """Parse ``appops get <package> READ_CLIPBOARD``/``WRITE_CLIPBOARD`` output."""
    result: dict[str, Any] = {
        "read_mode": None,
        "read_age_seconds": None,
        "write_mode": None,
        "write_age_seconds": None,
    }
    text = output or ""
    if "No operations." in text and not _APPOPS_LINE.search(text):
        result["read_mode"] = result["write_mode"] = "default"
        return result
    for match in _APPOPS_LINE.finditer(text):
        prefix = "read" if match.group("op") == "READ_CLIPBOARD" else "write"
        result[f"{prefix}_mode"] = match.group("mode").lower()
        age = _APPOPS_TIME.search(match.group("rest"))
        if age:
            result[f"{prefix}_age_seconds"] = parse_relative_age(age.group("age"))
    return result


def parse_clipboard_dump(output: str) -> dict[str, Any]:
    """Extract ownership metadata and a content digest from ``dumpsys clipboard``.

    The clip text itself is reduced to a SHA-256 and a length. ``dumpsys`` may
    print a shortened item summary on recent Android releases, so the digest
    is a change signal rather than a full-content hash; ``digest_source``
    records that.
    """
    text = output or ""
    present = _CLIP_PRESENT.search(text)
    if not present:
        return {"recognized": False}
    value = present.group("value").strip()
    empty = value in {"null", "", "none"}
    owner_uid_match = _CLIP_UID.search(text)
    owner_package_match = _CLIP_PACKAGE.search(text)
    item = _CLIP_TEXT.search(value)
    clip_text = item.group("text") if item else ""
    digest_input = clip_text if item else value
    return {
        "recognized": True,
        "empty": empty,
        "owner_uid": int(owner_uid_match.group("uid")) if owner_uid_match else None,
        "owner_package": owner_package_match.group("package") if owner_package_match else None,
        "sha256": hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
        if not empty
        else hashlib.sha256(b"").hexdigest(),
        "text_length_observed": len(clip_text) if item else None,
        "digest_source": "item_text" if item else "clip_summary",
        "has_text_item": bool(item),
    }


def attribute_clipboard(
    *,
    dump: dict[str, Any],
    target_uid: int | None,
    appops: dict[str, Any],
    window_seconds: float | None,
) -> dict[str, Any]:
    """Decide whether the current clip can be attributed to the target package."""
    signals: list[str] = []
    owner_uid = dump.get("owner_uid")
    attributed: bool | None = None
    if dump.get("empty"):
        attributed = False
        signals.append("clip_empty")
    elif owner_uid is not None and target_uid is not None:
        attributed = owner_uid == target_uid
        signals.append("owner_uid_match" if attributed else "owner_uid_other_app")
    elif dump.get("owner_package"):
        signals.append("owner_package_reported")
    write_age = appops.get("write_age_seconds")
    if write_age is not None and window_seconds is not None:
        if write_age <= window_seconds:
            signals.append("appops_write_within_window")
            if attributed is None:
                attributed = True
        else:
            signals.append("appops_write_outside_window")
    return {"attributed": attributed, "signals": signals}


class AndroidClipboardInspector:
    """Read clipboard ownership metadata for one validated package over ADB."""

    def __init__(
        self,
        device_id: str,
        package_name: str,
        *,
        settings: AppSettings | None = None,
    ):
        if not is_valid_app_identifier("android", package_name):
            raise ValueError("Android clipboard target package is invalid")
        self.settings = settings or get_settings()
        self.device_id = device_id
        self.package_name = package_name
        self.adb = self.settings.resolved_tool("adb")
        self._target_uid: int | None = None
        self._last_sha256: str | None = None

    async def _shell(self, *args: str):
        return await run_command(
            [self.adb, "-s", self.device_id, "shell", *args],
            timeout=self.settings.command_timeout_seconds,
        )

    async def _resolve_uid(self) -> int | None:
        if self._target_uid is not None:
            return self._target_uid
        listed = await self._shell("pm", "list", "packages", "-U", self.package_name)
        uid = parse_package_uid(listed.stdout if listed.ok else "", self.package_name)
        if uid is None:
            dumped = await self._shell("dumpsys", "package", self.package_name)
            uid = parse_package_uid(dumped.stdout if dumped.ok else "", self.package_name)
        self._target_uid = uid
        return uid

    async def snapshot(self, phase: str, *, window_seconds: float | None = None) -> dict[str, Any]:
        base: dict[str, Any] = {"phase": phase, "masked": True, "raw_text_stored": False}
        if not self.adb:
            return {
                **base,
                "status": CapabilityStatus.NOT_CONFIGURED.value,
                "message": "ADB가 설정되지 않아 Clipboard 귀속을 확인하지 못했습니다.",
            }
        dumped = await self._shell("dumpsys", "clipboard")
        if not dumped.ok:
            return {
                **base,
                "status": CapabilityStatus.FAILED.value,
                "message": dumped.error or dumped.stderr.strip() or "dumpsys clipboard 실패",
                "command": dumped.display_command,
            }
        dump = parse_clipboard_dump(dumped.stdout)
        if not dump.get("recognized"):
            return {
                **base,
                "status": CapabilityStatus.UNSUPPORTED.value,
                "message": "이 Android 버전의 dumpsys clipboard 형식을 해석하지 못해 귀속을 판단하지 않았습니다.",
                "command": dumped.display_command,
            }
        target_uid = await self._resolve_uid()
        appops_result = await self._shell("appops", "get", self.package_name)
        appops = parse_clipboard_appops(appops_result.stdout if appops_result.ok else "")
        attribution = attribute_clipboard(
            dump=dump, target_uid=target_uid, appops=appops, window_seconds=window_seconds
        )
        changed = self._last_sha256 is not None and self._last_sha256 != dump["sha256"]
        self._last_sha256 = dump["sha256"]
        length = dump.get("text_length_observed")
        preview = "<empty>" if dump.get("empty") else f"<masked:{length}>" if length is not None else "<masked>"
        return {
            **base,
            "status": CapabilityStatus.AVAILABLE.value,
            "message": (
                "현재 Clipboard 소유 uid가 대상 앱과 일치합니다."
                if attribution["attributed"]
                else "현재 Clipboard는 대상 앱에 귀속되지 않거나 비어 있습니다."
                if attribution["attributed"] is False
                else "Clipboard 소유 정보가 없어 귀속을 확정하지 않았습니다."
            ),
            "command": dumped.display_command,
            "sha256": dump["sha256"],
            "preview": preview,
            "digest_source": dump["digest_source"],
            "owner_uid": dump.get("owner_uid"),
            "owner_package": dump.get("owner_package"),
            "target_uid": target_uid,
            "attributed": attribution["attributed"],
            "signals": attribution["signals"],
            "appops": appops,
            "changed_signal": changed,
        }
