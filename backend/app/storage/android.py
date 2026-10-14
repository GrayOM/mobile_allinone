from __future__ import annotations

import asyncio
import hashlib
import shlex
import tarfile
import time
from pathlib import Path, PurePosixPath

from backend.app.core.command import run_command, run_streaming_command_to_file
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus
from backend.app.core.targets import is_valid_app_identifier

from .clipboard import AndroidClipboardInspector
from .inspector import inspect_sqlite_database
from .models import FileMetadata, StorageCapture, StorageSnapshot


# App-specific external storage lives under one of these bases depending on the
# shell user's mount namespace. Only the Android/{data,media,obb}/<package>
# subtrees are collected; shared folders such as Download are never read.
EXTERNAL_BASES: tuple[str, ...] = (
    "/storage/emulated/0/Android",
    "/sdcard/Android",
    "/data/media/0/Android",
)
EXTERNAL_SUBTREES: tuple[str, ...] = ("data", "media", "obb")


def _category(path: str, scope: str = "internal") -> str:
    parts = PurePosixPath(path).parts
    first = parts[0] if parts else "files"
    if scope == "external":
        return {
            "data": "external_data",
            "media": "external_media",
            "obb": "external_obb",
        }.get(first, "external_files")
    return {
        "shared_prefs": "shared_preferences",
        "databases": "database",
        "app_webview": "webview",
        "cache": "cache",
        "code_cache": "cache",
        "files": "files",
        "no_backup": "files",
    }.get(first, "files")


class AndroidStorageCollector:
    """Package-scoped Android data collector.

    ``capture`` reads /data/data/<package> and needs a rooted device.
    ``capture_external`` reads the app-specific external storage subtrees and
    tries the plain shell user first, falling back to root when available.
    """

    def __init__(
        self,
        device_id: str,
        package_name: str,
        *,
        privileged: bool | None,
        settings: AppSettings | None = None,
    ):
        self.settings = settings or get_settings()
        self.device_id = device_id
        self.package_name = package_name
        self.privileged = privileged
        self.adb = self.settings.resolved_tool("adb")
        if not is_valid_app_identifier("android", package_name):
            raise ValueError("Android storage target package is invalid")
        self._clipboard = (
            AndroidClipboardInspector(device_id, package_name, settings=self.settings)
            if self.adb
            else None
        )
        self._phase_started: dict[str, float] = {}

    def _remote(self, script: str, *, as_root: bool) -> list[str]:
        # Every token except the validated package name is a fixed literal, and
        # the whole script is passed as one quoted argument to the device shell.
        if as_root:
            return ["su", "-c", shlex.quote(script)]
        return ["sh", "-c", shlex.quote(script)]

    async def clipboard_snapshot(
        self, phase: str, *, window_seconds: float | None = None
    ) -> dict[str, object]:
        if self._clipboard is None:
            return {
                "phase": phase,
                "status": CapabilityStatus.NOT_CONFIGURED.value,
                "message": "ADB가 설정되지 않아 Clipboard 귀속을 확인하지 못했습니다.",
                "masked": True,
            }
        return await self._clipboard.snapshot(phase, window_seconds=window_seconds)

    async def capture(self, phase: str, destination: Path) -> StorageCapture:
        if not self.adb:
            return StorageCapture(
                CapabilityStatus.NOT_CONFIGURED.value,
                "ADB가 설정되지 않아 앱 전용 저장소를 수집하지 못했습니다.",
            )
        if self.privileged is not True:
            return StorageCapture(
                CapabilityStatus.UNSUPPORTED.value,
                "Root 권한이 확인된 Android 단말에서만 /data/data/<package>를 수집합니다.",
            )
        root = f"/data/data/{self.package_name}"
        remote_command = f"tar -C {shlex.quote(root)} -cf - ."
        result = await run_streaming_command_to_file(
            [self.adb, "-s", self.device_id, "exec-out", "su", "-c", remote_command],
            destination,
            timeout=max(60, self.settings.command_timeout_seconds),
            max_output_bytes=self.settings.storage_archive_max_bytes,
        )
        if not result.ok:
            return StorageCapture(
                CapabilityStatus.FAILED.value,
                result.error or result.stderr.strip() or "Root package archive collection failed",
                command=result.display_command,
            )
        try:
            snapshot = await asyncio.to_thread(
                self._inspect_archive, phase, destination, root, "internal"
            )
        except (OSError, tarfile.TarError, ValueError) as exc:
            destination.unlink(missing_ok=True)
            return StorageCapture(
                CapabilityStatus.FAILED.value,
                f"수집된 앱 저장소 archive 검증 실패: {exc}",
                command=result.display_command,
            )
        # The appops write age is compared against the time elapsed since the
        # before-phase capture so only writes during this Run's interaction
        # window count as an attribution signal.
        now = time.monotonic()
        started = self._phase_started.get("before_interaction")
        window = (now - started) if (started is not None and phase != "before_interaction") else None
        self._phase_started[phase] = now
        snapshot.clipboard = await self.clipboard_snapshot(phase, window_seconds=window)
        return StorageCapture(
            CapabilityStatus.AVAILABLE.value,
            f"대상 package 전용 저장소 파일 {len(snapshot.files)}개를 수집했습니다.",
            snapshot=snapshot,
            archive_path=str(destination),
            command=result.display_command,
        )

    async def _probe_external(self, as_root: bool) -> tuple[str | None, list[str], str]:
        """Return (base, present subtrees, raw output) for the first readable base."""
        package = shlex.quote(self.package_name)
        for base in EXTERNAL_BASES:
            checks = " ".join(
                f"[ -d {shlex.quote(base)}/{sub}/{package} ] && echo {sub};"
                for sub in EXTERNAL_SUBTREES
            )
            script = f"[ -d {shlex.quote(base)} ] || exit 3; {checks} exit 0"
            result = await run_command(
                [self.adb, "-s", self.device_id, "shell", *self._remote(script, as_root=as_root)],
                timeout=self.settings.command_timeout_seconds,
            )
            if result.return_code == 3:
                continue
            if not result.ok:
                return None, [], result.stderr.strip() or result.error or ""
            present = [
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip() in EXTERNAL_SUBTREES
            ]
            return base, present, result.stdout
        return None, [], "no external base"

    async def capture_external(self, phase: str, destination: Path) -> StorageCapture:
        if not self.adb:
            return StorageCapture(
                CapabilityStatus.NOT_CONFIGURED.value,
                "ADB가 설정되지 않아 앱 외부 저장소를 수집하지 못했습니다.",
            )
        attempts = [False] + ([True] if self.privileged is True else [])
        base: str | None = None
        present: list[str] = []
        as_root = False
        detail = ""
        for as_root in attempts:
            base, present, detail = await self._probe_external(as_root)
            if base is not None:
                break
        if base is None:
            return StorageCapture(
                CapabilityStatus.UNSUPPORTED.value,
                "앱 전용 외부 저장소 경로에 접근하지 못했습니다. Android 11 이상 비루팅 단말은 "
                "shell 사용자가 Android/data를 읽을 수 없으므로 Root 단말이 필요합니다."
                + (f" ({detail})" if detail else ""),
            )
        root = f"{base}/{{{','.join(EXTERNAL_SUBTREES)}}}/{self.package_name}"
        if not present:
            snapshot = StorageSnapshot(
                phase=phase,
                package_name=self.package_name,
                root=root,
                files={},
                scope="external",
            )
            return StorageCapture(
                CapabilityStatus.AVAILABLE.value,
                "대상 package의 앱 전용 외부 저장소 디렉터리가 없습니다.",
                snapshot=snapshot,
                command=f"probe {base} ({'root' if as_root else 'shell'})",
            )
        members = " ".join(f"{sub}/{shlex.quote(self.package_name)}" for sub in present)
        script = f"tar -C {shlex.quote(base)} -cf - {members}"
        result = await run_streaming_command_to_file(
            [self.adb, "-s", self.device_id, "exec-out", *self._remote(script, as_root=as_root)],
            destination,
            timeout=max(60, self.settings.command_timeout_seconds),
            max_output_bytes=self.settings.storage_archive_max_bytes,
        )
        if not result.ok:
            return StorageCapture(
                CapabilityStatus.FAILED.value,
                result.error or result.stderr.strip() or "External storage archive collection failed",
                command=result.display_command,
            )
        try:
            snapshot = await asyncio.to_thread(
                self._inspect_archive, phase, destination, root, "external"
            )
        except (OSError, tarfile.TarError, ValueError) as exc:
            destination.unlink(missing_ok=True)
            return StorageCapture(
                CapabilityStatus.FAILED.value,
                f"수집된 앱 외부 저장소 archive 검증 실패: {exc}",
                command=result.display_command,
            )
        return StorageCapture(
            CapabilityStatus.AVAILABLE.value,
            f"앱 전용 외부 저장소 파일 {len(snapshot.files)}개를 "
            f"{'root' if as_root else 'shell'} 권한으로 수집했습니다.",
            snapshot=snapshot,
            archive_path=str(destination),
            command=result.display_command,
        )

    def _inspect_archive(
        self, phase: str, archive_path: Path, root: str, scope: str = "internal"
    ) -> StorageSnapshot:
        files: dict[str, FileMetadata] = {}
        databases = []
        total_size = 0
        with tarfile.open(archive_path, mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > self.settings.storage_max_files:
                raise ValueError("package archive file count limit exceeded")
            for member in members:
                raw_name = member.name.removeprefix("./")
                logical = PurePosixPath(raw_name)
                if (
                    not raw_name
                    or logical.is_absolute()
                    or ".." in logical.parts
                    or member.issym()
                    or member.islnk()
                ):
                    if member.isdir() and raw_name in {"", "."}:
                        continue
                    raise ValueError(f"unsafe package archive entry: {member.name}")
                if member.isdir():
                    continue
                if not member.isfile():
                    raise ValueError(f"unsupported package archive entry: {member.name}")
                total_size += member.size
                if total_size > self.settings.storage_archive_max_bytes:
                    raise ValueError("package archive content limit exceeded")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError(f"cannot read package archive entry: {member.name}")
                digest = hashlib.sha256()
                header = b""
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    if len(header) < 16:
                        header += chunk[: 16 - len(header)]
                    digest.update(chunk)
                normalized = logical.as_posix()
                metadata = FileMetadata(
                    path=normalized,
                    category=_category(normalized, scope),
                    size=member.size,
                    mtime=int(member.mtime),
                    sha256=digest.hexdigest(),
                )
                files[normalized] = metadata
                if (
                    header == b"SQLite format 3\x00"
                    and member.size <= self.settings.storage_database_max_bytes
                ):
                    extracted = archive_path.parent / (
                        f".{phase}-{hashlib.sha256(normalized.encode()).hexdigest()[:16]}.db"
                    )
                    source = archive.extractfile(member)
                    if source is None:
                        continue
                    with extracted.open("wb") as output:
                        for chunk in iter(lambda: source.read(1024 * 1024), b""):
                            output.write(chunk)
                    try:
                        databases.append(
                            inspect_sqlite_database(
                                extracted,
                                logical_path=normalized,
                                max_bytes=self.settings.storage_database_max_bytes,
                                max_seconds=self.settings.storage_sqlite_timeout_seconds,
                            )
                        )
                    finally:
                        extracted.unlink(missing_ok=True)
        return StorageSnapshot(
            phase=phase,
            package_name=self.package_name,
            root=root,
            files=files,
            databases=databases,
            scope=scope,
        )
