from __future__ import annotations

import asyncio
import hashlib
import shlex
import tarfile
from pathlib import Path, PurePosixPath

from backend.app.core.command import run_streaming_command_to_file
from backend.app.core.config import AppSettings, get_settings
from backend.app.core.status import CapabilityStatus
from backend.app.core.targets import is_valid_app_identifier

from .inspector import inspect_sqlite_database
from .models import FileMetadata, StorageCapture, StorageSnapshot


def _category(path: str) -> str:
    first = PurePosixPath(path).parts[0] if PurePosixPath(path).parts else "files"
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
    """Root-only, package-scoped Android data collector."""

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

    def clipboard_snapshot(self, phase: str) -> dict[str, object]:
        return {
            "phase": phase,
            "status": CapabilityStatus.UNSUPPORTED.value,
            "message": (
                "ADB만으로 시스템 Clipboard 값을 대상 앱에 귀속할 수 없어 "
                "다른 앱 데이터 혼입을 막기 위해 자동 수집하지 않았습니다."
            ),
            "masked": True,
        }

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
        # package_name is strictly validated above; every other shell token is fixed.
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
                self._inspect_archive, phase, destination, root
            )
        except (OSError, tarfile.TarError, ValueError) as exc:
            destination.unlink(missing_ok=True)
            return StorageCapture(
                CapabilityStatus.FAILED.value,
                f"수집된 앱 저장소 archive 검증 실패: {exc}",
                command=result.display_command,
            )
        return StorageCapture(
            CapabilityStatus.AVAILABLE.value,
            f"대상 package 전용 저장소 파일 {len(snapshot.files)}개를 수집했습니다.",
            snapshot=snapshot,
            archive_path=str(destination),
            command=result.display_command,
        )

    def _inspect_archive(
        self, phase: str, archive_path: Path, root: str
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
                    category=_category(normalized),
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
            clipboard=self.clipboard_snapshot(phase),
        )
