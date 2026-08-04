from __future__ import annotations

import io
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from backend.app.core.config import AppSettings


class UnsafeArchiveError(ValueError):
    pass


@dataclass(slots=True)
class ArchiveSafetyReport:
    entry_count: int
    compressed_bytes: int
    uncompressed_bytes: int
    total_ratio: float
    nested_entries: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "entry_count": self.entry_count,
            "compressed_bytes": self.compressed_bytes,
            "uncompressed_bytes": self.uncompressed_bytes,
            "total_ratio": round(self.total_ratio, 2),
            "nested_entries": self.nested_entries,
            "status": "accepted",
        }


def validate_archive(
    archive: zipfile.ZipFile, settings: AppSettings, *, _depth: int = 0
) -> ArchiveSafetyReport:
    infos = archive.infolist()
    if len(infos) > settings.archive_max_entries:
        raise UnsafeArchiveError(
            f"압축 Entry 수 {len(infos):,}개가 제한 {settings.archive_max_entries:,}개를 초과했습니다."
        )

    compressed = sum(max(0, item.compress_size) for item in infos)
    uncompressed = sum(max(0, item.file_size) for item in infos)
    max_uncompressed = settings.archive_max_uncompressed_mb * 1024 * 1024
    if uncompressed > max_uncompressed:
        raise UnsafeArchiveError(
            f"예상 압축 해제 크기 {uncompressed:,}바이트가 제한 {max_uncompressed:,}바이트를 초과했습니다."
        )
    total_ratio = uncompressed / max(compressed, 1)
    if uncompressed > 10 * 1024 * 1024 and total_ratio > settings.archive_max_total_ratio:
        raise UnsafeArchiveError(
            f"전체 압축률 {total_ratio:.1f}:1이 제한 {settings.archive_max_total_ratio:.1f}:1을 초과했습니다."
        )

    seen: set[str] = set()
    nested: list[str] = []
    nested_bytes = 0
    max_entry = settings.archive_max_entry_mb * 1024 * 1024
    archive_suffixes = {".zip", ".apk", ".ipa", ".jar", ".aar"}
    for info in infos:
        raw_name = info.filename
        normalized_name = raw_name.replace("\\", "/")
        path = PurePosixPath(normalized_name)
        if (
            not raw_name
            or "\x00" in raw_name
            or raw_name.startswith(("/", "\\"))
            or any(part in {"", ".", ".."} for part in path.parts)
            or (path.parts and ":" in path.parts[0])
        ):
            raise UnsafeArchiveError(f"비정상 압축 경로가 포함되어 있습니다: {raw_name!r}")
        folded = normalized_name.casefold()
        if folded in seen:
            raise UnsafeArchiveError(f"중복되거나 대소문자만 다른 Entry가 있습니다: {raw_name}")
        seen.add(folded)
        if info.flag_bits & 0x1:
            raise UnsafeArchiveError(f"암호화된 Entry는 자동 분석하지 않습니다: {raw_name}")
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        if unix_mode and stat.S_ISLNK(unix_mode):
            raise UnsafeArchiveError(f"심볼릭 링크 Entry는 자동 분석하지 않습니다: {raw_name}")
        if info.file_size > max_entry:
            raise UnsafeArchiveError(
                f"Entry {raw_name}의 크기가 {settings.archive_max_entry_mb}MB 제한을 초과했습니다."
            )
        ratio = info.file_size / max(info.compress_size, 1)
        if info.file_size > 1024 * 1024 and ratio > settings.archive_max_entry_ratio:
            raise UnsafeArchiveError(
                f"Entry {raw_name}의 압축률 {ratio:.1f}:1이 제한을 초과했습니다."
            )
        if path.suffix.lower() in archive_suffixes and not info.is_dir():
            nested.append(raw_name)
            nested_bytes += info.file_size

    if len(nested) > settings.archive_max_nested_count:
        raise UnsafeArchiveError(
            f"중첩 압축 파일 {len(nested)}개가 제한 {settings.archive_max_nested_count}개를 초과했습니다."
        )
    if nested_bytes > settings.archive_max_nested_mb * 1024 * 1024:
        raise UnsafeArchiveError(
            f"중첩 압축 파일의 합계가 {settings.archive_max_nested_mb}MB 제한을 초과했습니다."
        )
    if nested and _depth >= 1:
        raise UnsafeArchiveError("2단계 이상 중첩된 압축 파일은 자동 분석하지 않습니다.")

    nested_uncompressed = 0
    info_by_name = {item.filename: item for item in infos}
    for nested_name in nested:
        try:
            nested_data = archive.read(info_by_name[nested_name])
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            raise UnsafeArchiveError(
                f"중첩 압축 파일을 안전하게 확인할 수 없습니다: {nested_name}"
            ) from exc
        stream = io.BytesIO(nested_data)
        if not zipfile.is_zipfile(stream):
            continue
        stream.seek(0)
        with zipfile.ZipFile(stream) as nested_archive:
            nested_report = validate_archive(
                nested_archive, settings, _depth=_depth + 1
            )
        nested_uncompressed += nested_report.uncompressed_bytes
        if nested_uncompressed > settings.archive_max_nested_mb * 1024 * 1024:
            raise UnsafeArchiveError(
                f"중첩 압축 해제 크기가 {settings.archive_max_nested_mb}MB 제한을 초과했습니다."
            )
    return ArchiveSafetyReport(
        entry_count=len(infos),
        compressed_bytes=compressed,
        uncompressed_bytes=uncompressed,
        total_ratio=total_ratio,
        nested_entries=nested,
    )
