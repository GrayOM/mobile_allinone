from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True, frozen=True)
class FileMetadata:
    path: str
    category: str
    size: int
    mtime: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class FileChange:
    path: str
    category: str
    change_type: str
    before_size: int | None
    after_size: int | None
    before_sha256: str | None
    after_sha256: str | None
    size_changed: bool
    hash_changed: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DatabaseArtifact:
    path: str
    size: int
    sha256: str
    tables: list[dict[str, Any]]
    masked: bool = True
    status: str = "available"
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class StorageSnapshot:
    phase: str
    package_name: str
    root: str
    files: dict[str, FileMetadata]
    databases: list[DatabaseArtifact] = field(default_factory=list)
    clipboard: dict[str, Any] = field(default_factory=dict)
    captured_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    synthetic: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "package_name": self.package_name,
            "root": self.root,
            "files": [item.to_dict() for item in self.files.values()],
            "databases": [item.to_dict() for item in self.databases],
            "clipboard": self.clipboard,
            "captured_at": self.captured_at,
            "synthetic": self.synthetic,
            "file_count": len(self.files),
            "database_count": len(self.databases),
        }


@dataclass(slots=True)
class StorageCapture:
    status: str
    message: str
    snapshot: StorageSnapshot | None = None
    archive_path: str | None = None
    command: str | None = None
    synthetic: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "message": self.message,
            "snapshot": self.snapshot.to_dict() if self.snapshot else None,
            "archive_path": self.archive_path,
            "command": self.command,
            "synthetic": self.synthetic,
        }


def diff_snapshots(
    before: StorageSnapshot, after: StorageSnapshot
) -> list[FileChange]:
    if before.package_name != after.package_name:
        raise ValueError("Storage snapshots belong to different packages")
    changes: list[FileChange] = []
    for path in sorted(set(before.files) | set(after.files)):
        old = before.files.get(path)
        new = after.files.get(path)
        if old is None and new is not None:
            change_type = "created"
        elif old is not None and new is None:
            change_type = "deleted"
        elif old and new and (old.sha256 != new.sha256 or old.size != new.size):
            change_type = "modified"
        else:
            continue
        changes.append(
            FileChange(
                path=path,
                category=(new or old).category,  # type: ignore[union-attr]
                change_type=change_type,
                before_size=old.size if old else None,
                after_size=new.size if new else None,
                before_sha256=old.sha256 if old else None,
                after_sha256=new.sha256 if new else None,
                size_changed=bool(old and new and old.size != new.size),
                hash_changed=bool(old and new and old.sha256 != new.sha256),
            )
        )
    return changes
