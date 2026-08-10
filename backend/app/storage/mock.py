from __future__ import annotations

import hashlib
import io
import sqlite3
import tarfile
import time
from pathlib import Path

from backend.app.core.status import CapabilityStatus

from .inspector import inspect_sqlite_database
from .models import FileMetadata, StorageCapture, StorageSnapshot


class MockAndroidStorageCollector:
    def __init__(self, package_name: str):
        self.package_name = package_name
        self._capture_count = 0

    @staticmethod
    def _metadata(path: str, category: str, content: bytes) -> FileMetadata:
        return FileMetadata(
            path=path,
            category=category,
            size=len(content),
            mtime=int(time.time()),
            sha256=hashlib.sha256(content).hexdigest(),
        )

    def _database(self, path: Path, *, after: bool) -> None:
        connection = sqlite3.connect(path)
        connection.execute(
            "CREATE TABLE profile (id INTEGER PRIMARY KEY, email TEXT, auth_token TEXT)"
        )
        connection.execute(
            "INSERT INTO profile(id, email, auth_token) VALUES (?, ?, ?)",
            (
                1,
                "analyst@example.invalid",
                "synthetic-token-after" if after else "synthetic-token-before",
            ),
        )
        if after:
            connection.execute(
                "INSERT INTO profile(id, email, auth_token) VALUES (?, ?, ?)",
                (2, "second@example.invalid", "synthetic-token-second"),
            )
        connection.commit()
        connection.close()

    async def capture(self, phase: str, destination: Path) -> StorageCapture:
        self._capture_count += 1
        after = self._capture_count > 1 or phase == "after_interaction"
        destination.parent.mkdir(parents=True, exist_ok=True)
        database_path = destination.parent / f".mock-storage-{phase}.db"
        self._database(database_path, after=after)
        database_bytes = database_path.read_bytes()
        preferences = (
            b'<map><string name="theme">dark</string><string name="session">synthetic-after</string></map>'
            if after
            else b'<map><string name="theme">light</string></map>'
        )
        contents = {
            "shared_prefs/settings.xml": preferences,
            "databases/profile.db": database_bytes,
        }
        if after:
            contents["files/session.json"] = b'{"scope":"synthetic","authenticated":true}'
        with tarfile.open(destination, mode="w") as archive:
            for name, content in contents.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                member.mtime = int(time.time())
                archive.addfile(member, io.BytesIO(content))
        database = inspect_sqlite_database(
            database_path,
            logical_path="databases/profile.db",
        )
        database_path.unlink(missing_ok=True)
        files = {
            path: self._metadata(
                path,
                "shared_preferences"
                if path.startswith("shared_prefs/")
                else "database"
                if path.startswith("databases/")
                else "files",
                content,
            )
            for path, content in contents.items()
        }
        clipboard_value = "" if not after else "synthetic-account-100"
        snapshot = StorageSnapshot(
            phase=phase,
            package_name=self.package_name,
            root=f"/data/data/{self.package_name}",
            files=files,
            databases=[database],
            clipboard={
                "phase": phase,
                "status": CapabilityStatus.AVAILABLE.value,
                "changed_signal": after,
                "sha256": hashlib.sha256(clipboard_value.encode()).hexdigest(),
                "preview": "<empty>" if not clipboard_value else "<masked:21>",
                "masked": True,
                "synthetic": True,
            },
            synthetic=True,
        )
        return StorageCapture(
            CapabilityStatus.AVAILABLE.value,
            f"Mock package 저장소 {len(files)}개 파일을 합성 수집했습니다.",
            snapshot=snapshot,
            archive_path=str(destination),
            command=f"mock storage capture {phase}",
            synthetic=True,
        )
