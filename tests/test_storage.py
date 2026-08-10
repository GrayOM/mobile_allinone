from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

from backend.app.core.command import run_binary_command, run_streaming_command_to_file
from backend.app.core.status import CapabilityStatus
from backend.app.storage import (
    FileMetadata,
    MockAndroidStorageCollector,
    StorageSnapshot,
    diff_snapshots,
    inspect_sqlite_database,
)


def _file(path: str, size: int, digest: str) -> FileMetadata:
    return FileMetadata(path, "files", size, 1, digest)


def test_filesystem_diff_classifies_created_modified_and_deleted():
    before = StorageSnapshot(
        "before",
        "com.example.demo",
        "/data/data/com.example.demo",
        {
            "files/deleted.txt": _file("files/deleted.txt", 1, "a" * 64),
            "files/changed.txt": _file("files/changed.txt", 2, "b" * 64),
            "files/same.txt": _file("files/same.txt", 3, "c" * 64),
        },
    )
    after = StorageSnapshot(
        "after",
        "com.example.demo",
        "/data/data/com.example.demo",
        {
            "files/changed.txt": _file("files/changed.txt", 4, "d" * 64),
            "files/same.txt": _file("files/same.txt", 3, "c" * 64),
            "files/created.txt": _file("files/created.txt", 5, "e" * 64),
        },
    )
    changes = {item.path: item for item in diff_snapshots(before, after)}
    assert changes["files/deleted.txt"].change_type == "deleted"
    assert changes["files/changed.txt"].change_type == "modified"
    assert changes["files/changed.txt"].size_changed is True
    assert changes["files/created.txt"].change_type == "created"
    assert "files/same.txt" not in changes


def test_sqlite_viewer_masks_sensitive_preview_by_default(tmp_path: Path):
    database = tmp_path / "app.db"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE account (id INTEGER, email TEXT, auth_token TEXT, theme TEXT)"
    )
    connection.execute(
        "INSERT INTO account VALUES (1, 'owner@example.test', 'secret-token-value', 'dark')"
    )
    connection.commit()
    connection.close()

    artifact = inspect_sqlite_database(database, logical_path="databases/app.db")
    assert artifact.status == CapabilityStatus.AVAILABLE.value
    preview = artifact.tables[0]["preview"][0]
    assert preview["email"] == {"masked": True, "type": "text", "size": 18}
    assert preview["auth_token"]["masked"] is True
    assert preview["theme"] == "dark"


def test_sqlite_viewer_enforces_processing_deadline(tmp_path: Path):
    database = tmp_path / "deadline.db"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE sample (id INTEGER)")
    connection.commit()
    connection.close()

    artifact = inspect_sqlite_database(database, max_seconds=1e-12)
    assert artifact.status == CapabilityStatus.FAILED.value
    assert "시간 제한" in artifact.message


@pytest.mark.asyncio
async def test_mock_storage_snapshot_produces_masked_database_and_diff(tmp_path: Path):
    collector = MockAndroidStorageCollector("com.example.demo")
    before = await collector.capture("before_interaction", tmp_path / "before.tar")
    after = await collector.capture("after_interaction", tmp_path / "after.tar")
    assert before.status == CapabilityStatus.AVAILABLE.value
    assert after.status == CapabilityStatus.AVAILABLE.value
    assert before.snapshot and after.snapshot
    changes = diff_snapshots(before.snapshot, after.snapshot)
    assert {item.change_type for item in changes} == {"created", "modified"}
    assert after.snapshot.databases[0].masked is True
    assert after.snapshot.databases[0].tables[0]["preview"][0]["email"]["masked"] is True
    assert after.snapshot.clipboard["preview"] == "<masked:21>"


@pytest.mark.asyncio
async def test_binary_command_output_limit_terminates_capture():
    result, output = await run_binary_command(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 4096)"],
        timeout=5,
        max_output_bytes=1024,
    )
    assert result.status == CapabilityStatus.FAILED
    assert "exceeded 1024 bytes" in str(result.error)
    assert output == b""


@pytest.mark.asyncio
async def test_streaming_command_writes_atomically_without_returning_payload(tmp_path: Path):
    destination = tmp_path / "capture.bin"
    result = await run_streaming_command_to_file(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 4096)"],
        destination,
        timeout=5,
        max_output_bytes=8192,
    )
    assert result.status == CapabilityStatus.AVAILABLE
    assert destination.read_bytes() == b"x" * 4096
    assert result.stdout == "<streamed 4096 bytes>"

    rejected = tmp_path / "rejected.bin"
    overflow = await run_streaming_command_to_file(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 4096)"],
        rejected,
        timeout=5,
        max_output_bytes=1024,
    )
    assert overflow.status == CapabilityStatus.FAILED
    assert not rejected.exists()
    assert not list(tmp_path.glob("*.partial"))
