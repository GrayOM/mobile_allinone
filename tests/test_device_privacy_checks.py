from __future__ import annotations

import io
import struct
import tarfile
import time
import zlib
from pathlib import Path

import pytest

from backend.app.core.command import CommandResult
from backend.app.core.config import AppSettings
from backend.app.core.status import CapabilityStatus
from backend.app.demo import create_demo_apk
from backend.app.devices.mock import MOCK_SCREEN_PNG
from backend.app.screen_protection import (
    dark_pixel_ratio,
    parse_snapshot_listing,
    parse_task_id,
    parse_window_protection,
)
from backend.app.storage import AndroidClipboardInspector, AndroidStorageCollector, MockAndroidStorageCollector, diff_snapshots
from backend.app.storage.clipboard import (
    attribute_clipboard,
    parse_clipboard_appops,
    parse_clipboard_dump,
    parse_package_uid,
    parse_relative_age,
)
from backend.app.storage import android as storage_android
from backend.app.storage import clipboard as storage_clipboard


# --- clipboard attribution -------------------------------------------------


def test_package_uid_parses_pm_and_dumpsys_formats():
    assert parse_package_uid("package:com.example.app uid:10123\n", "com.example.app") == 10123
    assert parse_package_uid("package:com.example.app.other uid:10999\n", "com.example.app") is None
    assert parse_package_uid("  Package [com.example.app] (abc):\n    userId=10456\n", "com.example.app") == 10456


def test_relative_age_and_appops_parsing():
    assert parse_relative_age("1h2m3s456ms") == pytest.approx(3723.456)
    assert parse_relative_age("45s") == 45.0
    assert parse_relative_age("garbage") is None
    appops = parse_clipboard_appops(
        "Uid 10123:\n  READ_CLIPBOARD: allow; time=+2m10s ago\n  WRITE_CLIPBOARD: allow; time=+3s512ms ago; duration=+1ms\n"
    )
    assert appops["write_mode"] == "allow"
    assert appops["write_age_seconds"] == pytest.approx(3.512)
    assert appops["read_age_seconds"] == pytest.approx(130.0)
    assert parse_clipboard_appops("No operations.")["write_mode"] == "default"


def test_clipboard_dump_keeps_only_digest_and_ownership():
    dump = parse_clipboard_dump(
        "Clipboard contents:\n  mPrimaryClip=ClipData { text/plain \"label\" {T:4111 1111 1111 1111} }\n"
        "  mPrimaryClipUid=10123\n  mPrimaryClipPackage=com.example.app\n"
    )
    assert dump["recognized"] is True
    assert dump["owner_uid"] == 10123
    assert dump["owner_package"] == "com.example.app"
    assert dump["text_length_observed"] == 19
    assert dump["digest_source"] == "item_text"
    assert "4111" not in str({k: v for k, v in dump.items() if k != "sha256"})
    assert parse_clipboard_dump("mPrimaryClip=null\n")["empty"] is True
    assert parse_clipboard_dump("no clipboard service here")["recognized"] is False


def test_clipboard_attribution_requires_uid_match_or_recent_target_write():
    other = attribute_clipboard(
        dump={"owner_uid": 10999, "empty": False}, target_uid=10123, appops={}, window_seconds=30
    )
    assert other["attributed"] is False
    assert "owner_uid_other_app" in other["signals"]
    same = attribute_clipboard(
        dump={"owner_uid": 10123, "empty": False},
        target_uid=10123,
        appops={"write_age_seconds": 4.0},
        window_seconds=30,
    )
    assert same["attributed"] is True
    assert same["signals"] == ["owner_uid_match", "appops_write_within_window"]
    unknown = attribute_clipboard(
        dump={"owner_uid": None, "empty": False},
        target_uid=10123,
        appops={"write_age_seconds": 500.0},
        window_seconds=30,
    )
    assert unknown["attributed"] is None
    assert "appops_write_outside_window" in unknown["signals"]


def _result(command, stdout="", rc=0, stderr=""):
    status = CapabilityStatus.AVAILABLE if rc == 0 else CapabilityStatus.FAILED
    return CommandResult(status=status, command=[str(c) for c in command], return_code=rc, stdout=stdout, stderr=stderr)


@pytest.mark.asyncio
async def test_clipboard_inspector_attributes_without_storing_text(monkeypatch, tmp_path: Path):
    adb = tmp_path / "adb"
    adb.write_text("#!/bin/sh\n")
    settings = AppSettings()
    settings.tools.adb = str(adb)
    calls: list[list[str]] = []

    async def fake_run(command, **kwargs):
        calls.append(list(command))
        joined = " ".join(command)
        if "dumpsys clipboard" in joined:
            return _result(command, "mPrimaryClip=ClipData { text/plain {T:secret-value} }\nmPrimaryClipUid=10123\n")
        if "pm list packages -U" in joined:
            return _result(command, "package:com.example.app uid:10123\n")
        if "appops get" in joined:
            return _result(command, "WRITE_CLIPBOARD: allow; time=+2s ago\n")
        return _result(command, "", rc=1)

    monkeypatch.setattr(storage_clipboard, "run_command", fake_run)
    inspector = AndroidClipboardInspector("serial-1", "com.example.app", settings=settings)
    snapshot = await inspector.snapshot("after_interaction", window_seconds=20)
    assert snapshot["status"] == "available"
    assert snapshot["attributed"] is True
    assert snapshot["preview"] == "<masked:12>"
    assert snapshot["raw_text_stored"] is False
    assert "secret-value" not in repr(snapshot)
    assert all(call[:3] == [str(adb), "-s", "serial-1"] for call in calls)


# --- external storage -------------------------------------------------------


def _tar_bytes(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, content in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            member.mtime = int(time.time())
            archive.addfile(member, io.BytesIO(content))
    return buffer.getvalue()


@pytest.mark.asyncio
async def test_external_storage_collects_only_app_specific_subtrees(monkeypatch, tmp_path: Path):
    adb = tmp_path / "adb"
    adb.write_text("#!/bin/sh\n")
    settings = AppSettings()
    settings.tools.adb = str(adb)
    scripts: list[str] = []

    async def fake_run(command, **kwargs):
        script = command[-1]
        scripts.append(script)
        if "/storage/emulated/0/Android" in script:
            return _result(command, "data\nmedia\n")
        return _result(command, "", rc=3)

    async def fake_stream(command, destination, **kwargs):
        scripts.append(command[-1])
        Path(destination).write_bytes(
            _tar_bytes({"data/com.example.app/files/export.csv": b"a,b\n", "media/com.example.app/x.jpg": b"\xff\xd8"})
        )
        return _result(command, "<streamed>")

    async def fake_clip(self, phase, *, window_seconds=None):
        return {"phase": phase, "status": "unsupported", "masked": True}

    monkeypatch.setattr(storage_android, "run_command", fake_run)
    monkeypatch.setattr(storage_android, "run_streaming_command_to_file", fake_stream)
    monkeypatch.setattr(storage_clipboard.AndroidClipboardInspector, "snapshot", fake_clip)
    collector = AndroidStorageCollector("serial-1", "com.example.app", privileged=False, settings=settings)
    capture = await collector.capture_external("before_interaction", tmp_path / "ext.tar")
    assert capture.status == "available", capture.message
    assert capture.snapshot is not None and capture.snapshot.scope == "external"
    assert {item.category for item in capture.snapshot.files.values()} == {"external_data", "external_media"}
    tar_script = next(item for item in scripts if item.startswith("'tar") or item.startswith("tar"))
    assert "data/com.example.app" in tar_script and "media/com.example.app" in tar_script
    assert "obb/" not in tar_script
    assert "Download" not in " ".join(scripts)
    assert "su" not in " ".join(scripts)


@pytest.mark.asyncio
async def test_external_storage_reports_unsupported_when_shell_cannot_read(monkeypatch, tmp_path: Path):
    adb = tmp_path / "adb"
    adb.write_text("#!/bin/sh\n")
    settings = AppSettings()
    settings.tools.adb = str(adb)

    async def fake_run(command, **kwargs):
        return _result(command, "", rc=1, stderr="Permission denied")

    monkeypatch.setattr(storage_android, "run_command", fake_run)
    collector = AndroidStorageCollector("serial-1", "com.example.app", privileged=None, settings=settings)
    capture = await collector.capture_external("before_interaction", tmp_path / "ext.tar")
    assert capture.status == "unsupported"
    assert "Root" in capture.message
    assert not (tmp_path / "ext.tar").exists()


@pytest.mark.asyncio
async def test_mock_external_snapshot_diff_is_scoped(tmp_path: Path):
    collector = MockAndroidStorageCollector("com.example.demo")
    before = await collector.capture_external("before_interaction", tmp_path / "b.tar")
    after = await collector.capture_external("after_interaction", tmp_path / "a.tar")
    assert before.snapshot and after.snapshot and after.snapshot.scope == "external"
    changes = diff_snapshots(before.snapshot, after.snapshot)
    assert {item.change_type for item in changes} == {"created", "modified"}
    internal = await collector.capture("after_interaction", tmp_path / "i.tar")
    assert internal.snapshot is not None
    with pytest.raises(ValueError, match="scopes"):
        diff_snapshots(internal.snapshot, after.snapshot)
    assert internal.snapshot.clipboard["attributed"] is True
    assert internal.snapshot.clipboard["raw_text_stored"] is False


# --- background screen protection ---------------------------------------------


_WINDOW_DUMP = """
  Window #5 Window{3a1b2c u0 com.other.app/com.other.app.Main}:
    mAttrs={(0,0)(fillxfill) ty=BASE_APPLICATION fmt=TRANSLUCENT fl=LAYOUT_IN_SCREEN SECURE HARDWARE_ACCELERATED}
  Window #6 Window{7d8e9f u0 com.example.app/com.example.app.LoginActivity}:
    mAttrs={(0,0)(fillxfill) sim={adjust=resize} ty=BASE_APPLICATION fmt=TRANSLUCENT wanim=0x10302f8 fl=LAYOUT_IN_SCREEN LAYOUT_INSET_DECOR HARDWARE_ACCELERATED}
    mHasSurface=true isReadyForDisplay()=true
  Window #7 Window{aa11bb u0 com.example.app/com.example.app.PinActivity}:
    mAttrs={(0,0)(fillxfill) ty=BASE_APPLICATION fmt=TRANSLUCENT fl=#81812100}
  mCurrentFocus=Window{7d8e9f u0 com.example.app/com.example.app.LoginActivity}
"""


def test_window_protection_parser_reads_symbolic_and_hex_flags():
    windows, focused_secure = parse_window_protection(_WINDOW_DUMP, "com.example.app")
    assert [item.name.rsplit(".", 1)[-1] for item in windows] == ["LoginActivity", "PinActivity"]
    assert windows[0].secure is False and windows[0].focused is True
    assert windows[1].secure is True and windows[1].focused is False
    assert focused_secure is False
    assert parse_window_protection(_WINDOW_DUMP, "com.example.application") == ([], None)


def test_task_id_parser_supports_old_and_new_formats():
    modern = "  * Task{1f2e3d #318 type=standard A=10123:com.example.app U=0 visible=true mode=fullscreen}\n"
    legacy = "  * TaskRecord{9ab #42 A=com.example.app U=0 StackId=1 sz=1}\n"
    assert parse_task_id(modern, "com.example.app") == 318
    assert parse_task_id(legacy, "com.example.app") == 42
    assert parse_task_id(modern, "com.example.ap") is None


def test_snapshot_listing_filters_to_target_task():
    listing = (
        "-rw------- 1 system system 48213 2026-10-14 10:00 318.jpg\n"
        "-rw------- 1 system system   912 2026-10-14 10:00 318.proto\n"
        "-rw------- 1 system system 12000 2026-10-14 10:00 3180.jpg\n"
        "-rw------- 1 system system  5000 2026-10-14 10:00 42.jpg\n"
    )
    entries = parse_snapshot_listing(listing, 318)
    assert [item["name"] for item in entries] == ["318.jpg", "318.proto"]
    assert entries[0]["size"] == 48213


def _solid_png(width: int, height: int, color: tuple[int, int, int]) -> bytes:
    raw = b"".join(b"\x00" + bytes(color) * width for _ in range(height))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def test_dark_pixel_ratio_distinguishes_blank_from_content():
    assert dark_pixel_ratio(_solid_png(40, 40, (0, 0, 0))) == 1.0
    assert dark_pixel_ratio(_solid_png(40, 40, (240, 240, 240))) == 0.0
    mock_ratio = dark_pixel_ratio(MOCK_SCREEN_PNG)
    assert mock_ratio is not None and mock_ratio < 0.2
    assert dark_pixel_ratio(b"\xff\xd8not-a-png") is None


# --- Mock Run integration -----------------------------------------------------


def _wait_for_run(client, run_id: str, timeout: float = 45):
    deadline = time.monotonic() + timeout
    run: dict = {}
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in {"completed", "completed_with_gaps", "failed", "stopped", "manual_required"}:
            return run
        time.sleep(0.05)
    raise AssertionError(f"run did not finish: {run.get('status')} {run.get('current_stage')} {run.get('error')}")


def test_mock_run_records_external_storage_clipboard_and_background_screen(client, tmp_path: Path):
    project = client.post(
        "/api/projects",
        json={"name": "privacy-efi", "run_mode": "mock", "assessment_profile": "electronic_financial", "ai_enabled": False},
    ).json()
    apk = create_demo_apk(tmp_path / "privacy.apk")
    with apk.open("rb") as stream:
        app = client.post(
            f"/api/projects/{project['id']}/apps/upload",
            files={"file": (apk.name, stream, "application/vnd.android.package-archive")},
        ).json()
    started = client.post(
        "/api/runs",
        json={
            "project_id": project["id"],
            "app_id": app["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
        },
    )
    assert started.status_code == 201
    assert started.json()["options"]["background_screen_check"] is True
    run = _wait_for_run(client, started.json()["id"])
    assert run["status"] == "completed", run.get("error")

    storage = run["options"]["storage"]
    assert storage["external"]["status"] == "available"
    assert storage["external"]["change_count"] >= 1
    assert all(change["category"].startswith("external_") for change in storage["external"]["changes"])
    assert storage["clipboard"]["attributed"] is True
    assert storage["clipboard"]["raw_text_stored"] is False
    assert storage["clipboard"]["synthetic"] is True

    background = run["options"]["background_screen"]
    assert background["status"] == "available"
    assert background["focused_window_secure"] is False
    assert background["restored_foreground"] is True
    assert background["synthetic"] is True
    assert background["task_snapshot"]["evidence_id"]

    evidence = client.get(f"/api/runs/{run['id']}/evidence").json()
    by_type: dict[str, list[dict]] = {}
    for item in evidence:
        by_type.setdefault(item["evidence_type"], []).append(item)
    assert len(by_type["background_screen_check"]) == 1
    assert len(by_type["task_snapshot"]) == 1
    assert by_type["task_snapshot"][0]["synthetic"] is True
    external_snapshots = [
        item for item in by_type["storage_snapshot"] if "외부" in item["title"]
    ]
    assert len(external_snapshots) == 2
    assert sum("외부" in item["title"] for item in by_type["storage_diff"]) == 1

    ledger = client.get(
        f"/api/coverage?run_id={run['id']}&scope=run&standard=electronic_financial"
    ).json()["tests"]
    rows = {item["control_id"]: item for item in ledger}
    background_row = rows["EFI-MA-50"]
    assert background_row["result"] == "needs_review"
    assert ["background_screen_check", "manual_assessment_attachment"] in background_row["evidence_requirements"]
    assert by_type["background_screen_check"][0]["id"] in background_row["evidence_ids"]
    storage_row = rows["EFI-MA-21"]
    assert storage_row["result"] == "needs_review"
    assert any(item["id"] in storage_row["evidence_ids"] for item in external_snapshots)
    assert not any(item["result"] == "confirmed" for item in ledger if item["control_id"] in {"EFI-MA-21", "EFI-MA-50"})
