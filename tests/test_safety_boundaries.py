from __future__ import annotations

import io
import json
import sys
import time
import zipfile
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

from backend.app.ai.masking import mask_context
from backend.app.ai.storage import save_ai_raw_response
from backend.app.analyzers.archive_safety import UnsafeArchiveError, validate_archive
from backend.app.core.command import run_command
from backend.app.core.config import AppSettings, ToolPaths
from backend.app.core.status import CapabilityStatus
from backend.app.database.base import Base
from backend.app.database.migrations import MIGRATION_ID, apply_migrations
from backend.app.frida.manager import FridaManager


def test_live_and_mock_adapters_cannot_be_mixed(client):
    live = client.post("/api/projects", json={"name": "Live boundary"}).json()
    rejected_mock = client.post(
        "/api/runs",
        json={
            "project_id": live["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
        },
    )
    assert rejected_mock.status_code == 422

    mock = client.post(
        "/api/projects", json={"name": "Mock boundary", "run_mode": "mock"}
    ).json()
    rejected_live = client.post(
        "/api/runs",
        json={
            "project_id": mock["id"],
            "device_id": "device-1",
            "device_adapter": "android_adb",
            "proxy_adapter": "mitmproxy",
            "options": {
                "proxy_listen_host": "192.0.2.10",
                "proxy_allowed_client_ip": "192.0.2.20",
            },
        },
    )
    assert rejected_live.status_code == 422

    unknown = client.post(
        "/api/runs",
        json={
            "project_id": live["id"],
            "device_id": "device-1",
            "device_adapter": "unknown",
            "proxy_adapter": "burp",
        },
    )
    assert unknown.status_code == 422
    wildcard_proxy = client.post(
        "/api/runs",
        json={
            "project_id": live["id"],
            "device_id": "device-1",
            "device_adapter": "android_adb",
            "proxy_adapter": "mitmproxy",
            "options": {
                "proxy_listen_host": "0.0.0.0",
                "proxy_allowed_client_ip": "192.0.2.20",
            },
        },
    )
    assert wildcard_proxy.status_code == 422
    unknown_action = client.post(
        "/api/devices/action",
        json={"adapter": "unknown", "device_id": "device-1", "action": "list_packages"},
    )
    assert unknown_action.status_code == 422
    assert client.delete(f"/api/projects/{live['id']}").status_code == 200
    assert client.delete(f"/api/projects/{mock['id']}").status_code == 200


def test_active_run_blocks_project_delete_until_stop_finishes(client):
    demo = client.post("/api/demo/bootstrap").json()
    started = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "pause_for_login": True,
        },
    ).json()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{started['id']}").json()
        if run["status"] == "paused":
            break
        time.sleep(0.05)
    assert run["status"] == "paused"
    assert client.delete(f"/api/projects/{demo['project']['id']}").status_code == 409
    stopped = client.post(f"/api/runs/{started['id']}/stop")
    assert stopped.status_code == 200
    assert stopped.json()["status"] == "stopped"
    assert client.delete(f"/api/projects/{demo['project']['id']}").status_code == 200


def test_archive_safety_rejects_traversal_and_high_compression_ratio():
    settings = AppSettings(
        archive_max_uncompressed_mb=10,
        archive_max_entry_ratio=10,
        archive_max_total_ratio=10,
    )
    traversal = io.BytesIO()
    with zipfile.ZipFile(traversal, "w") as archive:
        archive.writestr("../escape.txt", "unsafe")
    traversal.seek(0)
    with zipfile.ZipFile(traversal) as archive:
        with pytest.raises(UnsafeArchiveError, match="비정상 압축 경로"):
            validate_archive(archive, settings)

    bomb = io.BytesIO()
    with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("assets/repeated.bin", b"A" * (2 * 1024 * 1024))
    bomb.seek(0)
    with zipfile.ZipFile(bomb) as archive:
        with pytest.raises(UnsafeArchiveError, match="압축률"):
            validate_archive(archive, settings)

    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("expanded.bin", b"B" * (2 * 1024 * 1024))
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as archive:
        archive.writestr("assets/payload.zip", inner.getvalue())
    outer.seek(0)
    with zipfile.ZipFile(outer) as archive:
        with pytest.raises(UnsafeArchiveError, match="압축률"):
            validate_archive(archive, settings)


def test_structured_ai_masking_removes_sensitive_fields_and_url_values():
    masked, rules = mask_context(
        {
            "headers": {
                "Authorization": "Bearer live-token",
                "Cookie": "a=one; b=two",
            },
            "body": {
                "password": "correct horse battery staple",
                "sessionId": "session-1234567890",
                "tenantSecret": "custom-value",
            },
            "url": "https://customer.example/users/900101-1234567?token=abc&email=user@example.com",
        },
        custom_keys=["tenantSecret"],
    )
    assert "live-token" not in masked
    assert "one" not in masked and "two" not in masked
    assert "correct horse" not in masked
    assert "session-1234567890" not in masked
    assert "custom-value" not in masked
    assert "customer.example" not in masked
    assert "user@example.com" not in masked
    assert rules


def test_ai_raw_response_storage_is_opt_in_and_masks_custom_keys(tmp_path: Path):
    disabled = AppSettings(data_dir=tmp_path, store_ai_raw_responses=False)
    assert save_ai_raw_response(disabled, "response.json", '{"tenantSecret":"raw"}') is None

    enabled = AppSettings(
        data_dir=tmp_path,
        store_ai_raw_responses=True,
        ai_sensitive_keys=["tenantSecret"],
    )
    enabled.ensure_directories()
    stored = save_ai_raw_response(
        enabled,
        "../response.json",
        json.dumps({"tenantSecret": "customer-value", "password": "another-value"}),
    )
    assert stored == enabled.ai_raw_dir / "response.json"
    assert stored is not None
    content = stored.read_text(encoding="utf-8")
    assert "customer-value" not in content
    assert "another-value" not in content


@pytest.mark.asyncio
async def test_command_timeout_still_applies_without_resource_limits():
    started = time.monotonic()
    result = await run_command(
        [sys.executable, "-c", "import time; time.sleep(3)"], timeout=1
    )
    assert result.status == CapabilityStatus.FAILED
    assert "1초" in (result.error or "")
    assert time.monotonic() - started < 2.5


@pytest.mark.asyncio
async def test_frida_cannot_execute_when_node_validation_is_unavailable():
    settings = AppSettings(tools=ToolPaths(node="definitely-missing-node"))
    manager = FridaManager(settings)
    content = "setImmediate(function () { send({event: 'test'}); });"
    status, _ = await manager.check_syntax(content)
    execution = await manager.execute(
        device_id="mock-android-01",
        target="com.example.test",
        script_name="candidate",
        script_content=content,
        mock=True,
    )
    assert status == CapabilityStatus.NOT_CONFIGURED
    assert execution.status == CapabilityStatus.NOT_CONFIGURED
    assert execution.synthetic is False


def test_explicit_sqlite_migration_backs_up_and_classifies_legacy_mock(tmp_path: Path):
    database = tmp_path / "legacy.db"
    engine = create_engine(f"sqlite:///{database.as_posix()}")
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE projects ("
                "id VARCHAR(36) PRIMARY KEY, name VARCHAR(200) NOT NULL, "
                "description TEXT NOT NULL DEFAULT '', ai_enabled BOOLEAN NOT NULL DEFAULT 1, "
                "external_ai_allowed BOOLEAN NOT NULL DEFAULT 0, "
                "mock_mode BOOLEAN NOT NULL DEFAULT 0, created_at DATETIME, updated_at DATETIME)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO projects(id, name, mock_mode) "
                "VALUES ('legacy-mock', 'Legacy mock', 1)"
            )
        )
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO frida_scripts("
                "id, name, platform, category, target_framework, conditions, risk, content, "
                "source, approval_status, syntax_status, success_count, failure_count, "
                "created_at, updated_at) VALUES ("
                "'legacy-script', 'Legacy approved', 'android', 'Custom', 'generic', '[]', "
                "'medium', 'setImmediate(function () {});', 'custom', 'approved', "
                "'available', 0, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )

    apply_migrations(engine)

    columns = {item["name"] for item in inspect(engine).get_columns("projects")}
    assert "run_mode" in columns
    with engine.connect() as connection:
        assert connection.scalar(
            text("SELECT run_mode FROM projects WHERE id = 'legacy-mock'")
        ) == "mock"
        migration = connection.execute(
            text(
                "SELECT id, backup_path FROM schema_migrations WHERE id = :id"
            ),
            {"id": MIGRATION_ID},
        ).one()
        approval_status = connection.scalar(
            text(
                "SELECT approval_status FROM frida_scripts "
                "WHERE id = 'legacy-script'"
            )
        )
    assert migration.id == MIGRATION_ID
    assert migration.backup_path and Path(migration.backup_path).is_file()
    assert approval_status == "pending_approval"
