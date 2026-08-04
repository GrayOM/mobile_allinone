from __future__ import annotations

import io
import json
import sys
import time
import zipfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine, inspect, text

from backend.app.ai.masking import mask_context
from backend.app.ai.storage import save_ai_raw_response
from backend.app.analyzers.adapters import AndroguardAnalyzerAdapter, MobSFAnalyzerAdapter
from backend.app.analyzers.archive_safety import UnsafeArchiveError, validate_archive
from backend.app.core.command import CommandResult, run_command
from backend.app.core.config import AppSettings, ToolPaths
from backend.app.core.network import validate_mobsf_destination
from backend.app.core.security import ApiSecurityMiddleware
from backend.app.core.status import CapabilityStatus
from backend.app.database.models import DiagnosticRun
from backend.app.database.base import Base
from backend.app.database.migrations import MIGRATION_ID, apply_migrations
from backend.app.devices import IOSDeviceAdapter
from backend.app.frida.manager import FridaManager
from backend.app.orchestration import DiagnosticOrchestrator
from backend.app.orchestration.resources import allocate_available_port
from backend.app.proxy.base import ProxyCapture
from backend.app.schemas import AIFindingCandidate


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


def _wait_until_paused(client, run_id: str):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] == "paused":
            return run
        time.sleep(0.05)
    raise AssertionError("진단이 일시정지 상태에 도달하지 못했습니다.")


def test_run_rejects_app_device_and_frida_platform_mismatch(client):
    demo = client.post("/api/demo/bootstrap").json()
    wrong_device = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-ios-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
        },
    )
    assert wrong_device.status_code == 422
    assert "일치" in wrong_device.json()["detail"] or "실행할 수 없습니다" in wrong_device.json()["detail"]

    ios_script = client.post(
        "/api/frida/scripts",
        json={
            "name": "iOS only candidate",
            "platform": "ios",
            "category": "Custom",
            "content": "setImmediate(function () { send({event: 'ios'}); });",
        },
    ).json()
    wrong_script = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "frida_script_ids": [ios_script["id"]],
        },
    )
    assert wrong_script.status_code == 422
    assert "Frida" in wrong_script.json()["detail"]


def test_live_run_requires_app_and_valid_extracted_identifier(client):
    project = client.post("/api/projects", json={"name": "Live target boundary"}).json()
    no_app = client.post(
        "/api/runs",
        json={
            "project_id": project["id"],
            "device_id": "android-device",
            "device_adapter": "android_adb",
            "proxy_adapter": "burp",
        },
    )
    assert no_app.status_code == 422
    assert "app_id" in no_app.json()["detail"]

    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("classes.dex", b"no manifest package")
    upload = client.post(
        f"/api/projects/{project['id']}/apps/upload",
        files={"file": ("missing-package.apk", payload.getvalue(), "application/octet-stream")},
    )
    assert upload.status_code == 201
    assert not upload.json()["package_name"]
    rejected = client.post(
        "/api/runs",
        json={
            "project_id": project["id"],
            "app_id": upload.json()["id"],
            "device_id": "android-device",
            "device_adapter": "android_adb",
            "proxy_adapter": "burp",
        },
    )
    assert rejected.status_code == 409
    assert "식별자" in rejected.json()["detail"]


def test_direct_device_action_uses_one_time_approval_lease_and_evidence(client):
    demo = client.post("/api/demo/bootstrap").json()
    run = client.post(
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
    _wait_until_paused(client, run["id"])
    action = {
        "adapter": "mock",
        "device_id": "mock-android-01",
        "action": "start",
        "project_id": demo["project"]["id"],
        "run_id": run["id"],
    }
    assert client.post("/api/devices/action", json=action).status_code == 409
    approval = client.post(
        "/api/approvals",
        json={
            "project_id": demo["project"]["id"],
            "run_id": run["id"],
            "resource_type": "device",
            "action": "start",
        },
    ).json()
    action["approval_token"] = approval["token"]
    executed = client.post("/api/devices/action", json=action)
    assert executed.status_code == 200
    assert executed.json()["evidence_id"]
    assert client.post("/api/devices/action", json=action).status_code == 409
    evidence = client.get(f"/api/runs/{run['id']}/evidence").json()
    assert any(item["evidence_type"] == "manual_device_action" for item in evidence)

    bypass = client.post(
        "/api/runtime/execute",
        json={
            "adapter": "objection",
            "project_id": demo["project"]["id"],
            "run_id": run["id"],
            "action": "android_ssl_pinning_disable",
            "approved": True,
        },
    )
    assert bypass.status_code == 409
    assert client.post(f"/api/runs/{run['id']}/stop").status_code == 200


def test_lan_api_requires_bearer_and_separate_admin_token(tmp_path: Path):
    with pytest.raises(ValidationError):
        AppSettings(host="192.0.2.10")
    settings = AppSettings(
        host="192.0.2.10",
        lan_access=True,
        api_token="a" * 32,
        admin_token="b" * 32,
        data_dir=tmp_path,
    )
    app = FastAPI()
    app.add_middleware(ApiSecurityMiddleware, settings=settings)

    @app.get("/api/value")
    def read_value():
        return {"ok": True}

    @app.post("/api/value")
    def write_value():
        return {"ok": True}

    with TestClient(app, base_url="http://192.0.2.10") as secured:
        assert secured.get("/api/value").status_code == 401
        bearer = {"Authorization": f"Bearer {settings.api_token}"}
        assert secured.get("/api/value", headers=bearer).status_code == 200
        assert secured.post("/api/value", headers=bearer).status_code == 403
        bearer["X-MSW-Admin-Token"] = str(settings.admin_token)
        assert secured.post("/api/value", headers=bearer).status_code == 200


@pytest.mark.asyncio
async def test_ios_inputs_and_bundle_id_are_rejected_before_command(client):
    invalid_host = client.post(
        "/api/devices/ios/profiles",
        json={"name": "bad", "host": "host; whoami", "username": "root"},
    )
    assert invalid_host.status_code == 422
    invalid_user = client.post(
        "/api/devices/ios/profiles",
        json={"name": "bad", "host": "127.0.0.1", "username": "root;id"},
    )
    assert invalid_user.status_code == 422
    with pytest.raises(ValueError):
        IOSDeviceAdapter(host="127.0.0.1;id")
    operation = await IOSDeviceAdapter(host="127.0.0.1").start_app(
        "ios-ssh:127.0.0.1:22", "com.example.good; touch /tmp/bad"
    )
    assert operation.status == CapabilityStatus.FAILED
    assert operation.command is None


def test_mobsf_destination_and_project_policy_block_unapproved_upload(tmp_path: Path):
    external = AppSettings(mobsf_url="https://203.0.113.10", mobsf_api_key="test")
    allowed, _ = validate_mobsf_destination(external)
    assert allowed is False
    local = AppSettings(mobsf_url="http://127.0.0.1:8000", mobsf_api_key="test")
    allowed, _ = validate_mobsf_destination(local)
    assert allowed is True

    adapter = MobSFAnalyzerAdapter(local, transmission_allowed=False)
    artifact = tmp_path / "sample.apk"
    artifact.write_bytes(b"not sent")
    result = __import__("asyncio").run(
        adapter.analyze(artifact, tmp_path / "out", platform="android")
    )
    assert result.status == CapabilityStatus.MANUAL_REQUIRED
    assert result.metadata["transmission_allowed"] is False


@pytest.mark.asyncio
async def test_androguard_runs_in_limited_worker_process(tmp_path: Path, monkeypatch):
    import backend.app.analyzers.adapters as adapter_module

    captured = {}

    async def fake_run(command, **kwargs):
        captured["command"] = list(command)
        captured["kwargs"] = kwargs
        return CommandResult(
            CapabilityStatus.FAILED,
            list(command),
            return_code=1,
            error="worker stopped",
        )

    monkeypatch.setattr(adapter_module.importlib.metadata, "version", lambda _: "test")
    monkeypatch.setattr(adapter_module, "run_command", fake_run)
    settings = AppSettings(
        data_dir=tmp_path,
        external_tool_memory_mb=256,
        external_tool_cpu_seconds=10,
    )
    result = await AndroguardAnalyzerAdapter(settings).analyze(
        tmp_path / "sample.apk", tmp_path / "output", platform="android"
    )
    assert result.status == CapabilityStatus.FAILED
    assert "backend.app.analyzers.androguard_worker" in captured["command"]
    assert captured["kwargs"]["memory_limit_mb"] == 256
    assert captured["kwargs"]["cpu_limit_seconds"] == 10


@pytest.mark.asyncio
async def test_proxy_start_reallocates_port_up_to_success(tmp_path: Path):
    settings = AppSettings(data_dir=tmp_path)
    orchestrator = DiagnosticOrchestrator(settings)
    first_port = allocate_available_port("127.0.0.1")
    run = DiagnosticRun(
        id="proxy-retry-run",
        project_id="project",
        device_id="device",
        device_adapter="android_adb",
        proxy_adapter="mitmproxy",
        run_mode="live",
        options={"proxy_listen_host": "127.0.0.1", "proxy_port": first_port},
    )
    attempts: list[int] = []

    class FakeProxy:
        async def start(self, run_id):
            port = int(run.options["proxy_port"])
            attempts.append(port)
            status = CapabilityStatus.AVAILABLE if len(attempts) == 3 else CapabilityStatus.FAILED
            return ProxyCapture(status, "started" if status == CapabilityStatus.AVAILABLE else "bind failed", "127.0.0.1", port)

        async def stop(self, run_id):
            return ProxyCapture(CapabilityStatus.AVAILABLE, "stopped", "127.0.0.1", int(run.options["proxy_port"]))

    class FakeDb:
        def commit(self):
            return None

    orchestrator._proxy = lambda _: FakeProxy()  # type: ignore[method-assign]
    await orchestrator.leases.acquire(run.id, run.device_id, first_port)
    _, capture = await orchestrator._start_proxy_with_retry(FakeDb(), run, FakeProxy())
    await orchestrator.leases.release(run.id)
    assert capture.status == CapabilityStatus.AVAILABLE
    assert len(attempts) == 3
    assert len(set(attempts)) == 3


def test_ai_confirmed_verdict_requires_evidence_and_platform_enum():
    base = {
        "title": "candidate",
        "category": "test",
        "platform": "android",
        "severity": "medium",
        "location": "runtime",
        "verdict": "confirmed",
        "confidence": 0.9,
        "rationale": "test",
        "reproduction": ["step"],
        "evidence_ids": [],
        "false_positive_risk": "low",
        "additional_checks": [],
    }
    with pytest.raises(ValidationError):
        AIFindingCandidate.model_validate(base)
    with pytest.raises(ValidationError):
        AIFindingCandidate.model_validate(
            {**base, "platform": "windows", "evidence_ids": ["evidence"]}
        )
