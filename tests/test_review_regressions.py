from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import ssl
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import psutil
import pytest
from sqlalchemy import select
from starlette.websockets import WebSocketDisconnect

import backend.app.analyzers.adapters as adapter_module
import backend.app.api.router as router_module
import backend.app.devices.android as android_module
import backend.app.devices.ios as ios_module
from backend.app.analyzers.adapters import MobSFAnalyzerAdapter
from backend.app.analyzers.locks import AnalysisLeaseManager
from backend.app.core.command import (
    CommandResult,
    capture_command_for_duration,
    run_binary_command,
)
from backend.app.core.config import AppSettings, ToolPaths
from backend.app.core.network import (
    DestinationSnapshot,
    PinnedNetworkBackend,
    approval_matches_destination,
    check_mobsf_transport_compatibility,
    inspect_mobsf_destination,
    pinned_http_transport,
)
from backend.app.core.status import CapabilityStatus, RunStatus
from backend.app.database.models import (
    AnalysisRun,
    AppArtifact,
    DiagnosticRun,
    Project,
    ToolRun,
)
from backend.app.database.session import SessionLocal
from backend.app.devices import AndroidDeviceAdapter, IOSDeviceAdapter, MockDeviceAdapter
from backend.app.devices.base import DeviceOperation
from backend.app.frida import (
    FridaSessionManager,
    FridaSessionScript,
    FridaTarget,
)
from backend.app.orchestration import DiagnosticOrchestrator, ManualActionInProgress
from backend.app.orchestration.diagnostic import _frida_evidence_integrity


def _wait_for_status(client, run_id: str, statuses: set[str], timeout: float = 30):
    deadline = time.monotonic() + timeout
    run = {}
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in statuses:
            return run
        time.sleep(0.05)
    raise AssertionError(
        f"진단이 {timeout}초 안에 {statuses} 상태에 도달하지 못했습니다: "
        f"status={run.get('status')} stage={run.get('current_stage')} error={run.get('error')}"
    )


def test_frida_drops_fail_evidence_integrity_but_truncation_is_informational():
    intact, intact_message = _frida_evidence_integrity(
        {"dropped_count": 0, "truncated_count": 12}
    )
    lost, lost_message = _frida_evidence_integrity(
        {"dropped_count": 5000, "truncated_count": 0}
    )
    assert intact is True
    assert "12" in intact_message
    assert lost is False
    assert "5000" in lost_message


def test_frida_message_loss_finishes_mock_run_with_quality_gap(client, monkeypatch):
    manager = client.app.state.orchestrator.frida_sessions
    original_stop = manager.stop

    async def stop_with_loss(run_id: str):
        result = await original_stop(run_id)
        if result is not None:
            result.stats["dropped_count"] = 3
        return result

    monkeypatch.setattr(manager, "stop", stop_with_loss)
    demo = client.post("/api/demo/bootstrap").json()
    response = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "auto_select_frida": True,
        },
    )
    assert response.status_code == 201
    run = _wait_for_status(
        client,
        response.json()["id"],
        {"completed", "completed_with_gaps", "failed"},
    )
    assert run["status"] == "completed_with_gaps", run.get("error")
    assert "frida_evidence_integrity" in run["options"]["failed_required_stages"]


def test_frida_empty_selection_is_none_and_auto_select_is_safe(client):
    demo = client.post("/api/demo/bootstrap").json()
    common = {
        "project_id": demo["project"]["id"],
        "app_id": demo["app"]["id"],
        "device_id": "mock-android-01",
        "device_adapter": "mock",
        "proxy_adapter": "mock",
        "pause_for_login": False,
    }
    empty = client.post(
        "/api/runs",
        json={**common, "frida_script_ids": [], "auto_select_frida": False},
    )
    assert empty.status_code == 201
    empty_run = _wait_for_status(
        client, empty.json()["id"], {"completed", "failed"}
    )
    assert empty_run["status"] == "completed", empty_run.get("error")
    evidence = client.get(f"/api/runs/{empty_run['id']}/evidence").json()
    assert not any(item["evidence_type"] == "frida_script" for item in evidence)

    unsafe = client.post(
        "/api/frida/scripts",
        json={
            "name": "Unsafe automatic candidate",
            "platform": "android",
            "category": "Custom",
            "target_framework": "generic",
            "conditions": [],
            "risk": "medium",
            "content": "setImmediate(function () { send({event: 'unsafe'}); });",
        },
    ).json()
    rejected = client.post(
        "/api/runs",
        json={**common, "frida_script_ids": [unsafe["id"]]},
    )
    assert rejected.status_code == 422
    assert "builtin" in rejected.json()["detail"]

    automatic = client.post(
        "/api/runs",
        json={**common, "auto_select_frida": True},
    )
    assert automatic.status_code == 201
    automatic_run = _wait_for_status(
        client, automatic.json()["id"], {"completed", "failed"}
    )
    assert automatic_run["status"] == "completed", automatic_run.get("error")
    automatic_evidence = client.get(
        f"/api/runs/{automatic_run['id']}/evidence"
    ).json()
    executed = [
        item for item in automatic_evidence if item["evidence_type"] == "frida_script"
    ]
    assert executed
    assert all(item["inline_data"]["risk"] == "low" for item in executed)


@pytest.mark.asyncio
async def test_frida_session_loads_multiple_scripts_once_and_detaches_at_run_end(
    monkeypatch: pytest.MonkeyPatch,
):
    events: list[str] = []

    class FakeScript:
        def __init__(self, name: str):
            self.name = name
            self.callback = None

        def on(self, _event, callback):
            self.callback = callback

        def load(self):
            events.append(f"load:{self.name}")
            self.callback({"type": "send", "payload": self.name}, None)

        def unload(self):
            events.append(f"unload:{self.name}")

    class FakeSession:
        def __init__(self):
            self.created: list[FakeScript] = []

        def create_script(self, _content, *, name):
            script = FakeScript(name)
            self.created.append(script)
            return script

        def detach(self):
            events.append("detach")

    class FakeDevice:
        def __init__(self):
            self.session = FakeSession()
            self.spawn_count = 0
            self.attach_count = 0

        def spawn(self, targets):
            self.spawn_count += 1
            assert targets == ["com.example.app"]
            return 4242

        def attach(self, pid):
            self.attach_count += 1
            assert pid == 4242
            return self.session

        def resume(self, pid):
            assert pid == 4242
            events.append("resume")

    device = FakeDevice()

    class FakeFrida:
        @staticmethod
        def get_device(device_id, timeout):
            assert device_id == "device-1"
            assert timeout == 5
            return device

    manager = FridaSessionManager(AppSettings())

    async def syntax_ok(_content):
        return CapabilityStatus.AVAILABLE, "ok"

    monkeypatch.setattr(manager.syntax, "check_syntax", syntax_ok)
    monkeypatch.setattr(
        "backend.app.frida.session.importlib.import_module",
        lambda name: FakeFrida if name == "frida" else None,
    )
    result = await manager.start(
        run_id="run-1",
        device_id="device-1",
        target="com.example.app",
        mode="spawn",
        scripts=[
            FridaSessionScript("script-1", "one", "send('one')"),
            FridaSessionScript("script-2", "two", "send('two')"),
        ],
    )
    assert result.status == CapabilityStatus.AVAILABLE
    assert manager.is_active("run-1")
    assert device.spawn_count == 1
    assert device.attach_count == 1
    assert events == ["load:one", "load:two", "resume"]
    assert len(manager.snapshot("run-1")) == 2
    assert "detach" not in events

    streamed: list[dict] = []
    manager.set_message_callback("run-1", streamed.append)
    device.session.created[0].callback(
        {"type": "send", "payload": "after-checkpoint"}, None
    )
    assert streamed[0]["message"]["payload"] == "after-checkpoint"

    stopped = await manager.stop("run-1")
    assert stopped is not None
    assert stopped.status == CapabilityStatus.AVAILABLE
    assert events[-3:] == ["unload:two", "unload:one", "detach"]
    assert not manager.is_active("run-1")


@pytest.mark.asyncio
async def test_frida_messages_use_bounded_ring_binary_serialization_and_transcript_limits(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    callback = None

    class FakeScript:
        def on(self, _event, handler):
            nonlocal callback
            callback = handler

        def load(self):
            return None

        def unload(self):
            return None

    class FakeSession:
        def create_script(self, _content, *, name):
            assert name == "bounded"
            return FakeScript()

        def detach(self):
            return None

    class FakeDevice:
        def attach(self, target):
            assert target == "com.example.app"
            return FakeSession()

    class FakeFrida:
        @staticmethod
        def get_device(device_id, timeout):
            assert (device_id, timeout) == ("device-1", 5)
            return FakeDevice()

    settings = AppSettings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
        frida_message_buffer_size=500,
        frida_message_max_bytes=512,
        frida_transcript_max_bytes=4_096,
        frida_stream_events_per_second=1_000,
    )
    manager = FridaSessionManager(settings)

    async def syntax_ok(_content):
        return CapabilityStatus.AVAILABLE, "ok"

    monkeypatch.setattr(manager.syntax, "check_syntax", syntax_ok)
    monkeypatch.setattr(
        "backend.app.frida.session.importlib.import_module",
        lambda name: FakeFrida if name == "frida" else None,
    )
    result = await manager.start(
        run_id="run-bounded",
        device_id="device-1",
        target="com.example.app",
        mode="attach",
        scripts=[FridaSessionScript("script-1", "bounded", "send('ok')")],
    )
    assert result.status == CapabilityStatus.AVAILABLE
    assert callback is not None

    for index in range(510):
        callback(
            {"type": "send", "payload": {"index": index, "text": "x" * 900}},
            b"\x00\xff" * 300,
        )

    snapshot = manager.snapshot("run-bounded")
    assert len(snapshot) == 500
    assert snapshot[-1]["message_type"] == "send"
    assert snapshot[-1]["data"]["encoding"] == "base64"
    assert snapshot[-1]["data"]["size"] == 600
    assert snapshot[-1]["truncated"] is True
    assert snapshot[-1]["original_size"] > settings.frida_message_max_bytes

    health = manager.health("run-bounded")
    assert health["buffer_count"] == 500
    assert health["truncated_count"] >= 510
    assert health["dropped_count"] > 0
    assert await manager.flush_transcript("run-bounded") is True
    health = manager.health("run-bounded")
    assert health["transcript_queue_count"] == 0
    transcript = Path(str(health["transcript_path"]))
    assert transcript.is_file()
    assert transcript.stat().st_size <= settings.frida_transcript_max_bytes
    transcript_lines = transcript.read_bytes().splitlines()
    assert all(len(line) <= settings.frida_message_max_bytes for line in transcript_lines)
    assert all(json.loads(line) for line in transcript_lines)

    stopped = await manager.stop("run-bounded")
    assert stopped is not None
    assert stopped.stats["dropped_count"] == health["dropped_count"]


@pytest.mark.asyncio
async def test_frida_transcript_queue_saturation_drops_without_blocking_callback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    gate = threading.Event()
    settings = AppSettings(
        data_dir=tmp_path,
        database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}",
        frida_transcript_queue_size=100,
        frida_transcript_max_bytes=2 * 1024 * 1024,
    )
    manager = FridaSessionManager(settings)
    original_writer = manager._transcript_writer

    def delayed_writer(active):
        gate.wait(timeout=3)
        original_writer(active)

    async def syntax_ok(_content):
        return CapabilityStatus.AVAILABLE, "ok"

    monkeypatch.setattr(manager, "_transcript_writer", delayed_writer)
    monkeypatch.setattr(manager.syntax, "check_syntax", syntax_ok)
    result = await manager.start(
        run_id="run-queue",
        device_id="mock-device",
        target="com.example.app",
        mode="attach",
        mock=True,
        scripts=[FridaSessionScript("script-1", "queue", "send('ok')")],
    )
    assert result.status == CapabilityStatus.AVAILABLE
    active = manager._sessions["run-queue"]
    for index in range(150):
        manager._record(
            active,
            "script-1",
            "queue",
            {"type": "send", "payload": {"index": index}},
            None,
        )
    health = manager.health("run-queue")
    assert health["transcript_queue_count"] == 100
    assert health["dropped_count"] >= 51

    gate.set()
    assert await manager.flush_transcript("run-queue") is True
    stopped = await manager.stop("run-queue")
    assert stopped and stopped.status == CapabilityStatus.AVAILABLE


@pytest.mark.asyncio
async def test_frida_remote_target_uses_official_device_manager(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    calls: list[tuple[str, str]] = []

    class FakeScript:
        def on(self, _event, _callback):
            return None

        def load(self):
            return None

        def unload(self):
            return None

    class FakeSession:
        def create_script(self, _content, *, name):
            return FakeScript()

        def detach(self):
            return None

    class FakeRemoteDevice:
        def attach(self, target):
            calls.append(("attach", target))
            return FakeSession()

    class FakeDeviceManager:
        def add_remote_device(self, endpoint):
            calls.append(("remote", endpoint))
            return FakeRemoteDevice()

        def remove_remote_device(self, endpoint):
            calls.append(("remove_remote", endpoint))

    class FakeFrida:
        @staticmethod
        def get_device_manager():
            return FakeDeviceManager()

        @staticmethod
        def get_device(*_args, **_kwargs):
            raise AssertionError("remote target must not use get_device")

    manager = FridaSessionManager(AppSettings(data_dir=tmp_path))

    async def syntax_ok(_content):
        return CapabilityStatus.AVAILABLE, "ok"

    monkeypatch.setattr(manager.syntax, "check_syntax", syntax_ok)
    monkeypatch.setattr(
        "backend.app.frida.session.importlib.import_module",
        lambda name: FakeFrida if name == "frida" else None,
    )
    result = await manager.start(
        run_id="run-remote",
        frida_target=FridaTarget.remote("192.0.2.25:27042"),
        target="com.example.ios",
        mode="attach",
        scripts=[FridaSessionScript("script-1", "remote", "send('ok')")],
    )
    assert result.status == CapabilityStatus.AVAILABLE
    assert calls == [("remote", "192.0.2.25:27042"), ("attach", "com.example.ios")]
    assert result.transport == "remote"
    assert result.endpoint == "192.0.2.25:27042"
    await manager.stop("run-remote")
    assert calls[-1] == ("remove_remote", "192.0.2.25:27042")


def test_frida_attach_and_spawn_lifecycles_preserve_ordered_evidence(client):
    demo = client.post("/api/demo/bootstrap").json()
    common = {
        "project_id": demo["project"]["id"],
        "app_id": demo["app"]["id"],
        "device_id": "mock-android-01",
        "device_adapter": "mock",
        "proxy_adapter": "mock",
        "auto_select_frida": True,
    }

    attach_response = client.post(
        "/api/runs",
        json={**common, "options": {"frida_mode": "attach"}},
    )
    assert attach_response.status_code == 201
    attach_run = _wait_for_status(
        client, attach_response.json()["id"], {"completed", "failed"}
    )
    assert attach_run["status"] == "completed", attach_run.get("error")
    attach_evidence = client.get(
        f"/api/runs/{attach_run['id']}/evidence"
    ).json()
    attach_titles = [item["title"] for item in attach_evidence]
    assert "Frida Attach 대상 프로세스 확인" in attach_titles
    assert "Frida Attach 후 프로세스 유지 확인" in attach_titles
    assert "Frida Spawn 전 앱 정상 종료" not in attach_titles

    spawn_response = client.post(
        "/api/runs",
        json={**common, "options": {"frida_mode": "spawn"}},
    )
    assert spawn_response.status_code == 201
    spawn_run = _wait_for_status(
        client, spawn_response.json()["id"], {"completed", "failed"}
    )
    assert spawn_run["status"] == "completed", spawn_run.get("error")
    spawn_evidence = client.get(
        f"/api/runs/{spawn_run['id']}/evidence"
    ).json()
    ordered = sorted(spawn_evidence, key=lambda item: item["sequence"])
    positions = {item["title"]: index for index, item in enumerate(ordered)}
    assert positions["앱 실행 직후"] < positions["Frida Spawn 전 앱 정상 종료"]
    assert (
        positions["Frida Spawn 전 앱 정상 종료"]
        < positions["Frida Spawn 전 프로세스 종료 확인"]
        < positions["Frida Spawn 후 프로세스 실행 확인"]
        < positions["우회 적용 후"]
    )
    script_evidence = next(
        item for item in ordered if item["evidence_type"] == "frida_script"
    )
    lifecycle_ids = script_evidence["inline_data"]["lifecycle_evidence_ids"]
    lifecycle_titles = {
        item["title"] for item in ordered if item["id"] in lifecycle_ids
    }
    assert {
        "우회 적용 전",
        "Frida Spawn 전 앱 정상 종료",
        "Frida Spawn 전 프로세스 종료 확인",
        "Frida Spawn 후 프로세스 실행 확인",
        "우회 적용 후",
    } <= lifecycle_titles
    transcript = next(
        item
        for item in ordered
        if item["title"] == "Run 수명 Frida JSONL transcript"
    )
    assert transcript["mime_type"] == "application/x-ndjson"
    assert spawn_run["options"]["frida_health"]["active"] is False
    assert spawn_run["options"]["frida_health"]["transport"] == "usb"


def test_frida_spawn_stop_failure_is_not_reported_as_success(
    client,
    monkeypatch: pytest.MonkeyPatch,
):
    class StopFailingDevice(MockDeviceAdapter):
        async def stop_app(self, device_id: str, package_name: str):
            return DeviceOperation(
                CapabilityStatus.FAILED,
                "synthetic stop failure",
                synthetic=True,
            )

    device = StopFailingDevice()
    monkeypatch.setattr(
        client.app.state.orchestrator,
        "device_for_run",
        lambda _db, _run: device,
    )
    demo = client.post("/api/demo/bootstrap").json()
    response = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "auto_select_frida": True,
            "options": {"frida_mode": "spawn"},
        },
    )
    assert response.status_code == 201
    run = _wait_for_status(client, response.json()["id"], {"completed", "failed"})
    assert run["status"] == "failed"
    assert "Spawn 전 앱 종료 실패" in run["error"]
    assert not client.app.state.orchestrator.frida_sessions.is_active(run["id"])


def _live_artifact_from_demo(client) -> tuple[Project, AppArtifact]:
    demo = client.post("/api/demo/bootstrap").json()
    settings = client.app.state.settings
    with SessionLocal() as db:
        source = db.get(AppArtifact, demo["app"]["id"])
        assert source is not None
        project = Project(
            name=f"Manual proxy {uuid.uuid4()}",
            description="manual proxy regression",
            ai_enabled=False,
            external_ai_allowed=False,
            external_analyzer_allowed=False,
            mock_mode=False,
            run_mode="live",
        )
        db.add(project)
        db.flush()
        target = settings.uploads_dir / project.id / f"{uuid.uuid4()}.apk"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source.stored_path, target)
        artifact = AppArtifact(
            project_id=project.id,
            original_name="manual-proxy.apk",
            stored_path=str(target),
            sha256=source.sha256,
            size_bytes=source.size_bytes,
            platform="android",
            app_name=source.app_name,
            package_name=source.package_name,
            version=source.version,
            analysis_status="completed",
            analysis_result=source.analysis_result,
            synthetic=False,
        )
        db.add(artifact)
        db.commit()
        db.refresh(project)
        db.refresh(artifact)
        db.expunge(project)
        db.expunge(artifact)
        return project, artifact


def test_failed_app_launch_cannot_finish_as_completed(
    client, monkeypatch: pytest.MonkeyPatch
):
    demo = client.post("/api/demo/bootstrap").json()

    class LaunchFailingDevice(MockDeviceAdapter):
        async def start_app(self, device_id: str, package_name: str):
            return DeviceOperation(
                CapabilityStatus.FAILED,
                "simulated launch failure",
                command=f"mock launch {package_name}",
                synthetic=True,
            )

    monkeypatch.setattr(
        client.app.state.orchestrator,
        "_device",
        lambda _adapter: LaunchFailingDevice(),
    )
    started = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
        },
    )
    assert started.status_code == 201
    finished = _wait_for_status(
        client,
        started.json()["id"],
        {"completed", "completed_with_gaps", "manual_required", "failed"},
    )
    assert finished["status"] == "failed"
    assert "앱 실행 실패" in finished["error"]


def test_burp_run_waits_for_nonempty_har_and_links_flows(
    client, monkeypatch: pytest.MonkeyPatch
):
    project, artifact = _live_artifact_from_demo(client)
    monkeypatch.setattr(
        client.app.state.orchestrator,
        "_device",
        lambda _adapter: MockDeviceAdapter(),
    )
    started = client.post(
        "/api/runs",
        json={
            "project_id": project.id,
            "app_id": artifact.id,
            "device_id": "mock-android-01",
            "device_adapter": "android_adb",
            "proxy_adapter": "burp",
            "options": {
                "proxy_listen_host": "192.0.2.10",
                "proxy_port": 8080,
            },
        },
    )
    assert started.status_code == 201
    run_id = started.json()["id"]
    paused = _wait_for_status(client, run_id, {"safely_paused", "failed"})
    assert paused["status"] == "safely_paused", paused.get("error")
    assert paused["current_stage"] == "proxy_manual_setup"
    assert client.post(f"/api/runs/{run_id}/resume").status_code == 409

    premature = client.post(
        f"/api/runs/{run_id}/proxy/import",
        files={"file": ("early.har", json.dumps({"log": {"entries": [{}]}}), "application/json")},
    )
    assert premature.status_code == 409
    confirmed = client.post(f"/api/runs/{run_id}/proxy/confirm-setup")
    assert confirmed.status_code == 200
    assert client.post(f"/api/runs/{run_id}/resume").status_code == 200
    paused = _wait_for_status(client, run_id, {"safely_paused", "failed"})
    assert paused["status"] == "safely_paused", paused.get("error")
    assert paused["current_stage"] == "proxy_capture_import"

    empty = client.post(
        f"/api/runs/{run_id}/proxy/import",
        files={"file": ("empty.har", json.dumps({"log": {"entries": []}}), "application/json")},
    )
    assert empty.status_code == 422

    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.test/v1/profile",
                        "headers": [{"name": "Accept", "value": "application/json"}],
                    },
                    "response": {
                        "status": 200,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "content": {"text": '{"ok":true}'},
                    },
                }
            ]
        }
    }
    imported = client.post(
        f"/api/runs/{run_id}/proxy/import",
        files={"file": ("capture.har", json.dumps(har), "application/json")},
    )
    assert imported.status_code == 200, imported.text
    assert imported.json()["flow_count"] == 1
    assert client.post(f"/api/runs/{run_id}/resume").status_code == 200
    finished = _wait_for_status(
        client, run_id, {"completed", "completed_with_gaps", "failed"}
    )
    assert finished["status"] == "completed_with_gaps", finished.get("error")
    assert "app_interaction" in finished["options"]["failed_required_stages"]
    flows = client.get(f"/api/runs/{run_id}/flows").json()
    assert len(flows) == 1
    assert flows[0]["url"] == "https://api.example.test/v1/profile"
    evidence = client.get(f"/api/runs/{run_id}/evidence").json()
    assert {"manual_proxy_import", "network_capture"} <= {
        item["evidence_type"] for item in evidence
    }


def test_control_validation_stops_after_out_of_scope_manual_proxy_flow(
    client, monkeypatch: pytest.MonkeyPatch
):
    project, artifact = _live_artifact_from_demo(client)
    monkeypatch.setattr(
        client.app.state.orchestrator,
        "_device",
        lambda _adapter: MockDeviceAdapter(),
    )
    started = client.post(
        "/api/runs",
        json={
            "project_id": project.id,
            "app_id": artifact.id,
            "device_id": "mock-android-01",
            "device_adapter": "android_adb",
            "proxy_adapter": "burp",
            "options": {
                "proxy_listen_host": "192.0.2.10",
                "proxy_port": 8080,
                "control_validation": {
                    "enabled": True,
                    "authorization_reference": "CUSTOMER-TICKET-2048",
                    "approved_by": "Customer Security Owner",
                    "authorization_expires_at": (
                        datetime.now(timezone.utc) + timedelta(hours=8)
                    ).isoformat(),
                    "authorized_device_id": "mock-android-01",
                    "test_account_reference": "QA-ACCOUNT-03",
                    "allowed_network_hosts": ["api.allowed.test"],
                    "scope_description": "승인된 테스트 단말과 허용 테스트 서버만 검증",
                    "authorized_scope_confirmed": True,
                    "test_environment_confirmed": True,
                    "test_data_only_confirmed": True,
                },
            },
        },
    )
    assert started.status_code == 201, started.text
    run_id = started.json()["id"]
    paused = _wait_for_status(client, run_id, {"safely_paused", "failed"})
    assert paused["current_stage"] == "proxy_manual_setup"
    assert client.post(f"/api/runs/{run_id}/proxy/confirm-setup").status_code == 200
    assert client.post(f"/api/runs/{run_id}/resume").status_code == 200
    paused = _wait_for_status(client, run_id, {"safely_paused", "failed"})
    assert paused["current_stage"] == "proxy_capture_import"

    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://outside.example/v1/profile",
                        "headers": [],
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {"text": '{"ok":true}'},
                    },
                }
            ]
        }
    }
    imported = client.post(
        f"/api/runs/{run_id}/proxy/import",
        files={"file": ("outside.har", json.dumps(har), "application/json")},
    )
    assert imported.status_code == 200, imported.text
    assert client.post(f"/api/runs/{run_id}/resume").status_code == 200

    finished = _wait_for_status(
        client,
        run_id,
        {"manual_required", "failed", "completed", "completed_with_gaps"},
    )
    assert finished["status"] == "manual_required", finished.get("error")
    assert "범위 밖 네트워크 목적지" in finished["error"]
    enforcement = finished["options"]["control_scope_enforcement"]
    assert enforcement["violation_count"] == 1
    assert enforcement["automatic_execution_stopped"] is True
    assert "network_testing" not in finished["options"]
    evidence = client.get(f"/api/runs/{run_id}/evidence").json()
    assert {"approval_record", "control_scope_enforcement"} <= {
        item["evidence_type"] for item in evidence
    }
    preflight = next(item for item in evidence if item["evidence_type"] == "device_state")
    assert "CUSTOMER-TICKET-2048" not in json.dumps(preflight["inline_data"])
    assert preflight["inline_data"]["options"]["control_validation"] == {
        "enabled": True,
        "scope_recorded_locally": True,
        "external_ai_excluded": True,
    }


@pytest.mark.asyncio
async def test_pause_request_only_allows_manual_action_at_safe_checkpoint(client):
    orchestrator = DiagnosticOrchestrator(client.app.state.settings)
    with SessionLocal() as db:
        project = Project(name=f"Pause state {uuid.uuid4()}", run_mode="mock", mock_mode=True)
        db.add(project)
        db.flush()
        run = DiagnosticRun(
            project_id=project.id,
            device_id="checkpoint-device",
            device_adapter="mock",
            proxy_adapter="mock",
            run_mode="mock",
            synthetic=True,
            status=RunStatus.RUNNING.value,
            current_stage="long_operation",
            options={},
        )
        db.add(run)
        db.commit()
        run_id = run.id
        project_id = project.id

    event = asyncio.Event()
    event.set()
    orchestrator._pause_events[run_id] = event
    assert await orchestrator.begin_manual_action(run_id) is False
    assert await orchestrator.pause(run_id) is True
    with SessionLocal() as db:
        assert db.get(DiagnosticRun, run_id).status == RunStatus.PAUSE_REQUESTED.value
    assert await orchestrator.begin_manual_action(run_id) is False

    checkpoint = asyncio.create_task(orchestrator._checkpoint(run_id))
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        with SessionLocal() as db:
            if db.get(DiagnosticRun, run_id).status == RunStatus.SAFELY_PAUSED.value:
                break
        await asyncio.sleep(0.01)
    assert await orchestrator.begin_manual_action(run_id) is True
    assert await orchestrator.resume(run_id) is False
    await orchestrator.end_manual_action(run_id)
    assert await orchestrator.resume(run_id) is True
    await asyncio.wait_for(checkpoint, timeout=1)

    with SessionLocal() as db:
        project = db.get(Project, project_id)
        if project:
            db.delete(project)
            db.commit()


@pytest.mark.asyncio
async def test_stop_is_rejected_while_manual_action_holds_run_lease(client):
    orchestrator = DiagnosticOrchestrator(client.app.state.settings)
    with SessionLocal() as db:
        project = Project(name=f"Manual stop {uuid.uuid4()}", run_mode="mock", mock_mode=True)
        db.add(project)
        db.flush()
        run = DiagnosticRun(
            project_id=project.id,
            device_id="manual-device",
            device_adapter="mock",
            proxy_adapter="mock",
            run_mode="mock",
            synthetic=True,
            status=RunStatus.SAFELY_PAUSED.value,
            current_stage="manual_interaction",
            options={},
        )
        db.add(run)
        db.commit()
        run_id = run.id
        project_id = project.id

    blocker = asyncio.Event()
    task = asyncio.create_task(blocker.wait())
    orchestrator._tasks[run_id] = task
    orchestrator._safe_pause_waiting.add(run_id)
    assert await orchestrator.begin_manual_action(run_id) is True
    with pytest.raises(ManualActionInProgress):
        await orchestrator.stop(run_id)
    with SessionLocal() as db:
        assert db.get(DiagnosticRun, run_id).options["manual_action_active"] is True
    await orchestrator.end_manual_action(run_id)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    with SessionLocal() as db:
        project = db.get(Project, project_id)
        if project:
            db.delete(project)
            db.commit()


@pytest.mark.asyncio
async def test_mobsf_dns_and_artifact_confirmation_are_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    settings = AppSettings(
        mobsf_url="http://mobsf.internal:8000",
        mobsf_api_key="test-key",
        mobsf_allowed_hosts=["mobsf.internal"],
        mobsf_allowed_networks=["127.0.0.0/8"],
    )

    async def mixed_dns(_self, _host, _port, **_kwargs):
        return [
            (2, 1, 6, "", ("127.0.0.1", 8000)),
            (2, 1, 6, "", ("203.0.113.44", 8000)),
        ]

    monkeypatch.setattr(asyncio.BaseEventLoop, "getaddrinfo", mixed_dns)
    with pytest.raises(ValueError, match="모든 A/AAAA"):
        await inspect_mobsf_destination(settings)

    snapshot = DestinationSnapshot(
        base_url="http://mobsf.internal:8000",
        origin="http://mobsf.internal:8000",
        addresses=("127.0.0.1",),
        certificate_sha256=None,
    )
    assert approval_matches_destination(
        snapshot,
        approved_destination=snapshot.base_url,
        approved_addresses=["127.0.0.1"],
        approved_certificate_sha256=None,
    )
    assert not approval_matches_destination(
        snapshot,
        approved_destination=snapshot.base_url,
        approved_addresses=["127.0.0.2"],
        approved_certificate_sha256=None,
    )

    async def current_destination(_settings):
        return snapshot

    monkeypatch.setattr(adapter_module, "inspect_mobsf_destination", current_destination)
    artifact = tmp_path / "artifact.apk"
    artifact.write_bytes(b"customer application")
    adapter = MobSFAnalyzerAdapter(
        settings,
        transmission_allowed=True,
        approved_destination=snapshot.base_url,
        approved_addresses=list(snapshot.addresses),
        expected_artifact_sha256="0" * 64,
    )
    result = await adapter.analyze(artifact, tmp_path / "out", platform="android")
    assert result.status == CapabilityStatus.MANUAL_REQUIRED
    assert "SHA-256" in (result.error or "")
    assert result.metadata["artifact_sha256"] == hashlib.sha256(
        artifact.read_bytes()
    ).hexdigest()


@pytest.mark.asyncio
async def test_mobsf_transport_connects_to_snapshot_ip_and_rechecks_tls():
    certificate = b"approved-certificate"
    snapshot = DestinationSnapshot(
        base_url="https://mobsf.internal:8443",
        origin="https://mobsf.internal:8443",
        addresses=("127.0.0.7",),
        certificate_sha256=hashlib.sha256(certificate).hexdigest(),
    )
    connected_hosts: list[str] = []

    class FakeSSL:
        def getpeercert(self, *, binary_form):
            assert binary_form is True
            return certificate

    class FakeStream:
        async def read(self, _max_bytes, _timeout=None):
            return b""

        async def write(self, _buffer, _timeout=None):
            return None

        async def aclose(self):
            return None

        async def start_tls(self, _context, *, server_hostname, timeout=None):
            assert server_hostname == "mobsf.internal"
            assert timeout is None
            return self

        def get_extra_info(self, info):
            if info == "server_addr":
                return ("127.0.0.7", 8443)
            if info == "ssl_object":
                return FakeSSL()
            return None

    class FakeBackend:
        async def connect_tcp(self, host, _port, **_kwargs):
            connected_hosts.append(host)
            return FakeStream()

        async def sleep(self, _seconds):
            return None

    backend = PinnedNetworkBackend(snapshot)
    backend._backend = FakeBackend()
    stream = await backend.connect_tcp("mobsf.internal", 8443)
    assert connected_hosts == ["127.0.0.7"]
    secured = await stream.start_tls(
        ssl.create_default_context(), server_hostname="mobsf.internal"
    )
    assert secured.get_extra_info("ssl_object") is not None


@pytest.mark.asyncio
async def test_mobsf_http_transport_uses_pinned_peer_without_dns():
    requests: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        requests.append(await reader.readuntil(b"\r\n\r\n"))
        body = b'{"status":"ok"}'
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    snapshot = DestinationSnapshot(
        base_url=f"http://mobsf.internal:{port}",
        origin=f"http://mobsf.internal:{port}",
        addresses=("127.0.0.1",),
        certificate_sha256=None,
    )
    try:
        async with httpx.AsyncClient(
            transport=pinned_http_transport(snapshot),
            trust_env=False,
            follow_redirects=False,
        ) as client:
            response = await client.get(f"{snapshot.base_url}/api/v1/health")
        assert response.json() == {"status": "ok"}
        assert f"Host: mobsf.internal:{port}\r\n".encode() in requests[0]
    finally:
        server.close()
        await server.wait_closed()


def test_mobsf_private_transport_dependency_range_is_checked_at_startup():
    compatible, message = check_mobsf_transport_compatibility(
        httpx_version="0.28.1", httpcore_version="1.0.9"
    )
    assert compatible is True
    assert "compatible" in message

    incompatible, message = check_mobsf_transport_compatibility(
        httpx_version="0.29.0", httpcore_version="1.1.0"
    )
    assert incompatible is False
    assert "httpx>=0.28,<0.29" in message


def test_websocket_ticket_is_run_scoped_and_single_use(client):
    demo = client.post("/api/demo/bootstrap").json()
    started = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
        },
    ).json()
    _wait_for_status(client, started["id"], {"completed", "failed"})
    issued = client.post("/api/ws-ticket", json={"run_id": started["id"]})
    assert issued.status_code == 201
    ticket = issued.json()["ticket"]
    assert issued.json()["single_use"] is True
    with client.websocket_connect(
        f"ws://127.0.0.1/api/runs/{started['id']}/ws?ticket={ticket}"
    ) as websocket:
        assert websocket.receive_json()["type"] == "connected"
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            f"ws://127.0.0.1/api/runs/{started['id']}/ws?ticket={ticket}"
        ):
            pass
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            f"ws://127.0.0.1/api/runs/{started['id']}/ws?access_token={'a' * 40}"
        ):
            pass


@pytest.mark.asyncio
async def test_binary_helpers_stop_timed_out_processes_and_capture_output(tmp_path: Path):
    pid_file = tmp_path / "binary.pid"
    result, _ = await run_binary_command(
        [
            sys.executable,
            "-c",
            (
                "import os,time,pathlib; "
                f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); "
                "time.sleep(30)"
            ),
        ],
        timeout=1,
    )
    assert result.status == CapabilityStatus.FAILED
    pid = int(pid_file.read_text(encoding="utf-8"))
    assert not psutil.pid_exists(pid)

    captured, output = await capture_command_for_duration(
        [
            sys.executable,
            "-u",
            "-c",
            "import time; print('started', flush=True); time.sleep(30)",
        ],
        duration_seconds=1,
    )
    assert captured.status == CapabilityStatus.AVAILABLE
    assert b"started" in output


@pytest.mark.asyncio
async def test_device_capture_uses_cleanup_aware_binary_helpers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    calls: list[list[str]] = []

    async def fake_binary(command, **_kwargs):
        calls.append(list(command))
        return (
            CommandResult(
                CapabilityStatus.AVAILABLE,
                list(command),
                return_code=0,
            ),
            b"\x89PNG\r\n\x1a\nmock",
        )

    monkeypatch.setattr(android_module, "run_binary_command", fake_binary)
    android = AndroidDeviceAdapter(
        AppSettings(tools=ToolPaths(adb=sys.executable))
    )
    screenshot = await android.screenshot("device-1", tmp_path / "screen.png")
    assert screenshot.status == CapabilityStatus.AVAILABLE
    assert len(calls) == 1
    assert calls[0][-3:] == ["exec-out", "screencap", "-p"]

    async def fake_capture(command, **_kwargs):
        return (
            CommandResult(
                CapabilityStatus.AVAILABLE,
                list(command),
                return_code=0,
            ),
            b"ios log line\n",
        )

    monkeypatch.setattr(ios_module, "capture_command_for_duration", fake_capture)
    ios = IOSDeviceAdapter(
        AppSettings(tools=ToolPaths(idevicesyslog=sys.executable))
    )
    logs = await ios.collect_logs("ios-device-1", tmp_path / "ios.log")
    assert logs.status == CapabilityStatus.AVAILABLE
    assert (tmp_path / "ios.log").read_text(encoding="utf-8") == "ios log line\n"


@pytest.mark.asyncio
async def test_analysis_lease_is_exclusive():
    leases = AnalysisLeaseManager()
    assert await leases.try_acquire("app-1") is True
    assert await leases.try_acquire("app-1") is False
    assert await leases.try_acquire("app-2") is True
    await leases.release("app-1")
    assert await leases.try_acquire("app-1") is True


def test_reanalysis_returns_409_when_locked_and_activates_unique_directory(client):
    demo = client.post("/api/demo/bootstrap").json()
    app_id = demo["app"]["id"]
    before = demo["app"]["analysis_result"]["structure"]["analysis_output_dir"]
    leases = client.app.state.analysis_leases
    assert client.portal.call(leases.try_acquire, app_id) is True
    try:
        blocked = client.post(f"/api/apps/{app_id}/reanalyze")
        assert blocked.status_code == 409
        assert "analysis_in_progress" in blocked.json()["detail"]
    finally:
        client.portal.call(leases.release, app_id)

    completed = client.post(f"/api/apps/{app_id}/reanalyze")
    assert completed.status_code == 200, completed.text
    after = completed.json()["analysis_result"]["structure"]["analysis_output_dir"]
    assert after != before
    assert Path(after).parent.name == "runs"
    with SessionLocal() as db:
        artifact = db.get(AppArtifact, app_id)
        assert artifact is not None
        latest = (
            client.app.state.settings.analysis_dir
            / Path(artifact.stored_path).stem
            / "latest.json"
        )
    activated = json.loads(latest.read_text(encoding="utf-8"))
    assert activated["output_dir"] == after
    assert activated["analysis_run_id"] == completed.json()["active_analysis_run_id"]


def test_reanalysis_activation_failure_keeps_previous_db_and_pointer(
    client, monkeypatch: pytest.MonkeyPatch
):
    demo = client.post("/api/demo/bootstrap").json()
    app_id = demo["app"]["id"]
    with SessionLocal() as db:
        artifact = db.get(AppArtifact, app_id)
        assert artifact is not None
        previous_active = artifact.active_analysis_run_id
        previous_result = artifact.analysis_result
        previous_tool_ids = list(
            db.scalars(select(ToolRun.id).where(ToolRun.app_id == app_id))
        )
        latest = (
            client.app.state.settings.analysis_dir
            / Path(artifact.stored_path).stem
            / "latest.json"
        )
        previous_pointer = latest.read_bytes()

    real_replace = router_module.os.replace

    def fail_latest(source, destination):
        if Path(destination).name == "latest.json":
            raise OSError("simulated pointer activation failure")
        return real_replace(source, destination)

    monkeypatch.setattr(router_module.os, "replace", fail_latest)
    failed = client.post(f"/api/apps/{app_id}/reanalyze")
    assert failed.status_code == 422
    assert "활성" in failed.json()["detail"] or "재분석" in failed.json()["detail"]

    with SessionLocal() as db:
        artifact = db.get(AppArtifact, app_id)
        assert artifact is not None
        assert artifact.active_analysis_run_id == previous_active
        assert artifact.analysis_result == previous_result
        assert list(db.scalars(select(ToolRun.id).where(ToolRun.app_id == app_id))) == previous_tool_ids
        newest = db.scalars(
            select(AnalysisRun)
            .where(AnalysisRun.app_id == app_id)
            .order_by(AnalysisRun.created_at.desc())
        ).first()
        assert newest is not None
        assert newest.status == "failed"
    assert latest.read_bytes() == previous_pointer


def test_launcher_and_frontend_do_not_persist_access_tokens_in_urls():
    root = Path(__file__).resolve().parents[1]
    launcher = (root / "run_windows.ps1").read_text(encoding="utf-8")
    api_source = (root / "frontend" / "src" / "api.ts").read_text(encoding="utf-8")
    live_source = (root / "frontend" / "src" / "pages" / "LiveRunPage.tsx").read_text(encoding="utf-8")
    finding_source = (root / "frontend" / "src" / "pages" / "FindingDetailPage.tsx").read_text(encoding="utf-8")
    assert "access_token=" not in launcher
    assert "admin_token=" not in launcher
    assert "Start-Process $Url" in launcher
    assert "sessionStorage" not in api_source
    assert "?access_token=" not in api_source
    assert "/ws-ticket" in api_source
    assert "apiBlob" in api_source
    assert "src={\u0060/api/evidence/" not in live_source
    assert "src={\u0060/api/evidence/" not in finding_source
    assert "href={\u0060/api/evidence/" not in finding_source
    assert "openAuthenticatedFile" in finding_source
