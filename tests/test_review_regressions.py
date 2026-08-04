from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import sys
import time
import uuid
from pathlib import Path

import psutil
import pytest
from starlette.websockets import WebSocketDisconnect

import backend.app.analyzers.adapters as adapter_module
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
    approval_matches_destination,
    inspect_mobsf_destination,
)
from backend.app.core.status import CapabilityStatus, RunStatus
from backend.app.database.models import AppArtifact, DiagnosticRun, Project
from backend.app.database.session import SessionLocal
from backend.app.devices import AndroidDeviceAdapter, IOSDeviceAdapter, MockDeviceAdapter
from backend.app.orchestration import DiagnosticOrchestrator


def _wait_for_status(client, run_id: str, statuses: set[str], timeout: float = 12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in statuses:
            return run
        time.sleep(0.05)
    raise AssertionError(f"진단이 제한시간 안에 {statuses} 상태에 도달하지 못했습니다.")


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
    finished = _wait_for_status(client, run_id, {"completed", "failed"})
    assert finished["status"] == "completed", finished.get("error")
    flows = client.get(f"/api/runs/{run_id}/flows").json()
    assert len(flows) == 1
    assert flows[0]["url"] == "https://api.example.test/v1/profile"
    evidence = client.get(f"/api/runs/{run_id}/evidence").json()
    assert {"manual_proxy_import", "network_capture"} <= {
        item["evidence_type"] for item in evidence
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


def test_launcher_and_frontend_do_not_persist_access_tokens_in_urls():
    root = Path(__file__).resolve().parents[1]
    launcher = (root / "run_windows.ps1").read_text(encoding="utf-8")
    api_source = (root / "frontend" / "src" / "api.ts").read_text(encoding="utf-8")
    assert "access_token=" not in launcher
    assert "admin_token=" not in launcher
    assert "Start-Process $Url" in launcher
    assert "sessionStorage" not in api_source
    assert "?access_token=" not in api_source
    assert "/ws-ticket" in api_source
