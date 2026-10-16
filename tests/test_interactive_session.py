from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone

from backend.app.api.router import _normalize_control_validation_options
from backend.app.core.status import CapabilityStatus, RunMode
from backend.app.proxy.disabled import DisabledProxyAdapter


def _wait_for(client, run_id: str, statuses: set[str], timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    current: dict = {}
    while time.monotonic() < deadline:
        current = client.get(f"/api/runs/{run_id}").json()
        if current.get("status") in statuses:
            return current
        time.sleep(0.05)
    raise AssertionError(
        f"run timeout: {current.get('status')} {current.get('current_stage')}"
    )


def test_device_only_scope_accepts_no_network_hosts():
    device_id = "authorized-ios-device"
    scope = {
        "enabled": True,
        "authorization_reference": "LAB-DVIA-001",
        "approved_by": "local-owner",
        "authorization_expires_at": (
            datetime.now(timezone.utc) + timedelta(hours=2)
        ).isoformat(),
        "authorized_device_id": device_id,
        "test_account_reference": "local-lab",
        "allowed_network_hosts": [],
        "scope_description": "DVIA device-only interactive diagnostic session",
        "authorized_scope_confirmed": True,
        "test_environment_confirmed": True,
        "test_data_only_confirmed": True,
    }
    normalized = _normalize_control_validation_options(
        {
            "network_capture_required": False,
            "control_validation": scope,
        },
        RunMode.LIVE,
        device_id,
    )
    assert normalized is not None
    assert normalized["network_scope_policy"] == "not_in_scope"
    assert normalized["allowed_network_hosts"] == []


def test_device_only_session_preserves_explicit_server_allowlist():
    device_id = "authorized-ios-device"
    scope = {
        "enabled": True,
        "authorization_reference": "LAB-OJT-SERVER-001",
        "approved_by": "local-owner",
        "authorization_expires_at": (
            datetime.now(timezone.utc) + timedelta(hours=2)
        ).isoformat(),
        "authorized_device_id": device_id,
        "test_account_reference": "synthetic-account",
        "allowed_network_hosts": ["example.test"],
        "scope_description": "Device session with a separately approved server target",
        "authorized_scope_confirmed": True,
        "test_environment_confirmed": True,
        "test_data_only_confirmed": True,
    }
    normalized = _normalize_control_validation_options(
        {
            "network_capture_required": False,
            "control_validation": scope,
        },
        RunMode.LIVE,
        device_id,
    )
    assert normalized is not None
    assert normalized["network_scope_policy"] == "default_deny"
    assert normalized["allowed_network_hosts"] == ["example.test"]


def test_disabled_proxy_is_real_device_only_not_synthetic():
    adapter = DisabledProxyAdapter()
    status = asyncio.run(adapter.start("device-only-run"))
    assert status.status == CapabilityStatus.AVAILABLE
    assert status.synthetic is False
    assert asyncio.run(adapter.read_flows("device-only-run")) == []


def test_paused_run_supports_repeatable_manual_checkpoint(client):
    demo = client.post("/api/demo/bootstrap").json()
    started = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "pause_for_login": False,
            "options": {
                "interactive_session": True,
                "auto_navigation": False,
                "dynamic_storage": False,
                "background_screen_check": False,
            },
        },
    )
    assert started.status_code == 201, started.text
    run_id = started.json()["id"]
    paused = _wait_for(client, run_id, {"safely_paused"})
    assert paused["current_stage"] == "manual_interaction"

    captured = client.post(
        f"/api/runs/{run_id}/checkpoints",
        json={
            "label": "테스트 값 저장 후",
            "note": "수동 재현 직후 화면과 로그",
            "control_ids": [],
        },
    )
    assert captured.status_code == 200, captured.text
    assert len(captured.json()["evidence_ids"]) >= 4

    refreshed = client.get(f"/api/runs/{run_id}").json()
    assert refreshed["status"] == "safely_paused"
    assert refreshed["options"]["manual_checkpoints"][0]["label"] == "테스트 값 저장 후"
    evidence = client.get(f"/api/runs/{run_id}/evidence").json()
    kinds = {item["evidence_type"] for item in evidence}
    assert {"interaction_checkpoint", "screenshot", "device_log", "command_log"} <= kinds

    resumed = client.post(f"/api/runs/{run_id}/resume")
    assert resumed.status_code == 200, resumed.text
    finished = _wait_for(
        client,
        run_id,
        {"completed", "completed_with_gaps", "failed", "manual_required"},
    )
    assert finished["status"] == "completed", finished.get("error")
    assert len(finished["options"]["manual_checkpoints"]) == 1
    assert "체크포인트 1건" in finished["options"]["completion_checks"][
        "app_interaction"
    ]["message"]
    assert finished["options"]["completion_checks"]["app_interaction"]["passed"] is True
