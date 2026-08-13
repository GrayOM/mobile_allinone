from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from backend.app.api.router import _normalize_control_validation_options
from backend.app.core.status import RunMode


def _wait_for_run(client, run_id: str, timeout: float = 30):
    deadline = time.monotonic() + timeout
    run = {}
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] in {"completed", "failed", "stopped"}:
            return run
        time.sleep(0.05)
    raise AssertionError(
        f"진단 실행이 {timeout}초 안에 끝나지 않았습니다: "
        f"status={run.get('status')} stage={run.get('current_stage')} error={run.get('error')}"
    )


def test_healthcheck_is_minimal_and_available_without_frontend(client):
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {
        "service": "Mobile Security Workbench",
        "status": "ok",
        "version": "0.2.0",
    }


def test_control_validation_requires_live_scope_and_full_attestation():
    device_id = "authorized-rooted-android-01"
    requested = {
        "enabled": True,
        "authorization_reference": "TICKET-2048",
        "approved_by": "고객사 보안책임자",
        "authorization_expires_at": (
            datetime.now(timezone.utc) + timedelta(hours=8)
        ).isoformat(),
        "authorized_device_id": device_id,
        "test_account_reference": "QA-ACCOUNT-03",
        "allowed_network_hosts": ["API.TEST.EXAMPLE", "*.sandbox.example"],
        "scope_description": "전용 루팅 Android 단말, 테스트 계정, 검증 서버만 사용",
        "authorized_scope_confirmed": True,
        "test_environment_confirmed": True,
        "test_data_only_confirmed": True,
    }
    with pytest.raises(HTTPException, match="Live 진단"):
        _normalize_control_validation_options(
            {"control_validation": requested}, RunMode.MOCK, device_id
        )

    missing_scope = dict(requested)
    missing_scope["test_data_only_confirmed"] = False
    with pytest.raises(HTTPException, match="테스트 계정·데이터"):
        _normalize_control_validation_options(
            {"control_validation": missing_scope}, RunMode.LIVE, device_id
        )

    wrong_device = dict(requested)
    wrong_device["authorized_device_id"] = "another-device"
    with pytest.raises(HTTPException, match="현재 선택한 단말"):
        _normalize_control_validation_options(
            {"control_validation": wrong_device}, RunMode.LIVE, device_id
        )

    normalized = _normalize_control_validation_options(
        {"control_validation": requested}, RunMode.LIVE, device_id
    )
    assert normalized is not None
    assert normalized["mode"] == "authorized_control_validation"
    assert normalized["execution_policy"] == "observation_only"
    assert normalized["automatic_control_evasion"] is False
    assert normalized["external_ai_excluded"] is True
    assert normalized["network_scope_policy"] == "default_deny"
    assert normalized["authorized_device_id"] == device_id
    assert normalized["allowed_network_hosts"] == [
        "api.test.example",
        "*.sandbox.example",
    ]
    assert normalized["authorization_expires_at"].endswith("+00:00")
    assert normalized["consent_recorded_at"]


def test_mock_demo_runs_end_to_end(client):
    bootstrap = client.post("/api/demo/bootstrap")
    assert bootstrap.status_code == 200
    demo = bootstrap.json()
    assert demo["app"]["package_name"] == "com.example.msw.demo"
    assert demo["app"]["analysis_status"] == "completed"

    started = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-01",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "pause_for_login": False,
        },
    )
    assert started.status_code == 201
    run = _wait_for_run(client, started.json()["id"])
    assert run["status"] == "completed", run["error"]
    assert run["run_mode"] == "mock"
    assert run["synthetic"] is True
    assert run["options"]["navigation"]["state_count"] >= 2
    assert run["options"]["navigation"]["action_count"] >= 1
    assert any(
        item["label"] == "송금"
        for item in run["options"]["pending_navigation_actions"]
    )
    assert run["options"]["storage"]["change_count"] >= 1
    assert run["options"]["storage"]["databases"][0]["masked"] is True
    assert run["options"]["network_testing"]["executed_count"] >= 1
    assert run["options"]["network_testing"]["pending_count"] >= 1

    evidence = client.get(f"/api/runs/{run['id']}/evidence").json()
    flows = client.get(f"/api/runs/{run['id']}/flows").json()
    raw_flows_response = client.get(f"/api/runs/{run['id']}/flows/raw")
    raw_flows = raw_flows_response.json()
    findings = client.get(f"/api/findings?run_id={run['id']}").json()

    assert len(evidence) >= 10
    assert {"screenshot", "network_capture", "device_log"} <= {
        item["evidence_type"] for item in evidence
    }
    assert not any(item["evidence_type"] == "frida_script" for item in evidence)
    assert len(flows) == 2
    assert all(item["synthetic"] is True for item in evidence)
    assert all(item["synthetic"] is True for item in flows)
    assert flows[0]["request_headers"]["Authorization"] == "[MASKED_FIELD]"
    assert flows[0]["response_headers"]["Set-Cookie"] == "[MASKED_FIELD]"
    assert raw_flows_response.headers["Cache-Control"] == "no-store"
    assert raw_flows[0]["request_headers"]["Authorization"].startswith("Bearer mock-")
    assert findings and findings[0]["source"] == "ai:mock"
    assert findings[0]["synthetic"] is True
    sources = client.get(f"/api/findings/{findings[0]['id']}/sources").json()
    assert sources[0]["evidence_ids"]

    report = client.post(f"/api/findings/{findings[0]['id']}/report")
    assert report.status_code == 200
    html = client.get(report.json()["url"])
    assert html.status_code == 200
    assert "증적 설명서" in html.text
    assert "SYNTHETIC MOCK" in html.text
    assert "원본 파일 내려받기" in html.text

    deleted = client.delete(f"/api/projects/{demo['project']['id']}")
    assert deleted.status_code == 200
    assert deleted.json()["recoverable"] is False
    assert client.get(f"/api/projects/{demo['project']['id']}").status_code == 404


def test_run_creation_rechecks_that_selected_device_is_discovered(client):
    demo = client.post("/api/demo/bootstrap").json()

    response = client.post(
        "/api/runs",
        json={
            "project_id": demo["project"]["id"],
            "app_id": demo["app"]["id"],
            "device_id": "mock-android-not-connected",
            "device_adapter": "mock",
            "proxy_adapter": "mock",
            "pause_for_login": False,
        },
    )

    assert response.status_code == 422
    assert "선택한 단말을 찾을 수 없습니다" in response.json()["detail"]


def test_custom_frida_script_requires_approval(client):
    demo = client.post("/api/demo/bootstrap").json()
    created = client.post(
        "/api/frida/scripts",
        json={
            "name": "Test candidate",
            "platform": "android",
            "category": "Custom",
            "target_framework": "generic",
            "conditions": [],
            "risk": "medium",
            "content": "setImmediate(function () { send({event: 'test'}); });",
            "source": "ai",
        },
    )
    assert created.status_code == 201
    script = created.json()
    assert script["approval_status"] == "pending_approval"

    denied = client.post(
        f"/api/frida/scripts/{script['id']}/execute",
        json={"mock": True},
    )
    assert denied.status_code == 409

    missing_review = client.post(f"/api/frida/scripts/{script['id']}/approve")
    assert missing_review.status_code == 422

    stale_review = client.post(
        f"/api/frida/scripts/{script['id']}/approve",
        json={
            "approver": "local_user",
            "review_acknowledged": True,
            "reviewed_sha256": "0" * 64,
        },
    )
    assert stale_review.status_code == 409

    approved = client.post(
        f"/api/frida/scripts/{script['id']}/approve",
        json={
            "approver": "local_user",
            "review_acknowledged": True,
            "reviewed_sha256": hashlib.sha256(
                script["content"].encode("utf-8")
            ).hexdigest(),
        },
    )
    assert approved.status_code == 200
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
        paused = client.get(f"/api/runs/{started['id']}").json()
        if paused["status"] == "safely_paused":
            break
        time.sleep(0.05)
    assert paused["status"] == "safely_paused"
    approval = client.post(
        "/api/approvals",
        json={
            "project_id": demo["project"]["id"],
            "run_id": started["id"],
            "resource_type": "frida",
            "action": f"execute:{script['id']}",
        },
    ).json()
    executed = client.post(
        f"/api/frida/scripts/{script['id']}/execute",
        json={
            "project_id": demo["project"]["id"],
            "run_id": started["id"],
            "approval_token": approval["token"],
        },
    )
    assert executed.status_code == 200
    assert executed.json()["status"] == "available"
    assert executed.json()["evidence_id"]
    assert client.post(f"/api/runs/{started['id']}/stop").status_code == 200
    refreshed = next(
        item
        for item in client.get("/api/frida/scripts").json()
        if item["id"] == script["id"]
    )
    assert refreshed["success_count"] == script["success_count"]


def test_login_pause_and_resume(client):
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
    )
    run_id = started.json()["id"]
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        run = client.get(f"/api/runs/{run_id}").json()
        if run["status"] == "safely_paused":
            break
        time.sleep(0.05)
    assert run["status"] == "safely_paused"
    assert run["current_stage"] == "manual_interaction"

    resumed = client.post(f"/api/runs/{run_id}/resume")
    assert resumed.status_code == 200
    assert _wait_for_run(client, run_id)["status"] == "completed"
